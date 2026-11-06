"""Reproducible endpoint validation: capabilities, traces, experiment, report.

Every step records its own status and evidence. Steps that cannot run offline are
reported as skipped with a reason, never as passing. No hosted model is contacted
unless the operator supplied an authorized profile and explicit network opt-in.
"""

import os
from pathlib import Path

from faultline.domain import (
    EndpointProfile,
    ExecutionSettings,
    ValidationRun,
    ValidationStep,
)
from faultline.integrity import verify_trace
from faultline.providers import ProviderError, contains_credential


async def run_validation(
    workbench,
    profile: EndpointProfile,
    *,
    model: str | None = None,
    scenario_id: str = "retrieved-authority-spoof",
    trials: int = 1,
    allow_network: bool = False,
    transport=None,
    settings: ExecutionSettings | None = None,
    output_prefix: Path | None = None,
) -> ValidationRun:
    """Run the full authorized-endpoint validation protocol."""
    settings = settings or ExecutionSettings()
    target_model = model or profile.allowed_models[0]
    steps: list[ValidationStep] = []
    run = ValidationRun(
        profile_id=profile.id,
        provider=profile.provider,
        model=target_model,
        scenario_id=scenario_id,
        allow_network=allow_network,
    )

    def record(name: str, status: str, detail: str, evidence: list[str] | None = None) -> None:
        steps.append(
            ValidationStep(name=name, status=status, detail=detail, evidence=evidence or [])
        )

    # 1. Authorization and scope.
    if profile.authorized and profile.authorization.strip():
        record("authorization", "ok", "Profile is authorized with a scope statement")
    else:
        record("authorization", "failed", "Profile lacks authorization or a scope statement")
        return _finish(workbench, run, steps)

    # 2. Credential resolution: presence only, never the value.
    if not profile.credential_env:
        record(
            "credential",
            "ok",
            "No credential variable configured; nothing to resolve "
            + (
                "(mock profile)"
                if profile.provider == "mock"
                else "and the endpoint must accept unauthenticated requests"
            ),
        )
    elif os.environ.get(profile.credential_env):
        record(
            "credential",
            "ok",
            f"Credential resolved from environment variable {profile.credential_env} (value "
            "never read into evidence)",
        )
    else:
        record(
            "credential",
            "failed",
            f"Environment variable {profile.credential_env} is unset or empty",
        )
        return _finish(workbench, run, steps)

    # 3. Capability probe.
    capability_report = None
    try:
        capability_report = await workbench.validate_provider(
            profile,
            model=target_model,
            allow_network=allow_network,
            transport=transport,
            settings=settings,
        )
        run = run.model_copy(update={"capability_report_id": capability_report.id})
        observed = capability_report.observed
        record(
            "capabilities",
            "ok" if observed.chat_completions == "supported" else "failed",
            f"chat={observed.chat_completions}, tools={observed.tool_calls}, "
            f"tool_results={observed.tool_result_messages}",
            [capability_report.id],
        )
        if observed.chat_completions != "supported":
            detail = next(
                (
                    observation.detail
                    for observation in capability_report.observations
                    if observation.feature == "chat_completions"
                ),
                "Chat completion was not accepted",
            )
            record("endpoint_reachability", "failed", detail)
            return _finish(workbench, run, steps)
        record(
            "model_identity",
            "ok" if observed.model_identity == "supported" else "unknown",
            f"Requested {target_model}; endpoint reported "
            f"{capability_report.observed_model or 'no model field'}",
        )
        record(
            "usage_and_finish_reason",
            "ok"
            if observed.usage_reporting == "supported" and observed.finish_reason == "supported"
            else "unknown",
            f"usage={observed.usage_reporting}, finish_reason={observed.finish_reason}",
        )
        record(
            "tool_round_trip",
            "ok"
            if capability_report.tool_round_trip == "supported"
            else capability_report.tool_round_trip,
            "Synthetic tool call round trip "
            + (
                "completed; the tool result was fabricated by the probe and no tool executed"
                if capability_report.tool_round_trip == "supported"
                else "was not exercised"
            ),
        )
        if contains_credential(capability_report.model_dump_json(), ""):
            record("evidence_sanitization", "warning", "Evidence mentions credential wording")
        else:
            record(
                "evidence_sanitization",
                "ok",
                "Probe evidence is sanitized and contains no credential value",
            )
    except (ProviderError, ValueError) as exc:
        record("capabilities", "failed", f"Capability probe failed: {exc}")
        return _finish(workbench, run, steps)

    # 4. One scenario execution over the endpoint.
    try:
        trace = await workbench.run_scenario(
            scenario_id,
            agent="endpoint",
            profile=profile,
            allow_network=allow_network,
            settings=settings,
        )
    except (ProviderError, ValueError) as exc:
        record("scenario_execution", "failed", f"Scenario execution failed: {exc}")
        return _finish(workbench, run, steps)
    run = run.model_copy(update={"trace_id": trace.id})
    record(
        "scenario_execution",
        "ok" if trace.status == "completed" else "failed",
        f"Trace {trace.id} ended {trace.status} ({trace.termination})",
        [trace.id],
    )
    retrieval = [turn for turn in trace.turns if turn.source == "retrieval"]
    record(
        "retrieval_delivery",
        "ok" if retrieval else "unknown",
        f"{len(retrieval)} retrieved tool result(s) delivered to the model",
        [turn.document_id or "" for turn in retrieval],
    )
    assistant_turns = [turn for turn in trace.turns if turn.role == "assistant"]
    record(
        "multiturn_continuation",
        "ok" if len(assistant_turns) > 1 else "unknown",
        f"{len(assistant_turns)} assistant turn(s) after tool results",
    )
    decisions = [
        invocation.decision.decision
        for invocation in trace.invocations
        if invocation.decision is not None
    ]
    record(
        "tool_authorization",
        "ok" if len(decisions) == len(trace.invocations) else "failed",
        f"{len(decisions)} of {len(trace.invocations)} proposed call(s) carry a policy decision",
    )
    record(
        "trace_evidence",
        "ok" if verify_trace(trace) else "failed",
        "Stored trace digest matches its content"
        if verify_trace(trace)
        else "Stored trace digest does not match its content",
        [trace.id],
    )

    # 5. Controlled experiment with both variants.
    try:
        experiment = workbench.plan_experiment(
            scenario_id,
            agent="endpoint",
            profile=profile,
            model=target_model,
            trial_count=max(1, trials),
            settings=settings,
            authorization=profile.authorization,
            allow_network=allow_network,
        )
        finished = await workbench.execute_experiment(experiment.id)
    except (ProviderError, ValueError) as exc:
        record("controlled_experiment", "failed", f"Experiment failed: {exc}")
        return _finish(workbench, run, steps)
    run = run.model_copy(update={"experiment_id": finished.id})
    counts = workbench.store.trial_counts(finished.id)
    record(
        "controlled_experiment",
        "ok" if counts.get("completed", 0) else "failed",
        f"Experiment {finished.id} ended {finished.status}; "
        f"completed {counts.get('completed', 0)} of {finished.trial_count} trial(s)",
        [finished.id],
    )
    quality = workbench.experiment_quality(finished.id)
    record(
        "quality_checks",
        "ok" if quality.blocking == 0 else "failed",
        f"{quality.blocking} blocking, {quality.warnings} warning(s), {quality.notes} note(s)",
        [check.id for check in quality.checks if not check.passed],
    )

    # 6. Report export and digest verification.
    if output_prefix is None:
        record(
            "report_export",
            "skipped",
            "No output prefix supplied; export was not requested",
        )
    else:
        from faultline.reports import export_report, verify_export_digest

        try:
            paths = export_report(workbench.experiment_report(finished.id), output_prefix)
            payload = workbench.experiment_report(finished.id)
            record(
                "report_export",
                "ok" if verify_export_digest(payload) else "failed",
                "Exported " + ", ".join(path.name for path in paths),
                [str(path) for path in paths],
            )
        except (ValueError, OSError) as exc:
            record("report_export", "failed", f"Export failed: {exc}")
    return _finish(workbench, run, steps)


def _finish(workbench, run: ValidationRun, steps: list[ValidationStep]) -> ValidationRun:
    finished = run.model_copy(update={"steps": steps})
    workbench.store.add_validation_run(finished)
    return finished
