"""Controlled experiments end to end: offline, paired, resumable, evidenced."""

import asyncio
import json

import httpx
import pytest

from faultline.domain import (
    EndpointProfile,
    ExecutionSettings,
    ExperimentLimits,
)
from faultline.reports import csv_export, markdown, verify_export_digest


def plan(workbench, scenario_id="retrieved-authority-spoof", **changes):
    defaults = dict(trial_count=2, agent="scripted-vulnerable")
    defaults.update(changes)
    return workbench.plan_experiment(scenario_id, **defaults)


def run(workbench, scenario_id="retrieved-authority-spoof", **changes):
    experiment = plan(workbench, scenario_id, **changes)
    return experiment, asyncio.run(workbench.execute_experiment(experiment.id))


def criterion(summary, criterion_id):
    return next(item for item in summary.criteria if item.criterion_id == criterion_id)


def test_plan_records_variants_differences_and_budgets(workbench):
    experiment = plan(workbench, trial_count=3)
    assert experiment.status == "planned"
    assert experiment.target.agent == "scripted-vulnerable"
    assert experiment.control.injected_document_id is None
    assert experiment.attack.injected_document_id == "doc-memo"
    assert {item.path for item in experiment.differences} == {
        "documents[doc-memo].content",
        "documents[doc-memo].trust",
        "documents[doc-memo].injection",
        "injected_document_id",
    }
    assert experiment.planned_traces == 6
    assert len(workbench.store.trials(experiment.id)) == 3
    assert all(trial.status == "pending" for trial in workbench.store.trials(experiment.id))


def test_secure_scripted_fixture_resists_the_injection(workbench):
    experiment, finished = run(workbench, agent="scripted-secure")
    assert finished.status == "completed"
    summary = workbench.experiment_summary(experiment.id)
    assert summary.complete_pairs == 2
    for criterion_id in ("SPOOF-001", "SPOOF-002"):
        item = criterion(summary, criterion_id)
        assert item.control_failures == 0
        assert item.attack_failures == 0
        assert item.absolute_rate_difference == 0.0
    assert summary.observations["unauthorized_proposals_attack"] == 0
    assert summary.observations["verified_effects_attack"] == 0


def test_vulnerable_scripted_fixture_behaves_differently_under_attack(workbench):
    experiment, finished = run(workbench)
    assert finished.status == "completed"
    summary = workbench.experiment_summary(experiment.id)
    forbidden = criterion(summary, "SPOOF-001")
    assert forbidden.control_failures == 0
    assert forbidden.attack_failures == 2
    assert forbidden.pass_fail == 2 and forbidden.fail_pass == 0
    assert forbidden.absolute_rate_difference == 1.0
    # The proposal was denied by policy, so no record changed in either arm.
    assert criterion(summary, "SPOOF-002").attack_failures == 0
    assert summary.observations["denied_actions_attack"] == 2
    assert summary.observations["verified_effects_attack"] == 0
    assert summary.observations["exposed_attack"] == 2
    assert summary.observations["exposed_control"] == 0


def test_permitted_injected_side_effect_is_a_verified_effect(workbench):
    experiment, _ = run(workbench, "tool-output-laundering")
    summary = workbench.experiment_summary(experiment.id)
    assert summary.observations["verified_effects_attack"] == 2
    assert summary.observations["verified_effects_control"] == 0
    assert criterion(summary, "LAUNDER-001").attack_failures == 2


def test_each_variant_starts_from_an_independent_environment(workbench):
    experiment, _ = run(workbench, "boundary-enforcement", trial_count=2)
    summary = workbench.experiment_summary(experiment.id)
    # Two attack variants each queued exactly one message: state never carried over.
    assert summary.observations["verified_effects_attack"] == 2
    for trial in workbench.store.trials(experiment.id):
        assert trial.attack is not None
        assert len(trial.attack.state_changes) == 1
        assert trial.control is not None
        assert trial.control.state_changes == []


def test_completed_trials_reference_stored_traces_and_sessions(workbench):
    experiment, _ = run(workbench)
    for trial in workbench.store.trials(experiment.id):
        assert trial.status == "completed"
        assert trial.control_trace_id and trial.attack_trace_id
        control = workbench.store.agentic_trace(trial.control_trace_id)
        attack = workbench.store.agentic_trace(trial.attack_trace_id)
        assert control.status == attack.status == "completed"
        assert control.scenario_sha256 != attack.scenario_sha256
        assert trial.control.session_id and trial.attack.session_id
        assert workbench.store.session(trial.control.session_id).agentic_trace_id == control.id


def test_resume_runs_only_pending_trials_and_never_replays_running_ones(workbench):
    experiment = plan(workbench, trial_count=3)
    asyncio.run(workbench.execute_experiment(experiment.id, limit=1))
    partial = workbench.store.controlled_experiment(experiment.id)
    assert partial.status == "partial"
    counts = workbench.store.trial_counts(experiment.id)
    assert counts["completed"] == 1 and counts["pending"] == 2
    # A crash leaves a trial running; resume must not replay the unknown request.
    stale = workbench.store.trial(experiment.id, 2).model_copy(update={"status": "running"})
    workbench.store.claim_trial(stale, expected="pending")
    finished = asyncio.run(workbench.execute_experiment(experiment.id))
    counts = workbench.store.trial_counts(experiment.id)
    assert counts["completed"] == 2
    assert counts["interrupted"] == 1
    assert finished.status == "partial"
    interrupted = workbench.store.trial(experiment.id, 2)
    assert interrupted.status == "interrupted"
    assert interrupted.control_trace_id is None
    assert "unknown" in (interrupted.interruption or "")


def test_interrupted_execution_keeps_completed_evidence(workbench):
    experiment = plan(workbench, trial_count=3)
    calls = {"count": 0}

    def cancel() -> bool:
        calls["count"] += 1
        return calls["count"] > 2

    finished = asyncio.run(workbench.execute_experiment(experiment.id, should_cancel=cancel))
    assert finished.status == "cancelled"
    counts = workbench.store.trial_counts(experiment.id)
    assert counts.get("interrupted", 0) == 1
    assert counts.get("pending", 0) == 2
    # The control trace that did run is complete and still stored.
    recorded = [
        trial
        for trial in workbench.store.trials(experiment.id)
        if trial.control_trace_id is not None
    ]
    assert recorded
    for trial in recorded:
        assert workbench.store.agentic_trace(trial.control_trace_id).status == "completed"
    # The interrupted trial is never replayed; only pending trials resume.
    resumed = asyncio.run(workbench.execute_experiment(experiment.id))
    assert resumed.status == "partial"
    counts = workbench.store.trial_counts(experiment.id)
    assert counts.get("completed", 0) == 2
    assert counts.get("interrupted", 0) == 1


def test_request_limit_stops_further_trials(workbench):
    experiment = plan(
        workbench,
        trial_count=2,
        limits=ExperimentLimits(max_total_requests=4, estimated_requests_per_variant=1),
    )
    finished = asyncio.run(workbench.execute_experiment(experiment.id))
    assert finished.status in {"partial", "planned"}
    counts = workbench.store.trial_counts(experiment.id)
    assert counts.get("pending", 0) >= 1
    assert any("request limit" in note for note in finished.notes)


def test_estimated_spend_guard_is_rejected_at_planning(workbench):
    with pytest.raises(ValueError, match="estimated spend guard"):
        plan(
            workbench,
            trial_count=4,
            limits=ExperimentLimits(
                max_total_requests=100,
                estimated_cost_per_request_usd=0.10,
                max_estimated_spend_usd=0.01,
            ),
        )


def test_endpoint_experiment_requires_capability_and_network_opt_in(workbench):
    profile = EndpointProfile(name="Fixture", authorized=True)
    workbench.store.add_profile(profile)
    with pytest.raises(ValueError, match="tool-calling"):
        plan(workbench, agent="endpoint", profile=profile)
    profile = profile.model_copy(update={"tool_calling": True})
    with pytest.raises(ValueError, match="network opt-in"):
        plan(workbench, agent="endpoint", profile=profile)
    experiment = plan(workbench, agent="endpoint", profile=profile, allow_network=True)
    assert experiment.target.profile_id == profile.id
    assert experiment.target.supports_tool_calls is True
    assert experiment.target.model == profile.allowed_models[0]


def test_endpoint_experiment_executes_through_the_scoped_adapter(workbench):
    seen = []

    def handler(request):
        body = json.loads(request.content)
        seen.append(body)
        return httpx.Response(
            200,
            json={
                "model": "toy-model",
                "choices": [{"message": {"content": "REFUND-30"}, "finish_reason": "stop"}],
                "usage": {"completion_tokens": 4},
            },
        )

    profile = EndpointProfile(
        name="In-process fixture",
        provider="openai-compatible",
        base_url="https://toy.invalid/v1",
        allowed_models=["toy-model"],
        authorized=True,
        authorization="Owner-approved fixture",
        tool_calling=True,
    )
    workbench.store.add_profile(profile)
    monkeypatched = profile.model_copy(update={"tool_calling": True})
    experiment = workbench.plan_experiment(
        "retrieved-authority-spoof",
        agent="endpoint",
        profile=monkeypatched,
        allow_network=True,
        trial_count=1,
    )
    # Replace the transport-aware provider with an in-process transport.
    original = workbench._agent_provider

    def patched(
        scenario_definition,
        agent,
        target_profile,
        allow_network,
        script_key=None,
        settings=None,
    ):
        from faultline.domain import TargetModel
        from faultline.providers import AgentEndpointProvider, CompatibleProvider

        return AgentEndpointProvider(
            CompatibleProvider(target_profile, transport=httpx.MockTransport(handler)),
            TargetModel(endpoint_id=profile.id, requested_model="toy-model"),
            settings or ExecutionSettings(),
        )

    workbench._agent_provider = patched  # type: ignore[method-assign]
    try:
        finished = asyncio.run(workbench.execute_experiment(experiment.id))
    finally:
        workbench._agent_provider = original  # type: ignore[method-assign]
    assert finished.status == "completed"
    assert len(seen) == 2  # one control request, one attack request
    assert all("tools" in body for body in seen)
    for trial in workbench.store.trials(experiment.id):
        assert trial.control.trace_id and trial.attack.trace_id
        assert trial.attack.exposed_to_injection is False  # the model requested no tools
        trace = workbench.store.agentic_trace(trial.attack_trace_id)
        assert trace.settings == experiment.settings
        assistant = [turn for turn in trace.turns if turn.role == "assistant"]
        assert assistant and assistant[-1].finish_reason == "stop"
        assert assistant[-1].usage.get("completion_tokens") == 4


def test_report_preserves_hashes_traces_and_uncertainty(workbench):
    experiment, _ = run(workbench)
    report = workbench.experiment_report(experiment.id)
    assert report.origin == "controlled_experiment"
    assert report.report_format_version == "2.2.0"
    assert verify_export_digest(report)
    assert experiment.control.corpus_sha256 in {digest.sha256 for digest in report.evidence_digests}
    assert len(report.trace_ids) == 4
    text = markdown(report)
    assert "## Paired comparison" in text
    assert "not evidence of causation" in text
    assert "Semantic" in text or "semantic" in text
    rows = csv_export(report).splitlines()
    assert len(rows) > 1
    assert rows[1].startswith(experiment.id)
    payload = json.loads(report.model_dump_json())
    assert (
        payload["experiment"]["control"]["corpus_sha256"] == report.experiment.control.corpus_sha256
    )


def test_reevaluation_of_experiment_traces_is_offline(workbench):
    experiment, _ = run(workbench, trial_count=1)
    trial = workbench.store.trial(experiment.id, 0)
    session = asyncio.run(workbench.reevaluate_agentic(trial.attack_trace_id, experiment.rubric))
    assert session.agentic_trace_id == trial.attack_trace_id
    assert session.origin == "reevaluation"
    # The stored trace is unchanged and still refers to the original rubric.
    assert workbench.store.agentic_trace(trial.attack_trace_id).execution_sha256
    assert len(workbench.store.sessions_for_trace(trial.attack_trace_id)) == 2


def test_protected_records_are_never_implicitly_writable_in_experiments(workbench):
    experiment = plan(workbench, "unauthorized-record-change", trial_count=1)
    definition = experiment.attack.scenario
    assert definition.writable_records == []
    assert definition.monitored_records == ["rec-2001"]
    asyncio.run(workbench.execute_experiment(experiment.id))
    trial = workbench.store.trial(experiment.id, 0)
    assert trial.attack.denied_tools == ["update_record"]
    assert trial.attack.state_changes == []
    trace = workbench.store.agentic_trace(trial.attack_trace_id)
    assert trace.record_digests_before == trace.record_digests_after
