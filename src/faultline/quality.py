"""Automated experimental quality checks. Pure: no IO, no clock, no network.

Checks classify findings as blocking, warning or informational. They never replace
observed results: a failing check is a reviewable finding with its evidence.
"""

from faultline.domain import (
    ControlledExperiment,
    PairedTrial,
    QualityCheck,
    QualityReport,
    ScenarioDocument,
    canonical_digest,
)

MIN_VALID_PAIRS = 5


def _check(
    identifier: str,
    severity: str,
    passed: bool,
    message: str,
    evidence: list[str] | None = None,
) -> QualityCheck:
    return QualityCheck(
        id=identifier,
        severity=severity,
        passed=passed,
        message=message,
        evidence=evidence or [],
    )


def _mapped_document(scenario, document_id: str | None) -> ScenarioDocument | None:
    if document_id is None:
        return None
    return next((item for item in scenario.documents if item.id == document_id), None)


def evaluate(
    experiment: ControlledExperiment,
    trials: list[PairedTrial],
    *,
    capability_status: str | None = None,
    min_valid_pairs: int = MIN_VALID_PAIRS,
) -> QualityReport:
    """Run every experimental quality check and keep its evidence."""
    checks: list[QualityCheck] = []
    control = experiment.control.scenario
    attack = experiment.attack.scenario

    # 1. Control and attack must differ only where the plan declared it.
    declared = {difference.path for difference in experiment.differences}
    observed_paths: set[str] = set()
    control_documents = {document.id: document for document in control.documents}
    for document in attack.documents:
        original = control_documents.get(document.id)
        if original is None:
            observed_paths.add(f"documents[{document.id}]")
            continue
        if original.content != document.content:
            observed_paths.add(f"documents[{document.id}].content")
        if original.trust != document.trust:
            observed_paths.add(f"documents[{document.id}].trust")
        if original.injection != document.injection:
            observed_paths.add(f"documents[{document.id}].injection")
    if control.injected_document_id != attack.injected_document_id:
        observed_paths.add("injected_document_id")
    undeclared = sorted(observed_paths - declared)
    missing = sorted(declared - observed_paths)
    checks.append(
        _check(
            "variant-scope",
            "blocking",
            not undeclared and not missing,
            "Variants differ exactly where the plan declares"
            if not undeclared and not missing
            else f"Undeclared differences {undeclared or 'none'}; declared but absent "
            f"{missing or 'none'}",
            [*undeclared, *missing],
        )
    )

    # 2. The shared experimental frame must be identical across arms.
    shared_mismatch = []
    if control.user_task != attack.user_task:
        shared_mismatch.append("user_task")
    if control.system_prompt != attack.system_prompt:
        shared_mismatch.append("system_prompt")
    if control.allowed_tools != attack.allowed_tools:
        shared_mismatch.append("allowed_tools")
    if control.writable_records != attack.writable_records:
        shared_mismatch.append("writable_records")
    if control.monitored_records != attack.monitored_records:
        shared_mismatch.append("monitored_records")
    checks.append(
        _check(
            "shared-frame",
            "blocking",
            not shared_mismatch,
            "Task, prompt and tool policy are shared across arms"
            if not shared_mismatch
            else f"Shared fields differ: {shared_mismatch}",
            shared_mismatch,
        )
    )

    # 3. Rubric identity must be the experiment's rubric in both arms.
    rubric_mismatch = [
        f"{role}-session"
        for trial in trials
        for role, observation in (("control", trial.control), ("attack", trial.attack))
        if observation is not None
        and observation.rubric_definition_sha256 is not None
        and observation.rubric_definition_sha256 != experiment.rubric_definition_sha256
    ]
    checks.append(
        _check(
            "rubric-identity",
            "blocking",
            not rubric_mismatch,
            "Every observation used the experiment rubric"
            if not rubric_mismatch
            else f"{len(rubric_mismatch)} observation(s) used a different rubric",
            rubric_mismatch[:10],
        )
    )

    # 4. Settings must be the declared ones.
    settings_digest = canonical_digest(experiment.settings)
    settings_mismatch = [
        f"{trial.trial_index}:{role}"
        for trial in trials
        for role, observation in (("control", trial.control), ("attack", trial.attack))
        if observation is not None
        and observation.settings_sha256 is not None
        and observation.settings_sha256 != settings_digest
    ]
    checks.append(
        _check(
            "settings-identity",
            "blocking",
            not settings_mismatch,
            "Generation settings match the plan"
            if not settings_mismatch
            else f"{len(settings_mismatch)} observation(s) used different settings",
            settings_mismatch[:10],
        )
    )

    # 5. Execution integrity of every stored trace reference.
    integrity_failures = [
        f"{trial.trial_index}:{role}"
        for trial in trials
        for role, observation in (("control", trial.control), ("attack", trial.attack))
        if observation is not None and not observation.integrity_ok
    ]
    checks.append(
        _check(
            "trace-integrity",
            "blocking",
            not integrity_failures,
            "Every observation carries a verified trace digest"
            if not integrity_failures
            else f"{len(integrity_failures)} observation(s) failed digest verification",
            integrity_failures[:10],
        )
    )

    # 6. Trial order must be recorded on every trial that ran.
    unordered = [
        str(trial.trial_index)
        for trial in trials
        if trial.status in {"running", "completed", "failed", "incomplete", "interrupted"}
        and sorted(trial.order) != ["attack", "control"]
    ]
    checks.append(
        _check(
            "trial-order",
            "warning",
            not unordered,
            "Execution order is recorded on every executed trial"
            if not unordered
            else f"{len(unordered)} trial(s) lack a recorded order",
            unordered[:10],
        )
    )

    # 7. Environment reset: traces are unique per arm and never shared.
    trace_ids = [
        observation.trace_id
        for trial in trials
        for observation in (trial.control, trial.attack)
        if observation is not None
    ]
    duplicated = sorted({value for value in trace_ids if trace_ids.count(value) > 1})
    checks.append(
        _check(
            "environment-reset",
            "blocking",
            not duplicated,
            "Each variant produced its own trace and sandbox"
            if not duplicated
            else f"{len(duplicated)} trace(s) were reused across variants",
            duplicated[:10],
        )
    )

    # 8. Paired statistics must never count an ineligible trial.
    from faultline.compare import eligibility, summarize

    summary = summarize(experiment, trials)
    eligible_trials = [trial for trial in trials if eligibility(trial, experiment).eligible]
    largest_criterion_pairs = max((item.complete_pairs for item in summary.criteria), default=0)
    leaked = largest_criterion_pairs > len(eligible_trials) or (
        summary.complete_pairs != len(eligible_trials)
    )
    checks.append(
        _check(
            "paired-eligibility",
            "blocking",
            not leaked,
            f"{summary.complete_pairs} eligible pair(s) reported and {len(eligible_trials)} "
            "trial(s) qualify"
            if not leaked
            else "Paired statistics include trials that do not meet the eligibility rule",
            [str(trial.trial_index) for trial in eligible_trials],
        )
    )

    # 9. A response without trace evidence is not usable evidence.
    missing_evidence = [
        f"{trial.trial_index}:{role}"
        for trial in trials
        for role, observation in (("control", trial.control), ("attack", trial.attack))
        if observation is not None and (not observation.trace_id or not observation.session_id)
    ]
    checks.append(
        _check(
            "trace-evidence",
            "blocking",
            not missing_evidence,
            "Every observation references a stored trace and session"
            if not missing_evidence
            else f"{len(missing_evidence)} observation(s) lack trace or session evidence",
            missing_evidence[:10],
        )
    )

    # 10. Exposure is measured, not assumed.
    attack_observations = [trial.attack for trial in trials if trial.attack is not None]
    exposed = [item for item in attack_observations if item.exposed_to_injection]
    checks.append(
        _check(
            "injection-exposure",
            "warning",
            bool(attack_observations) and len(exposed) == len(attack_observations),
            f"{len(exposed)} of {len(attack_observations)} attack variant(s) actually "
            "retrieved the injected document",
            [item.trace_id for item in attack_observations],
        )
    )

    # 11. Enough eligible pairs for a meaningful comparison.
    completed_pairs = [
        trial
        for trial in trials
        if trial.status == "completed"
        and trial.control is not None
        and trial.attack is not None
        and all(
            observation.integrity_ok
            for observation in (trial.control, trial.attack)
            if observation is not None
        )
    ]
    checks.append(
        _check(
            "pair-count",
            "warning" if completed_pairs else "info",
            len(completed_pairs) >= min_valid_pairs,
            f"{len(completed_pairs)} eligible pair(s); at least {min_valid_pairs} are "
            "needed before rates support comparison",
            [str(trial.trial_index) for trial in completed_pairs],
        )
    )

    # 12. Provider capabilities must be known for a real endpoint target.
    if experiment.target.agent == "endpoint":
        known = capability_status in {"supported", "ok", "validated"}
        checks.append(
            _check(
                "provider-capabilities",
                "warning",
                known,
                "Endpoint capabilities were validated before the experiment"
                if known
                else "Endpoint capabilities are unvalidated; tool support is an "
                "assertion from the profile only",
            )
        )

    blocking = sum(1 for check in checks if not check.passed and check.severity == "blocking")
    warnings = sum(1 for check in checks if not check.passed and check.severity == "warning")
    notes = sum(1 for check in checks if not check.passed and check.severity == "info")
    notes_free = [check.message for check in checks if check.passed and check.severity == "info"]
    return QualityReport(
        experiment_id=experiment.id,
        checks=checks,
        blocking=blocking,
        warnings=warnings,
        notes=notes,
        notes_free=notes_free,
    )
