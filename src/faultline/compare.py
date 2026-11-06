"""Pure paired statistics for controlled experiments. No IO, no clock, no network.

Estimators are deliberately simple and documented:

- A criterion is scored from observed outcomes only. ``uncertain`` and
  ``not_applicable`` are counted but never treated as passes or failures.
- An arm failure rate is ``failures / (failures + passes)`` for that arm; the
  denominator is reported so a reader can recompute it.
- Paired comparisons use only complete pairs where both variants produced a
  pass/fail outcome. Incomplete pairs are excluded and counted.
- ``wilson-score-95`` intervals describe one arm's proportion in this sample alone.
- The exact McNemar test is the two-sided exact binomial test on discordant pairs
  (``b`` = control pass/attack fail, ``c`` = control fail/attack pass). It is
  reported as a calculation, never as proof of causation, and a missing value
  always carries a reason.
"""

from math import comb, sqrt

from faultline.domain import (
    ConfidenceInterval,
    ControlledExperiment,
    CriterionComparison,
    ExperimentalSummary,
    PairedTrial,
    TrialResult,
)

Z_95 = 1.959963984540054
SMALL_SAMPLE_PAIRS = 5
SCORED = {"pass", "fail"}


def wilson_interval(successes: int, total: int) -> ConfidenceInterval:
    """Wilson score interval for one proportion; undefined without observations."""
    if total <= 0:
        return ConfidenceInterval(method="none", reason="No scored observations")
    if successes < 0 or successes > total:  # pragma: no cover - internal guard
        return ConfidenceInterval(method="none", reason="Inconsistent counts")
    p = successes / total
    denominator = 1 + Z_95**2 / total
    centre = (p + Z_95**2 / (2 * total)) / denominator
    spread = Z_95 * sqrt(p * (1 - p) / total + Z_95**2 / (4 * total**2)) / denominator
    return ConfidenceInterval(
        method="wilson-score-95",
        low=max(0.0, centre - spread),
        high=min(1.0, centre + spread),
    )


def exact_mcnemar(pass_fail: int, fail_pass: int) -> tuple[float | None, str | None]:
    """Two-sided exact binomial test on discordant pairs."""
    discordant = pass_fail + fail_pass
    if discordant == 0:
        return None, "No discordant pairs; the test is undefined"
    tail = min(pass_fail, fail_pass)
    probability = sum(comb(discordant, index) for index in range(tail + 1)) / 2**discordant
    return min(1.0, 2 * probability), None


def _scored(outcomes: dict[str, str], criterion_id: str) -> str | None:
    outcome = outcomes.get(criterion_id)
    return outcome if outcome in SCORED else None


def _criterion(
    criterion, trials: list[PairedTrial], flattened: list[TrialResult]
) -> CriterionComparison:
    control_outcomes: list[str | None] = []
    attack_outcomes: list[str | None] = []
    for trial in trials:
        control_outcomes.append(
            _scored(trial.control.rubric_outcomes, criterion.id) if trial.control else None
        )
        attack_outcomes.append(
            _scored(trial.attack.rubric_outcomes, criterion.id) if trial.attack else None
        )
    control_present = [item for item in control_outcomes if item is not None]
    attack_present = [item for item in attack_outcomes if item is not None]
    control_failures = sum(1 for item in control_present if item == "fail")
    attack_failures = sum(1 for item in attack_present if item == "fail")
    control_uncertain = sum(
        1
        for trial in trials
        if trial.control is not None
        and trial.control.rubric_outcomes.get(criterion.id) == "uncertain"
    )
    attack_uncertain = sum(
        1
        for trial in trials
        if trial.attack is not None
        and trial.attack.rubric_outcomes.get(criterion.id) == "uncertain"
    )
    control_na = sum(
        1
        for trial in trials
        if trial.control is not None
        and trial.control.rubric_outcomes.get(criterion.id) == "not_applicable"
    )
    attack_na = sum(
        1
        for trial in trials
        if trial.attack is not None
        and trial.attack.rubric_outcomes.get(criterion.id) == "not_applicable"
    )
    pass_pass = pass_fail = fail_pass = fail_fail = 0
    for control, attack in zip(control_outcomes, attack_outcomes, strict=True):
        if control is None or attack is None:
            continue
        if control == "pass" and attack == "pass":
            pass_pass += 1
        elif control == "pass" and attack == "fail":
            pass_fail += 1
        elif control == "fail" and attack == "pass":
            fail_pass += 1
        else:
            fail_fail += 1
    pairs = pass_pass + pass_fail + fail_pass + fail_fail
    excluded = sum(
        1
        for trial in trials
        if (trial.control is None) != (trial.attack is None)
        or (trial.control is not None and trial.attack is not None and trial.status != "completed")
    )
    control_rate = control_failures / len(control_present) if control_present else None
    attack_rate = attack_failures / len(attack_present) if attack_present else None
    difference = (pass_fail - fail_pass) / pairs if pairs else None
    control_interval = wilson_interval(control_failures, len(control_present))
    attack_interval = wilson_interval(attack_failures, len(attack_present))
    p_value, p_reason = exact_mcnemar(pass_fail, fail_pass)
    notes: list[str] = []
    if pairs and pairs < SMALL_SAMPLE_PAIRS:
        notes.append(
            f"Only {pairs} complete pair(s); rates and intervals are descriptive and "
            "cannot support a significance claim"
        )
    if pass_fail or fail_pass:
        notes.append(
            f"Transitions are reported as observations: {pass_fail} control-pass/attack-fail "
            f"and {fail_pass} control-fail/attack-pass"
        )
    if fail_fail:
        notes.append(
            f"{fail_fail} pair(s) failed in both arms; the control failure is not "
            "attributable to the injected document"
        )
    if excluded:
        notes.append(f"{excluded} incomplete or non-completed pair(s) excluded from pairing")
    return CriterionComparison(
        criterion_id=criterion.id,
        scale_kind=criterion.scale_kind,
        control_trials=len(control_present),
        attack_trials=len(attack_present),
        complete_pairs=pairs,
        control_failures=control_failures,
        attack_failures=attack_failures,
        control_uncertain=control_uncertain,
        attack_uncertain=attack_uncertain,
        control_not_applicable=control_na,
        attack_not_applicable=attack_na,
        excluded_incomplete=excluded,
        control_failure_rate=control_rate,
        attack_failure_rate=attack_rate,
        absolute_rate_difference=difference,
        control_interval=control_interval,
        attack_interval=attack_interval,
        pass_pass=pass_pass,
        pass_fail=pass_fail,
        fail_pass=fail_pass,
        fail_fail=fail_fail,
        discordant_pairs=pass_fail + fail_pass,
        exact_binomial_p=p_value,
        p_value_reason=p_reason,
        notes=notes,
    )


def flatten(trial: PairedTrial) -> TrialResult:
    """Preserve the raw per-trial observation in a flat, exportable row."""
    return TrialResult(
        trial_index=trial.trial_index,
        status=trial.status,
        complete=trial.status == "completed"
        and trial.control is not None
        and trial.attack is not None,
        order=list(trial.order),
        control_trace_id=trial.control_trace_id,
        attack_trace_id=trial.attack_trace_id,
        control_session_id=trial.control.session_id if trial.control else None,
        attack_session_id=trial.attack.session_id if trial.attack else None,
        control_outcomes=dict(trial.control.rubric_outcomes) if trial.control else {},
        attack_outcomes=dict(trial.attack.rubric_outcomes) if trial.attack else {},
        error=trial.error,
    )


def summarize(experiment: ControlledExperiment, trials: list[PairedTrial]) -> ExperimentalSummary:
    """Aggregate trials into explicit, recomputable denominators."""
    definition = experiment.rubric.definition
    if definition is None:
        raise ValueError("Experiment requires an executable rubric")
    statuses = [trial.status for trial in trials]
    completed = [trial for trial in trials if trial.status == "completed"]
    criteria = [
        _criterion(criterion, trials, [flatten(trial) for trial in trials])
        for criterion in definition.criteria
    ]
    observations = {
        "executed_variants": sum(
            1
            for trial in trials
            for variant in (trial.control, trial.attack)
            if variant is not None
        ),
        "exposed_control": sum(
            1 for trial in trials if trial.control and trial.control.exposed_to_injection
        ),
        "exposed_attack": sum(
            1 for trial in trials if trial.attack and trial.attack.exposed_to_injection
        ),
        "unauthorized_proposals_control": sum(
            len(trial.control.unauthorized_requests) for trial in trials if trial.control
        ),
        "unauthorized_proposals_attack": sum(
            len(trial.attack.unauthorized_requests) for trial in trials if trial.attack
        ),
        "denied_actions_control": sum(
            len(trial.control.denied_tools) for trial in trials if trial.control
        ),
        "denied_actions_attack": sum(
            len(trial.attack.denied_tools) for trial in trials if trial.attack
        ),
        "verified_effects_control": sum(
            len(trial.control.state_changes) for trial in trials if trial.control
        ),
        "verified_effects_attack": sum(
            len(trial.attack.state_changes) for trial in trials if trial.attack
        ),
        "disclosures_control": sum(
            1 for trial in trials if trial.control and trial.control.canary_disclosed
        ),
        "disclosures_attack": sum(
            1 for trial in trials if trial.attack and trial.attack.canary_disclosed
        ),
        "marker_present_control": sum(
            1 for trial in trials if trial.control and trial.control.task_marker_present
        ),
        "marker_present_attack": sum(
            1 for trial in trials if trial.attack and trial.attack.task_marker_present
        ),
    }
    pairs = sum(item.complete_pairs for item in criteria[:1])
    if not criteria:
        pairs = len(
            [trial for trial in completed if trial.control is not None and trial.attack is not None]
        )
    notes: list[str] = []
    if not trials:
        notes.append("No trial has been executed for this experiment")
    if pairs and pairs < SMALL_SAMPLE_PAIRS:
        notes.append(f"{pairs} complete pair(s): report rates as descriptive, not inferential")
    if statuses.count("incomplete"):
        notes.append(
            f"{statuses.count('incomplete')} incomplete pair(s) excluded from paired statistics"
        )
    if statuses.count("pending"):
        notes.append(f"{statuses.count('pending')} trial(s) have not run yet")
    if statuses.count("interrupted"):
        notes.append(
            f"{statuses.count('interrupted')} trial(s) were interrupted and are never blindly "
            "replayed"
        )
    if experiment.order in {"alternate", "randomized"}:
        notes.append("Execution order was varied per trial and recorded on each trial")
    return ExperimentalSummary(
        experiment_id=experiment.id,
        trials_total=len(trials),
        trials_completed=len(completed),
        trials_failed=statuses.count("failed"),
        trials_interrupted=statuses.count("interrupted"),
        trials_pending=statuses.count("pending") + statuses.count("running"),
        trials_incomplete=statuses.count("incomplete"),
        complete_pairs=pairs,
        criteria=criteria,
        responses_observed=observations["executed_variants"],
        control_failures=sum(item.control_failures for item in criteria),
        attack_failures=sum(item.attack_failures for item in criteria),
        control_metric="failed deterministic criteria across control variants",
        attack_metric="failed deterministic criteria across attack variants",
        observations=observations,
        notes=notes,
    )
