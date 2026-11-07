"""Pure paired statistics for controlled experiments. No IO, no clock, no network.

Estimators are deliberately simple and documented:

- A criterion is scored from observed outcomes only. ``uncertain`` and
  ``not_applicable`` are counted but never treated as passes or failures.
- An arm failure rate is ``failures / (failures + passes)`` for that arm; the
  denominator is reported so a reader can recompute it.
- Paired inference uses one explicit eligibility predicate (``eligibility``): the
  trial must be completed, both observations must exist, both must be scored for
  the criterion, the rubric definition and generation settings must match the
  experiment, and no execution integrity failure may be unresolved. Arm summaries
  also describe partial trials, but they are labelled descriptive and never feed a
  paired estimate.
- ``wilson-score-95`` intervals describe one arm's proportion in this sample alone.
- The paired risk difference uses Newcombe's MOVER score interval (method 10), a
  recognised approximate **unconditional** interval for the difference between two
  paired proportions. The earlier exact-conditional Clopper-Pearson calculation is
  retained as a separately labelled sensitivity interval (``conditional_*``) because
  its coverage is conditional on the observed discordance count and must never be
  presented as unconditional.
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
    PairEligibility,
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


def _binomial_tail_upper(total: int, successes: int, probability: float) -> float:
    """P(X >= successes) for a binomial, summed exactly."""
    if successes <= 0:
        return 1.0
    if successes > total:
        return 0.0
    return sum(
        comb(total, index) * probability**index * (1 - probability) ** (total - index)
        for index in range(successes, total + 1)
    )


def _binomial_tail_lower(total: int, successes: int, probability: float) -> float:
    """P(X <= successes) for a binomial, summed exactly."""
    return 1.0 - _binomial_tail_upper(total, successes + 1, probability)


def clopper_pearson(successes: int, total: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact Clopper-Pearson interval by bisection on the exact binomial tails.

    ``P(X >= x)`` increases with ``p`` and ``P(X <= x)`` decreases with ``p``, so
    each limit is the root of a monotone function. No approximation and no
    external statistics library are involved.
    """
    if total <= 0:  # pragma: no cover - guarded by callers
        raise ValueError("A binomial interval needs at least one trial")

    def bisect(residual, *, increasing: bool) -> float:
        low, high = 0.0, 1.0
        for _ in range(200):
            middle = (low + high) / 2
            value = residual(middle)
            if increasing:
                low, high = (middle, high) if value < 0 else (low, middle)
            else:
                low, high = (middle, high) if value > 0 else (low, middle)
        return (low + high) / 2

    lower = 0.0
    if successes > 0:
        lower = bisect(
            lambda p: _binomial_tail_upper(total, successes, p) - alpha / 2,
            increasing=True,
        )
    upper = 1.0
    if successes < total:
        upper = bisect(
            lambda p: _binomial_tail_lower(total, successes, p) - alpha / 2,
            increasing=False,
        )
    return lower, upper


def conditional_paired_difference_interval(
    pass_fail: int, fail_pass: int, pairs: int, alpha: float = 0.05
) -> ConfidenceInterval:
    """Exact **conditional** interval for ``(b - c) / n`` (sensitivity analysis).

    Conditioned on the ``m = b + c`` discordant pairs, ``b`` is binomial(m, theta)
    with ``theta`` the probability that a discordant pair favours the attack arm.
    A Clopper-Pearson interval for ``theta`` maps to the difference through
    ``(2 * theta - 1) * m / n``, which is exact-conditional and conservative for
    small samples. It is undefined when there is no discordant pair, because such
    data cannot bound the difference away from zero.
    """
    if pairs <= 0:
        return ConfidenceInterval(
            method="none",
            coverage="none",
            confidence=1 - alpha,
            sample_size=0,
            reason="No complete scored pairs",
        )
    discordant = pass_fail + fail_pass
    estimate = (pass_fail - fail_pass) / pairs
    if discordant == 0:
        return ConfidenceInterval(
            method="none",
            coverage="none",
            confidence=1 - alpha,
            sample_size=pairs,
            estimate=estimate,
            reason=(
                "No discordant pairs; a conditional interval cannot bound the "
                "difference away from zero"
            ),
        )
    theta_low, theta_high = clopper_pearson(pass_fail, discordant, alpha)
    scale = discordant / pairs
    return ConfidenceInterval(
        method="exact-conditional-clopper-pearson",
        coverage="conditional-exact",
        confidence=1 - alpha,
        sample_size=pairs,
        estimate=estimate,
        low=max(-1.0, (2 * theta_low - 1) * scale),
        high=min(1.0, (2 * theta_high - 1) * scale),
    )


def paired_difference_interval(
    pass_fail: int,
    fail_pass: int,
    pairs: int,
    alpha: float = 0.05,
    *,
    pass_pass: int = 0,
    fail_fail: int = 0,
) -> ConfidenceInterval:
    """Newcombe's MOVER score interval for the paired risk difference.

    With ``a = pass/pass``, ``b = pass/fail``, ``c = fail/pass``, ``d = fail/fail``
    and ``n = a + b + c + d``, the estimate is ``phi = (b - c) / n``. MOVER combines
    the two arm Wilson intervals with the estimated phi coefficient``rho`` of the
    2x2 paired table:

        L = phi - sqrt((p1 - l1)^2 + (u2 - p2)^2 - 2 rho (p1 - l1)(u2 - p2))
        U = phi + sqrt((u1 - p1)^2 + (p2 - l2)^2 - 2 rho (u1 - p1)(p2 - l2))

    where ``p1`` is the attack failure proportion, ``p2`` the control failure
    proportion, and ``l1, u1, l2, u2`` their Wilson limits (Newcombe 1998, method
    10). The result is an approximate **unconditional** interval: it does not
    condition on the observed number of discordant pairs. It is approximate, not
    exact, and it is a confidence interval, not a significance test.

    Boundary cases: with no eligible pairs the interval is undefined; with no
    discordant pairs ``rho`` sits on its boundary and the interval reduces to the
    shared marginal (Wilson) uncertainty, which is a conservative approximation and
    is labelled as such. The interval is always clipped to [-1, 1] and always
    contains the estimate.
    """
    if pairs <= 0:
        return ConfidenceInterval(
            method="none",
            coverage="none",
            confidence=1 - alpha,
            sample_size=0,
            reason="No complete scored pairs",
        )
    estimate = (pass_fail - fail_pass) / pairs
    attack_failures = pass_fail + fail_fail
    control_failures = fail_pass + fail_fail
    p1 = attack_failures / pairs
    p2 = control_failures / pairs
    arm_one = wilson_interval(attack_failures, pairs)
    arm_two = wilson_interval(control_failures, pairs)
    lower_one, upper_one = arm_one.low, arm_one.high
    lower_two, upper_two = arm_two.low, arm_two.high
    denominator = (
        (pass_pass + pass_fail)
        * (pass_fail + fail_fail)
        * (pass_pass + fail_pass)
        * (fail_pass + fail_fail)
    )
    if denominator > 0:
        correlation = ((pass_pass * fail_fail) - (pass_fail * fail_pass)) / denominator**0.5
    else:
        # A degenerate 2x2 table (all concordant, or one arm constant) leaves the
        # correlation unidentified; zero is the neutral choice and widens the
        # interval rather than narrowing it.
        correlation = 0.0
    correlation = max(-1.0, min(1.0, correlation))
    left = max(
        0.0,
        (p1 - lower_one) ** 2
        + (upper_two - p2) ** 2
        - 2 * correlation * (p1 - lower_one) * (upper_two - p2),
    )
    right = max(
        0.0,
        (upper_one - p1) ** 2
        + (p2 - lower_two) ** 2
        - 2 * correlation * (upper_one - p1) * (p2 - lower_two),
    )
    low = max(-1.0, estimate - left**0.5)
    high = min(1.0, estimate + right**0.5)
    return ConfidenceInterval(
        method="newcombe-mover-95",
        coverage="unconditional-approximate",
        confidence=1 - alpha,
        sample_size=pairs,
        estimate=estimate,
        low=min(low, estimate),
        high=max(high, estimate),
    )


def _scored(outcomes: dict[str, str], criterion_id: str) -> str | None:
    outcome = outcomes.get(criterion_id)
    return outcome if outcome in SCORED else None


def eligibility(
    trial: PairedTrial,
    experiment: ControlledExperiment,
    criterion_id: str | None = None,
    *,
    strict: bool = True,
    blocking_checks: tuple[str, ...] = (),
) -> PairEligibility:
    """The single eligibility rule for paired inference.

    Strict (default) inference requires: the trial belongs to this experiment and is
    completed; both variant observations exist; the rubric-definition digest and the
    generation-settings digest are **present and identical** to the experiment's;
    execution integrity is verified; and no blocking quality check is outstanding.
    When a criterion is given, it must also be scored (``pass``/``fail``) in both arms.

    ``strict=False`` exists only to describe historical records whose observations
    predate identity metadata; such pairs are still reported as descriptive but the
    strict predicate is the one used for every inferential statistic.
    """
    reasons: list[str] = []
    if trial.experiment_id != experiment.id:
        reasons.append("experiment-identity-mismatch")
    if trial.status != "completed":
        reasons.append(f"trial-status:{trial.status}")
    if trial.control is None:
        reasons.append("missing-control-observation")
    if trial.attack is None:
        reasons.append("missing-attack-observation")
    expected_settings = canonical_settings_digest(experiment)
    for role, observation in (("control", trial.control), ("attack", trial.attack)):
        if observation is None:
            continue
        if observation.rubric_definition_sha256 is None:
            if strict:
                reasons.append(f"{role}-rubric-definition-missing")
        elif observation.rubric_definition_sha256 != experiment.rubric_definition_sha256:
            reasons.append(f"{role}-rubric-definition-differs")
        if observation.settings_sha256 is None:
            if strict:
                reasons.append(f"{role}-settings-missing")
        elif observation.settings_sha256 != expected_settings:
            reasons.append(f"{role}-settings-differ")
        if not observation.integrity_ok:
            reasons.append(f"{role}-integrity-failure")
    for check in blocking_checks:
        reasons.append(f"blocking-quality:{check}")
    if criterion_id is not None and trial.control is not None and trial.attack is not None:
        if _scored(trial.control.rubric_outcomes, criterion_id) is None:
            reasons.append("control-outcome-not-scored")
        if _scored(trial.attack.rubric_outcomes, criterion_id) is None:
            reasons.append("attack-outcome-not-scored")
    return PairEligibility(
        trial_index=trial.trial_index,
        criterion_id=criterion_id,
        eligible=not reasons,
        reasons=sorted(set(reasons)),
    )


def canonical_settings_digest(experiment: ControlledExperiment) -> str:
    """Identity of the generation settings the plan declared."""
    from faultline.domain import canonical_digest

    return canonical_digest(experiment.settings)


def _criterion(
    criterion,
    experiment: ControlledExperiment,
    trials: list[PairedTrial],
    *,
    blocking_checks: tuple[str, ...] = (),
    strict: bool = True,
) -> CriterionComparison:
    reasons: dict[str, int] = {}
    control_scored: list[str] = []
    attack_scored: list[str] = []
    control_uncertain = attack_uncertain = 0
    control_na = attack_na = 0
    pass_pass = pass_fail = fail_pass = fail_fail = 0
    descriptive_arm_trials = 0
    for trial in trials:
        control = _scored(trial.control.rubric_outcomes, criterion.id) if trial.control else None
        attack = _scored(trial.attack.rubric_outcomes, criterion.id) if trial.attack else None
        if control is not None:
            control_scored.append(control)
        if attack is not None:
            attack_scored.append(attack)
        if trial.control is not None:
            outcome = trial.control.rubric_outcomes.get(criterion.id)
            control_uncertain += outcome == "uncertain"
            control_na += outcome == "not_applicable"
        if trial.attack is not None:
            outcome = trial.attack.rubric_outcomes.get(criterion.id)
            attack_uncertain += outcome == "uncertain"
            attack_na += outcome == "not_applicable"
        verdict = eligibility(
            trial,
            experiment,
            criterion.id,
            strict=strict,
            blocking_checks=blocking_checks,
        )
        if verdict.eligible:
            if control == "pass" and attack == "pass":
                pass_pass += 1
            elif control == "pass" and attack == "fail":
                pass_fail += 1
            elif control == "fail" and attack == "pass":
                fail_pass += 1
            else:
                fail_fail += 1
        else:
            for reason in verdict.reasons:
                reasons[reason] = reasons.get(reason, 0) + 1
            if control is not None or attack is not None:
                descriptive_arm_trials += 1
    pairs = pass_pass + pass_fail + fail_pass + fail_fail
    control_failures = sum(1 for item in control_scored if item == "fail")
    attack_failures = sum(1 for item in attack_scored if item == "fail")
    control_rate = control_failures / len(control_scored) if control_scored else None
    attack_rate = attack_failures / len(attack_scored) if attack_scored else None
    difference = (pass_fail - fail_pass) / pairs if pairs else None
    p_value, p_reason = exact_mcnemar(pass_fail, fail_pass)
    notes: list[str] = []
    if not pairs:
        notes.append("No eligible complete pair; paired statistics are undefined")
    if descriptive_arm_trials:
        notes.append(
            f"{descriptive_arm_trials} ineligible trial(s) still contribute to the "
            "descriptive arm counts only"
        )
    if pairs and pairs < SMALL_SAMPLE_PAIRS:
        notes.append(
            f"Only {pairs} complete pair(s); rates and intervals are descriptive and "
            "cannot support a significance claim"
        )
    if pass_fail or fail_pass:
        notes.append(
            f"Transitions are observations: {pass_fail} control-pass/attack-fail and "
            f"{fail_pass} control-fail/attack-pass"
        )
    if fail_fail:
        notes.append(
            f"{fail_fail} pair(s) failed in both arms; the control failure is not "
            "attributable to the injected document"
        )
    if reasons:
        notes.append(
            "Excluded from pairing: "
            + ", ".join(f"{name}={count}" for name, count in sorted(reasons.items()))
        )
    interval = paired_difference_interval(
        pass_fail,
        fail_pass,
        pairs,
        pass_pass=pass_pass,
        fail_fail=fail_fail,
    )
    conditional = conditional_paired_difference_interval(pass_fail, fail_pass, pairs)
    if interval.reason and pairs:
        notes.append(f"Paired difference interval: {interval.reason}")
    if pairs and interval.low is not None and interval.high is not None:
        notes.append(
            "Paired difference interval is Newcombe's MOVER score interval "
            "(approximate unconditional coverage); it is not a test of significance"
        )
    if conditional.reason and pairs:
        notes.append(f"Conditional sensitivity interval is undefined: {conditional.reason}")
    return CriterionComparison(
        criterion_id=criterion.id,
        scale_kind=criterion.scale_kind,
        control_trials=len(control_scored),
        attack_trials=len(attack_scored),
        complete_pairs=pairs,
        control_failures=control_failures,
        attack_failures=attack_failures,
        control_uncertain=control_uncertain,
        attack_uncertain=attack_uncertain,
        control_not_applicable=control_na,
        attack_not_applicable=attack_na,
        excluded_incomplete=sum(
            count for name, count in reasons.items() if name.startswith("trial-status")
        ),
        excluded_reasons=reasons,
        descriptive_arm_trials=descriptive_arm_trials,
        control_failure_rate=control_rate,
        attack_failure_rate=attack_rate,
        absolute_rate_difference=difference,
        control_interval=wilson_interval(control_failures, len(control_scored)),
        attack_interval=wilson_interval(attack_failures, len(attack_scored)),
        paired_difference_interval=interval,
        conditional_difference_interval=conditional,
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


def summarize(
    experiment: ControlledExperiment,
    trials: list[PairedTrial],
    *,
    blocking_checks: tuple[str, ...] = (),
    strict: bool = True,
) -> ExperimentalSummary:
    """Aggregate trials into explicit, recomputable denominators.

    ``blocking_checks`` are unresolved blocking quality findings: while any is
    present no pair enters inference, because the experimental frame itself is not
    trustworthy yet.
    """
    definition = experiment.rubric.definition
    if definition is None:
        raise ValueError("Experiment requires an executable rubric")
    statuses = [trial.status for trial in trials]
    completed = [trial for trial in trials if trial.status == "completed"]
    criteria = [
        _criterion(
            criterion,
            experiment,
            trials,
            blocking_checks=blocking_checks,
            strict=strict,
        )
        for criterion in definition.criteria
    ]
    trial_verdicts = [
        eligibility(trial, experiment, strict=strict, blocking_checks=blocking_checks)
        for trial in trials
    ]
    eligible_pairs = len([verdict for verdict in trial_verdicts if verdict.eligible])
    observations = {
        "executed_variants": sum(
            1
            for trial in trials
            for variant in (trial.control, trial.attack)
            if variant is not None
        ),
        "excluded_trials": len([verdict for verdict in trial_verdicts if not verdict.eligible]),
        "eligible_pairs": eligible_pairs,
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
    notes: list[str] = []
    if not trials:
        notes.append("No trial has been executed for this experiment")
    if eligible_pairs and eligible_pairs < SMALL_SAMPLE_PAIRS:
        notes.append(
            f"{eligible_pairs} eligible pair(s): report rates as descriptive, not inferential"
        )
    if statuses.count("incomplete"):
        notes.append(
            f"{statuses.count('incomplete')} incomplete pair(s) excluded from paired statistics"
        )
    if statuses.count("pending"):
        notes.append(f"{statuses.count('pending')} trial(s) have not run yet")
    if statuses.count("interrupted"):
        notes.append(
            f"{statuses.count('interrupted')} trial(s) were interrupted; their observations "
            "stay visible but never enter paired inference"
        )
    if statuses.count("failed"):
        notes.append(
            f"{statuses.count('failed')} trial(s) failed; partial evidence is preserved and "
            "excluded from pairing"
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
        complete_pairs=eligible_pairs,
        criteria=criteria,
        responses_observed=observations["executed_variants"],
        control_failures=sum(item.control_failures for item in criteria),
        attack_failures=sum(item.attack_failures for item in criteria),
        control_metric="failed deterministic criteria across control variants",
        attack_metric="failed deterministic criteria across attack variants",
        observations=observations,
        excluded_trials=[verdict for verdict in trial_verdicts if not verdict.eligible],
        notes=notes,
    )
