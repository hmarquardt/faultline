"""Paired eligibility: only completed, scored, compatible pairs are inferred on."""

import pytest

from faultline.compare import (
    clopper_pearson,
    eligibility,
    exact_mcnemar,
    paired_difference_interval,
    summarize,
)
from faultline.domain import (
    AgentBudget,
    ControlledExperiment,
    ExecutionSettings,
    ExperimentLimits,
    ExperimentTarget,
    PairedTrial,
    VariantObservation,
    canonical_digest,
)
from faultline.scenarios import rubric_for, scenario, variant_differences, variant_pair


def experiment(**changes):
    attack = scenario("retrieved-authority-spoof")
    control, injected = variant_pair(attack, "scripted-vulnerable")
    rubric = rubric_for(attack)
    values = dict(
        name="fixture",
        objective=attack.objective,
        scenario_id=attack.id,
        scenario_version=attack.version,
        control=control,
        attack=injected,
        differences=variant_differences(control, injected),
        rubric=rubric,
        rubric_definition_sha256=canonical_digest(rubric.definition),
        target=ExperimentTarget(
            agent="scripted-vulnerable",
            provider="scripted-mock",
            model="scripted-vulnerable/1",
        ),
        settings=ExecutionSettings(),
        budget=AgentBudget(),
        limits=ExperimentLimits(max_total_requests=200),
        trial_count=2,
        authorization="Offline fixture",
    )
    values.update(changes)
    return ControlledExperiment(**values)


PASS = {"SPOOF-001": "pass", "SPOOF-002": "pass", "SPOOF-003": "pass"}
FAIL = {"SPOOF-001": "fail", "SPOOF-002": "pass", "SPOOF-003": "fail"}


def observation(role, outcomes, *, suffix, **changes):
    plan = experiment()
    values = dict(
        role=role,
        trace_id=f"trace-{role}-{suffix}",
        status="completed",
        termination="final_answer",
        rubric_outcomes=outcomes,
        rubric_definition_sha256=plan.rubric_definition_sha256,
        settings_sha256=canonical_digest(plan.settings),
        integrity_ok=True,
    )
    values.update(changes)
    return VariantObservation(**values)


def trial(index, control, attack, status="completed"):
    return PairedTrial(
        experiment_id="experiment",
        trial_index=index,
        status=status,
        control=control,
        attack=attack,
        control_trace_id=control.trace_id if control else None,
        attack_trace_id=attack.trace_id if attack else None,
    )


def criterion(summary, criterion_id="SPOOF-001"):
    return next(item for item in summary.criteria if item.criterion_id == criterion_id)


@pytest.mark.parametrize("status", ["interrupted", "failed", "incomplete"])
def test_non_completed_trial_with_both_observations_is_excluded(status):
    plan = experiment()
    value = trial(
        0,
        observation("control", PASS, suffix="a"),
        observation("attack", FAIL, suffix="a"),
        status=status,
    )
    verdict = eligibility(value, plan, "SPOOF-001")
    assert verdict.eligible is False
    assert f"trial-status:{status}" in verdict.reasons
    summary = summarize(plan, [value])
    item = criterion(summary)
    assert item.complete_pairs == 0
    assert item.pass_fail == 0
    assert item.absolute_rate_difference is None
    assert item.exact_binomial_p is None
    # The partial evidence is still visible as a descriptive arm count.
    assert item.control_trials == 1 and item.attack_trials == 1
    assert item.descriptive_arm_trials == 1
    assert item.control_failures == 0 and item.attack_failures == 1
    assert summary.complete_pairs == 0
    assert summary.excluded_trials


def test_one_uncertain_outcome_excludes_the_pair_only_for_that_criterion():
    plan = experiment()
    value = trial(
        0,
        observation("control", {**PASS, "SPOOF-002": "uncertain"}, suffix="a"),
        observation("attack", FAIL, suffix="a"),
    )
    summary = summarize(plan, [value])
    assert criterion(summary, "SPOOF-001").complete_pairs == 1
    other = criterion(summary, "SPOOF-002")
    assert other.complete_pairs == 0
    assert other.control_uncertain == 1
    assert "control-outcome-not-scored" in other.excluded_reasons


def test_one_not_applicable_outcome_is_not_a_failure_and_blocks_pairing():
    plan = experiment()
    value = trial(
        0,
        observation("control", PASS, suffix="a"),
        observation("attack", {**FAIL, "SPOOF-002": "not_applicable"}, suffix="a"),
    )
    summary = summarize(plan, [value])
    other = criterion(summary, "SPOOF-002")
    assert other.complete_pairs == 0
    assert other.attack_not_applicable == 1
    assert other.attack_failures == 0
    assert "attack-outcome-not-scored" in other.excluded_reasons


def test_missing_observation_is_excluded_and_named():
    plan = experiment()
    value = trial(0, observation("control", PASS, suffix="a"), None, status="incomplete")
    verdict = eligibility(value, plan)
    assert "missing-attack-observation" in verdict.reasons
    summary = summarize(plan, [value])
    item = criterion(summary)
    assert item.complete_pairs == 0
    assert item.descriptive_arm_trials == 1
    assert item.excluded_reasons["missing-attack-observation"] == 1


def test_completed_fully_scored_pair_is_eligible():
    plan = experiment()
    value = trial(
        0,
        observation("control", PASS, suffix="a"),
        observation("attack", FAIL, suffix="a"),
    )
    assert eligibility(value, plan, "SPOOF-001").eligible is True
    summary = summarize(plan, [value])
    item = criterion(summary)
    assert item.complete_pairs == 1
    assert (item.pass_pass, item.pass_fail, item.fail_pass, item.fail_fail) == (0, 1, 0, 0)
    assert item.absolute_rate_difference == 1.0
    assert summary.complete_pairs == 1
    assert summary.excluded_trials == []


def test_rubric_or_settings_mismatch_excludes_the_pair():
    plan = experiment()
    other_rubric = trial(
        0,
        observation("control", PASS, suffix="a", rubric_definition_sha256="a" * 64),
        observation("attack", FAIL, suffix="a"),
    )
    verdict = eligibility(other_rubric, plan, "SPOOF-001")
    assert "control-rubric-definition-differs" in verdict.reasons
    other_settings = trial(
        1,
        observation("control", PASS, suffix="b"),
        observation("attack", FAIL, suffix="b", settings_sha256="b" * 64),
    )
    assert "attack-settings-differ" in eligibility(other_settings, plan).reasons
    tampered = trial(
        2,
        observation("control", PASS, suffix="c"),
        observation("attack", FAIL, suffix="c", integrity_ok=False),
    )
    assert "attack-integrity-failure" in eligibility(tampered, plan).reasons
    summary = summarize(plan, [other_rubric, other_settings, tampered])
    assert criterion(summary).complete_pairs == 0
    assert criterion(summary).descriptive_arm_trials == 3


def test_mixed_complete_and_incomplete_samples_preserve_denominators():
    plan = experiment()
    trials = [
        trial(0, observation("control", PASS, suffix="a"), observation("attack", FAIL, suffix="a")),
        trial(1, observation("control", PASS, suffix="b"), observation("attack", PASS, suffix="b")),
        trial(2, observation("control", PASS, suffix="c"), None, status="incomplete"),
        trial(
            3,
            observation("control", FAIL, suffix="d"),
            observation("attack", FAIL, suffix="d"),
            status="interrupted",
        ),
        PairedTrial(experiment_id="experiment", trial_index=4, status="pending"),
    ]
    summary = summarize(plan, trials)
    item = criterion(summary)
    assert summary.trials_total == 5
    assert summary.complete_pairs == 2
    assert item.complete_pairs == 2
    assert (item.pass_pass, item.pass_fail, item.fail_pass, item.fail_fail) == (1, 1, 0, 0)
    # Descriptive arms include the interrupted trial's scored outcomes.
    assert item.control_trials == 4
    assert item.attack_trials == 3
    assert item.descriptive_arm_trials == 2
    assert item.absolute_rate_difference == 0.5
    assert walrus_matches(item.excluded_reasons) is True


def walrus_matches(reasons):
    return (
        reasons.get("trial-status:incomplete") == 1 and reasons.get("trial-status:interrupted") == 1
    )


def test_reference_calculations_for_transitions_and_mcnemar():
    plan = experiment()
    # b = 5 (control pass / attack fail), c = 0, n = 5 -> diff 1.0, p = 0.0625.
    trials = [
        trial(
            index,
            observation("control", PASS, suffix=str(index)),
            observation("attack", FAIL, suffix=str(index)),
        )
        for index in range(5)
    ]
    item = criterion(summarize(plan, trials))
    assert item.complete_pairs == 5
    assert item.pass_fail == 5 and item.fail_pass == 0
    assert item.absolute_rate_difference == pytest.approx(1.0)
    assert item.exact_binomial_p == pytest.approx(0.0625)
    interval = item.paired_difference_interval
    assert interval.method == "exact-conditional-clopper-pearson"
    assert interval.sample_size == 5
    assert interval.estimate == pytest.approx(1.0)
    # theta = 5/5 -> CP lower 0.4782 -> (2*0.4782-1)*1 = -0.0436
    assert interval.low == pytest.approx(-0.0436, abs=1e-3)
    assert interval.high == pytest.approx(1.0)


def test_paired_interval_reference_examples():
    balanced = paired_difference_interval(2, 2, 10)
    assert balanced.estimate == pytest.approx(0.0)
    assert balanced.low < 0 < balanced.high
    no_events = paired_difference_interval(0, 0, 4)
    assert no_events.method == "none"
    assert "No discordant pairs" in (no_events.reason or "")
    empty = paired_difference_interval(0, 0, 0)
    assert empty.method == "none" and empty.sample_size == 0
    # One discordant pair favouring the attack arm: theta=1/1 -> CP [0.025, 1].
    single = paired_difference_interval(1, 0, 3)
    assert single.estimate == pytest.approx(1 / 3)
    assert single.low == pytest.approx(max(-1.0, (2 * 0.025 - 1) / 3), abs=1e-3)
    assert single.high == pytest.approx(1 / 3, abs=1e-6)


def test_clopper_pearson_matches_published_reference_values():
    assert clopper_pearson(0, 5) == (0.0, pytest.approx(0.5218, abs=5e-4))
    assert clopper_pearson(5, 5)[0] == pytest.approx(0.4782, abs=5e-4)
    assert clopper_pearson(5, 5)[1] == 1.0
    low, high = clopper_pearson(1, 10)
    assert low == pytest.approx(0.0025, abs=5e-5)
    assert high == pytest.approx(0.4450, abs=5e-4)
    low, high = clopper_pearson(2, 5)
    assert low == pytest.approx(0.0527, abs=5e-4)
    assert high == pytest.approx(0.8534, abs=5e-4)
    low, high = clopper_pearson(3, 3)
    assert low == pytest.approx(0.2924, abs=5e-4)
    # The interval is always ordered and inside [0, 1].
    for successes, total in ((7, 10), (30, 40), (1, 3)):
        low, high = clopper_pearson(successes, total)
        assert 0.0 <= low <= high <= 1.0


def test_exact_mcnemar_reference_values():
    assert exact_mcnemar(5, 0)[0] == pytest.approx(0.0625)
    assert exact_mcnemar(6, 0)[0] == pytest.approx(0.03125)
    assert exact_mcnemar(4, 1)[0] == pytest.approx(0.375)
    assert exact_mcnemar(0, 0) == (None, "No discordant pairs; the test is undefined")
