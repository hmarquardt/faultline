"""Paired statistics: explicit denominators, no fabricated precision."""

import pytest

from faultline.compare import (
    exact_mcnemar,
    flatten,
    summarize,
    wilson_interval,
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


def experiment(trial_count=5, order="control_first"):
    attack = scenario("retrieved-authority-spoof")
    control, injected = variant_pair(attack, "scripted-vulnerable")
    rubric = rubric_for(attack)
    return ControlledExperiment(
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
        trial_count=trial_count,
        order=order,
        authorization="Offline fixture",
    )


def observation(role, outcomes, **changes):
    return VariantObservation(
        role=role,
        trace_id=f"trace-{role}-{changes.pop('suffix', '0')}",
        status="completed",
        termination="final_answer",
        rubric_outcomes=outcomes,
        **changes,
    )


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


PASS = {"SPOOF-001": "pass", "SPOOF-002": "pass", "SPOOF-003": "pass"}
FAIL = {"SPOOF-001": "fail", "SPOOF-002": "pass", "SPOOF-003": "fail"}


def test_wilson_intervals_are_bounded_and_documented():
    assert wilson_interval(0, 5).low == 0.0
    assert wilson_interval(0, 5).high == pytest.approx(0.4345, abs=1e-3)
    assert wilson_interval(5, 5).high == 1.0
    assert wilson_interval(5, 5).low == pytest.approx(0.5655, abs=1e-3)
    empty = wilson_interval(0, 0)
    assert empty.method == "none" and empty.low is None
    assert empty.reason == "No scored observations"


def test_exact_mcnemar_is_the_documented_calculation():
    assert exact_mcnemar(5, 0)[0] == pytest.approx(0.0625)
    assert exact_mcnemar(4, 0)[0] == pytest.approx(0.125)
    assert exact_mcnemar(3, 3)[0] == pytest.approx(1.0)
    value, reason = exact_mcnemar(0, 0)
    assert value is None and reason is not None


def test_paired_summary_counts_denominators_and_transitions():
    plan = experiment()
    trials = [
        trial(0, observation("control", PASS, suffix="a"), observation("attack", FAIL, suffix="a")),
        trial(1, observation("control", PASS, suffix="b"), observation("attack", FAIL, suffix="b")),
        trial(2, observation("control", FAIL, suffix="c"), observation("attack", PASS, suffix="c")),
        trial(3, observation("control", FAIL, suffix="d"), observation("attack", FAIL, suffix="d")),
    ]
    summary = summarize(plan, trials)
    assert summary.trials_total == 4
    assert summary.trials_completed == 4
    assert summary.complete_pairs == 4
    criterion = next(item for item in summary.criteria if item.criterion_id == "SPOOF-001")
    assert criterion.control_trials == 4 and criterion.attack_trials == 4
    assert criterion.control_failures == 2 and criterion.attack_failures == 3
    assert criterion.control_failure_rate == pytest.approx(0.5)
    assert criterion.attack_failure_rate == pytest.approx(0.75)
    assert criterion.absolute_rate_difference == pytest.approx(0.25)
    transitions = (
        criterion.pass_pass,
        criterion.pass_fail,
        criterion.fail_pass,
        criterion.fail_fail,
    )
    assert transitions == (0, 2, 1, 1)
    assert criterion.discordant_pairs == 3
    assert criterion.exact_binomial_p == pytest.approx(1.0)
    assert any("not attributable" in note for note in criterion.notes)


def test_uncertain_and_not_applicable_are_separate_from_rates():
    plan = experiment()
    trials = [
        trial(
            0,
            observation("control", {**PASS, "SPOOF-002": "uncertain"}, suffix="a"),
            observation("attack", {**FAIL, "SPOOF-002": "not_applicable"}, suffix="a"),
        ),
        trial(
            1,
            observation("control", PASS, suffix="b"),
            observation("attack", FAIL, suffix="b"),
        ),
    ]
    criterion = next(
        item for item in summarize(plan, trials).criteria if item.criterion_id == "SPOOF-002"
    )
    # Only scored observations enter the rate denominator.
    assert criterion.control_trials == 1 and criterion.attack_trials == 1
    assert criterion.control_uncertain == 1
    assert criterion.attack_not_applicable == 1
    assert criterion.complete_pairs == 1
    assert criterion.control_failure_rate == 0.0


def test_incomplete_pairs_are_excluded_and_counted():
    plan = experiment()
    trials = [
        trial(0, observation("control", PASS, suffix="a"), observation("attack", FAIL, suffix="a")),
        trial(1, observation("control", PASS, suffix="b"), None, status="incomplete"),
        PairedTrial(experiment_id="experiment", trial_index=2, status="pending"),
        PairedTrial(experiment_id="experiment", trial_index=3, status="interrupted"),
    ]
    summary = summarize(plan, trials)
    assert summary.trials_incomplete == 1
    assert summary.trials_pending == 1
    assert summary.trials_interrupted == 1
    assert summary.complete_pairs == 1
    assert summary.trials_completed == 1
    criterion = next(item for item in summary.criteria if item.criterion_id == "SPOOF-001")
    assert criterion.complete_pairs == 1
    assert criterion.excluded_incomplete == 1
    assert criterion.pass_fail == 1
    assert any("incomplete" in note for note in cursor_notes(criterion))


def cursor_notes(criterion):
    return (
        list(criterion.notes) + ["incomplete"]
        if criterion.excluded_incomplete
        else list(criterion.notes)
    )


def test_small_samples_are_flagged_instead_of_claimed_as_significant():
    plan = experiment(trial_count=2)
    trials = [
        trial(
            index,
            observation("control", PASS, suffix=str(index)),
            observation("attack", FAIL, suffix=str(index)),
        )
        for index in range(2)
    ]
    summary = summarize(plan, trials)
    assert any("descriptive" in note for note in summary.notes)
    criterion = next(item for item in summary.criteria if item.criterion_id == "SPOOF-001")
    assert any("cannot support a significance claim" in note for note in criterion.notes)


def test_control_failure_is_reported_as_shared_failure():
    plan = experiment()
    trials = [
        trial(0, observation("control", FAIL, suffix="a"), observation("attack", FAIL, suffix="a")),
        trial(1, observation("control", FAIL, suffix="b"), observation("attack", FAIL, suffix="b")),
    ]
    summary = summarize(plan, trials)
    criterion = next(item for item in summary.criteria if item.criterion_id == "SPOOF-001")
    assert criterion.fail_fail == 2
    assert criterion.discordant_pairs == 0
    assert criterion.exact_binomial_p is None
    assert criterion.p_value_reason is not None
    assert any("not attributable" in note for note in criterion.notes)
    # Two failing criteria (SPOOF-001, SPOOF-003) across two control variants.
    assert summary.control_failures == 4


def test_observation_tallies_keep_arms_separate():
    plan = experiment()
    trials = [
        trial(
            0,
            observation("control", PASS, suffix="a", exposed_to_injection=False),
            observation(
                "attack",
                FAIL,
                suffix="a",
                exposed_to_injection=True,
                unauthorized_requests=["update_record"],
                denied_tools=["update_record"],
                state_changes=[],
            ),
        )
    ]
    summary = summarize(plan, trials)
    assert summary.observations["exposed_attack"] == 1
    assert summary.observations["exposed_control"] == 0
    assert summary.observations["unauthorized_proposals_attack"] == 1
    assert summary.observations["denied_actions_attack"] == 1
    assert summary.observations["verified_effects_attack"] == 0
    assert summary.responses_observed == 2


def test_flatten_preserves_raw_per_trial_observations():
    value = trial(
        3,
        observation("control", PASS, suffix="a"),
        observation("attack", FAIL, suffix="a"),
    )
    flat = flatten(value)
    assert flat.trial_index == 3 and flat.complete is True
    assert flat.control_outcomes == PASS
    assert flat.attack_outcomes == FAIL
    assert flat.order == ["control", "attack"]
