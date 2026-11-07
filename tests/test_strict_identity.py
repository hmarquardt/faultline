"""Strict identity: missing or inconsistent metadata never enters inference."""

import pytest

from faultline.compare import eligibility, summarize
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


def plan():
    attack = scenario("retrieved-authority-spoof")
    control, injected = variant_pair(attack, "scripted-vulnerable")
    rubric = rubric_for(attack)
    return ControlledExperiment(
        name="strict fixture",
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
        trial_count=1,
        authorization="Offline fixture",
    )


PLAN = plan()
PASS = {"SPOOF-001": "pass"}
FAIL = {"SPOOF-001": "fail"}


def observation(role, outcomes=PASS, /, **changes):
    values = dict(
        role=role,
        trace_id=f"trace-{role}",
        status="completed",
        termination="final_answer",
        rubric_outcomes=outcomes,
        rubric_definition_sha256=PLAN.rubric_definition_sha256,
        settings_sha256=canonical_digest(PLAN.settings),
        integrity_ok=True,
    )
    values.update(changes)
    return VariantObservation(**values)


def trial(control=None, attack=None, /, **changes):
    values = dict(
        experiment_id=PLAN.id,
        trial_index=0,
        status="completed",
        control=control if control is not None else observation("control"),
        attack=attack if attack is not None else observation("attack", FAIL),
    )
    if values["control"] is not None:
        values["control_trace_id"] = values["control"].trace_id
    if values["attack"] is not None:
        values["attack_trace_id"] = values["attack"].trace_id
    values.update(changes)
    return PairedTrial(**values)


def test_valid_metadata_is_eligible():
    verdict = eligibility(trial(), PLAN, "SPOOF-001")
    assert verdict.eligible is True and verdict.reasons == []
    summary = summarize(PLAN, [trial()])
    assert summary.complete_pairs == 1


def test_missing_rubric_digest_excludes_the_pair():
    value = trial(
        control=observation("control", rubric_definition_sha256=None),
    )
    verdict = eligibility(value, PLAN, "SPOOF-001")
    assert verdict.eligible is False
    assert "control-rubric-definition-missing" in verdict.reasons
    summary = summarize(PLAN, [value])
    assert summary.complete_pairs == 0
    item = next(item for item in summary.criteria if item.criterion_id == "SPOOF-001")
    assert item.complete_pairs == 0
    assert item.excluded_reasons["control-rubric-definition-missing"] == 1
    # The observation stays visible as a descriptive arm summary.
    assert item.control_trials == 1
    assert item.descriptive_arm_trials == 1


def test_missing_settings_digest_excludes_the_pair():
    value = trial(attack=observation("attack", FAIL, settings_sha256=None))
    verdict = eligibility(value, PLAN)
    assert "attack-settings-missing" in verdict.reasons
    assert verdict.eligible is False


def test_inconsistent_digests_exclude_the_pair():
    value = trial(
        attack=observation(
            "attack", FAIL, rubric_definition_sha256="f" * 64, settings_sha256="e" * 64
        )
    )
    verdict = eligibility(value, PLAN)
    assert "attack-rubric-definition-differs" in verdict.reasons
    assert "attack-settings-differ" in verdict.reasons


def test_malformed_digest_is_rejected_by_the_contract():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        observation("control", rubric_definition_sha256="not-a-digest")


def test_integrity_failure_excludes_the_pair():
    value = trial(control=observation("control", integrity_ok=False))
    assert "control-integrity-failure" in eligibility(value, PLAN).reasons


def test_experiment_identity_mismatch_excludes_the_pair():
    value = trial(experiment_id="some-other-experiment")
    verdict = eligibility(value, PLAN)
    assert "experiment-identity-mismatch" in verdict.reasons
    assert verdict.eligible is False
    assert summarize(PLAN, [value]).complete_pairs == 0


def test_blocking_quality_findings_exclude_every_pair():
    clean = summarize(PLAN, [trial()])
    assert clean.complete_pairs == 1
    blocked = summarize(PLAN, [trial()], blocking_checks=("variant-scope",))
    assert blocked.complete_pairs == 0
    item = next(item for item in blocked.criteria if item.criterion_id == "SPOOF-001")
    assert item.complete_pairs == 0
    assert item.excluded_reasons["blocking-quality:variant-scope"] == 1
    assert blocked.excluded_trials


def test_service_summary_excludes_pairs_when_quality_blocks(workbench):
    experiment = workbench.plan_experiment("retrieved-authority-spoof", trial_count=1)
    import asyncio

    asyncio.run(workbench.execute_experiment(experiment.id))
    clean = workbench.experiment_summary(experiment.id)
    assert clean.complete_pairs == 1
    # Tamper with the declared differences so the variant-scope check blocks.
    stored = workbench.store.controlled_experiment(experiment.id)
    from faultline.quality import evaluate as quality_evaluate

    trimmed = stored.model_copy(update={"differences": stored.differences[:1]})
    quality = quality_evaluate(trimmed, workbench.store.trials(experiment.id))
    assert quality.blocking >= 1
    blocking = tuple(
        check.id for check in quality.checks if check.severity == "blocking" and not check.passed
    )
    blocked = summarize(trimmed, workbench.store.trials(experiment.id), blocking_checks=blocking)
    assert blocked.complete_pairs == 0


def test_historical_observations_without_metadata_are_descriptive_only():
    legacy = trial(
        control=observation("control", rubric_definition_sha256=None, settings_sha256=None),
        attack=observation("attack", FAIL, rubric_definition_sha256=None, settings_sha256=None),
    )
    strict = summarize(PLAN, [legacy])
    assert strict.complete_pairs == 0
    assert strict.excluded_trials
    descriptive = summarize(PLAN, [legacy], strict=False)
    assert descriptive.complete_pairs == 1
    item = next(item for item in descriptive.criteria if item.criterion_id == "SPOOF-001")
    assert item.pass_fail == 1
