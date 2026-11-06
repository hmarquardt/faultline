"""Multi-model comparison: segregated results, disclosed differences, budgets."""

import asyncio
import json

import pytest

from faultline.compare import summarize
from faultline.domain import BenchmarkLimits, ExecutionSettings
from faultline.reports import csv_export, markdown, verify_export_digest


def plan(workbench, **changes):
    values = dict(
        trials=2,
        targets=[
            {"agent": "scripted-vulnerable"},
            {"agent": "scripted-secure"},
        ],
    )
    values.update(changes)
    return workbench.plan_model_comparison("retrieved-authority-spoof", **values)


def test_comparison_creates_one_experiment_per_model(workbench):
    comparison = plan(workbench)
    assert len(comparison.entries) == 2
    ids = [entry.experiment_id for entry in comparison.entries]
    assert len(set(ids)) == 2
    for entry in comparison.entries:
        experiment = workbench.store.controlled_experiment(entry.experiment_id)
        assert experiment.scenario_id == comparison.scenario_id
        assert experiment.trial_count == 2
        assert experiment.rubric_definition_sha256 == comparison.rubric_definition_sha256
    assert comparison.status == "planned"
    # Distinct model identities are required.
    with pytest.raises(ValueError, match="distinct model identity"):
        workbench.plan_model_comparison(
            "retrieved-authority-spoof",
            [{"agent": "scripted-vulnerable"}, {"agent": "scripted-vulnerable"}],
            trials=1,
        )


def test_comparison_requires_at_least_two_models(workbench):
    with pytest.raises(ValueError, match="at least two models"):
        plan(workbench, targets=[{"agent": "scripted-vulnerable"}])


def test_results_stay_segregated_per_model(workbench):
    comparison = plan(workbench)
    finished = asyncio.run(workbench.execute_model_comparison(comparison.id))
    assert finished.status == "completed"
    vulnerable, secure = finished.entries
    vulnerable_criterion = next(
        item for item in vulnerable.summary.criteria if item.criterion_id == "SPOOF-001"
    )
    secure_criterion = next(
        item for item in secure.summary.criteria if item.criterion_id == "SPOOF-001"
    )
    assert vulnerable_criterion.attack_failures == 2
    assert secure_criterion.attack_failures == 0
    # No pooled figure exists: each entry keeps its own denominators.
    assert vulnerable.summary.experiment_id != secure.summary.experiment_id
    assert vulnerable.summary.complete_pairs == 2
    assert secure.summary.complete_pairs == 2


def test_capability_gaps_are_disclosed_as_notes(workbench):
    comparison = plan(workbench)
    kinds = {note.kind for note in comparison.notes}
    assert "capabilities" in kinds
    assert all(note.severity in {"blocking", "warning", "info"} for note in comparison.notes)
    messages = " ".join(note.message for note in comparison.notes)
    assert "never observed" in messages


def test_non_comparable_settings_are_reported_not_hidden(workbench):
    from faultline.domain import ModelComparisonEntry, VariantObservation
    from faultline.service import comparability_notes

    base = dict(
        agent="scripted-vulnerable",
        provider="scripted-mock",
        model="scripted-vulnerable/1",
        trial_count=2,
        settings_sha256="a" * 64,
        budget_sha256="b" * 64,
    )
    first = ModelComparisonEntry(
        experiment_id="one",
        summary=summarize(
            workbench.plan_experiment("retrieved-authority-spoof", trial_count=1), []
        ),
        **base,
    )
    second = first.model_copy(
        update={"experiment_id": "two", "settings_sha256": "c" * 64, "trial_count": 4}
    )
    notes = comparability_notes([first, second])
    kinds = {(note.kind, note.severity) for note in notes}
    assert ("settings", "blocking") in kinds
    assert any(note.kind == "trials" for note in notes)
    _ = VariantObservation


def test_comparison_report_is_per_model_and_digested(workbench):
    comparison = plan(workbench)
    asyncio.run(workbench.execute_model_comparison(comparison.id))
    report = workbench.comparison_report(comparison.id)
    assert report.origin == "model_comparison"
    assert report.report_format_version == "2.3.0"
    assert verify_export_digest(report)
    assert len(report.experiment_ids) == 2
    assert report.trace_ids and report.evaluation_sessions
    text = markdown(report)
    assert "never pooled" in text
    assert "## Comparability notes" in text
    assert "## Experimental quality checks" in text
    rows = csv_export(report).splitlines()
    assert len(rows) > 1
    assert rows[1].startswith(comparison.id)
    payload = json.loads(report.model_dump_json())
    assert len(payload["comparison"]["entries"]) == 2
    for entry in payload["comparison"]["entries"]:
        assert "summary" in entry


def test_benchmark_plans_every_scenario_and_model(workbench):
    plan_value = workbench.plan_benchmark(
        "boundary-core-suite",
        [{"agent": "scripted-vulnerable"}, {"agent": "scripted-secure"}],
        trials=1,
        limits=BenchmarkLimits(max_total_requests=400, max_total_tokens=400_000),
    )
    assert len(plan_value.results) == 3 * 2
    assert len(plan_value.model_labels) == 2
    assert plan_value.status == "planned"
    assert all(row.status == "pending" for row in plan_value.results)
    assert {row.scenario_id for row in plan_value.results} == {
        "retrieved-authority-spoof",
        "synthetic-secret-disclosure",
        "unauthorized-record-change",
    }


def test_benchmark_budgets_are_enforced_at_planning(workbench):
    with pytest.raises(ValueError, match="scenario limit"):
        workbench.plan_benchmark(
            "retrieval-injection-suite",
            [{"agent": "scripted-vulnerable"}],
            trials=1,
            limits=BenchmarkLimits(max_scenarios=2, max_total_requests=400),
        )
    with pytest.raises(ValueError, match="request limit"):
        workbench.plan_benchmark(
            "boundary-core-suite",
            [{"agent": "scripted-vulnerable"}],
            trials=1,
            limits=BenchmarkLimits(max_total_requests=4),
        )
    with pytest.raises(ValueError, match="token limit"):
        workbench.plan_benchmark(
            "boundary-core-suite",
            [{"agent": "scripted-vulnerable"}],
            trials=1,
            limits=BenchmarkLimits(
                max_total_requests=400, max_total_tokens=10, estimated_tokens_per_request=800
            ),
        )
    with pytest.raises(ValueError, match="trial limit"):
        workbench.plan_benchmark(
            "boundary-core-suite",
            [{"agent": "scripted-vulnerable"}],
            trials=4,
            limits=BenchmarkLimits(max_total_requests=400, max_trials_per_scenario=2),
        )


def test_benchmark_runs_offline_and_reports_each_scenario(workbench):
    plan_value = workbench.plan_benchmark(
        "boundary-core-suite",
        [{"agent": "scripted-vulnerable"}],
        trials=1,
        limits=BenchmarkLimits(max_total_requests=400, max_total_tokens=400_000),
    )
    finished = asyncio.run(workbench.execute_benchmark(plan_value.id))
    assert finished.status == "completed"
    assert all(row.status == "completed" for row in finished.results)
    assert all(row.summary is not None for row in finished.results)
    report = workbench.benchmark_report(plan_value.id)
    assert report.origin == "benchmark"
    assert verify_export_digest(report)
    text = markdown(report)
    assert "Nothing is pooled across scenarios" in text
    assert "## Scenario results" in text
    rows = csv_export(report).splitlines()
    assert len(rows) > 3


def test_benchmark_resumes_without_replaying_completed_scenarios(workbench):
    plan_value = workbench.plan_benchmark(
        "boundary-core-suite",
        [{"agent": "scripted-vulnerable"}],
        trials=1,
        limits=BenchmarkLimits(max_total_requests=400, max_total_tokens=400_000),
    )
    first = asyncio.run(workbench.execute_benchmark(plan_value.id, limit=1))
    completed_first = [row.experiment_id for row in first.results if row.status == "completed"]
    assert len(completed_first) == 1
    assert first.status == "partial"
    assert any(row.status == "pending" for row in first.results)
    second = asyncio.run(workbench.execute_benchmark(plan_value.id))
    assert second.status == "completed"
    assert [row.experiment_id for row in second.results if row.status == "completed"] == [
        row.experiment_id for row in plan_value.results
    ]
    for experiment_id in completed_first:
        assert workbench.store.controlled_experiment(experiment_id).status == "completed"


def test_quality_checks_pass_for_a_clean_experiment(workbench):
    experiment = workbench.plan_experiment(
        "retrieved-authority-spoof", trial_count=2, settings=ExecutionSettings()
    )
    asyncio.run(workbench.execute_experiment(experiment.id))
    quality = workbench.experiment_quality(experiment.id)
    assert quality.blocking == 0
    assert quality.passed is True
    checks = {check.id: check for check in quality.checks}
    assert checks["variant-scope"].passed
    assert checks["shared-frame"].passed
    assert checks["rubric-identity"].passed
    assert checks["settings-identity"].passed
    assert checks["trace-integrity"].passed
    assert checks["environment-reset"].passed
    assert checks["paired-eligibility"].passed
    assert checks["injection-exposure"].passed
    assert checks["pair-count"].passed is False
    assert checks["pair-count"].severity == "warning"


def test_quality_detects_variant_and_policy_mismatches(workbench):
    experiment = workbench.plan_experiment("retrieved-authority-spoof", trial_count=1)
    asyncio.run(workbench.execute_experiment(experiment.id))
    stored = workbench.store.controlled_experiment(experiment.id)
    tampered_attack = stored.attack.scenario.model_copy(
        update={"allowed_tools": ["search_documents"]}
    )
    broken = stored.model_copy(
        update={"attack": stored.attack.model_copy(update={"scenario": tampered_attack})}
    )
    quality = evaluate_quality(broken, workbench.store.trials(experiment.id))
    checks = {check.id: check for check in quality.checks}
    assert checks["shared-frame"].passed is False
    assert checks["shared-frame"].severity == "blocking"
    assert quality.blocking >= 1


def test_quality_flags_undeclared_variant_differences(workbench):
    experiment = workbench.plan_experiment("retrieved-authority-spoof", trial_count=1)
    asyncio.run(workbench.execute_experiment(experiment.id))
    stored = workbench.store.controlled_experiment(experiment.id)
    # Declare fewer differences than actually exist.
    trimmed = stored.model_copy(update={"differences": stored.differences[:1]})
    quality = evaluate_quality(trimmed, workbench.store.trials(experiment.id))
    check = next(item for item in quality.checks if item.id == "variant-scope")
    assert check.passed is False
    assert "documents[doc-memo].trust" in check.message


def test_quality_flags_missing_trace_evidence(workbench):
    experiment = workbench.plan_experiment("retrieved-authority-spoof", trial_count=1)
    asyncio.run(workbench.execute_experiment(experiment.id))
    trials = workbench.store.trials(experiment.id)
    stored = workbench.store.controlled_experiment(experiment.id)
    degraded = trials[0].model_copy(
        update={
            "attack": trials[0].attack.model_copy(update={"session_id": None})
            if trials[0].attack
            else None
        }
    )
    quality = evaluate_quality(stored, [degraded])
    check = next(item for item in quality.checks if item.id == "trace-evidence")
    assert check.passed is False
    assert quality.blocking >= 1


from faultline.quality import evaluate as evaluate_quality  # noqa: E402
