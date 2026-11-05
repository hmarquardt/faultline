import json
import sqlite3
from pathlib import Path

import pytest

from faultline.domain import (
    EndpointProfile,
    ExecutionBudget,
    ExecutionSettings,
    HumanOverride,
    Report,
    digest,
)
from faultline.providers import MockProvider, ProviderError
from faultline.reports import export_report, fenced, verify_export_digest
from faultline.service import Workbench
from faultline.storage import Store
from faultline.techniques import render_cases, techniques


@pytest.mark.parametrize("fixture", ["secure", "vulnerable"])
async def test_complete_vertical_slice(workbench, rubric, tmp_path, fixture):
    expected = json.loads((Path(__file__).parent / "fixtures" / f"{fixture}.json").read_text())
    profile = EndpointProfile(name=fixture, authorized=True, mock_behavior=expected["behavior"])
    workbench.store.add_profile(profile)
    workbench.store.add_rubric(rubric)
    experiment = workbench.prepare(profile, rubric)
    report = await workbench.execute(experiment)
    assert report.experiment.status == "completed"
    assert [r.response.text for r in report.runs] == [expected["baseline"], expected["attack"]]
    assert [v.outcome for v in report.runs[1].evaluations] == expected["attack_outcomes"]
    assert len(report.findings) == expected["findings"]
    assert all(f.classification == "simulated" for f in report.findings)
    assert report.automated_scores[0].weighted_compliance == 1
    assert report.automated_scores[1].coverage == 1
    for run in report.runs:
        assert run.started_at.tzinfo is not None
        assert run.completed_at >= run.started_at
        assert run.response.returned_model == "toy-model"
        for artifact in run.evidence:
            assert digest(artifact.content) == artifact.sha256
        assert all(v.evidence_ids == [run.evidence[0].id] for v in run.evaluations)
        assert all(v.rubric_version == "1.0.0" for v in run.evaluations)
    # Real close/reopen and schema validation, not an in-memory store assertion.
    reopened = Workbench(Store(workbench.store.path))
    saved = reopened.report(experiment.id)
    assert saved.experiment == report.experiment
    assert saved.runs == report.runs
    assert reopened.store.profiles() == [profile]
    assert reopened.store.rubrics() == [rubric]
    paths = export_report(saved, tmp_path / fixture)
    exported = Report.model_validate_json(paths[0].read_text())
    assert exported.export_digest is not None
    assert verify_export_digest(exported)
    # Export identity is new; every source record is unchanged by exporting.
    assert exported.model_dump(exclude={"export_digest"}) == saved.model_dump(
        exclude={"export_digest"}
    )
    md = paths[1].read_text()
    assert rubric.source.sha256 in md
    assert all(a.sha256 in md for r in saved.runs for a in r.evidence)
    assert "Complete reproducibility" in md
    with pytest.raises(ValueError, match="exists"):
        export_report(saved, tmp_path / fixture)
    with pytest.raises(ValueError, match="finalized"):
        reopened.store.finish_run(saved.runs[0], [])


@pytest.mark.parametrize("technique", list(techniques()))
async def test_every_technique_executes_independently(workbench, profile, rubric, technique):
    report = await workbench.execute(workbench.prepare(profile, rubric, technique))
    assert len(report.runs) == 2
    assert not report.findings
    assert report.runs[0].case.messages[0] == report.runs[1].case.messages[0]
    assert report.runs[0].case.messages != report.runs[1].case.messages


def test_parameters_and_family_coverage():
    registry = techniques()
    assert len({t.family for t in registry.values()}) == 9
    for technique in registry.values():
        cases = render_cases(technique, {"canary": "FAULTLINE_SYNTHETIC_DIFFERENT_1234"})
        assert "FAULTLINE_SYNTHETIC_DIFFERENT_1234" in cases[0].messages[0].content
    with pytest.raises(ValueError, match="Unknown"):
        render_cases(registry["authority-spoof"], {"unexpected": "x"})
    with pytest.raises(ValueError, match="synthetic"):
        render_cases(registry["authority-spoof"], {"canary": "real-secret"})


@pytest.mark.parametrize(
    "change, message",
    [
        ({"budget": ExecutionBudget(max_requests=1)}, "Request budget"),
        ({"budget": ExecutionBudget(max_total_output_tokens=1)}, "Output-token"),
        ({"budget": ExecutionBudget(max_input_bytes=1)}, "input-byte"),
        ({"settings": ExecutionSettings(max_output_tokens=1000)}, "Output-token"),
    ],
)
async def test_budget_rejection_happens_before_persistence(
    workbench, profile, rubric, change, message
):
    experiment = workbench.prepare(profile, rubric).model_copy(update=change)
    with pytest.raises(ValueError, match=message):
        await workbench.execute(experiment)
    assert not workbench.store.history()


async def test_dry_run_never_calls_adapter(workbench, profile, rubric):
    class ForbiddenProvider:
        async def complete(self, *args):
            pytest.fail("Dry-run called an endpoint")

    experiment = workbench.prepare(profile, rubric, dry_run=True)
    report = await workbench.execute(experiment, provider=ForbiddenProvider())
    assert report.experiment.status == "dry_run"
    assert all(r.status == "dry_run" and not r.evaluations for r in report.runs)
    assert all(s.coverage == 0 for s in report.automated_scores)
    assert all(r.response is None for r in report.runs)


async def test_partial_failure_is_persisted_and_does_not_become_a_pass(workbench, profile, rubric):
    class FailAttack(MockProvider):
        async def complete(self, case, *args):
            if case.kind == "attack":
                raise ProviderError("Endpoint returned HTTP 429")
            return await super().complete(case, *args)

    report = await workbench.execute(workbench.prepare(profile, rubric), provider=FailAttack())
    assert report.experiment.status == "failed"
    assert [r.status for r in report.runs] == ["completed", "failed"]
    assert report.runs[1].error == "Endpoint returned HTTP 429"
    assert report.automated_scores[1].weighted_compliance is None
    assert report.automated_scores[1].coverage == 0


async def test_human_override_preserves_original_and_rejects_unknown_id(workbench, profile, rubric):
    report = await workbench.execute(workbench.prepare(profile, rubric))
    original = report.runs[0].evaluations[0]
    first = HumanOverride(
        evaluation_id=original.id,
        reviewer="Tester",
        outcome="uncertain",
        rationale="Reviewing encoded variants separately",
    )
    second = HumanOverride(
        evaluation_id=original.id,
        reviewer="Peer",
        outcome="pass",
        rationale="Exact literal criterion only",
    )
    workbench.store.add_override(first)
    workbench.store.add_override(second)
    saved = workbench.report(report.experiment.id)
    assert saved.runs[0].evaluations[0] == original
    assert saved.human_overrides == [first, second]
    with pytest.raises(sqlite3.IntegrityError):
        workbench.store.add_override(
            first.model_copy(update={"id": "other", "evaluation_id": "missing"})
        )
    with (
        workbench.store.connect() as db,
        pytest.raises(sqlite3.IntegrityError, match="append-only"),
    ):
        db.execute("DELETE FROM overrides")


def test_markdown_fences_cannot_be_escaped_by_response():
    hostile = "```\n# injected heading\n``````"
    result = fenced(hostile)
    assert result.startswith("```````text\n")
    assert result.endswith("\n```````\n")


def test_unknown_database_schema_fails_closed(tmp_path):
    path = tmp_path / "future.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=999")
    with pytest.raises(ValueError, match="Unsupported"):
        Store(path)


async def test_evaluator_failure_does_not_erase_received_evidence(workbench, profile, rubric):
    from faultline.evaluation import Evaluator

    class BrokenEvaluator(Evaluator):
        def evaluate(self, *args):
            raise RuntimeError("Sensitive unhandled detail")

    workbench.evaluator = BrokenEvaluator()
    report = await workbench.execute(workbench.prepare(profile, rubric))
    assert report.experiment.status == "failed"
    assert report.runs[0].response.text == "SAFE"
    assert report.runs[0].evidence
    assert not report.runs[0].evaluations
    assert "Sensitive unhandled detail" not in report.model_dump_json()
    assert "evidence preserved" in report.runs[0].error
