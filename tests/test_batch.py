"""Batch evaluation: offline, resumable, and never a fabricated execution."""

import json
from pathlib import Path

from faultline.domain import AdjudicationPolicy, BatchBudget
from faultline.evaluation import Evaluator
from faultline.rubrics import sample_rubric

FIXTURES = Path(__file__).parent / "fixtures" / "datasets"


def import_fixture(workbench, name="reviewed-batch.jsonl"):
    return workbench.import_dataset(FIXTURES / name)


def test_batch_plans_cases_within_the_budget(workbench):
    rubric = sample_rubric()
    workbench.store.add_rubric(rubric)
    dataset = import_fixture(workbench)
    batch = workbench.create_batch(dataset.id, rubric)
    assert batch.status == "planned"
    assert batch.origin == "dataset_import"
    assert batch.dataset_sha256 == dataset.dataset_sha256
    assert batch.rubric_definition_id == "synthetic-canary"
    cases = workbench.batch_cases(batch.id)
    assert [case.case_id for case in cases] == dataset.record_ids
    assert all(case.status == "pending" for case in cases)
    limited = workbench.create_batch(dataset.id, rubric, max_cases=2)
    assert len(workbench.batch_cases(limited.id)) == 2
    budgeted = workbench.create_batch(dataset.id, rubric, budget=BatchBudget(max_cases=1))
    assert budgeted.budget.max_cases == 1


def test_execution_never_contacts_a_provider_or_creates_a_run(workbench, monkeypatch):
    rubric = sample_rubric()
    workbench.store.add_rubric(rubric)
    dataset = import_fixture(workbench)
    batch = workbench.create_batch(dataset.id, rubric)

    async def forbidden(*args, **kwargs):
        raise AssertionError("Batch evaluation must not contact a model endpoint")

    monkeypatch.setattr("faultline.providers.MockProvider.complete", forbidden)
    monkeypatch.setattr("faultline.providers.CompatibleProvider.complete", forbidden)

    finished = workbench.execute_batch(batch.id)
    assert finished.status == "completed"
    sessions = workbench.store.sessions_for_dataset(dataset.id)
    assert sessions and all(session.origin == "dataset_import" for session in sessions)
    # No ExecutionRun exists anywhere in the database.
    with workbench.store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM experiments").fetchone()[0] == 0


def test_partial_execution_resumes_without_duplicates(workbench):
    rubric = sample_rubric()
    workbench.store.add_rubric(rubric)
    dataset = import_fixture(workbench)
    batch = workbench.create_batch(dataset.id, rubric)

    first = workbench.execute_batch(batch.id, limit=2)
    assert first.status == "partial"
    counts = workbench.store.batch_case_counts(batch.id)
    assert counts.get("completed", 0) + counts.get("skipped", 0) == 2
    assert counts["pending"] == 3
    processed = len([case for case in workbench.batch_cases(batch.id) if case.status != "pending"])
    assert processed == 2
    assert len(workbench.store.sessions_for_dataset(dataset.id)) == counts["completed"]

    second = workbench.execute_batch(batch.id)
    assert second.status == "completed"
    assert second.completed_at is not None
    assert workbench.store.batch_case_counts(batch.id).get("pending", 0) == 0
    sessions = workbench.store.sessions_for_dataset(dataset.id)
    completed = [case for case in workbench.batch_cases(batch.id) if case.status == "completed"]
    assert len(sessions) == len(completed)
    assert len({session.dataset_case_id for session in sessions}) == len(sessions)
    # Resuming a completed batch duplicates nothing.
    again = workbench.execute_batch(batch.id)
    assert again.status == "completed"
    assert len(workbench.store.sessions_for_dataset(dataset.id)) == len(sessions)


def test_empty_responses_are_skipped_not_failed(workbench):
    rubric = sample_rubric()
    workbench.store.add_rubric(rubric)
    dataset = import_fixture(workbench)
    batch = workbench.create_batch(dataset.id, rubric)
    workbench.execute_batch(batch.id)
    skipped = [case for case in workbench.batch_cases(batch.id) if case.status == "skipped"]
    assert [case.case_id for case in skipped] == ["batch-005"]
    assert skipped[0].skip_reason == "Imported response is empty"
    assert skipped[0].session_id is None
    report = workbench.batch_report(batch.id)
    assert report.coverage.cases_skipped == 1
    assert report.coverage.excluded_case_ids == ["batch-005"]
    assert any("neither pass nor fail" in note for note in report.coverage.notes)


def test_evaluator_failure_marks_one_case_failed_and_continues(workbench, tmp_path):
    class ExplodingEvaluator(Evaluator):
        def evaluate(self, rubric, case, response, run_id, evidence):
            if response.text == "trigger failure":
                raise RuntimeError("Sensitive unhandled detail")
            return super().evaluate(rubric, case, response, run_id, evidence)

    workbench.evaluator = ExplodingEvaluator()
    rubric = sample_rubric()
    workbench.store.add_rubric(rubric)
    payload = tmp_path / "mixed.jsonl"
    payload.write_text(
        "\n".join(
            [
                json.dumps({"id": "ok-1", "prompt": "p", "response": "SAFE"}),
                json.dumps({"id": "bad-1", "prompt": "p", "response": "trigger failure"}),
                json.dumps({"id": "ok-2", "prompt": "p", "response": "SAFE"}),
            ]
        )
    )
    dataset = workbench.import_dataset(payload)
    batch = workbench.create_batch(dataset.id, rubric)
    workbench.execute_batch(batch.id)

    cases = {case.case_id: case for case in workbench.batch_cases(batch.id)}
    assert cases["bad-1"].status == "failed"
    assert cases["bad-1"].error == "Evaluation failed; imported evidence preserved for review"
    assert cases["bad-1"].session_id is None
    assert "Sensitive unhandled detail" not in cases["bad-1"].model_dump_json()
    assert cases["ok-1"].status == "completed"
    assert cases["ok-2"].status == "completed"
    report = workbench.batch_report(batch.id)
    assert report.progress.cases_failed == 1
    assert report.coverage.cases_failed == 1
    assert any("failed evaluation" in note for note in report.coverage.notes)


def test_dataset_sessions_preserve_imported_evidence(workbench):
    rubric = sample_rubric()
    workbench.store.add_rubric(rubric)
    dataset = import_fixture(workbench)
    batch = workbench.create_batch(dataset.id, rubric)
    workbench.execute_batch(batch.id)
    session = workbench.store.sessions_for_dataset(dataset.id)[0]
    assert session.evidence_kind == "dataset"
    assert session.run_id is None
    assert session.experiment_id is None
    assert session.dataset_id == dataset.id
    assert [artifact.kind for artifact in session.evidence] == [
        "dataset-record",
        "imported-response",
    ]
    assert len(session.execution_sha256) == 64
    assert all(value.run_id == session.dataset_case_id for value in session.evaluations)


def test_batch_and_sessions_survive_reopening(workbench):
    rubric = sample_rubric()
    workbench.store.add_rubric(rubric)
    dataset = import_fixture(workbench)
    batch = workbench.create_batch(dataset.id, rubric)
    workbench.execute_batch(batch.id, limit=3)

    from faultline.service import Workbench
    from faultline.storage import Store

    reopened = Workbench(Store(workbench.store.path))
    saved = reopened.batch(batch.id)
    assert saved.status == "partial"
    cases = reopened.batch_cases(batch.id)
    assert [case.status for case in cases].count("pending") == 2
    sessions = reopened.store.sessions_for_dataset(dataset.id)
    assert len(sessions) == len([case for case in cases if case.status == "completed"])
    # Streaming reads remain available after reopening.
    assert len(list(reopened.store.dataset_records(dataset.id))) == dataset.record_count
    finished = reopened.execute_batch(batch.id)
    assert finished.status == "completed"


def test_a_finished_case_cannot_be_finalized_twice(workbench):
    rubric = sample_rubric()
    workbench.store.add_rubric(rubric)
    dataset = import_fixture(workbench)
    batch = workbench.create_batch(dataset.id, rubric)
    workbench.execute_batch(batch.id)
    completed = next(case for case in workbench.batch_cases(batch.id) if case.status == "completed")
    import sqlite3

    import pytest

    with pytest.raises(ValueError, match="already finalized"):
        workbench.store.finish_batch_case(completed)
    with workbench.store.connect() as db, pytest.raises(sqlite3.IntegrityError, match="retained"):
        db.execute("DELETE FROM batch_cases")


def test_batch_sessions_accept_judgments_and_adjudication(workbench):
    rubric = sample_rubric()
    workbench.store.add_rubric(rubric)
    dataset = import_fixture(workbench)
    batch = workbench.create_batch(dataset.id, rubric)
    workbench.execute_batch(batch.id)
    session = workbench.store.sessions_for_dataset(dataset.id)[0]
    alice = workbench.record_judgment(
        session.id, "CONF-001", reviewer="Alice", outcome="fail", rationale="Present"
    )
    assert alice.evidence_ids == [artifact.id for artifact in session.evidence]
    workbench.adjudicate(
        session.id,
        policy=AdjudicationPolicy(kind="single_reviewer", reviewer="Alice"),
        reviewer="Lead",
        rationale="Designated reviewer decision",
    )
    report = workbench.batch_report(batch.id)
    result = next(
        item
        for item in report.effective_results
        if item.session_id == session.id and item.criterion_id == "CONF-001"
    )
    assert result.status in {"confirmed", "overridden", "human_assessed"}
    assert report.coverage.session_criteria_adjudicated == 1


def test_batch_dry_run_validates_without_evaluating(workbench):
    rubric = sample_rubric()
    workbench.store.add_rubric(rubric)
    dataset = import_fixture(workbench)
    batch = workbench.create_batch(dataset.id, rubric)
    planned = workbench.pending_batch_cases(batch.id, limit=2)
    assert len(planned) == 2
    unchanged = workbench.execute_batch(batch.id, limit=2, dry_run=True)
    assert unchanged.status == "planned"
    assert workbench.store.sessions_for_dataset(dataset.id) == []
    assert workbench.store.batch_case_counts(batch.id) == {"pending": 5}
    # A pending rubric cannot be batched even as a dry run.
    from faultline.rubrics import import_document

    pending = import_document(b"Free-form notes", ".md", "notes")
    workbench.store.add_rubric(pending)
    import pytest

    with pytest.raises(ValueError, match="normalization"):
        workbench.create_batch(dataset.id, pending)
