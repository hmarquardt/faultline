"""Batch reports: provenance, separation, agreement, CSV and export identity."""

from pathlib import Path

from faultline.domain import BatchReport
from faultline.reports import (
    CSV_COLUMNS,
    evaluation_rows,
    export_report,
    verify_export_digest,
)
from faultline.rubrics import sample_rubric

FIXTURES = Path(__file__).parent / "fixtures" / "datasets"
BATCH_HEADINGS = (
    "## Dataset provenance and membership",
    "## Batch progress and aggregate compliance",
    "## Case-level evaluations",
    "## Human judgments (append-only)",
    "## Adjudication and effective results",
    "## Unresolved disagreements",
    "## Inter-rater agreement",
    "## Coverage, uncertainty and limitations",
    "## Complete reproducibility and evidence bundle",
)


def build_reviewed_batch(workbench):
    rubric = sample_rubric()
    workbench.store.add_rubric(rubric)
    dataset = workbench.import_dataset(FIXTURES / "reviewed-batch.jsonl")
    batch = workbench.create_batch(dataset.id, rubric)
    workbench.execute_batch(batch.id)
    session = workbench.store.sessions_for_dataset(dataset.id)[0]
    return dataset, batch, session


def test_batch_report_carries_complete_provenance(workbench):
    dataset, batch, session = build_reviewed_batch(workbench)
    report = workbench.batch_report(batch.id)
    assert isinstance(report, BatchReport)
    assert report.origin == "dataset_import"
    assert report.report_format_version == "2.1.0"
    assert report.dataset.id == dataset.id
    assert report.dataset.source.sha256 == dataset.source.sha256
    assert report.dataset.dataset_sha256 == dataset.dataset_sha256
    assert report.batch.id == batch.id
    assert report.batch.rubric_source_sha256 == sample_rubric().source.sha256
    assert {record.id for record in report.records} == {case.case_id for case in report.cases}
    assert {item.session_id for item in report.effective_results} == {
        item.id for item in report.evaluation_sessions
    }
    assert report.progress.cases_total == len(report.cases) == 5
    assert report.progress.cases_completed + report.progress.cases_skipped == 5
    assert report.agreement is not None and report.agreement.scope == "batch"
    assert {digest.kind for digest in report.evidence_digests} <= {
        "evaluation",
        "judgment",
        "adjudication",
    }
    # No experiment, run or provider reference describes these cases.
    assert "experiment" not in report.model_dump()
    assert all(session.run_id is None for session in report.evaluation_sessions)


def test_batch_report_markdown_and_csv_are_complete(workbench, tmp_path):
    dataset, batch, session = build_reviewed_batch(workbench)
    workbench.record_judgment(
        session.id, "CONF-001", reviewer="Alice", outcome="pass", rationale="No literal match"
    )
    workbench.record_judgment(
        session.id, "CONF-001", reviewer="Bob", outcome="fail", rationale="Literal match"
    )
    report = workbench.batch_report(batch.id)
    paths = export_report(report, tmp_path / "batch")
    assert [path.suffix for path in paths] == [".json", ".md", ".csv"]
    markdown = paths[1].read_text()
    for heading in BATCH_HEADINGS:
        assert heading in markdown
    assert "No request was sent by Faultline" in markdown
    assert dataset.source.sha256 in markdown
    assert batch.rubric_source_sha256 in markdown
    assert "unresolved disagreement" in markdown.lower()

    exported = BatchReport.model_validate_json(paths[0].read_text())
    assert verify_export_digest(exported)
    assert exported.export_digest.sha256 not in {
        digest.sha256 for digest in exported.evidence_digests
    }
    rows = paths[2].read_text().splitlines()
    assert rows[0] == ",".join(CSV_COLUMNS)
    assert len(rows) - 1 == len(evaluation_rows(exported))
    assert "batch-001" in paths[2].read_text()
    assert "CONF-001" in paths[2].read_text()


def test_agreement_statistics_appear_in_batch_and_experiment_reports(workbench, tmp_path):
    dataset, batch, session = build_reviewed_batch(workbench)
    workbench.record_judgment(
        session.id, "INST-001", reviewer="Alice", outcome="pass", rationale="Marker present"
    )
    workbench.record_judgment(
        session.id, "INST-001", reviewer="Bob", outcome="fail", rationale="Marker absent"
    )
    report = workbench.batch_report(batch.id)
    group = next(item for item in report.agreement.groups if item.criterion_id == "INST-001")
    assert group.units_compared == 1
    assert group.outcome_agreement == 0.0
    assert group.kappa is not None and not group.kappa.defined
    assert report.coverage.session_criteria_with_human_judgment >= 1
    markdown = export_report(report, tmp_path / "agreement")[1].read_text()
    assert "kappa: undefined" in markdown
    assert "pair Alice/Bob" in markdown

    # An experiment report uses the same statistics block for its own reviews.
    from faultline.domain import EndpointProfile

    executed = workbench.report(
        workbench.store.experiment(
            _seeded_experiment(workbench, EndpointProfile(name="mock", authorized=True))
        ).id
    )
    assert executed.report_format_version == "2.1.0"
    assert executed.agreement is not None and executed.agreement.scope == "experiment"
    assert (
        "## Inter-rater agreement"
        in export_report(executed, tmp_path / "experiment")[1].read_text()
    )


def _seeded_experiment(workbench, profile):
    import asyncio

    report = asyncio.run(workbench.execute(workbench.prepare(profile, sample_rubric())))
    return report.experiment.id


def test_csv_neutralises_formula_prefixes():
    from faultline.reports import _safe_cell

    assert _safe_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert _safe_cell("+1234") == "'+1234"
    assert _safe_cell("-1") == "'-1"
    assert _safe_cell("@SUM(A1)") == "'@SUM(A1)"
    assert _safe_cell("ordinary") == "ordinary"
    assert _safe_cell(None) == ""


def test_export_identity_is_reproducible_and_distinct_from_source_evidence(workbench, tmp_path):
    dataset, batch, _ = build_reviewed_batch(workbench)
    report = workbench.batch_report(batch.id)
    first = export_report(report, tmp_path / "one")
    second = export_report(report, tmp_path / "two")
    assert first[0].read_text() == second[0].read_text()
    assert first[2].read_text() == second[2].read_text()
    exported = BatchReport.model_validate_json(first[0].read_text())
    assert exported.export_digest is not None
    assert exported.dataset.source.sha256 not in {
        digest.sha256 for digest in exported.evidence_digests
    }
    tampered = exported.model_copy(update={"limitations": []})
    assert not verify_export_digest(tampered)


def test_report_exports_never_claim_a_provider_request(workbench, tmp_path):
    dataset, batch, _ = build_reviewed_batch(workbench)
    paths = export_report(workbench.batch_report(batch.id), tmp_path / "claims")
    text = paths[0].read_text() + paths[1].read_text()
    assert "endpoint" not in paths[0].read_text()
    assert "No provider request was made" in text or "No provider request" in text
    assert "returned_model" not in paths[1].read_text().split("Complete reproducibility")[0]
    assert dataset.id in text
