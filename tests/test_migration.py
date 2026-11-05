"""Explicit Phase 1 → Phase 2A migration: preserve rows, IDs and evidence."""

import json
import sqlite3
from pathlib import Path

import pytest

from faultline.domain import AdjudicationPolicy, Report
from faultline.integrity import execution_digest
from faultline.reports import export_report, verify_export_digest
from faultline.rubrics import sample_rubric
from faultline.service import Workbench
from faultline.storage import SCHEMA_VERSION, Store

FIXTURES = Path(__file__).parent / "fixtures" / "phase1"

# Verbatim Phase 1 schema. Kept in the test so the fixture cannot drift with src.
PHASE1_DDL = """
CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, snapshot TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rubrics (id TEXT PRIMARY KEY, snapshot TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS experiments (
    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, snapshot TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES experiments(id),
    status TEXT NOT NULL, snapshot TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_experiment ON runs(experiment_id);
CREATE TABLE IF NOT EXISTS evaluations (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), snapshot TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES experiments(id),
    evaluation_id TEXT NOT NULL REFERENCES evaluations(id), snapshot TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS overrides (
    id TEXT PRIMARY KEY, evaluation_id TEXT NOT NULL REFERENCES evaluations(id),
    snapshot TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS overrides_no_update BEFORE UPDATE ON overrides
BEGIN SELECT RAISE(ABORT, 'Overrides are append-only'); END;
CREATE TRIGGER IF NOT EXISTS overrides_no_delete BEFORE DELETE ON overrides
BEGIN SELECT RAISE(ABORT, 'Overrides are append-only'); END;
PRAGMA user_version=1;
"""

TABLES = ("profiles", "rubrics", "experiments", "runs", "evaluations", "findings", "overrides")


def phase1_rows() -> dict:
    return json.loads((FIXTURES / "database.json").read_text())["tables"]


def build_phase1_database(path: Path) -> dict:
    """Recreate a real Phase 1 database from captured rows."""
    payload = phase1_rows()
    with sqlite3.connect(path) as db:
        db.executescript(PHASE1_DDL)
        for table in TABLES:
            for row in payload[table]:
                placeholders = ", ".join("?" for _ in row)
                db.execute(f"INSERT INTO {table} VALUES ({placeholders})", row)
    return payload


def snapshots(path: Path) -> dict[str, list[str]]:
    with sqlite3.connect(path) as db:
        return {
            table: [row[0] for row in db.execute(f"SELECT snapshot FROM {table} ORDER BY rowid")]
            for table in TABLES
        }


def user_version(path: Path) -> int:
    with sqlite3.connect(path) as db:
        return db.execute("PRAGMA user_version").fetchone()[0]


def table_columns(path: Path, table: str) -> list[str]:
    with sqlite3.connect(path) as db:
        return [row[1] for row in db.execute(f"PRAGMA table_info({table})").fetchall()]


def table_names(path: Path) -> set[str]:
    with sqlite3.connect(path) as db:
        return {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def test_phase1_database_migrates_without_changing_stored_records(tmp_path):
    path = tmp_path / "phase1.sqlite3"
    build_phase1_database(path)
    before = snapshots(path)
    assert user_version(path) == 1

    store = Store(path)
    assert store.schema_version == SCHEMA_VERSION == 2
    # Every existing row survives byte-for-byte, including the legacy override.
    assert snapshots(path) == before

    experiment_id = json.loads(before["experiments"][0])["id"]
    sessions = store.sessions(experiment_id=experiment_id)
    assert len(sessions) == 2
    for session in sessions:
        run = store.run(session.run_id)
        assert session.origin == "migration"
        assert session.status == "completed"
        assert session.evaluator_settings == {"derived_from": "phase-1-evaluations"}
        assert session.completed_at is not None
        assert session.execution_sha256 == execution_digest(run)
        assert [e.id for e in session.evaluations] == [e.id for e in run.evaluations]
        assert session.rubric_definition_sha256
        experiment = json.loads(before["experiments"][0])
        assert session.rubric.source.sha256 == experiment["rubric"]["source"]["sha256"]
    with store.connect() as db:
        linked = db.execute(
            "SELECT COUNT(*) FROM evaluations WHERE session_id IS NOT NULL"
        ).fetchone()[0]
    assert linked == 4
    # Append-only triggers now also cover the new records.
    with store.connect() as db, pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.execute("DELETE FROM evaluation_sessions")


def test_migrated_database_supports_reevaluation_and_review(tmp_path):
    path = tmp_path / "phase1.sqlite3"
    payload = build_phase1_database(path)
    store = Store(path)
    workbench = Workbench(store)
    experiment_id = json.loads(payload["experiments"][0][2])["id"]
    run_id = json.loads(payload["runs"][1][3])["id"]

    report = workbench.report(experiment_id)
    assert report.report_format_version == "2.0.0"
    # Legacy overrides stay visible and are never treated as adjudications.
    assert report.human_overrides and not report.adjudications
    assert all(result.status == "automated_only" for result in report.effective_results)

    rubric = sample_rubric()
    store.add_rubric(rubric)
    session = workbench.reevaluate(run_id, rubric)
    assert session.origin == "reevaluation"
    workbench.record_judgment(
        session.id,
        "CONF-001",
        reviewer="Post-migration reviewer",
        outcome="pass",
        rationale="Literal criterion only",
    )
    workbench.adjudicate(
        session.id,
        policy=AdjudicationPolicy(kind="single_reviewer", reviewer="Post-migration reviewer"),
        reviewer="Lead",
        rationale="Explicit policy after migration",
    )
    final = workbench.report(experiment_id)
    assert len(final.evaluation_sessions) == 3
    assert any(result.status == "overridden" for result in final.effective_results)
    paths = export_report(final, tmp_path / "migrated")
    assert verify_export_digest(Report.model_validate_json(paths[0].read_text()))


def test_failed_migration_rolls_back_and_keeps_version_1(tmp_path):
    path = tmp_path / "broken.sqlite3"
    payload = build_phase1_database(path)
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE runs SET snapshot=? WHERE id=?",
            ("{not a run snapshot}", json.loads(payload["runs"][0][3])["id"]),
        )
    with pytest.raises(ValueError, match="migration failed"):
        Store(path)
    assert user_version(path) == 1
    assert "evaluation_sessions" not in table_names(path)
    assert "judgments" not in table_names(path)
    assert "session_id" not in table_columns(path, "evaluations")


def test_reopening_a_migrated_database_is_stable(tmp_path):
    path = tmp_path / "phase1.sqlite3"
    payload = build_phase1_database(path)
    first = Store(path).sessions()
    second = Store(path).sessions()
    assert [s.id for s in first] == [s.id for s in second]
    assert user_version(path) == 2
    experiment_id = json.loads(payload["experiments"][0][2])["id"]
    assert Store(path).experiment(experiment_id).id == experiment_id


def test_historical_phase1_report_still_loads_and_reexports(tmp_path):
    historical = Report.model_validate_json((FIXTURES / "report.v1.json").read_text())
    assert historical.report_format_version == "2.0.0"
    assert not historical.evaluation_sessions
    assert not historical.effective_results
    assert historical.human_overrides[0].reviewer == "Phase 1 reviewer"
    assert len(historical.findings) == 2
    paths = export_report(historical, tmp_path / "historical")
    reexported = Report.model_validate_json(paths[0].read_text())
    assert reexported.model_dump(exclude={"export_digest"}) == historical.model_dump(
        exclude={"export_digest"}
    )
    assert verify_export_digest(reexported)
    assert "Legacy Phase 1 overrides" in paths[1].read_text()
