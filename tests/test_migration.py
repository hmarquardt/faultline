"""Explicit Phase 1 → Phase 2A migration: preserve rows, IDs and evidence."""

import asyncio
import json
import sqlite3
from pathlib import Path

import pytest

from faultline.domain import AdjudicationPolicy, EndpointProfile, Report
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
    assert store.schema_version == SCHEMA_VERSION == 5
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
    assert report.report_format_version == "2.1.0"
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
    assert user_version(path) == 5
    experiment_id = json.loads(payload["experiments"][0][2])["id"]
    assert Store(path).experiment(experiment_id).id == experiment_id


def test_historical_phase1_report_still_loads_and_reexports(tmp_path):
    historical = Report.model_validate_json((FIXTURES / "report.v1.json").read_text())
    # A Phase 1 file predates the format field, so it loads with the current one.
    assert historical.report_format_version == "2.1.0"
    # A file that recorded format 2.0.0 keeps it; 2.1.0 is also accepted.
    two_zero = json.loads(historical.model_dump_json())
    two_zero["report_format_version"] = "2.0.0"
    assert Report.model_validate(two_zero).report_format_version == "2.0.0"
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


# Verbatim Phase 2A schema (commit f26ad7f). Kept here so the fixture cannot drift.
V2_DDL = """
CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, snapshot TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rubrics (id TEXT PRIMARY KEY, snapshot TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS experiments (
    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, snapshot TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES experiments(id),
    status TEXT NOT NULL, snapshot TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evaluation_sessions (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
    experiment_id TEXT NOT NULL REFERENCES experiments(id),
    rubric_id TEXT NOT NULL, rubric_version TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL, execution_sha256 TEXT NOT NULL, snapshot TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evaluations (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
    session_id TEXT REFERENCES evaluation_sessions(id), snapshot TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES experiments(id),
    evaluation_id TEXT NOT NULL REFERENCES evaluations(id), snapshot TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS overrides (
    id TEXT PRIMARY KEY, evaluation_id TEXT NOT NULL REFERENCES evaluations(id),
    snapshot TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS judgments (
    id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES evaluation_sessions(id),
    run_id TEXT NOT NULL REFERENCES runs(id), criterion_id TEXT NOT NULL,
    reviewer TEXT NOT NULL, snapshot TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS adjudications (
    id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES evaluation_sessions(id),
    criterion_id TEXT NOT NULL, snapshot TEXT NOT NULL
);
PRAGMA user_version=2;
"""


def build_phase2a_database(source: Path, target: Path) -> None:
    """Copy a real Phase 2A-shaped database from current records into v2 tables."""
    with sqlite3.connect(source) as origin, sqlite3.connect(target) as db:
        db.executescript(V2_DDL)
        db.executescript(
            """
            CREATE TRIGGER IF NOT EXISTS overrides_no_update BEFORE UPDATE ON overrides
            BEGIN SELECT RAISE(ABORT, 'Overrides are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS overrides_no_delete BEFORE DELETE ON overrides
            BEGIN SELECT RAISE(ABORT, 'Overrides are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS evaluations_no_update BEFORE UPDATE ON evaluations
            BEGIN SELECT RAISE(ABORT, 'Evaluations are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS evaluations_no_delete BEFORE DELETE ON evaluations
            BEGIN SELECT RAISE(ABORT, 'Evaluations are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS evaluation_sessions_no_update
                BEFORE UPDATE ON evaluation_sessions
            BEGIN SELECT RAISE(ABORT, 'Evaluation sessions are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS evaluation_sessions_no_delete
                BEFORE DELETE ON evaluation_sessions
            BEGIN SELECT RAISE(ABORT, 'Evaluation sessions are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS judgments_no_update BEFORE UPDATE ON judgments
            BEGIN SELECT RAISE(ABORT, 'Human judgments are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS judgments_no_delete BEFORE DELETE ON judgments
            BEGIN SELECT RAISE(ABORT, 'Human judgments are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS adjudications_no_update BEFORE UPDATE ON adjudications
            BEGIN SELECT RAISE(ABORT, 'Adjudications are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS adjudications_no_delete BEFORE DELETE ON adjudications
            BEGIN SELECT RAISE(ABORT, 'Adjudications are append-only'); END;
            """
        )
        for table in (
            "experiments",
            "runs",
            "findings",
            "overrides",
            "adjudications",
        ):
            for row in origin.execute(f"SELECT * FROM {table} ORDER BY rowid"):
                placeholders = ", ".join("?" for _ in row)
                db.execute(f"INSERT INTO {table} VALUES ({placeholders})", tuple(row))
        for row in origin.execute(
            "SELECT id, run_id, experiment_id, rubric_id, rubric_version, status, "
            "created_at, execution_sha256, snapshot FROM evaluation_sessions ORDER BY rowid"
        ):
            db.execute(
                "INSERT INTO evaluation_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(row),
            )
        for row in origin.execute(
            "SELECT id, run_id, session_id, snapshot FROM evaluations ORDER BY rowid"
        ):
            db.execute("INSERT INTO evaluations VALUES (?, ?, ?, ?)", tuple(row))
        for row in origin.execute(
            "SELECT id, session_id, run_id, criterion_id, reviewer, snapshot FROM judgments"
        ):
            db.execute("INSERT INTO judgments VALUES (?, ?, ?, ?, ?, ?)", tuple(row))


def test_phase2a_database_migrates_to_dataset_capable_schema(tmp_path):
    import asyncio

    from faultline.domain import AdjudicationPolicy, EndpointProfile

    source = tmp_path / "current.sqlite3"
    workbench = Workbench(Store(source))
    profile = EndpointProfile(name="mock", authorized=True)
    report = asyncio.run(workbench.execute(workbench.prepare(profile, sample_rubric())))
    session = report.evaluation_sessions[0]
    workbench.record_judgment(
        session.id, "CONF-001", reviewer="Alice", outcome="pass", rationale="Literal only"
    )
    workbench.adjudicate(
        session.id,
        policy=AdjudicationPolicy(kind="single_reviewer", reviewer="Alice"),
        reviewer="Lead",
        rationale="Designated reviewer decision",
    )

    legacy = tmp_path / "phase2a.sqlite3"
    build_phase2a_database(source, legacy)
    with sqlite3.connect(legacy) as db:
        before_sessions = [
            row[0] for row in db.execute("SELECT snapshot FROM evaluation_sessions ORDER BY rowid")
        ]
        before_judgments = [
            row[0] for row in db.execute("SELECT snapshot FROM judgments ORDER BY rowid")
        ]
        before_ids = [
            row[0] for row in db.execute("SELECT id FROM evaluation_sessions ORDER BY rowid")
        ]
    assert user_version(legacy) == 2

    migrated = Store(legacy)
    assert migrated.schema_version == 5
    assert [session.id for session in migrated.sessions()] == before_ids
    with sqlite3.connect(legacy) as db:
        assert [
            row[0] for row in db.execute("SELECT snapshot FROM evaluation_sessions ORDER BY rowid")
        ] == before_sessions
        assert [
            row[0] for row in db.execute("SELECT snapshot FROM judgments ORDER BY rowid")
        ] == before_judgments
        nulls = db.execute(
            "SELECT COUNT(*) FROM evaluation_sessions "
            "WHERE evidence_kind='execution' AND dataset_id IS NULL "
            "AND dataset_case_id IS NULL AND run_id IS NOT NULL"
        ).fetchone()[0]
        assert nulls == len(before_ids)
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        assert db.execute("PRAGMA user_version").fetchone()[0] == 5
    # The migrated database supports new dataset sessions and imported evidence.
    workbench = Workbench(migrated)
    rubric = sample_rubric()
    migrated.add_rubric(rubric)
    dataset = workbench.import_dataset(
        Path(__file__).parent / "fixtures" / "datasets" / "reviewed-batch.json"
    )
    batch = workbench.create_batch(dataset.id, rubric)
    assert workbench.execute_batch(batch.id).status == "completed"
    assert len(migrated.sessions_for_dataset(dataset.id)) == 2
    # Historical experiment records stay readable and reportable.
    historical = workbench.report(report.experiment.id)
    assert historical.report_format_version == "2.1.0"
    assert historical.runs == report.runs
    assert historical.human_judgments[0].reviewer == "Alice"
    assert historical.adjudications[0].status == "agreed"


def test_v3_database_migrates_to_agentic_schema_and_stays_append_only(tmp_path):
    """A Phase 2B database gains traces and an agentic subject without data loss."""
    path = tmp_path / "phase2b.sqlite3"
    store = Store(path)
    rubric = sample_rubric()
    store.add_rubric(rubric)
    profile = EndpointProfile(name="Fixture", authorized=True, mock_behavior="vulnerable")
    store.add_profile(profile)
    report = asyncio.run(Workbench(store).execute(Workbench(store).prepare(profile, rubric)))
    session = store.sessions(experiment_id=report.experiment.id)[0]
    workbench = Workbench(store)
    workbench.record_judgment(
        session.id,
        session.evaluations[0].criterion_id,
        reviewer="Alice",
        outcome="pass",
        rationale="ok",
    )
    with sqlite3.connect(path) as db:
        before_sessions = [
            row[0] for row in db.execute("SELECT snapshot FROM evaluation_sessions ORDER BY rowid")
        ]
        before_judgments = [
            row[0] for row in db.execute("SELECT snapshot FROM judgments ORDER BY rowid")
        ]
        before_runs = [row[0] for row in db.execute("SELECT snapshot FROM runs ORDER BY rowid")]
    assert user_version(path) == 5
    # Simulate the Phase 2B schema version and migrate again.
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=3")
        db.execute("DROP TABLE agentic_traces")
        db.execute("DROP INDEX IF EXISTS sessions_agentic")
    migrated = Store(path)
    assert migrated.schema_version == 5
    with sqlite3.connect(path) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"agentic_traces", "evaluation_sessions", "judgments"} <= tables
        assert [
            row[0] for row in db.execute("SELECT snapshot FROM evaluation_sessions ORDER BY rowid")
        ] == before_sessions
        assert [
            row[0] for row in db.execute("SELECT snapshot FROM judgments ORDER BY rowid")
        ] == before_judgments
        assert [
            row[0] for row in db.execute("SELECT snapshot FROM runs ORDER BY rowid")
        ] == before_runs
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        columns = {row[1] for row in db.execute("PRAGMA table_info(evaluation_sessions)")}
        assert "agentic_trace_id" in columns
    # The migrated database accepts an agentic trace and its session.
    trace = asyncio.run(Workbench(migrated).run_scenario("retrieved-authority-spoof"))
    assert migrated.agentic_trace(trace.id).id == trace.id
    with sqlite3.connect(path) as db, pytest.raises(sqlite3.IntegrityError):
        db.execute("DELETE FROM agentic_traces WHERE id=?", (trace.id,))


def test_v4_database_migrates_to_controlled_experiment_schema(tmp_path):
    """A Phase 3A database gains experiment tables without losing any record."""
    path = tmp_path / "phase3a.sqlite3"
    store = Store(path)
    trace = asyncio.run(Workbench(store).run_scenario("retrieved-authority-spoof"))
    (session,) = store.sessions_for_trace(trace.id)
    with sqlite3.connect(path) as db:
        before_traces = [
            row[0] for row in db.execute("SELECT snapshot FROM agentic_traces ORDER BY rowid")
        ]
        before_sessions = [
            row[0] for row in db.execute("SELECT snapshot FROM evaluation_sessions ORDER BY rowid")
        ]
    assert user_version(path) == 5
    # Simulate the Phase 3A schema version and migrate again.
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=4")
        db.execute("DROP TABLE paired_trials")
        db.execute("DROP TABLE controlled_experiments")
    migrated = Store(path)
    assert migrated.schema_version == 5
    with sqlite3.connect(path) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"controlled_experiments", "paired_trials", "agentic_traces"} <= tables
        assert [
            row[0] for row in db.execute("SELECT snapshot FROM agentic_traces ORDER BY rowid")
        ] == before_traces
        assert [
            row[0] for row in db.execute("SELECT snapshot FROM evaluation_sessions ORDER BY rowid")
        ] == before_sessions
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("DELETE FROM agentic_traces WHERE id=?", (trace.id,))
    assert migrated.agentic_trace(trace.id).id == trace.id
    assert migrated.session(session.id).id == session.id
    # The migrated database supports a new controlled experiment.
    workbench = Workbench(migrated)
    experiment = workbench.plan_experiment("retrieved-authority-spoof", trial_count=1)
    assert asyncio.run(workbench.execute_experiment(experiment.id)).status == "completed"
    with sqlite3.connect(path) as db, pytest.raises(sqlite3.IntegrityError):
        db.execute("DELETE FROM controlled_experiments WHERE id=?", (experiment.id,))
