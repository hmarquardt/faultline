"""SQLite snapshots with relational evidence links and append-only overrides."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from faultline.domain import (
    EndpointProfile,
    ExecutionRun,
    Experiment,
    Finding,
    HumanOverride,
    Rubric,
)

DDL = """
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


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.exists():
            path.touch(mode=0o600)
        with self.connect() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, 1}:
                raise ValueError(f"Unsupported database schema version {version}")
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(DDL)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def add_profile(self, profile: EndpointProfile) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO profiles VALUES (?, ?)", (profile.id, profile.model_dump_json())
            )

    def profiles(self) -> list[EndpointProfile]:
        with self.connect() as db:
            return [
                EndpointProfile.model_validate_json(r[0])
                for r in db.execute("SELECT snapshot FROM profiles ORDER BY rowid")
            ]

    def profile(self, identifier: str) -> EndpointProfile:
        for profile in self.profiles():
            if profile.id == identifier:
                return profile
        raise ValueError("Unknown endpoint profile ID")

    def add_rubric(self, rubric: Rubric) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO rubrics VALUES (?, ?)", (rubric.id, rubric.model_dump_json()))

    def rubrics(self) -> list[Rubric]:
        with self.connect() as db:
            return [
                Rubric.model_validate_json(r[0])
                for r in db.execute("SELECT snapshot FROM rubrics ORDER BY rowid")
            ]

    def rubric(self, identifier: str) -> Rubric:
        for rubric in self.rubrics():
            if rubric.id == identifier:
                return rubric
        raise ValueError("Unknown rubric ID")

    def add_experiment(self, experiment: Experiment) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO experiments VALUES (?, ?, ?)",
                (
                    experiment.id,
                    experiment.created_at.isoformat(),
                    experiment.model_dump_json(),
                ),
            )

    def update_experiment(self, experiment: Experiment) -> None:
        original = self.experiment(experiment.id)
        if original.status != "running" or original.model_dump(
            exclude={"status", "completed_at"}
        ) != experiment.model_dump(exclude={"status", "completed_at"}):
            raise ValueError("Only lifecycle fields of a running experiment may change")
        with self.connect() as db:
            db.execute(
                "UPDATE experiments SET snapshot=? WHERE id=?",
                (
                    experiment.model_dump_json(),
                    experiment.id,
                ),
            )

    def experiment(self, identifier: str) -> Experiment:
        with self.connect() as db:
            row = db.execute(
                "SELECT snapshot FROM experiments WHERE id=?", (identifier,)
            ).fetchone()
        if row is None:
            raise ValueError("Unknown experiment ID")
        return Experiment.model_validate_json(row[0])

    def history(self) -> list[Experiment]:
        with self.connect() as db:
            return [
                Experiment.model_validate_json(r[0])
                for r in db.execute("SELECT snapshot FROM experiments ORDER BY created_at DESC")
            ]

    def start_run(self, run: ExecutionRun) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO runs VALUES (?, ?, ?, ?)",
                (
                    run.id,
                    run.experiment_id,
                    run.status,
                    run.model_dump_json(),
                ),
            )

    def finish_run(self, run: ExecutionRun, findings: list[Finding]) -> None:
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE runs SET status=?, snapshot=? WHERE id=? AND status='running'",
                (run.status, run.model_dump_json(), run.id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Run is missing or already finalized")
            for value in run.evaluations:
                db.execute(
                    "INSERT INTO evaluations VALUES (?, ?, ?)",
                    (
                        value.id,
                        run.id,
                        value.model_dump_json(),
                    ),
                )
            for finding in findings:
                db.execute(
                    "INSERT INTO findings VALUES (?, ?, ?, ?)",
                    (
                        finding.id,
                        run.experiment_id,
                        finding.evaluation_id,
                        finding.model_dump_json(),
                    ),
                )

    def record_response(self, run: ExecutionRun) -> None:
        """Checkpoint response evidence before evaluation, while the request is still running."""
        if run.status != "running" or run.response is None or not run.evidence:
            raise ValueError("Response checkpoint requires a running request and evidence")
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE runs SET snapshot=? WHERE id=? AND status='running'",
                (run.model_dump_json(), run.id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Run is missing or already finalized")

    def runs(self, experiment_id: str) -> list[ExecutionRun]:
        with self.connect() as db:
            return [
                ExecutionRun.model_validate_json(r[0])
                for r in db.execute(
                    "SELECT snapshot FROM runs WHERE experiment_id=? ORDER BY rowid",
                    (experiment_id,),
                )
            ]

    def findings(self, experiment_id: str) -> list[Finding]:
        with self.connect() as db:
            return [
                Finding.model_validate_json(r[0])
                for r in db.execute(
                    "SELECT snapshot FROM findings WHERE experiment_id=? ORDER BY rowid",
                    (experiment_id,),
                )
            ]

    def add_override(self, override: HumanOverride) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO overrides VALUES (?, ?, ?)",
                (
                    override.id,
                    override.evaluation_id,
                    override.model_dump_json(),
                ),
            )

    def overrides(self, experiment_id: str) -> list[HumanOverride]:
        with self.connect() as db:
            return [
                HumanOverride.model_validate_json(r[0])
                for r in db.execute(
                    "SELECT o.snapshot FROM overrides o JOIN evaluations e ON e.id=o.evaluation_id "
                    "JOIN runs r ON r.id=e.run_id WHERE r.experiment_id=? ORDER BY o.rowid",
                    (experiment_id,),
                )
            ]
