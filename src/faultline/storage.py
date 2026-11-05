"""SQLite snapshots with relational links, append-only review records and migrations."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from faultline.domain import (
    Adjudication,
    CriterionEvaluation,
    EndpointProfile,
    EvaluationSession,
    ExecutionRun,
    Experiment,
    Finding,
    HumanJudgment,
    HumanOverride,
    Rubric,
    canonical_digest,
)
from faultline.integrity import execution_digest

SCHEMA_VERSION = 2

TABLES = [
    "CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, snapshot TEXT NOT NULL);",
    "CREATE TABLE IF NOT EXISTS rubrics (id TEXT PRIMARY KEY, snapshot TEXT NOT NULL);",
    """CREATE TABLE IF NOT EXISTS experiments (
    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, snapshot TEXT NOT NULL
);""",
    """CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES experiments(id),
    status TEXT NOT NULL, snapshot TEXT NOT NULL
);""",
    "CREATE INDEX IF NOT EXISTS runs_experiment ON runs(experiment_id);",
    """CREATE TABLE IF NOT EXISTS evaluation_sessions (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
    experiment_id TEXT NOT NULL REFERENCES experiments(id),
    rubric_id TEXT NOT NULL, rubric_version TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL, execution_sha256 TEXT NOT NULL, snapshot TEXT NOT NULL
);""",
    "CREATE INDEX IF NOT EXISTS sessions_run ON evaluation_sessions(run_id);",
    "CREATE INDEX IF NOT EXISTS sessions_experiment ON evaluation_sessions(experiment_id);",
    """CREATE TABLE IF NOT EXISTS evaluations (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
    session_id TEXT REFERENCES evaluation_sessions(id), snapshot TEXT NOT NULL
);""",
    "CREATE INDEX IF NOT EXISTS evaluations_run ON evaluations(run_id);",
    """CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES experiments(id),
    evaluation_id TEXT NOT NULL REFERENCES evaluations(id), snapshot TEXT NOT NULL
);""",
    """CREATE TABLE IF NOT EXISTS overrides (
    id TEXT PRIMARY KEY, evaluation_id TEXT NOT NULL REFERENCES evaluations(id),
    snapshot TEXT NOT NULL
);""",
    """CREATE TABLE IF NOT EXISTS judgments (
    id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES evaluation_sessions(id),
    run_id TEXT NOT NULL REFERENCES runs(id), criterion_id TEXT NOT NULL,
    reviewer TEXT NOT NULL, snapshot TEXT NOT NULL
);""",
    "CREATE INDEX IF NOT EXISTS judgments_session ON judgments(session_id);",
    """CREATE TABLE IF NOT EXISTS adjudications (
    id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES evaluation_sessions(id),
    criterion_id TEXT NOT NULL, snapshot TEXT NOT NULL
);""",
    "CREATE INDEX IF NOT EXISTS adjudications_session ON adjudications(session_id);",
]

APPEND_ONLY = [
    ("overrides", "Overrides are append-only"),
    ("evaluations", "Evaluations are append-only"),
    ("evaluation_sessions", "Evaluation sessions are append-only"),
    ("judgments", "Human judgments are append-only"),
    ("adjudications", "Adjudications are append-only"),
]

TRIGGERS = [
    f"""CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()}
BEFORE {operation} ON {table}
BEGIN SELECT RAISE(ABORT, '{message}'); END;"""
    for table, message in APPEND_ONLY
    for operation in ("UPDATE", "DELETE")
]

DDL = "\n".join(
    [
        *TABLES,
        "CREATE INDEX IF NOT EXISTS evaluations_session ON evaluations(session_id);",
        *TRIGGERS,
        f"PRAGMA user_version={SCHEMA_VERSION};",
    ]
)


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.exists():
            path.touch(mode=0o600)
        with self.connect() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise ValueError(f"Unsupported database schema version {version}")
        if version < SCHEMA_VERSION:
            self._migrate(version)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(DDL)

    @property
    def schema_version(self) -> int:
        with self.connect() as db:
            return db.execute("PRAGMA user_version").fetchone()[0]

    def _migrate(self, from_version: int) -> None:
        """Run every pending step in one transaction; leave version 1 on failure."""
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            try:
                version = from_version
                while version < SCHEMA_VERSION:
                    MIGRATIONS[version](db)
                    version += 1
                db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            except Exception:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")
        except Exception:
            # Controlled message: schema contents and snapshot data are not echoed.
            raise ValueError(
                "Database migration failed; the previous schema version was retained"
            ) from None
        finally:
            db.close()

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

    def finish_run(
        self,
        run: ExecutionRun,
        findings: list[Finding],
        sessions: list[EvaluationSession] | None = None,
    ) -> None:
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE runs SET status=?, snapshot=? WHERE id=? AND status='running'",
                (run.status, run.model_dump_json(), run.id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Run is missing or already finalized")
            for session in sessions or []:
                self._insert_session(db, session)
            evaluation_sessions = {
                evaluation.id: session.id
                for session in sessions or []
                for evaluation in session.evaluations
            }
            for value in run.evaluations:
                db.execute(
                    "INSERT INTO evaluations (id, run_id, session_id, snapshot) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        value.id,
                        run.id,
                        evaluation_sessions.get(value.id),
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

    def run(self, run_id: str) -> ExecutionRun:
        with self.connect() as db:
            row = db.execute("SELECT snapshot FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown execution run ID")
        return ExecutionRun.model_validate_json(row[0])

    @staticmethod
    def _insert_session(db: sqlite3.Connection, session: EvaluationSession) -> None:
        assert session.rubric.definition is not None
        db.execute(
            "INSERT INTO evaluation_sessions "
            "(id, run_id, experiment_id, rubric_id, rubric_version, status, created_at, "
            "execution_sha256, snapshot) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                session.id,
                session.run_id,
                session.experiment_id,
                session.rubric.definition.id,
                session.rubric.definition.version,
                session.status,
                session.created_at.isoformat(),
                session.execution_sha256,
                session.model_dump_json(),
            ),
        )

    def add_session(self, session: EvaluationSession) -> None:
        with self.connect() as db:
            self._insert_session(db, session)

    def session(self, session_id: str) -> EvaluationSession:
        with self.connect() as db:
            row = db.execute(
                "SELECT snapshot FROM evaluation_sessions WHERE id=?", (session_id,)
            ).fetchone()
        if row is None:
            raise ValueError("Unknown evaluation session ID")
        return EvaluationSession.model_validate_json(row[0])

    def sessions(
        self, *, experiment_id: str | None = None, run_id: str | None = None
    ) -> list[EvaluationSession]:
        query = "SELECT snapshot FROM evaluation_sessions"
        clauses, parameters = [], []
        if experiment_id is not None:
            clauses.append("experiment_id=?")
            parameters.append(experiment_id)
        if run_id is not None:
            clauses.append("run_id=?")
            parameters.append(run_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY rowid"
        with self.connect() as db:
            return [
                EvaluationSession.model_validate_json(r[0])
                for r in db.execute(query, tuple(parameters))
            ]

    def add_judgment(self, judgment: HumanJudgment) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO judgments (id, session_id, run_id, criterion_id, reviewer, snapshot) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    judgment.id,
                    judgment.session_id,
                    judgment.run_id,
                    judgment.criterion_id,
                    judgment.reviewer,
                    judgment.model_dump_json(),
                ),
            )

    def judgments(
        self, *, experiment_id: str | None = None, session_id: str | None = None
    ) -> list[HumanJudgment]:
        query = "SELECT j.snapshot FROM judgments j JOIN evaluation_sessions s ON s.id=j.session_id"
        clauses, parameters = [], []
        if experiment_id is not None:
            clauses.append("s.experiment_id=?")
            parameters.append(experiment_id)
        if session_id is not None:
            clauses.append("j.session_id=?")
            parameters.append(session_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY j.rowid"
        with self.connect() as db:
            return [
                HumanJudgment.model_validate_json(r[0])
                for r in db.execute(query, tuple(parameters))
            ]

    def add_adjudication(self, adjudication: Adjudication) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO adjudications (id, session_id, criterion_id, snapshot) "
                "VALUES (?, ?, ?, ?)",
                (
                    adjudication.id,
                    adjudication.session_id,
                    adjudication.criterion_id,
                    adjudication.model_dump_json(),
                ),
            )

    def adjudications(
        self, *, experiment_id: str | None = None, session_id: str | None = None
    ) -> list[Adjudication]:
        query = (
            "SELECT a.snapshot FROM adjudications a JOIN evaluation_sessions s ON s.id=a.session_id"
        )
        clauses, parameters = [], []
        if experiment_id is not None:
            clauses.append("s.experiment_id=?")
            parameters.append(experiment_id)
        if session_id is not None:
            clauses.append("a.session_id=?")
            parameters.append(session_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY a.rowid"
        with self.connect() as db:
            return [
                Adjudication.model_validate_json(r[0]) for r in db.execute(query, tuple(parameters))
            ]

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


def _create_schema(db: sqlite3.Connection) -> None:
    """Version 0: a new database gets the current schema directly."""
    for statement in TABLES:
        db.execute(statement)
    db.execute("CREATE INDEX IF NOT EXISTS evaluations_session ON evaluations(session_id)")
    for statement in TRIGGERS:
        db.execute(statement)


def _migrate_v1_to_v2(db: sqlite3.Connection) -> None:
    """Add evaluation sessions and review records without touching stored evidence."""
    for statement in TABLES:
        db.execute(statement)
    columns = {row[1] for row in db.execute("PRAGMA table_info(evaluations)")}
    if "session_id" not in columns:
        db.execute(
            "ALTER TABLE evaluations ADD COLUMN session_id TEXT REFERENCES evaluation_sessions(id)"
        )
    db.execute("CREATE INDEX IF NOT EXISTS evaluations_session ON evaluations(session_id)")
    for run_id, experiment_id, snapshot in db.execute(
        "SELECT id, experiment_id, snapshot FROM runs ORDER BY rowid"
    ).fetchall():
        rows = db.execute(
            "SELECT id, snapshot FROM evaluations WHERE run_id=? ORDER BY rowid", (run_id,)
        ).fetchall()
        if not rows:
            continue
        run = ExecutionRun.model_validate_json(snapshot)
        row = db.execute("SELECT snapshot FROM experiments WHERE id=?", (experiment_id,)).fetchone()
        if row is None:
            raise ValueError("Run references a missing experiment")
        experiment = Experiment.model_validate_json(row[0])
        evaluations = [CriterionEvaluation.model_validate_json(r[1]) for r in rows]
        completed = run.completed_at or run.started_at
        session = EvaluationSession(
            run_id=run_id,
            experiment_id=experiment_id,
            rubric=experiment.rubric,
            rubric_definition_sha256=canonical_digest(experiment.rubric.definition),
            execution_sha256=execution_digest(run),
            origin="migration",
            evaluator=evaluations[0].evaluator,
            evaluator_settings={"derived_from": "phase-1-evaluations"},
            status="completed",
            evaluations=evaluations,
            created_at=completed,
            completed_at=completed,
        )
        Store._insert_session(db, session)
        db.execute("UPDATE evaluations SET session_id=? WHERE run_id=?", (session.id, run_id))
    for statement in TRIGGERS:
        db.execute(statement)


MIGRATIONS = {0: _create_schema, 1: _migrate_v1_to_v2}
