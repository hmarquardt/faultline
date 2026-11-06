"""SQLite snapshots with relational links, append-only review records and migrations."""

import sqlite3
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from faultline.domain import (
    Adjudication,
    BatchCase,
    BatchEvaluation,
    CriterionEvaluation,
    Dataset,
    DatasetRecord,
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

SCHEMA_VERSION = 4

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
    id TEXT PRIMARY KEY,
    run_id TEXT REFERENCES runs(id),
    experiment_id TEXT REFERENCES experiments(id),
    dataset_id TEXT,
    dataset_case_id TEXT,
    agentic_trace_id TEXT,
    evidence_kind TEXT NOT NULL DEFAULT 'execution',
    rubric_id TEXT NOT NULL, rubric_version TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL, execution_sha256 TEXT NOT NULL, snapshot TEXT NOT NULL,
    CHECK (
        (evidence_kind = 'execution' AND run_id IS NOT NULL)
        OR (evidence_kind = 'dataset' AND dataset_id IS NOT NULL
            AND dataset_case_id IS NOT NULL)
        OR (evidence_kind = 'agentic' AND agentic_trace_id IS NOT NULL)
    )
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
    run_id TEXT REFERENCES runs(id), criterion_id TEXT NOT NULL,
    reviewer TEXT NOT NULL, snapshot TEXT NOT NULL
);""",
    "CREATE INDEX IF NOT EXISTS judgments_session ON judgments(session_id);",
    """CREATE TABLE IF NOT EXISTS adjudications (
    id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES evaluation_sessions(id),
    criterion_id TEXT NOT NULL, snapshot TEXT NOT NULL
);""",
    "CREATE INDEX IF NOT EXISTS adjudications_session ON adjudications(session_id);",
    """CREATE TABLE IF NOT EXISTS datasets (
    id TEXT PRIMARY KEY, version TEXT NOT NULL, created_at TEXT NOT NULL,
    dataset_sha256 TEXT NOT NULL, snapshot TEXT NOT NULL
);""",
    """CREATE TABLE IF NOT EXISTS dataset_records (
    dataset_id TEXT NOT NULL REFERENCES datasets(id), case_id TEXT NOT NULL,
    position INTEGER NOT NULL, source_sha256 TEXT NOT NULL, snapshot TEXT NOT NULL,
    PRIMARY KEY (dataset_id, case_id)
);""",
    "CREATE INDEX IF NOT EXISTS dataset_records_position ON dataset_records(dataset_id, position);",
    """CREATE TABLE IF NOT EXISTS batches (
    id TEXT PRIMARY KEY, dataset_id TEXT NOT NULL REFERENCES datasets(id),
    rubric_id TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
    snapshot TEXT NOT NULL
);""",
    """CREATE TABLE IF NOT EXISTS batch_cases (
    batch_id TEXT NOT NULL REFERENCES batches(id), case_id TEXT NOT NULL,
    position INTEGER NOT NULL, status TEXT NOT NULL,
    session_id TEXT REFERENCES evaluation_sessions(id), snapshot TEXT NOT NULL,
    PRIMARY KEY (batch_id, case_id)
);""",
    "CREATE INDEX IF NOT EXISTS batch_cases_status ON batch_cases(batch_id, status);",
    """CREATE TABLE IF NOT EXISTS agentic_traces (
    id TEXT PRIMARY KEY, scenario_id TEXT NOT NULL, scenario_version TEXT NOT NULL,
    status TEXT NOT NULL, created_at TEXT NOT NULL, execution_sha256 TEXT NOT NULL,
    snapshot TEXT NOT NULL
);""",
    "CREATE INDEX IF NOT EXISTS agentic_traces_scenario ON agentic_traces(scenario_id);",
]

APPEND_ONLY = [
    ("overrides", "Overrides are append-only"),
    ("evaluations", "Evaluations are append-only"),
    ("evaluation_sessions", "Evaluation sessions are append-only"),
    ("judgments", "Human judgments are append-only"),
    ("adjudications", "Adjudications are append-only"),
    ("datasets", "Datasets are append-only"),
    ("dataset_records", "Dataset records are append-only"),
]

NO_DELETE = [
    ("batches", "Batches are retained"),
    ("batch_cases", "Batch case results are retained"),
    ("agentic_traces", "Agentic traces are retained"),
]

TRIGGERS = [
    *[
        f"""CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()}
BEFORE {operation} ON {table}
BEGIN SELECT RAISE(ABORT, '{message}'); END;"""
        for table, message in APPEND_ONLY
        for operation in ("UPDATE", "DELETE")
    ],
    *[
        f"""CREATE TRIGGER IF NOT EXISTS {table}_no_delete
BEFORE DELETE ON {table}
BEGIN SELECT RAISE(ABORT, '{message}'); END;"""
        for table, message in NO_DELETE
    ],
]

DDL = "\n".join(
    [
        *TABLES,
        "CREATE INDEX IF NOT EXISTS evaluations_session ON evaluations(session_id);",
        "CREATE INDEX IF NOT EXISTS sessions_dataset ON evaluation_sessions(dataset_id);",
        "CREATE INDEX IF NOT EXISTS sessions_agentic ON evaluation_sessions(agentic_trace_id);",
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
        """Run every pending step in one transaction; leave the old version on failure.

        Foreign keys are disabled on the migration connection because SQLite's
        documented table-rebuild procedure requires it; a full foreign_key_check
        runs before the transaction commits, so a broken rebuild cannot persist.
        """
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA foreign_keys=OFF")
            db.execute("BEGIN IMMEDIATE")
            try:
                version = from_version
                while version < SCHEMA_VERSION:
                    MIGRATIONS[version](db)
                    version += 1
                violations = db.execute("PRAGMA foreign_key_check").fetchall()
                if violations:
                    raise ValueError("Migration left dangling references")
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
            "(id, run_id, experiment_id, dataset_id, dataset_case_id, agentic_trace_id, "
            "evidence_kind, rubric_id, rubric_version, status, created_at, "
            "execution_sha256, snapshot) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                session.id,
                session.run_id,
                session.experiment_id,
                session.dataset_id,
                session.dataset_case_id,
                session.agentic_trace_id,
                session.evidence_kind,
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

    # --- Datasets ------------------------------------------------------------

    def add_dataset(self, dataset: Dataset, records: Iterable[DatasetRecord]) -> None:
        """Store dataset metadata and its records in one transaction."""
        with self.connect() as db:
            db.execute(
                "INSERT INTO datasets (id, version, created_at, dataset_sha256, snapshot) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    dataset.id,
                    dataset.version,
                    dataset.imported_at.isoformat(),
                    dataset.dataset_sha256,
                    dataset.model_dump_json(),
                ),
            )
            inserted = 0
            for position, record in enumerate(records):
                db.execute(
                    "INSERT INTO dataset_records "
                    "(dataset_id, case_id, position, source_sha256, snapshot) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        dataset.id,
                        record.id,
                        position,
                        record.source_sha256 or "",
                        record.model_dump_json(),
                    ),
                )
                inserted += 1
            if inserted != dataset.record_count:
                raise ValueError("Dataset record count does not match the stored records")

    def datasets(self) -> list[Dataset]:
        with self.connect() as db:
            return [
                Dataset.model_validate_json(r[0])
                for r in db.execute("SELECT snapshot FROM datasets ORDER BY rowid")
            ]

    def dataset(self, dataset_id: str) -> Dataset:
        with self.connect() as db:
            row = db.execute("SELECT snapshot FROM datasets WHERE id=?", (dataset_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown dataset ID")
        return Dataset.model_validate_json(row[0])

    def dataset_records(self, dataset_id: str) -> Iterator[DatasetRecord]:
        """Stream records one at a time; the dataset is never fully materialized."""
        db = sqlite3.connect(self.path, timeout=10)
        try:
            cursor = db.execute(
                "SELECT snapshot FROM dataset_records WHERE dataset_id=? ORDER BY position",
                (dataset_id,),
            )
            for row in cursor:
                yield DatasetRecord.model_validate_json(row[0])
        finally:
            db.close()

    def dataset_records_page(
        self, dataset_id: str, *, offset: int = 0, limit: int = 50
    ) -> list[DatasetRecord]:
        with self.connect() as db:
            return [
                DatasetRecord.model_validate_json(r[0])
                for r in db.execute(
                    "SELECT snapshot FROM dataset_records WHERE dataset_id=? "
                    "ORDER BY position LIMIT ? OFFSET ?",
                    (dataset_id, limit, offset),
                )
            ]

    def dataset_record(self, dataset_id: str, case_id: str) -> DatasetRecord:
        with self.connect() as db:
            row = db.execute(
                "SELECT snapshot FROM dataset_records WHERE dataset_id=? AND case_id=?",
                (dataset_id, case_id),
            ).fetchone()
        if row is None:
            raise ValueError("Unknown dataset case ID")
        return DatasetRecord.model_validate_json(row[0])

    # --- Batches -------------------------------------------------------------

    def add_batch(self, batch: BatchEvaluation, cases: Sequence[BatchCase]) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO batches "
                "(id, dataset_id, rubric_id, status, created_at, snapshot) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    batch.id,
                    batch.dataset_id,
                    batch.rubric_id,
                    batch.status,
                    batch.created_at.isoformat(),
                    batch.model_dump_json(),
                ),
            )
            for case in cases:
                db.execute(
                    "INSERT INTO batch_cases "
                    "(batch_id, case_id, position, status, session_id, snapshot) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        case.batch_id,
                        case.case_id,
                        case.position,
                        case.status,
                        case.session_id,
                        case.model_dump_json(),
                    ),
                )

    def batch(self, batch_id: str) -> BatchEvaluation:
        with self.connect() as db:
            row = db.execute("SELECT snapshot FROM batches WHERE id=?", (batch_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown batch ID")
        return BatchEvaluation.model_validate_json(row[0])

    def batches(self) -> list[BatchEvaluation]:
        with self.connect() as db:
            return [
                BatchEvaluation.model_validate_json(r[0])
                for r in db.execute("SELECT snapshot FROM batches ORDER BY rowid")
            ]

    def update_batch(self, batch: BatchEvaluation) -> None:
        """Only batch lifecycle fields may change after planning."""
        original = self.batch(batch.id)
        immutable = {"status", "updated_at", "completed_at"}
        if original.model_dump(exclude=immutable) != batch.model_dump(exclude=immutable):
            raise ValueError("Only batch lifecycle fields may change")
        with self.connect() as db:
            db.execute(
                "UPDATE batches SET status=?, snapshot=? WHERE id=?",
                (batch.status, batch.model_dump_json(), batch.id),
            )

    def batch_cases(self, batch_id: str) -> list[BatchCase]:
        with self.connect() as db:
            return [
                BatchCase.model_validate_json(r[0])
                for r in db.execute(
                    "SELECT snapshot FROM batch_cases WHERE batch_id=? ORDER BY position",
                    (batch_id,),
                )
            ]

    def pending_batch_cases(self, batch_id: str, limit: int) -> list[BatchCase]:
        with self.connect() as db:
            return [
                BatchCase.model_validate_json(r[0])
                for r in db.execute(
                    "SELECT snapshot FROM batch_cases WHERE batch_id=? AND status='pending' "
                    "ORDER BY position LIMIT ?",
                    (batch_id, limit),
                )
            ]

    def finish_batch_case(self, case: BatchCase) -> None:
        """Move one pending case to a terminal state exactly once."""
        if case.status == "pending":
            raise ValueError("A batch case must be finished with a terminal status")
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE batch_cases SET status=?, session_id=?, snapshot=? "
                "WHERE batch_id=? AND case_id=? AND status='pending'",
                (
                    case.status,
                    case.session_id,
                    case.model_dump_json(),
                    case.batch_id,
                    case.case_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("Batch case is missing or already finalized")

    def complete_batch_case(self, case: BatchCase, session: EvaluationSession) -> None:
        """Persist one case result and its session in a single transaction."""
        if case.status != "completed" or case.session_id != session.id:
            raise ValueError("A completed batch case must reference its session")
        with self.connect() as db:
            self._insert_session(db, session)
            cursor = db.execute(
                "UPDATE batch_cases SET status=?, session_id=?, snapshot=? "
                "WHERE batch_id=? AND case_id=? AND status='pending'",
                (case.status, case.session_id, case.model_dump_json(), case.batch_id, case.case_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Batch case is missing or already finalized")

    def batch_case_counts(self, batch_id: str) -> dict[str, int]:
        with self.connect() as db:
            return {
                str(status): int(count)
                for status, count in db.execute(
                    "SELECT status, COUNT(*) FROM batch_cases WHERE batch_id=? GROUP BY status",
                    (batch_id,),
                )
            }

    def sessions_for_dataset(self, dataset_id: str) -> list[EvaluationSession]:
        with self.connect() as db:
            return [
                EvaluationSession.model_validate_json(r[0])
                for r in db.execute(
                    "SELECT snapshot FROM evaluation_sessions WHERE dataset_id=? ORDER BY rowid",
                    (dataset_id,),
                )
            ]

    # --- Agentic traces ------------------------------------------------------

    def add_agentic_trace(self, trace) -> None:
        """Store a trace that is already terminal (for example a dry run)."""
        if trace.status == "running":
            raise ValueError("A running trace is created with start_agentic_trace")
        with self.connect() as db:
            db.execute(
                "INSERT INTO agentic_traces "
                "(id, scenario_id, scenario_version, status, created_at, "
                "execution_sha256, snapshot) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    trace.id,
                    trace.scenario.id,
                    trace.scenario.version,
                    trace.status,
                    trace.started_at.isoformat(),
                    trace.execution_sha256,
                    trace.model_dump_json(),
                ),
            )

    def start_agentic_trace(self, trace) -> None:
        if trace.status != "running":
            raise ValueError("Only a running trace can be started")
        with self.connect() as db:
            db.execute(
                "INSERT INTO agentic_traces "
                "(id, scenario_id, scenario_version, status, created_at, "
                "execution_sha256, snapshot) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    trace.id,
                    trace.scenario.id,
                    trace.scenario.version,
                    trace.status,
                    trace.started_at.isoformat(),
                    trace.execution_sha256,
                    trace.model_dump_json(),
                ),
            )

    def save_agentic_trace(self, trace) -> None:
        """Checkpoint a running trace; a finished trace is never rewritten."""
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE agentic_traces SET status=?, snapshot=? WHERE id=? AND status='running'",
                (trace.status, trace.model_dump_json(), trace.id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Trace is missing or already finalized")

    def finish_agentic_trace(self, trace, session=None) -> None:
        """Store the evaluation session and finalize the trace atomically."""
        if trace.status == "running":
            raise ValueError("A trace must be finalized with a terminal status")
        with self.connect() as db:
            if session is not None:
                self._insert_session(db, session)
            cursor = db.execute(
                "UPDATE agentic_traces SET status=?, snapshot=? WHERE id=? AND status='running'",
                (trace.status, trace.model_dump_json(), trace.id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Trace is missing or already finalized")

    def agentic_trace(self, trace_id: str):
        from faultline.domain import AgenticExecutionTrace

        with self.connect() as db:
            row = db.execute(
                "SELECT snapshot FROM agentic_traces WHERE id=?", (trace_id,)
            ).fetchone()
        if row is None:
            raise ValueError("Unknown agentic trace ID")
        return AgenticExecutionTrace.model_validate_json(row[0])

    def agentic_traces(self) -> list:
        from faultline.domain import AgenticExecutionTrace

        with self.connect() as db:
            return [
                AgenticExecutionTrace.model_validate_json(r[0])
                for r in db.execute("SELECT snapshot FROM agentic_traces ORDER BY rowid")
            ]

    def sessions_for_trace(self, trace_id: str) -> list[EvaluationSession]:
        with self.connect() as db:
            return [
                EvaluationSession.model_validate_json(r[0])
                for r in db.execute(
                    "SELECT snapshot FROM evaluation_sessions WHERE agentic_trace_id=? "
                    "ORDER BY rowid",
                    (trace_id,),
                )
            ]


def _create_schema(db: sqlite3.Connection) -> None:
    """Version 0: a new database gets the current schema directly."""
    for statement in TABLES:
        db.execute(statement)
    db.execute("CREATE INDEX IF NOT EXISTS evaluations_session ON evaluations(session_id)")
    db.execute("CREATE INDEX IF NOT EXISTS sessions_dataset ON evaluation_sessions(dataset_id)")
    db.execute(
        "CREATE INDEX IF NOT EXISTS sessions_agentic ON evaluation_sessions(agentic_trace_id)"
    )
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


def _rebuild_table(db: sqlite3.Connection, table: str, create: str, columns: str) -> None:
    """SQLite's documented rebuild: create, copy, drop, rename (foreign keys off)."""
    new_table = f"{table}_rebuild"
    db.execute(create.format(table=new_table))
    db.execute(f"INSERT INTO {new_table} ({columns}) SELECT {columns} FROM {table}")
    db.execute(f"DROP TABLE {table}")
    db.execute(f"ALTER TABLE {new_table} RENAME TO {table}")


def _migrate_v2_to_v3(db: sqlite3.Connection) -> None:
    """Allow dataset sessions and imported-response evidence without losing anything."""
    for statement in TABLES:
        db.execute(statement)
    _rebuild_table(
        db,
        "evaluation_sessions",
        """CREATE TABLE {table} (
    id TEXT PRIMARY KEY,
    run_id TEXT REFERENCES runs(id),
    experiment_id TEXT REFERENCES experiments(id),
    dataset_id TEXT,
    dataset_case_id TEXT,
    evidence_kind TEXT NOT NULL DEFAULT 'execution',
    rubric_id TEXT NOT NULL, rubric_version TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL, execution_sha256 TEXT NOT NULL, snapshot TEXT NOT NULL,
    CHECK (
        (evidence_kind = 'execution' AND run_id IS NOT NULL)
        OR (evidence_kind = 'dataset' AND dataset_id IS NOT NULL
            AND dataset_case_id IS NOT NULL)
    )
)""",
        "id, run_id, experiment_id, rubric_id, rubric_version, status, created_at, "
        "execution_sha256, snapshot",
    )
    db.execute(
        "UPDATE evaluation_sessions SET evidence_kind='execution' "
        "WHERE evidence_kind IS NULL OR evidence_kind=''"
    )
    _rebuild_table(
        db,
        "judgments",
        """CREATE TABLE {table} (
    id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES evaluation_sessions(id),
    run_id TEXT REFERENCES runs(id), criterion_id TEXT NOT NULL,
    reviewer TEXT NOT NULL, snapshot TEXT NOT NULL
)""",
        "id, session_id, run_id, criterion_id, reviewer, snapshot",
    )
    db.execute("CREATE INDEX IF NOT EXISTS sessions_run ON evaluation_sessions(run_id)")
    db.execute(
        "CREATE INDEX IF NOT EXISTS sessions_experiment ON evaluation_sessions(experiment_id)"
    )
    db.execute("CREATE INDEX IF NOT EXISTS sessions_dataset ON evaluation_sessions(dataset_id)")
    db.execute("CREATE INDEX IF NOT EXISTS judgments_session ON judgments(session_id)")
    for statement in TRIGGERS:
        db.execute(statement)


def _migrate_v3_to_v4(db: sqlite3.Connection) -> None:
    """Allow agentic traces as an evaluation subject without losing anything."""
    for statement in TABLES:
        db.execute(statement)
    present = {row[1] for row in db.execute("PRAGMA table_info(evaluation_sessions)")}
    carried = (
        "id, run_id, experiment_id, dataset_id, dataset_case_id, agentic_trace_id, "
        "evidence_kind, rubric_id, rubric_version, status, created_at, "
        "execution_sha256, snapshot"
        if "agentic_trace_id" in present
        else "id, run_id, experiment_id, dataset_id, dataset_case_id, evidence_kind, "
        "rubric_id, rubric_version, status, created_at, execution_sha256, snapshot"
    )
    _rebuild_table(
        db,
        "evaluation_sessions",
        """CREATE TABLE {table} (
    id TEXT PRIMARY KEY,
    run_id TEXT REFERENCES runs(id),
    experiment_id TEXT REFERENCES experiments(id),
    dataset_id TEXT,
    dataset_case_id TEXT,
    agentic_trace_id TEXT,
    evidence_kind TEXT NOT NULL DEFAULT 'execution',
    rubric_id TEXT NOT NULL, rubric_version TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL, execution_sha256 TEXT NOT NULL, snapshot TEXT NOT NULL,
    CHECK (
        (evidence_kind = 'execution' AND run_id IS NOT NULL)
        OR (evidence_kind = 'dataset' AND dataset_id IS NOT NULL
            AND dataset_case_id IS NOT NULL)
        OR (evidence_kind = 'agentic' AND agentic_trace_id IS NOT NULL)
    )
)""",
        carried,
    )
    db.execute(
        "UPDATE evaluation_sessions SET evidence_kind='execution' "
        "WHERE evidence_kind IS NULL OR evidence_kind=''"
    )
    for statement in (
        "CREATE INDEX IF NOT EXISTS sessions_run ON evaluation_sessions(run_id)",
        "CREATE INDEX IF NOT EXISTS sessions_experiment ON evaluation_sessions(experiment_id)",
        "CREATE INDEX IF NOT EXISTS sessions_dataset ON evaluation_sessions(dataset_id)",
        "CREATE INDEX IF NOT EXISTS sessions_agentic ON evaluation_sessions(agentic_trace_id)",
        "CREATE INDEX IF NOT EXISTS judgments_session ON judgments(session_id)",
    ):
        db.execute(statement)
    for statement in TRIGGERS:
        db.execute(statement)


MIGRATIONS = {0: _create_schema, 1: _migrate_v1_to_v2, 2: _migrate_v2_to_v3, 3: _migrate_v3_to_v4}
