# Contributor guide

Faultline is an authorized LLM evaluation workbench. Keep the Python core
independent of Textual. Never equate a model's success claim with evidence.

## Commands

- `uv sync --dev`
- `uv run ruff check .` and `uv run ruff format --check .`
- `uv run pytest` (offline; no credentials or real HTTP)
- `uv run faultline demo --behavior vulnerable --output reports/demo`
- `uv run faultline tui`
- `uv build`
- `uv run python scripts/local_http_smoke.py --allow-loopback` (explicit localhost IO)

## Boundaries

Schemas: `domain.py`; canonical hashing helpers: `domain.py`; record digests and
evidence verification: `integrity.py`; review policy and effective outcomes:
`adjudication.py`; orchestration: `service.py`; IO: `providers.py`, `storage.py`,
`reports.py`; strict JSON parsing: `documents.py`; rubric provenance/review:
`rubrics.py`; scoring: `evaluation.py`. CLI and TUI call services. New providers
must enforce scope and budgets through the service. Keep network access explicit,
no implicit retries, redirects, telemetry or network-dependent tests. Never
persist credential values. Rubric imports are data, never code.

Execution evidence is immutable: never rewrite a stored run, its response or its
execution-time evaluations. Additional scoring is a new `EvaluationSession`.
Human judgments and adjudications are append-only (SQLite triggers enforce it);
revisions link through `supersedes_id` and never delete the earlier record. No
effective outcome may be produced without an explicit adjudication policy.
Ordinal and categorical rubric content keeps its original labels, wording, weights
and thresholds; never convert it to binary pass/fail. Use `storage.SCHEMA_VERSION`
plus an explicit migration for schema changes, and keep existing rows, IDs and
report compatibility.

## Conventions and current status

Python 3.12+, src layout, Pydantic strict extra-field rejection, UTC timestamps,
schema version 1 contracts, SQLite schema version 2 with tested migrations.
Packaged JSON definitions are original synthetic scenarios. Read
`docs/ARCHITECTURE.md` and `docs/IMPLEMENTATION_PLAN.md` before changing
boundaries, and `docs/REPORT_SCHEMA.md` before changing exports. Phase 2A is the
current scope: CLI/TUI, nine synthetic families, offline mocks, optional bounded
HTTP, rubric import/review, rubric scale fidelity, independent evaluation
sessions, SQLite history with append-only judgments and adjudications, evidence
reports and canonical digests. See `docs/VERIFICATION.md` for local checks and
README for remaining work. Do not claim remote CI or hosted model validation from
local tests. Keep tests focused on observable behavior and evidence integrity.
The offline suite blocks sockets/DNS. The loopback smoke script is an explicitly
separate check.
