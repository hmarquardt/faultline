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

Schemas: `domain.py`; orchestration: `service.py`; IO: `providers.py`, `storage.py`,
`reports.py`; strict JSON parsing: `documents.py`; rubric provenance/review: `rubrics.py`; scoring:
`evaluation.py`. CLI and TUI call services. New providers must enforce scope and
budgets through the service. Keep network access explicit, no implicit retries,
redirects, telemetry or network-dependent tests. Never persist credential values.
Rubric imports are data, never code. Human overrides append, never rewrite scores.

## Conventions and current status

Python 3.12+, src layout, Pydantic strict extra-field rejection, UTC timestamps,
schema version 1, SQLite snapshots with relational keys. Packaged JSON definitions
are original synthetic scenarios. Read `docs/ARCHITECTURE.md` and
`docs/IMPLEMENTATION_PLAN.md` before changing boundaries. Phase 1 is the current
scope. The working slice includes CLI/TUI, nine synthetic families, offline mocks,
optional bounded HTTP, rubric import/review, SQLite history, evidence reports and
append-only judgment. See `docs/VERIFICATION.md` for local checks and README for
remaining work. Do not claim remote CI or hosted model validation from local tests.
Keep tests focused on observable behavior and evidence integrity. The offline suite
blocks sockets/DNS. The loopback smoke script is an explicitly separate check.
