# Release checklist

A developer-facing release of Faultline. Publishing to an index, changing repository
visibility or provisioning infrastructure is **not** part of this checklist and needs
explicit authorization.

## 1. Code and tests

- [ ] `uv sync --locked --dev` completes.
- [ ] `uv run ruff check .` clean.
- [ ] `uv run ruff format --check .` clean.
- [ ] `uv run pytest -q` fully offline and green (blocked sockets/DNS).
- [ ] `uv run pytest -q -s tests/test_performance.py` prints the baseline and passes.
- [ ] `uv run python scripts/evaluator_workflow.py --output /tmp/release-workflow`
      completes with `errors=0` and `digest=ok`.

## 2. Build and package

- [ ] `uv build` produces sdist and wheel.
- [ ] Wheel contains `data/scenarios.v1.json`, `data/benchmarks.v1.json`,
      `data/techniques.v1.json`, `data/canary-rubric.v1.json` and every module.
- [ ] Wheel installs into a clean environment and `faultline version` reports the
      expected version.
- [ ] `faultline doctor --json` reports no problems on a fresh database directory.

## 3. CLI and TUI smoke

- [ ] `faultline demo --behavior vulnerable --output /tmp/release-demo` writes three
      report files.
- [ ] `faultline run-scenario boundary-enforcement --agent scripted-secure` completes.
- [ ] `faultline plan-comparison ... --agent ... --agent ...` + `run-comparison` +
      `comparison-report` produce JSON/Markdown/CSV.
- [ ] `faultline plan-benchmark boundary-core-suite --agent scripted-vulnerable` +
      `run-benchmark` + `benchmark-report` produce JSON/Markdown/CSV.
- [ ] `faultline verify-report <report>.json` reports zero errors.
- [ ] `faultline tui` starts and every tab is reachable at 100x30, 120x40, 150x60.

## 4. Migrations and compatibility

- [ ] `faultline migrate` prints schema version 6 on a fresh database.
- [ ] A version 1–5 database migrates with rows, IDs and snapshots preserved
      (`tests/test_migration.py`).
- [ ] Historical report files from formats 1, 2.0.0, 2.1.0, 2.2.0 and 2.3.0 load.
- [ ] `faultline verify-report` passes on a historical export.

## 5. Security posture

- [ ] No credential value appears in any report, CSV, Markdown, database row, log or
      exception (`tests/test_redaction.py`).
- [ ] `docs/THREAT_BOUNDARIES.md` matches the code for tools, network, credentials and
      review records.
- [ ] The offline suite still blocks sockets and DNS.
- [ ] `git grep -nE "sk-[A-Za-z0-9]{8,}"` finds no real credential.

## 6. Documentation

- [ ] `README.md`, `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/IMPLEMENTATION_PLAN.md`,
      `docs/VERIFICATION.md`, `docs/THREAT_BOUNDARIES.md`, `docs/REPORT_SCHEMA.md`
      describe the current behaviour.
- [ ] `CHANGELOG.md` records the release.
- [ ] Known limitations and troubleshooting are current.
- [ ] No document claims hosted-model validation or CI results that were not observed.

## 7. Repository state

- [ ] Working tree clean; `HEAD == origin/main`.
- [ ] GitHub Actions result inspected with `gh run view` and recorded in
      `docs/VERIFICATION.md`.
- [ ] No release, tag, index upload or visibility change without explicit approval.
