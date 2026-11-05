# Verification record

## Phase 2A (current)

Local environment: macOS arm64, Python 3.12.13, uv 0.12.x, Textual 6.12,
Pydantic 2.14. CI is configured for macOS/Linux and Python 3.12/3.13; those
remote jobs were not run from this workspace.

### Automated checks

- `uv run ruff check .` and `uv run ruff format --check .`.
- `uv run pytest -q`: 113 tests, fully offline (socket connect/connect_ex and DNS
  lookup are patched to raise inside every test).
- `uv build` (sdist + wheel) and a wheel-content smoke import.

Coverage added in Phase 2A:

| Requirement | Test |
| --- | --- |
| One saved response, two distinct rubric evaluations | `tests/test_sessions.py::test_one_saved_response_supports_two_independent_rubric_evaluations` |
| Reevaluation never calls the model endpoint | `...::test_reevaluation_never_contacts_the_model` |
| Ordinal partial credit keeps its meaning | `...::test_ordinal_partial_credit_keeps_its_original_meaning`, `tests/test_evaluation.py::test_partial_credit_keeps_its_fractional_compliance` |
| Categorical results are not binary | `...::test_categorical_assessment_is_not_converted_to_binary`, `tests/test_evaluation.py::test_non_binary_scales_never_become_binary_observations` |
| Two reviewers disagree without data loss | `...::test_two_reviewers_can_disagree_without_losing_records` |
| Adjudication without destroying evidence | `...::test_adjudication_produces_an_effective_outcome_without_destroying_evidence` |
| Reports distinguish original and adjudicated results | `...::test_report_separates_automated_human_and_adjudicated_results`, `...::test_overridden_failure_is_reported_as_contested` |
| Append-only review records | `...::test_review_records_are_append_only_in_storage` |
| Explicit adjudication policy only | `...::test_adjudication_policy_requires_an_explicit_choice`, `...::test_judgment_validation_rejects_contradictions` |
| Deterministic digests, distinct export identity | `...::test_digests_are_deterministic_and_keep_identities_separate` |
| Phase 1 database migration | `tests/test_migration.py` (5 tests: preserve records, new workflows, rollback, reopen, historical report) |
| Reviewer workbench | `tests/test_tui.py::test_tui_reviewer_workbench_records_review_and_adjudication` |
| CLI review surface | `tests/test_cli.py::test_cli_reevaluate_review_adjudicate_and_migrate` |

### Fixtures

- `tests/fixtures/rubrics/graded-disclosure.v2.json`: ordinal levels with verbatim
  descriptions, a categorical criterion with explicit outcomes, and a numeric
  criterion (partial credit, disagreement, reevaluation).
- `tests/fixtures/phase1/database.json` and `report.v1.json`: a real Phase 1
  database dump and a real Phase 1 report export, both generated from the
  committed Phase 1 code (`ac4e180`) and stored as reviewable JSON.

### Local application smoke tests

1. `faultline demo --behavior vulnerable`: two execution sessions, two simulated
   findings, report format 2.0.0 with every documented section.
2. `faultline reevaluate RUN_ID --rubric RUBRIC_ID`: third session with rubric
   2.0.0, unchanged run snapshot, no network access.
3. `faultline judge` / `faultline adjudicate` / `faultline disagreements`:
   judgment appended, adjudication recorded, effective result confirmed,
   overridden or `human_assessed`.
4. `faultline export`: Markdown and JSON contain source hashes, canonical digests,
   automated evaluations, human judgments, adjudications, disagreement status and
   the full evidence bundle; the export digest verifies.
5. `faultline migrate` against a Phase 1 database: reports schema version 2 with
   all rows, IDs and overrides intact.

### Not verified

Remote CI, hosted providers, real model endpoints, cryptographic signing, and any
claim about attack efficacy against a real model. The toy HTTP server remains
deliberately vulnerable and is not an LLM.

## Phase 1 (historical)

Local environment: macOS arm64, Python 3.12.13, uv 0.12.17. Dependencies are pinned
in `uv.lock`. CI is configured for macOS/Linux and Python 3.12/3.13; those remote
jobs have not been run from this workspace.

## Automated checks (Phase 1)

- Ruff lint and formatting checks.
- Offline pytest suite: 81 tests passed, with socket connections and DNS lookup blocked by fixture.
- Source distribution and wheel build, including the packaged versioned JSON files.
- Wheel-content smoke verification independent of the editable source import.

Coverage includes secure and deliberately vulnerable fixtures; all nine technique
families; rubric source fidelity/hashes, explicit normalization and ambiguous-input
rejection; scoring, coverage, uncertain/not-applicable outcomes; scope/budget gates;
HTTP redirection/retry suppression, bounded responses, timeouts, malformed bodies
and credential echo redaction; SQLite reopen and append-only overrides; checkpointed
responses on evaluation errors; and working TUI selection/create/import/run,
baseline comparison, criterion evidence, history loading and report export.

## Local application smoke tests

1. CLI vulnerable mock: baseline `SAFE`; attack discloses the exact synthetic
   canary; both attack criteria fail; two explicitly simulated findings; Markdown
   and JSON reports persisted under `.faultline/`.
2. CLI secure mock: both responses `SAFE`, all criteria pass, no findings; both
   report formats exported.
3. Real terminal session: launch Textual, Ctrl+R runs the secure fixture, Ctrl+Q
   exits; a completed experiment is visible through a separate CLI history call.
4. `scripts/local_http_smoke.py --allow-loopback`: bind an ephemeral loopback toy
   server, use the actual HTTP adapter, observe a compliant baseline and exact
   attack disclosure, persist both runs and export reports. No external model,
   credential or hosted endpoint is used.

Generated databases/reports, probe screenshots and build artifacts remain ignored.
No GitHub workflow, hosted provider call or remote publish is implied by these
results. The toy HTTP server is deliberately vulnerable; it is not an LLM and
does not validate attack efficacy against any model.
