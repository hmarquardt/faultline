# Phase 2A architectural decisions

Status: accepted for Phase 2A (professional rubric-driven human evaluation).
Scope: execution/evaluation separation, rubric fidelity, human judgment and
adjudication, reviewer workbench, report schema 2.0.0, evidence hashing, SQLite
schema version 2. No new attack techniques, agents or network behavior.

## D1. Execution is immutable; evaluation is a session that references it

An `ExecutionRun` is the only place a request/response pair is produced. It is
written once (with a checkpoint while running) and never rewritten by review
activity. Every evaluation of that evidence is an `EvaluationSession` record:

- `origin`: `execution` (created inside the run transaction), `reevaluation`
  (automated re-scoring of a stored response), `human_review` (a session opened
  for manual assessment only), or `migration` (derived from a Phase 1 database).
- `rubric`: full rubric snapshot (source artifact, definition, review provenance).
- `evaluator`/`evaluator_settings`: identity and policy of the scorer.
- `execution_sha256`: canonical digest of the run evidence that was evaluated.
- `evaluations`: criterion results produced in that session.

A run therefore supports any number of independent sessions over different
rubric versions, evaluators and scales. `ExecutionRun.evaluations` keeps the
execution-time results exactly as Phase 1 stored them; sessions are additive.

Rejected alternative: storing the rubric/evaluator on the run. That would force
one rubric per response and force evidence mutation on review.

## D2. Rubric scales are explicit data, never inferred

`RubricCriterion.scale_kind` is `binary`, `ordinal`, `categorical` or `numeric`.
Ordinal and numeric criteria declare `levels` (original label, verbatim
description, numeric anchor). Categorical criteria declare `categories` with an
explicit `outcome` chosen during human normalization; they carry no numeric
score. `scale_min`, `scale_max`, `pass_threshold` and `weight` keep their
original meaning for ordered scales.

The deterministic evaluator only produces binary observations. Any criterion
with a non-binary scale returns `uncertain` with the reason that human
assessment is required, so an ordinal or categorical rubric can never be
silently collapsed into pass/fail.

## D3. Human judgment is append-only; adjudication is a separate act

`HumanJudgment` records reviewer, criterion, session, outcome, optional original
label, optional numeric score, rationale, optional confidence and
`supersedes_id`. Rows are insert-only in SQLite (triggers), so revisions keep
their history.

`Adjudication` records the explicit policy (`single_reviewer`, `unanimous`,
`majority`, `first_reviewer`), the reviewer who adjudicated, the rationale, the
basis judgment IDs, the dissenting IDs and an optional `supersedes_id`.

No effective outcome is produced without an explicit adjudication record. A
single human judgment, or the most recent judgment seen, is therefore never
automatically authoritative. Effective outcomes are derived per session and
criterion:

| status | meaning |
| --- | --- |
| `automated_only` | no human judgment exists; the automated result stands |
| `awaiting_human_review` | human judgments exist but no adjudication covers them |
| `human_assessed` | the adjudicated result supplies what the automated evaluator could not |
| `confirmed` | adjudicated outcome equals the automated outcome |
| `overridden` | adjudicated outcome differs from the automated outcome |
| `unresolved` | adjudication could not resolve disagreement |

"Latest judgment per reviewer" is used only to collapse a reviewer's own
revisions; it never arbitrates between reviewers.


## D4. Findings stay attached to the execution-time session

Findings are derived from execution-time evaluations and are not rewritten by
reevaluation. Reports add `finding_reviews`, which state the effective status of
the criterion that produced each finding. A finding from an overridden automated
failure is therefore reported as contested rather than as an uncontested
finding, and the original observation remains in the bundle.

## D5. Two identities: source evidence and export artifact

- `EvidenceArtifact.sha256` (Phase 1): SHA-256 of retained bytes, unchanged.
- Canonical digest (`sha256-canonical-json/1`): SHA-256 of canonical JSON
  (sorted keys, compact separators) of a typed record. Used for
  `execution_sha256`, session and judgment evidence digests, and
  `Report.export_digest`.
- `export_digest` is computed over the report with `export_digest` excluded. It
  identifies one export artifact (it includes the report ID and generation
  time), so it deliberately differs from the source evidence digests that it
  covers.

No cryptographic signature is introduced: digests detect accidental alteration
and link records, but there is no key management or trust anchor in scope.

## D6. SQLite schema version 2 migration

Version 1 tables, rows, IDs and JSON snapshots are retained. Version 2 adds
`evaluation_sessions`, `judgments`, `adjudications`, and a nullable
`evaluations.session_id` index column, plus insert-only triggers for
evaluations, sessions, judgments and adjudications.

Migration runs in one explicit transaction (`BEGIN IMMEDIATE` … `COMMIT`) on a
dedicated autocommit connection so DDL and DML roll back together. Failure
leaves `user_version` at 1 and raises a controlled error; nothing is deleted or
reinterpreted. Legacy runs that already carry evaluations get one derived
session with `origin="migration"` and the experiment's rubric snapshot. Legacy
`overrides` rows are left untouched and are still reported, in a separate
"legacy overrides" section.

Historical report files remain loadable: every new `Report` field has a default,
so schema-1 JSON validates unchanged and can be re-exported.

## D7. Module boundaries

- `domain.py`: schemas and canonical digest helpers (no IO).
- `integrity.py`: record digests and evidence verification (pure).
- `adjudication.py`: judgment collapsing, policy resolution, effective results,
  disagreements and coverage (pure; no storage, no UI).
- `storage.py`: schema, migration, append-only persistence.
- `service.py`: use cases (`reevaluate`, `start_human_session`,
  `record_judgment`, `adjudicate`, `report`), policy and persistence order.
- `reports.py`: portable export and export identity.
- `cli.py`/`tui.py`: clients only; the TUI performs no scoring or policy.

## D8. Compatibility guarantees

- Phase 1 CLI commands (`demo`, `run`, `export`, `override`, …) keep working.
  `override` is documented as the legacy Phase 1 append-only record type.
- Phase 1 JSON reports validate against the Phase 2A `Report` model because all
  additions are defaulted, and they can be re-exported (Phase 2B emits 2.1.0).
- `faultline report` schema JSON export is generated from the live models, so
  `faultline schemas DIR` documents the new contracts automatically.

