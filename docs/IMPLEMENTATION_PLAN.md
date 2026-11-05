# Implementation plan

## Phase 1: runnable vertical slice

Delivered and locally verified; see [verification record](VERIFICATION.md). The
initial TUI intentionally delegates advanced configuration and review to the CLI.

1. Define versioned domain schemas, rubric review workflow and module boundaries.
2. Add source-hashed sample rubric and small declarative synthetic techniques.
3. Implement secure/vulnerable mocks and an explicitly scoped compatible adapter.
4. Add policy preflight, baseline/attack execution, deterministic scoring and evidence.
5. Persist complete and partial runs, evaluations, findings and human overrides.
6. Expose profile creation, rubric import/review, run/dry-run/history/export via CLI.
7. Add a working Textual client for selection, execution, comparison and export.
8. Verify offline unit/integration/TUI tests, lint, package and local smoke runs.
9. Document operation, boundaries, limitations and contributor commands; commit.

## Phase 2A: professional rubric-driven human evaluation

Delivered and locally verified; see [verification record](VERIFICATION.md) and
[Phase 2A decisions](PHASE2A_DECISIONS.md).

1. Introduced the versioned `EvaluationSession` contract so one stored execution
   supports many independent evaluations with different rubric versions and
   evaluators, plus offline `reevaluate` in service, CLI and TUI.
2. Expanded rubric scales: binary, ordinal levels with original labels and
   wording, categorical outcomes, numeric ranges, and manual/uncertain/NA human
   outcomes. Non-binary criteria are never auto-collapsed to pass/fail.
3. Added append-only human judgments with reviewer attribution, rationale
   history and `supersedes_id`, plus explicit adjudication policies and derived
   effective outcomes that never overwrite automated records.
4. Built a keyboard-first Textual reviewer workbench: run/session selection,
   rubric selection, full criterion wording, evidence panel, judgment authoring,
   adjudication, unresolved-disagreement indicator and export.
5. Extended reports to format 2.0.0 with separated execution evidence, rubric
   identity, automated evaluations, human judgments, adjudicated results,
   disagreements, finding review status, coverage and limitations.
6. Added deterministic canonical digests for execution, session and export
   artifacts, keeping source-byte hashes distinct from export identity.
7. Implemented and tested the SQLite version 1 → 2 migration, including rollback,
   reopen and historical report compatibility.

## Phase 2B and later

1. Resumable interrupted runs, cancellation and request-level events.
2. Isolated assertion workers and instrumented toy tools with receipts.
3. Deterministic checks for encoded canaries and richer instruction constraints.
4. Native provider adapters with capability negotiation.
5. Optional model-as-judge with separate provenance and human calibration.
6. Dataset batches, paired comparisons, agreement statistics and regression diffs.
7. Remaining TUI editors for real profiles and rubric normalization review.

## Later

Signed evidence bundles, community rubric exchange with review, larger authorized
corpora, local-only judge integrations, statistical reporting and scoped tool labs.
No autonomous external attack campaigns or ambient credential/tool authority.

