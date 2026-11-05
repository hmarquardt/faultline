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

## Phase 2: professional evaluation workflow

1. Expand TUI profile editing, normalization review and human override authoring.
2. Add resumable interrupted runs, cancellation, request-level events and migrations.
3. Introduce isolated assertion workers and instrumented toy tools with receipts.
4. Extend deterministic checks for encoded canaries and richer instruction constraints.
5. Add native provider adapters with capability negotiation and explicit parameter support.
6. Add optional model-as-judge with separate provenance and calibration against humans.
7. Add dataset batches, paired comparisons, coverage summaries and regression diffs.

## Later

Signed evidence bundles, community rubric exchange with review, larger authorized
corpora, local-only judge integrations, statistical reporting and scoped tool labs.
No autonomous external attack campaigns or ambient credential/tool authority.
