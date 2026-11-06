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

## Phase 2B: conformance, batches, agreement and reporting

Delivered and locally verified; see [verification record](VERIFICATION.md) and
[Phase 2B decisions](PHASE2B_DECISIONS.md).

1. Made disagreement multi-dimensional (outcome, label, score, ordinal gap) and
   scale-aware in adjudication policy.
2. Added a reusable conformance suite with six realistic rubric packs covering
   instruction adherence, quality, factual accuracy, safety/privacy, structured
   output and prompt-injection resistance.
3. Introduced a versioned, bounded, streaming dataset format and a resumable
   `BatchEvaluation` that evaluates imported responses offline with no fabricated
   execution records.
4. Added `agreement.py` with exact/outcome/label agreement, Cohen's kappa, linear
   weighted kappa and pairwise tables, explicit about exclusions and undefined
   estimates.
5. Extended reports to format 2.1.0 with a `BatchReport`, an agreement section and
   CSV evaluation rows.
6. Added a keyboard-friendly Batch tab to the Textual workbench and CLI commands
   for datasets, batches, agreement and conformance.
7. Migrated SQLite to schema version 3 with table rebuilds, a foreign-key check and
   preserved historical rows.

## Phase 3A: instrumented agentic red-team evaluation

Delivered and locally verified; see [verification record](VERIFICATION.md) and
[Phase 3A decisions](PHASE3A_DECISIONS.md).

1. Corrected two Phase 2B agreement issues first: applicability disputes are now
   retained with reviewer attribution instead of being silently discarded, and
   groups are keyed by the canonical rubric-definition digest; weighted kappa uses
   declared rubric levels only, with counts for missing labels and out-of-level
   ratings and a documented (validator-enforced) level requirement for numeric
   criteria.
2. Added `tooling.py`: a closed registry of five synthetic tools, an in-memory
   sandbox environment, an explicit authorization policy and versioned execution
   receipts with verified state-change digests.
3. Added `agents.py`: a bounded agent loop over an `AgentProvider` Protocol with
   declared capabilities, a deterministic scripted provider, and a tool-calling
   path on the existing compatible adapter that is used only when the profile
   declares the capability.
4. Added six packaged retrieval-injection scenarios with secure and vulnerable
   scripted fixtures, embedded rubrics and recorded trust boundaries.
5. Added `agentic_eval.py` trace checks that read proposals, decisions, receipts,
   verified digests and recorded turns, and stay `uncertain` where intent cannot
   be decided deterministically.
6. Extended persistence to schema version 4 (`agentic_traces`, agentic session
   subject) and reports with `AgenticReport`, Markdown and CSV exports.
7. Added CLI (`scenarios`, `run-scenario`, `traces`, `trace`, `trace-turns`,
   `trace-tools`, `agentic-report`, `reevaluate-trace`, `agreement --trace`) and a
   keyboard-first Agentic tab in the Textual workbench.

## Phase 3B and later

1. Interruption recovery and cancellation for live runs and live agent loops,
   including request-level events.
2. Isolated assertion workers and additional instrumented toy tools.
3. Agreement confidence intervals, paired comparisons and regression diffs.
4. Calibrated optional model-as-judge with separate provenance.
5. Native provider adapters with capability negotiation for tool-call schemas.
6. Remaining TUI editors for real profiles and rubric normalization review.

## Later

Signed evidence bundles, community rubric exchange with review, larger authorized
corpora, local-only judge integrations, statistical reporting and scoped tool labs.
No autonomous external attack campaigns or ambient credential/tool authority.

