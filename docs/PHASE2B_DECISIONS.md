# Phase 2B architectural decisions

Status: accepted for Phase 2B (rubric conformance, batch evaluation, inter-rater
agreement, professional reporting). Baseline: Phase 2A (`f26ad7f`).

Phase 2A invariants are unchanged: execution evidence is immutable, sessions are
independent of execution, regrading never contacts a model, rubric wording and
scales survive unchanged, judgments and adjudications are append-only, effective
outcomes need an explicit policy, and source-evidence identity stays distinct from
export identity.

## D1. Imported responses are evidence, never simulated executions

A dataset record is not an `ExecutionRun`. Fabricating a run would imply the
harness dispatched a request it never sent. Instead `EvaluationSession` is
generalized to reference exactly one *subject*:

- `evidence_kind="execution"` with `run_id` and `experiment_id` (Phase 2A, unchanged)
- `evidence_kind="dataset"` with `dataset_case_id` and no run or experiment

`dataset_case_id` is stored in the same subject slot that Phase 2A used for the
run id inside `CriterionEvaluation.run_id`, `HumanJudgment.run_id` and
`Adjudication.run_id`; those fields become optional and are documented as "the
evidence subject", not "a provider execution". Reports always carry
`evidence_kind`, and batch reports never use run-oriented wording.

Dataset sessions own their evidence: `EvaluationSession.evidence` holds the
imported record and the imported response artifacts. Execution sessions leave it
empty because their evidence lives on the run, exactly as in Phase 2A. The
`evaluations` table stays a run-linked index; dataset evaluations live in the
session snapshot only, so no foreign key implies a run.

## D2. Dataset format and limits

JSON (object with `records`, or a bare array) and JSONL (one record per line) are
supported. Each record has a stable `id`, `provenance`, `prompt`, `response`, and
optional `model`, `system_context`, `expected_behavior`, `reference_answer`,
`case_kind` (`baseline` or `attack`), `parameters` (for canary-style checks),
`metadata`, `source_sha256`.

Limits are explicit data (`DatasetLimits`): 5 MB source bytes, 2 000 records,
200 000 response characters per record. The raw source is retained once as a
`dataset-source` evidence artifact; each record is hashed canonically
(`sha256-canonical-json/1` over the normalized record without its own hash) and the
dataset digest is the canonical digest of the ordered `(id, source_sha256)` index.
Records are inserted and read one row at a time; JSONL import never materializes
the whole file as parsed objects, and batch execution iterates a database cursor.

Imported text is untrusted data. It is never executed, never treated as a
technique template, and never rendered as markup in reports.

## D3. Batch lifecycle, resume and partial completion

`BatchEvaluation` (metadata) and `BatchCase` (one row per dataset case) are
separate records. Case rows move `pending → completed | failed | skipped` once;
the transition is guarded in SQL (`WHERE status='pending'`), so a repeated or
interrupted run cannot duplicate an evaluation or rewrite a finished case.

- Every case is evaluated and persisted in its own transaction. A crash leaves
  unfinished cases `pending`, never half-written results.
- `execute_batch(limit=N)` processes at most N pending cases per call, so partial
  completion is explicit; the batch status becomes `partial` while work remains.
- Resumed batches report `completed`, `pending`, `failed` and `skipped` counts.
- `skipped` means the record could not be evaluated for a reason recorded on the
  case (empty response, unsupported rubric, explicit budget exclusion). It is not
  a pass and not a failure.
- Batch execution performs no network access at all and therefore never retries a
  remote request: there is nothing to retry.

## D4. Disagreement is multi-dimensional, and policies are scale-aware

Outcome equality is not agreement. The rating used for agreement is the tuple of
the dimensions the rubric actually declares:

| scale | agreement dimensions |
| --- | --- |
| binary | outcome |
| categorical | outcome and label |
| ordinal | outcome, label and derived score |
| numeric | outcome and exact score |

`resolve` therefore distinguishes `full`, `outcome_only` and `none` agreement.
Reviewers with the same outcome but different categories or grades are a real
disagreement; `unanimous` cannot resolve them, `majority` needs a strict majority
of identical *ratings*, `single_reviewer` and `first_reviewer` adopt one named
record. No effective numeric score is ever invented, averaged or interpolated:
`score` is only ever a value some reviewer recorded or that the rubric derives
from the adopted label.


`Disagreement` records carry `outcome_disagreement`, `label_disagreement`,
`score_disagreement`, the raw per-reviewer outcomes, labels and scores, and the
maximum ordinal gap, so a report can state *how* reviewers differ.

## D5. Statistics are descriptive, per-scale and explicit about undefined cases

`faultline.agreement` computes statistics only inside one comparable group: the
same rubric version, criterion and scale. It never mixes scales or criteria.

- Exact agreement: all reviewers' full ratings identical.
- Outcome agreement: all reviewers' outcomes identical.
- Cohen's kappa: two raters, categorical ratings, standard
  `κ = (p_o − p_e) / (1 − p_e)`; undefined when `p_e = 1` or fewer than two
  complete pairs.
- Weighted Cohen's kappa: linear weights `1 − |i − j| / (k − 1)` over the rubric's
  ordered categories (level order for ordinal, observed sorted scores for numeric).
- Pairwise tables: per reviewer pair, `n`, observed agreement, kappa, weighted
  kappa, mean absolute score difference and the raw contingency counts.

Missing ratings are not disagreements: a unit is only compared where every
reviewer in that pair has a rating. `not_applicable` units are excluded by default
and counted as excluded; `uncertain` remains a rating category because it is an
explicit human decision. Sample sizes are always reported. Kappa is a
chance-corrected agreement statistic for these raters on these items; it is not
accuracy, not ground truth, and not generalizable beyond the sampled items.

## D6. Report format 2.1.0 and a separate batch report

`Report.report_format_version` accepts `2.0.0` and `2.1.0`, emits `2.1.0`, and
gains an optional `agreement` section. Existing fields keep their meaning; the
only behavioral change is that a rubric with additional dimensions can no longer
be reported as full agreement on outcome alone.

`BatchReport` is a distinct contract (format `2.1.0`) rather than a `Report`
variant: it has no experiment, endpoint, technique or provider fields, so an
imported response cannot be mistaken for a model execution. It carries dataset
identity and provenance, batch membership and per-case status, sessions and
criterion evaluations, human judgments, disagreements, adjudications, effective
results, aggregate compliance, coverage/uncertainty, agreement statistics, sample
sizes, excluded cases, error counts and evidence digests.

Exports are JSON and Markdown plus a CSV of evaluation rows (`csv` module quoting,
no formula prefixes) for both batch and experiment reports.

## D7. SQLite schema version 3

Version 2 constraints block dataset sessions (`evaluation_sessions.run_id` and
`experiment_id` are `NOT NULL`, `judgments.run_id` is `NOT NULL`). Version 3
rebuilds those two tables with nullable subject columns plus `dataset_case_id` and
`evidence_kind`, and adds `datasets`, `dataset_records`, `batches` and
`batch_cases`.

The migration keeps the Phase 2A procedure (one transaction, rollback on failure,
version retained on error) and adds SQLite's documented table-rebuild sequence with
foreign keys disabled on the migration connection, followed by
`PRAGMA foreign_key_check` before commit. All rows, IDs and snapshots survive;
`evaluation_kind` defaults to `execution` for existing sessions. Batch case rows are
mutable state, so they are the only table without an insert-only trigger; every
transition is guarded by a `pending` predicate.

## D8. Conformance suite is a library, not a claim

`faultline.conformance` validates an unfamiliar rubric without executing it
against a model: structure and semantics (ids, weights, thresholds, scale
declarations, evidence requirements), byte-exact preservation of wording, labels
and weights through an evaluation session, conservative evaluator behaviour
(non-binary and manual criteria must stay `uncertain`), and report rendering of
the fixtures. It returns findings with severities, never a score, and never claims
that deterministic checks resolve subjective criteria. `faultline
rubric-conformance` exposes it locally.
