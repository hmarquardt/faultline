# Report schema

Current report formats: **2.1.0** for the experiment `Report`, the dataset
`BatchReport` and the agentic `AgenticReport`, and **2.2.0** for the
`ControlledExperimentReport`. Existing formats are never rewritten or
reinterpreted. Domain contract version: `schema_version: 1` (all
contracts). Generated from the live Pydantic models, so
`faultline schemas DIRECTORY` always matches this document.

## Compatibility

Phase 1 exports (format 1) predate `report_format_version`; Phase 2A exports
recorded `2.0.0`. Every later addition has a default, so older files validate and
re-export as 2.1.0. The model accepts `2.0.0` and `2.1.0`; a document keeps the
format it recorded and new exports emit `2.1.0`. `report_format_version` states
the format of the document that was written, not the format of the file read.

Unknown fields are rejected (`extra="forbid"`). A report that contains fields
from a future format fails closed rather than being silently downgraded.

## Top-level fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Contract version, always `1` for now |
| `report_format_version` | Export format, `"2.0.0"` or `"2.1.0"` |
| `id`, `generated_at` | Identity and generation time of this report object |
| `experiment` | Endpoint/model/technique/rubric snapshot, settings, budgets, status |
| `runs` | Immutable execution evidence, including execution-time automated evaluations |
| `evaluation_sessions` | Every independent evaluation of those runs |
| `findings` | Automated failed-criterion observations produced at execution time |
| `finding_reviews` | Effective status of the criterion behind each finding |
| `automated_scores` | Weighted compliance and coverage per session (and per run without a session) |
| `human_judgments` | Append-only reviewer decisions |
| `adjudications` | Append-only explicit policy decisions |
| `effective_results` | Automated observation, human judgments and effective outcome per criterion |
| `disagreements` | Unresolved disagreements only |
| `human_overrides` | Legacy Phase 1 append-only records, retained verbatim |
| `coverage` | Run/session/criterion coverage, uncertainty notes |
| `agreement` | Inter-rater agreement statistics (2.1.0) |
| `evidence_digests` | Canonical source-evidence digests |
| `export_digest` | Identity of this export artifact |
| `limitations` | Interpretation limits for the whole report |

## Separation of concerns enforced by the schema

1. **Execution evidence** (`runs`) is never rewritten. `runs[].evaluations` and
   `runs[].evidence` are exactly what the execution produced.
2. **Rubric identity** lives on each `EvaluationSession`
   (`rubric.source.sha256`, `rubric_definition_sha256`, `rubric.definition.id`,
   `rubric.definition.version`, review provenance). Two sessions over the same
   run may cite different rubric versions.
3. **Automated evaluations** are `evaluation_sessions[].evaluations`. They can be
   `uncertain` or `not_applicable`; `score` is `null` for categorical scales.
4. **Human judgments** (`human_judgments`) carry reviewer, outcome, optional
   rubric label, optional numeric score, rationale, confidence and
   `supersedes_id`.
5. **Effective results** (`effective_results`) are derived. `effective_source` is
   `automated`, `adjudicated` or `none`. `status` is one of:

   | Status | Meaning |
   | --- | --- |
   | `automated_only` | No human judgment exists; the automated outcome stands |
   | `awaiting_human_review` | Judgments exist, no adjudication covers them |
   | `human_assessed` | Adjudicated outcome supplies a result the automated evaluator could not produce |
   | `confirmed` | Adjudicated outcome equals the automated outcome |
   | `overridden` | Adjudicated outcome contradicts the automated outcome |
   | `unresolved` | Adjudication could not resolve the disagreement |

6. **Findings** stay bound to the execution-time session. `finding_reviews`
   states whether a finding is confirmed, overridden, awaiting review or
   unresolved, so an overridden automated failure is never presented as an
   uncontested final finding.

## Identities

- `evidence_digests[].kind == "execution"`: canonical digest of one stored run
  (`sha256-canonical-json/1`, sorted keys, compact separators).
- `evidence_digests[].kind == "evaluation"`: canonical digest of one session.
- `evidence_digests[].kind == "judgment"` / `"adjudication"`: canonical digest of
  one review record, so an export can be linked to the exact decisions it cites.
- `runs[].evidence[].sha256`: SHA-256 of the retained source bytes (Phase 1
  behavior, unchanged).
- `export_digest`: digest of this report with `export_digest` excluded. It
  identifies the export artifact and is expected to differ from every source
  digest it covers. `faultline.reports.verify_export_digest` recomputes it.

Digests detect accidental alteration and link records. They are not signatures:
a local operator who can rewrite the database can also rewrite digests.

## Markdown export

`reports.markdown` renders the same content in fixed sections:

1. Execution evidence
2. Rubric identity and evaluation sessions
3. Automated evaluations
4. Human judgments (append-only)
5. Adjudication and effective results
6. Unresolved disagreements
7. Findings (automated observations with review status)
8. Legacy Phase 1 overrides (only when present)
9. Coverage, uncertainty and limitations
10. Complete reproducibility and evidence bundle (full JSON)

All model- or human-supplied text is emitted inside length-matched code fences,
so hostile response text cannot escape into report structure.

Both report types also export `csv` with one row per session criterion
(`report_type`, document/batch/dataset/case/run/session identifiers, rubric and
criterion identity, scale, automated outcome/label/score, reviewer
outcome/label/score, reviewer agreement level, effective outcome/label/score,
status, adjudication and judgment ids, disagreement dimensions). Cells that begin
with `=`, `+`, `-` or `@` are prefixed with `'` so spreadsheet software cannot
treat imported text as a formula.

## Disagreement dimensions (2.1.0)

`Disagreement` records state *how* reviewers differ, not only that they do:
`outcome_disagreement`, `label_disagreement`, `score_disagreement`,
`max_ordinal_gap`, plus the raw `reviewer_outcomes`, `reviewer_labels` and
`reviewer_scores`. Identical outcomes with different categories or grades are a
reported disagreement, and an unresolved criterion has no effective outcome and
no effective numeric score.

## Agreement statistics (2.1.0)

`AgreementReport` is descriptive and per rubric version/criterion/scale:

- `units_total`, `units_compared`, `units_excluded_not_applicable`,
  `units_excluded_incomplete` and the reviewer list (sample sizes are explicit).
- Per `AgreementGroup`: `rubric_definition_sha256` (groups never merge distinct
  definitions), `exact_agreement`, `outcome_agreement`, `label_agreement`,
  `mean_absolute_score_difference`, `max_ordinal_gap`, per-pair rows and the
  exclusion counters `units_not_applicable_disputed`, `units_missing_labels` and
  `units_outside_declared_levels`.
- `KappaResult` records `value`, `defined`, `reason`, `observed_agreement`,
  `expected_agreement`, `weighting`, `categories` and `n`. Undefined estimates
  always carry a reason instead of a fabricated number.
- `PairwiseAgreement` keeps the raw `contingency` counts.

`not_applicable` units are excluded from agreement and counted separately, but a
unit where one reviewer says `not_applicable` and another rates it is reported as
an `ApplicabilityDisagreement` (`applicability_disputes`) with reviewer
attribution and counts. A missing rating is not a disagreement. Kappa is chance-corrected agreement for
these raters on these items, never accuracy and never ground truth.

## Dataset batch report

`BatchReport` (format 2.1.0) is a distinct contract with no experiment, endpoint,
provider or technique fields, so imported responses cannot be mistaken for a
harness execution. It contains:

| Field | Meaning |
| --- | --- |
| `origin` | Always `dataset_import` |
| `dataset` | Dataset identity, version, provenance, source artifact and index digest |
| `batch` | Batch identity, status, budget and rubric identity/digests |
| `progress` | Case counts plus aggregate compliance over completed cases |
| `cases` | One row per case with status, session link, error or skip reason |
| `records` | The imported records in batch order (prompt, response, provenance) |
| `evaluation_sessions` | Dataset sessions with imported evidence artifacts |
| `automated_scores` | Per-session weighted compliance and coverage |
| `human_judgments`, `adjudications` | Append-only review records |
| `effective_results`, `disagreements` | Derived outcomes and contest details |
| `coverage` | Case/criterion coverage, excluded cases and notes |
| `agreement` | Inter-rater statistics for the batch |
| `evidence_digests`, `export_digest` | Session/judgment/adjudication identities and export identity |

The Markdown rendering states explicitly that no request was sent by Faultline for
these cases. See [dataset format](DATASET_FORMAT.md) for import and lifecycle
rules.

## Agentic report

`AgenticReport` (format 2.1.0, `origin="agentic"`) describes one stored synthetic
trace and is a distinct contract: it has no experiment, endpoint or provider
request, so a simulated tool interaction can never be read as an external action.

| Field | Meaning |
| --- | --- |
| `trace` | Scenario snapshot and digest, rubric snapshot and definition digest, agent kind, declared capabilities, model identity, status, termination, budgets, ordered turns, invocations, prior/post record digests, execution digest |
| `result` | Derived `AgenticResult`: verdict (`secure`/`compromised`/`inconclusive`), requested/denied/executed tools, unauthorized requests, verified state changes, canary disclosure, task completion and the observed basis |
| `evaluation_sessions` | Agentic sessions (`evidence_kind="agentic"`) with trace checks |
| `automated_scores` | Per-session weighted compliance and coverage |
| `human_judgments`, `adjudications` | Append-only review records |
| `effective_results`, `disagreements` | Derived outcomes and contest details |
| `agreement` | Inter-rater statistics scoped to the trace |
| `evidence_digests`, `export_digest` | Scenario, trace, session, judgment and export identities |
| `limitations` | Fixed statements about synthetic tools, denied requests, scripted agents, human-assessed adoption and sandbox-only state changes |

The Markdown rendering opens with "synthetic, simulated", shows the legitimate
objective, the trusted user request, the attack surface with the injected payload
and content hash, the conversation timeline with each turn's source and trust, a
tool request/decision/execution table with structured receipts, the observed outcome
with an explicit "no external system was touched" statement, the rubric evaluation
table, the reproduction command, human review records, agreement and limitations.
`reevaluate-trace` produces a new session without re-running the agent.

## Controlled-experiment report

`ControlledExperimentReport` (format 2.2.0, `origin="controlled_experiment"`) covers
one paired experiment and is a distinct contract.

| Field | Meaning |
| --- | --- |
| `experiment` | The plan: objective, authorization, control and attack variants, declared differences, rubric identity and digest, target identity, settings, budgets, limits, trial count, order policy, seed, environment policy, status and timestamps |
| `summary` | `ExperimentalSummary`: trial counts by status, complete pairs, per-criterion `CriterionComparison` rows and arm-separated observation tallies |
| `trials` | Every `PairedTrial` with status, recorded order, both trace IDs, both `VariantObservation`s and any error/interruption reason |
| `trace_ids` | Every trace the report refers to |
| `evaluation_sessions` | Sessions for both arms |
| `human_judgments`, `adjudications`, `effective_results` | Append-only review records and derived outcomes |
| `evidence_digests`, `export_digest` | Variant corpus hashes, trace digests, session/judgment/adjudication identities and export identity |
| `limitations` | Fixed statements on authorization, synthetic tools, small samples, human-assessed adoption and advisory seeds |

Per criterion the report gives control/attack trial counts, failures, uncertain and
not-applicable counts, excluded incomplete pairs, both failure rates with 95% Wilson
intervals, the paired absolute difference, the four transition counts, and the exact
McNemar p-value with its reason when undefined.

The Markdown rendering states which target ran (scripted fixture or authorized
endpoint), shows the legitimate task once, lists every variant difference with
hashes, prints the injected payload with its provenance, includes the tool policy,
settings, budgets and caps, the comparison and observation tables, every trial with
its trace references, human review records, reproduction commands and limitations,
and then the complete evidence bundle. The CSV export is trial-level: one row per
trial, variant and criterion with the raw outcome, trace/session identity and
observation flags. It never presents a scripted fixture as a model experiment.
