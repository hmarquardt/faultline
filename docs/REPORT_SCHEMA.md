# Report schema

Current report format: **2.0.0**. Domain contract version: `schema_version: 1`
(all contracts). Generated from the live Pydantic models, so
`faultline schemas DIRECTORY` always matches this document.

## Compatibility

Phase 1 exports (format 1) omit every Phase 2A field. Each addition has a
default, so an old file validates as a `Report` and can be re-exported as format
2.0.0. `report_format_version` therefore states the format of the document that
was written, not the format of the file that was read.

Unknown fields are rejected (`extra="forbid"`). A report that contains fields
from a future format fails closed rather than being silently downgraded.

## Top-level fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Contract version, always `1` for now |
| `report_format_version` | Export format, `"2.0.0"` |
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
