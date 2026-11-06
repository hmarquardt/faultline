# Dataset format

Faultline datasets carry **prerecorded model responses**. Importing a dataset
never contacts a provider and never creates an `ExecutionRun`; the record's
`provenance` field is the only claim about where the text came from.

## Supported files

| Format | Suffix | Shape |
| --- | --- | --- |
| JSON array | `.json` | `[{record}, …]` |
| JSON object | `.json` | `{"title"?, "version"?, "provenance"?, "records": [{record}, …]}` |
| JSONL | `.jsonl`, `.ndjson` | one record object per non-empty line |

JSON parsing rejects duplicate keys and non-finite numbers. JSONL is parsed line
by line and imported in two streaming passes, so a file is never materialized as
one object graph. Files must be valid UTF-8.

## Record fields

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable case ID, unique within the dataset |
| `provenance` | no | Source note; defaults to the dataset provenance |
| `prompt` | yes | The task or user prompt that produced the response |
| `response` | yes | The recorded model output (may be empty) |
| `model` | no | Model identity as recorded by the producer |
| `system_context` | no | System/developer context used for the case |
| `expected_behavior` | no | Human description of the intended behavior |
| `reference_answer` | no | Reference answer for factual comparison |
| `case_kind` | no | `baseline` (default) or `attack`; drives `applies_to` criteria |
| `parameters` | no | String parameters, e.g. `{"canary": "FAULTLINE_SYNTHETIC_…"}` |
| `metadata` | no | Free-form JSON object retained verbatim |

An empty `response` is legal input. The case is then **skipped** with the reason
`Imported response is empty`; a skipped case is neither a pass nor a failure.

## Limits and budgets

`DatasetLimits` caps the import: 5 MB of source bytes, 2 000 records and 200 000
characters per response by default. `BatchBudget` caps execution: 200 cases per
batch and an optional per-run cap. Override them with explicit arguments
(`--max-records`, `--max-cases`, `--per-run`) rather than editing a file. Nothing
is imported, planned or evaluated when a cap is exceeded.

```sh
uv run faultline import-dataset cases.jsonl --title 'Lab batch' --version 1.2.0
uv run faultline datasets
uv run faultline dataset-records DATASET_ID --limit 20
uv run faultline create-batch DATASET_ID --rubric RUBRIC_ID --max-cases 50
uv run faultline run-batch BATCH_ID --dry-run
uv run faultline run-batch BATCH_ID --limit 10      # partial pass, then resume
uv run faultline batch-status BATCH_ID
uv run faultline batch-report BATCH_ID --output reports/batch
```

## Identity and integrity

- The file is retained once as a `dataset-source` evidence artifact (its SHA-256
  is the source-byte hash, exactly like Phase 1 rubric artifacts).
- Each record is hashed canonically: `sha256-canonical-json/1` over the record
  without its own `source_sha256` (sorted keys, compact separators).
- The dataset identity is the canonical digest of the ordered
  `(case_id, source_sha256)` index. Reordering or editing a record changes it.
- A session that evaluates a record stores a `dataset-record` artifact, an
  `imported-response` artifact, and an `execution_sha256` over
  `{dataset_id, case_id, record_sha256}`.

`dataset_records.source_sha256` is verified when a record is loaded, so a modified
row is detectable.

## Batch lifecycle

| Status | Meaning |
| --- | --- |
| `planned` | Cases are registered; nothing has been evaluated |
| `running` | A pass is in progress |
| `partial` | Pending cases remain; call `run-batch` again to resume |
| `completed` | No pending cases remain (failures and skips are counted separately) |
| `failed` | Reserved for a batch-level failure; individual case failures are per case |

Case statuses are `pending → completed | failed | skipped`. Each case is evaluated
and persisted in one transaction, so an interruption cannot duplicate an
evaluation or lose a finished one. Batch case rows are never deleted.

## Untrusted data

Imported text is data. It is never executed, never used as a template, never
rendered as markup and never sent anywhere. Reports wrap every record and response
in length-matched code fences.
