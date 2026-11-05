# Faultline architecture

Status: Phase 1 foundation plus Phase 2A professional human evaluation
(rubric-driven sessions, adjudication, reviewer workbench, report format 2.0.0,
SQLite schema version 2). Python 3.12+, local SQLite, Textual interface.

## Boundaries and decisions

`domain.py` owns strict, versioned Pydantic schemas and canonical hashing.
`rubrics.py` imports and validates documents. `techniques.py` renders packaged
declarative techniques. `evaluation.py` makes deterministic observations.
`integrity.py` computes record digests and verifies stored evidence.
`adjudication.py` applies explicit review policy without any IO.
`providers.py` owns the sole network boundary. `service.py` coordinates policy,
execution, evaluation sessions, review and persistence. `storage.py` owns SQLite
transactions and migrations. `reports.py` renders portable evidence.
`cli.py` and `tui.py` are clients of the same service; neither scores responses.
No agent framework, automatic tool execution, hosted state, or mandatory judge.

```mermaid
flowchart LR
  CLI --> Service
  TUI --> Service
  Service --> RubricImport
  Service --> TechniqueRegistry
  Service --> ProviderProtocol
  Service --> Evaluator
  Service --> AdjudicationPolicyEngine
  Service --> IntegrityDigests
  Service --> SQLite
  SQLite --> ReportExporter
  ProviderProtocol --> Mock
  ProviderProtocol --> CompatibleHTTP
```

## Explicit domain contracts

All contracts carry a schema version; stable IDs, UTC timestamps and source hashes
link records. JSON Schema can be emitted with `faultline schemas DIRECTORY`.

| Contract | Responsibility |
| --- | --- |
| EndpointProfile | Provider, URL, credential environment reference, scope approval |
| TargetModel | Requested identity and endpoint ID; returned identity lives on response |
| TechniqueDefinition | Version, family, parameter defaults, templates, references |
| AttackCase | Fully rendered role/content messages, baseline/attack kind, parameters |
| Experiment | Endpoint/model snapshot, authorization, rubric, technique, budgets/settings |
| ExecutionRun | Case, lifecycle, request timing, response, execution-time evaluations, error |
| ModelResponse | Exact response text and decoded provider body, returned identity, tool requests |
| EvidenceArtifact | Source type, content, SHA-256, provenance, timestamp |
| Rubric / RubricCriterion | Source artifact, review state, wording, scale, levels/categories |
| EvaluationSession | Versioned, independent evaluation of one run with its own rubric/evaluator |
| CriterionEvaluation | Criterion/version, scale, label, facts, outcome, score, rationale, evidence |
| HumanJudgment | Append-only reviewer decision with label, score, rationale, supersedes link |
| AdjudicationPolicy / Adjudication | Explicit resolution policy and its append-only decision |
| HumanOverride | Legacy Phase 1 append-only record, retained verbatim |
| EffectiveResult / Disagreement | Derived automated + human + adjudicated view per criterion |
| Finding / FindingReview | Automated observation and whether review confirmed, overrode or left it open |
| CoverageSummary | Evaluated, reviewed, adjudicated and unresolved counts with notes |
| EvidenceDigest | Canonical digest of an execution, session or export artifact |
| Report | Complete experiment, sessions, judgments, adjudications, findings, digests, limits |

Criteria score normalized compliance (higher is better). Binary checks map to
the criterion's minimum/maximum scale; threshold determines pass. Uncertain and
not-applicable have no score. Weighted scores exclude those outcomes but report
coverage; unknown behavior never becomes a pass.


## Rubric fidelity and scales

`scale_kind` is `binary`, `ordinal`, `categorical` or `numeric`. Ordinal and
numeric criteria declare `levels` that keep the source label, verbatim description
and numeric anchor; categorical criteria declare `categories` with an explicit
outcome chosen during human normalization and carry no numeric score. Weight,
threshold, range and criterion wording are preserved verbatim.

The deterministic evaluator produces binary observations only. A non-binary
criterion returns `uncertain` and states that human assessment is required, so an
ordinal or categorical rubric can never be silently collapsed into pass/fail.
Human judgments must use a declared label or a score inside the declared range,
and an outcome that contradicts the rubric's own threshold or category meaning is
rejected. Categorical outcomes stay outside the weighted numeric figure and are
counted in coverage instead.

## Evaluation sessions

One stored `ExecutionRun` supports any number of `EvaluationSession` records:
`execution` (created with the run), `reevaluation` (a stored response scored again
under another rubric), `human_review` (manual assessment only) and `migration`
(derived from a Phase 1 database). Each session snapshots the rubric, the
rubric-definition digest, the evaluator identity/settings and the canonical
execution digest of the evidence it evaluated. `faultline reevaluate RUN_ID
--rubric RUBRIC_ID` performs no provider access and creates no new execution.

See [Phase 2A decisions](PHASE2A_DECISIONS.md) for the full record.

## Human judgment and adjudication

`HumanJudgment` rows are insert-only (SQLite triggers) and record reviewer,
criterion, session, outcome, optional rubric label, optional numeric score,
rationale, confidence and `supersedes_id`. `Adjudication` rows record the policy
(`single_reviewer`, `unanimous`, `majority`, `first_reviewer`), the adjudicator,
rationale, basis judgment IDs, dissenting IDs and `supersedes_id`.

No effective outcome exists without an explicit adjudication record. A single
human judgment, or the most recent judgment overall, is never authoritative.
"Latest judgment per reviewer" only collapses one reviewer's own revisions.
Effective statuses are `automated_only`, `awaiting_human_review`,
`human_assessed` (the adjudicated result supplies what the automated evaluator
could not produce), `confirmed`, `overridden` and `unresolved`. Disagreements
between reviewers, or between a reviewer and a definite automated outcome, are
listed until an adjudication resolves them.

## Evidence identity

`integrity.py` hashes typed records as canonical JSON (`sha256-canonical-json/1`):
sorted keys, compact separators, UTF-8. This yields an `execution_sha256` per run,
a digest per session and per report export. Retained source bytes keep their
Phase 1 SHA-256, so raw evidence identity is unchanged. `export_digest` covers a
report excluding itself and therefore differs from the source digests it covers.
This is integrity, not a signature: there is no key or trust anchor.

## Rubric normalization

JSON/YAML imports use safe parsing and schema validation. Original UTF-8 bytes
(including newlines/BOM) are retained in a hashed artifact. Markdown and plain
text are staged as unreviewed documents with no executable interpretation. A
tester supplies a normalized structured draft, reviewer identity and rationale
to approve it; original and draft remain linked. Ambiguous structured criteria
can use `manual` and yield `uncertain`. Imported Python never executes.

## Execution and evidence

An experiment snapshots rubric, technique, endpoint, model and rendered cases.
The service preflights scope, maximum requests, input bytes and output-token
allocation before any provider access. Dry runs persist their rendered plan
without opening a connection. Each attempted request is persisted as running
before dispatch; each result/error commits immediately, preserving partial work.
The two requests are independent baseline and attack conversations. A crash can
leave a running record; history reports it honestly rather than retrying it.

The HTTP adapter sends one non-streaming Chat Completions POST per case. It has
no retries, redirects, environment proxies or model discovery. TLS verification
is enabled; cleartext is limited to loopback. Credentials are resolved from the
named launch environment variable; their values are never stored. Credential
occurrences in decoded responses are redacted before persistence, with an
explicit record that the preserved body changed. Raw wire bytes and HTTP headers
are deliberately excluded. Error text is controlled, never a provider error body.
Mock execution never resolves credentials or touches the network. Dry-run may
inspect an already-set credential environment variable to reject accidental
credential material in input snapshots; it does not require one or dispatch IO.

Provider tool requests are untrusted proposals, not executed actions. Tool-use
checks require harness-owned execution receipts; absent telemetry yields
uncertain. Phase 1 executes no tools and no arbitrary Python. A local registry
can receive trusted Python assertion callables through the library API only;
enabling this requires explicit service policy. These run with process authority,
not a sandbox. Untrusted assertions require future process/container isolation.

## Storage and portability

SQLite uses foreign keys, WAL, schema version checking, short transactions and an
explicit migration path. JSON snapshots preserve full typed records alongside
relational IDs/indexes for history, evaluation, review and lookup. This avoids
premature ORM complexity while keeping evidence immutable and queryable. Reopening
revalidates snapshots.

Schema version 2 adds `evaluation_sessions`, `judgments`, `adjudications` and a
`session_id` index column on `evaluations`. The migration from version 1 runs in
one `BEGIN IMMEDIATE` transaction on an autocommit connection, retains every row,
ID and snapshot byte-for-byte, and derives one `migration`-origin session per run
that already carried evaluations. On failure it rolls back and leaves version 1
with a controlled error. Unknown or future versions fail closed. Insert-only
triggers protect overrides, evaluations, sessions, judgments and adjudications;
only run and experiment lifecycle fields are updated by supported operations.

Exports are versioned JSON and Markdown with complete cases, responses, criteria,
source artifacts, rationales and settings (see [report schema](REPORT_SCHEMA.md)).
Source material is potentially hostile; Markdown fences are selected to prevent
content escaping into report structure. No export publishes anything. Reports
contain synthetic secrets and may contain sensitive target outputs; operators
control the export paths.

## Extension points and tradeoffs

The provider Protocol permits Anthropic, OpenRouter, Ollama or future adapters
without changing evaluation. The declarative technique registry covers nine
families with small synthetic templates; this is not a discovery/loading system
for arbitrary third-party Python. Evaluator identity distinguishes deterministic
facts, heuristics and human judgments; a future model judge must implement the
same criterion contract, record its own model/settings and never write into an
existing session. New scales extend `RubricCriterion` rather than the evaluator
policy on the service. The TUI is one client of the review use cases; a web or
CLI-only front end needs no domain change.

Exact substring checks miss encoded or paraphrased disclosure. A confirmed
synthetic disclosure proves only that observation for that run. Seed and zero
temperature are settings, not a guarantee of remote reproducibility. Output
budgets are requested bounds, not dollar billing enforcement; token usage is
retained when provided. Ordinal and categorical results depend on human
assessment; inter-rater agreement is reported as disagreement, not as accuracy.
No production robustness or universal jailbreak claims.
