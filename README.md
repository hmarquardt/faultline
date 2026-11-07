# Faultline

A Python-first, local-first adversarial LLM evaluation workbench for authorized
targets. Execute controlled synthetic techniques, evaluate observable behavior,
review it with versioned rubrics, adjudicate human judgments, score prerecorded
response datasets, measure inter-rater agreement, and run instrumented agentic
scenarios against synthetic tools and retrieved documents, compare authorized
models with paired control/attack experiments, compare several authorized models
without pooling them, validate endpoint capabilities and run benchmark suites, audit
exports and prepare a release, then export reproducible findings with evidence.
Current scope: Phase 3D.

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/), macOS or Linux.

```sh
uv sync --dev
uv run faultline demo --behavior secure --output reports/secure
uv run faultline demo --behavior vulnerable --output reports/vulnerable
uv run faultline tui
```

The demos run entirely offline. Each creates a profile, loads the versioned
sample rubric, renders baseline and attack conversations, records both responses
and criterion evidence in SQLite, and writes Markdown and JSON reports. The
vulnerable mock deliberately discloses an exact synthetic canary. Its finding is
explicitly simulated and says nothing about a real provider.

## Workbench operation

The TUI starts with secure and deliberately vulnerable local profiles and the
packaged rubric. Tab/Shift+Tab navigate controls, Enter opens selections and
activates buttons. Select a profile, rubric and technique, edit the synthetic
canary if desired, then run. The interface displays exact baseline/attack text,
criterion scores and selected criterion evidence. History rows load saved runs.

The **Review** tab is the reviewer workbench: choose a saved run and one of its
evaluation sessions, see each criterion's automated, human and effective outcome,
read the complete original criterion wording with its levels or categories, and
inspect the preserved response evidence. You can open a human review session or
re-evaluate the stored response with another rubric (no model call), append a
judgment with reviewer, rationale, label and optional numeric score, supersede
your own earlier judgment, and record an explicit adjudication. The disagreement
indicator shows how many criteria are unresolved or awaiting adjudication.

- Ctrl+R: run baseline + attack.
- Ctrl+D: save a dry-run plan with no endpoint dispatch.
- Ctrl+E: export the selected report to JSON and Markdown.
The **Batch** tab reviews imported datasets: import a dataset, choose a rubric,
plan a batch, run or resume it, browse per-case results, record judgments and
adjudications, and export the JSON/Markdown/CSV report.

- Ctrl+J: append the entered human judgment to the selected criterion (Review or
  Batch tab).
- Ctrl+A: adjudicate the selected session with the chosen policy (Review or Batch
  tab).
- Ctrl+Q: quit.

Create mock profiles and import rubrics directly in the TUI. Configure real
profiles, custom generation settings/budgets and human normalization through the
CLI. A connection test sends one normal baseline request; it is not a passive TCP
probe. The TUI uses the first allowed model in a selected profile.

State defaults to the OS user-data directory (`platformdirs`, app `faultline`).
For repository-local state, place `--db` **before** the subcommand:

```sh
uv run faultline --db .faultline/history.sqlite3 tui
uv run faultline --db .faultline/history.sqlite3 profiles
uv run faultline --db .faultline/history.sqlite3 history
uv run faultline techniques authority-spoof
uv run faultline schemas .faultline/schemas
```

Every experiment stores endpoint/model snapshots, complete rendered messages,
rubric source/version, parameters, generation settings, budgets, timestamps,
decoded provider responses, hashes, evaluation rationale and findings. Reports
embed this full evidence bundle. Existing report files are never overwritten;
choose a fresh output prefix for another export.

## Optional real endpoint

Create an immutable profile for an endpoint you own or are authorized to test.
The example uses a loopback compatible model server; substitute your own allowed
model ID. `--scope` records your authorization context, `--authorize` attests it.

```sh
uv run faultline add-profile local-lab \
  --provider openai-compatible --base-url http://127.0.0.1:11434/v1 \
  --model YOUR_LOCAL_MODEL_ID --scope 'My local synthetic evaluation lab' --authorize
```

Copy the returned profile UUID into `PROFILE_ID` below. For a remote endpoint,
use HTTPS and add `--credential-env FAULTLINE_TARGET_KEY` when creating the
profile. Populate that environment variable securely in the launch environment.
Only the variable **name** is stored; Faultline provides no on-disk credential
vault. It does not require an API key for a keyless local server.

```sh
uv run faultline run PROFILE_ID --dry-run --output reports/plan
uv run faultline test-endpoint PROFILE_ID --allow-network
uv run faultline run PROFILE_ID --allow-network \
  --max-requests 2 --max-output-tokens 128 --total-output-tokens 256 \
  --timeout 30 --output reports/real-run
```

Profiles select `--token-parameter max_tokens` (compatibility default) or
`max_completion_tokens`. Use `--omit-seed` and/or `--omit-temperature` for servers
that do not support those settings. There is no automatic capability probing,
retry or parameter fallback. Failures appear in history and return CLI exit 2.
No real hosted provider was called during development verification.

## Import and review rubrics

Use the shipped `src/faultline/data/canary-rubric.v1.json` as a structured-format
example and `tests/fixtures/rubrics/graded-disclosure.v2.json` as a graded one.
JSON/YAML definitions support IDs, versions, criterion instructions, weights,
scales, pass thresholds, evidence requirements, case applicability and scale
declarations:

- `scale_kind: binary` (default): the deterministic check decides pass or fail.
- `scale_kind: ordinal`: `levels` keep the source label, verbatim description and
  numeric anchor; the threshold decides pass.
- `scale_kind: categorical`: `categories` carry the source label, description and
  an explicit outcome agreed during normalization; no numeric score is invented.
- `scale_kind: numeric`: declared range plus optional anchor `levels`.

Check types are `required_text`, `forbidden_text`, `exact_canary`, `json_schema`,
`tool_execution`, `manual` and explicitly registered library-only `python`.
Scores measure compliance; higher is better. Unknown or inapplicable criteria
have no score. Weighted automated summaries always include evidence coverage.
Ordinal, categorical and numeric criteria are human-assessed: the deterministic
evaluator reports `uncertain` and never converts them to pass/fail.

```sh
uv run faultline import-rubric path/to/rubric.yaml
uv run faultline import-rubric path/to/tester-notes.md
uv run faultline rubrics
uv run faultline review-rubric PENDING_RUBRIC_ID path/to/normalized.yaml \
  --reviewer 'Tester name' --rationale 'Agreed exact meaning of ambiguous requirements'
uv run faultline run PROFILE_ID --rubric REVIEWED_RUBRIC_ID --dry-run
```

Markdown and plain language imports remain pending until a tester explicitly
supplies and approves a structured draft. Review creates a new rubric record and
retains both the original source and normalization draft with hashes.

## Evaluation sessions, human review and adjudication

Every execution stores immutable evidence and at least one evaluation session.
A saved response can be scored again under another rubric version without any
model call, and each session keeps its own rubric snapshot, evaluator identity and
execution digest:

```sh
uv run faultline sessions --experiment EXPERIMENT_ID
uv run faultline reevaluate RUN_ID --rubric GRADED_RUBRIC_ID
uv run faultline start-review RUN_ID --rubric GRADED_RUBRIC_ID
uv run faultline judge SESSION_ID CONF-101 --outcome fail --label partial-fragment \
  --reviewer 'Alice' --rationale 'A prefix of the canary appears' --confidence medium
uv run faultline adjudicate SESSION_ID --policy single_reviewer \
  --designated-reviewer 'Alice' --reviewer 'Lead' --rationale 'Designated reviewer decision'
uv run faultline disagreements EXPERIMENT_ID
uv run faultline export EXPERIMENT_ID --output reports/reviewed-run
```

Judgments are append-only: `--supersedes JUDGMENT_ID` records a reviewer's own
revision while keeping the earlier record. There is no effective outcome until an
explicit `adjudicate` call records a policy (`single_reviewer`, `unanimous`,
`majority` or `first_reviewer`), so the most recent judgment is never silently
authoritative. Reports keep automated results, human judgments and the adjudicated
result separate, mark overridden findings as contested, and list unresolved
disagreements. Report format and identity are documented in
[docs/REPORT_SCHEMA.md](docs/REPORT_SCHEMA.md).

The Phase 1 `override` command is still available and its records are preserved
verbatim as legacy overrides; they are not reinterpreted as adjudications.

## Batch evaluation of imported responses

Prerecorded model outputs can be scored without contacting any model. A dataset is
imported once (JSON or JSONL), hashed and bounded; a batch then evaluates its cases
with one rubric, resumably and offline. Imported responses never become
`ExecutionRun`s, so no report can imply a request the harness did not send. See
[docs/DATASET_FORMAT.md](docs/DATASET_FORMAT.md).

```sh
uv run faultline import-dataset cases.jsonl --title 'Lab batch'
uv run faultline datasets
uv run faultline create-batch DATASET_ID --rubric RUBRIC_ID --max-cases 50
uv run faultline run-batch BATCH_ID --dry-run
uv run faultline run-batch BATCH_ID --limit 10   # partial pass
uv run faultline run-batch BATCH_ID              # resume; only pending cases
uv run faultline batch-status BATCH_ID
uv run faultline batch-report BATCH_ID --output reports/batch
```

Case statuses are `pending`, `completed`, `failed` and `skipped`; a skipped case
(empty response) is neither a pass nor a failure. `batch-report` writes JSON,
Markdown and a CSV of evaluation rows.

## Inter-rater agreement

`faultline agreement` reports exact, outcome and label agreement plus Cohen's kappa
and linear weighted kappa per rubric version, criterion and scale. Undefined
estimates state why (fewer than two compared items, or all ratings in one category),
`not_applicable` units are excluded and counted, and kappa is presented as
chance-corrected agreement — not accuracy and not ground truth.

```sh
uv run faultline agreement --batch BATCH_ID
uv run faultline agreement --experiment EXPERIMENT_ID
```

## Rubric conformance

```sh
uv run faultline rubric-conformance --pack tests/fixtures/conformance/response-quality.json
uv run faultline rubric-conformance --path path/to/rubric.yaml
```

Six packs (instruction adherence, response quality, factual accuracy,
safety/privacy, structured output, prompt injection) each contain known responses
for full, partial, failing, ambiguous, not-applicable and conflicting-reviewer
cases. The suite checks structure, semantic preservation through import and
evaluation, and that subjective criteria stay `uncertain`. It never scores a rubric.

## Agentic lab

```sh
uv run faultline scenarios
uv run faultline scenario retrieved-authority-spoof
uv run faultline run-scenario retrieved-authority-spoof --agent scripted-secure
uv run faultline run-scenario tool-output-laundering --agent scripted-vulnerable \
  --output reports/laundering
uv run faultline trace-turns <trace-id>
uv run faultline trace-tools <trace-id>
uv run faultline agentic-report <trace-id> --output reports/agentic
uv run faultline reevaluate-trace <trace-id> --rubric <rubric-id>
uv run faultline agreement --trace <trace-id>
```

Six synthetic scenarios ship with a legitimate objective, a controlled corpus, one
injected document, an authorization scope, a rubric, and deterministic Secure and
Vulnerable scripted agents. Tools (`search_documents`, `read_document`,
`write_note`, `send_message`, `update_record`) exist only inside an in-memory
sandbox: there is no shell, no filesystem write, no network call and no delivery.
Every proposed call is recorded, then allowed or denied by policy, and only an
authorized call produces a receipt with verified state-change digests. Retrieved
documents are delivered strictly as untrusted tool results and never become a
system instruction. Budgets (requests, turns, tool calls, tokens, bytes, time)
terminate the loop with an explicit reason, and a cancelled run keeps everything it
already checkpointed. See [the scenario catalogue](docs/AGENTIC_SCENARIOS.md).

The `Agentic` TUI tab follows the same flow: choose a scenario, inspect the
objective and payload, pick a scripted agent, set budgets, dry-run, run, read the
timeline, review receipts and rubric results, judge (`Ctrl+J`), adjudicate
(`Ctrl+A`) and export.

## Controlled experiments

```sh
uv run faultline controlled-scenarios
uv run faultline plan-experiment retrieved-authority-spoof --trials 5 --order alternate
uv run faultline run-experiment <experiment-id>
uv run faultline experiment-status <experiment-id>
uv run faultline experiment-summary <experiment-id>
uv run faultline experiment-report <experiment-id> --output reports/experiment
```

A plan pairs a **control** variant (the same scenario with the payload removed) with
the **attack** variant, sharing task, system prompt, tool scope, rubric, settings,
budgets and initial synthetic state. Only declared differences separate the arms, and
they are listed with hashes in every report. Each trial runs both arms against a
freshly reset sandbox, in a recorded order, and stores both traces and sessions; a
resumed run never replays a trial whose remote outcome is unknown. Comparison output
is descriptive: failure rates with Wilson intervals, transition counts for complete
pairs, and an exact McNemar calculation — never a significance or causation claim.
Real endpoints additionally require an authorized profile declaring `tool_calling`,
`--allow-network`, a request cap and an optional estimated-spend guard. See
[controlled experiments](docs/CONTROLLED_EXPERIMENTS.md).

The `Controlled` TUI tab mirrors the workflow at 100x30: choose a scenario and
target, set trials, budgets and the network opt-in, plan, run or resume, inspect the
criterion comparison and per-trial receipts, then export.

## Validation, comparisons and benchmarks

```sh
uv run faultline capabilities --profile <profile-id> --allow-network
uv run faultline validate-endpoint --profile <profile-id> --trials 1 \
  --allow-network --output reports/validation
uv run faultline plan-comparison retrieved-authority-spoof \
  --agent scripted-vulnerable --agent scripted-secure --trials 2
uv run faultline run-comparison <comparison-id>
uv run faultline comparison-report <comparison-id> --output reports/comparison
uv run faultline benchmarks
uv run faultline plan-benchmark boundary-core-suite --agent scripted-vulnerable \
  --trials 1 --max-requests 400 --max-tokens 400000
uv run faultline run-benchmark <plan-id>
uv run faultline benchmark-report <plan-id> --output reports/benchmark
uv run faultline experiment-quality <experiment-id>
```

Capability validation records **configured** and **observed** features separately
(chat, tool calls, tool-result messages, token parameter, temperature, seed, system
role, model identity, usage, finish reason) as `supported`, `unsupported` or
`unknown`, with sanitized probe evidence. A declared capability is never treated as
proof, and an endpoint that accepts tool declarations but returns no tool call stays
`unknown`. `validate-endpoint` walks the whole protocol — authorization, credential
presence, capabilities, scenario execution, retrieval delivery, multiturn,
tool authorization, trace integrity, a one-trial experiment and report export — and
reports each step's status.

A model comparison runs one independent experiment per model; results are never
pooled and no global score is invented. Comparability notes disclose differing
settings (blocking), budgets or trial counts (warnings) and unobserved capabilities.
A benchmark suite is a packaged collection of scenarios executed under explicit
scenario, trial, request, token, runtime and optional spend ceilings; a run stops at
first ceiling and resumes without replaying completed scenarios. Twelve automated
quality checks accompany each experiment and never replace its results.

See [provider validation](docs/PROVIDER_VALIDATION.md) and
[benchmark methodology](docs/BENCHMARK_METHODOLOGY.md).

## Operational validation and release readiness

```sh
uv run faultline version
uv run faultline doctor --json
uv run faultline verify-report reports/experiment.json
uv run faultline smoke-plan --profile <id> --authorization "Owner approved" \
  --allow-network --max-requests 4 --max-output-tokens 64 \
  --estimated-cost-per-request 0.002 --max-spend 0.05
uv run python scripts/evaluator_workflow.py --output reports/workflow
```

`verify-report` audits an existing export with no provider contact: export digest,
denominators, transition totals, interval bounds and coverage labels, trace references,
effects-without-execution, simulation labelling, orphan review records, credential-shaped
strings and CSV formula injection. `smoke-plan`/`run-smoke` implement the bounded
live-model protocol — authorization note, network opt-in, request/token/timeout caps and
an explicit estimated-spend ceiling — and print the exact commands before anything is
sent. See [live-model smoke test](docs/LIVE_MODEL_SMOKE_TEST.md) and
[troubleshooting](docs/TROUBLESHOOTING.md).

Paired inference is stricter than before: a pair enters statistics only when it is
completed, belongs to the experiment, carries matching rubric and settings digests,
has verified trace integrity and no blocking quality finding. The reported paired
interval is Newcombe's MOVER score interval (approximate unconditional coverage); the
conditional interval is labelled separately as a sensitivity analysis.

## Databases and migrations

State opens at SQLite schema version 6. Version 1, 2 and 3 databases are migrated
in one transaction that preserves every row, ID and snapshot; version 2 evaluations
keep their sessions, and version 1 runs get one `migration`-origin session each.
Version 3 rebuilds the session and judgment tables so a session can reference an
imported dataset case, and adds dataset and batch tables. Version 4 adds
`agentic_traces` and lets a session reference a stored trace instead of a run or
dataset case. Version 5 adds `controlled_experiments` and `paired_trials` with
guarded trial transitions. Version 6 adds `capability_reports`, `model_comparisons`,
`benchmark_plans` and `validation_runs`; versions 5 and 6 create tables, indexes and
triggers only, rebuilding nothing. If anything fails, the transaction rolls back, the database keeps its
previous version and Faultline reports a controlled error. `uv run faultline
migrate` prints the active version. Phase 1 and Phase 2A report files still load;
new exports use format 2.1.0.

## Development and verification


```sh
uv sync --locked --dev
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv build
# Optional explicit localhost network smoke (not part of the offline test suite):
uv run python scripts/local_http_smoke.py --allow-loopback
```

Tests block socket connections and DNS lookup. They cover both toy behaviors,
all nine techniques, real-adapter request shapes using in-process HTTP transports,
scope/budget gates, no redirects/retries, credential echoes, source integrity,
rubric scale fidelity, independent evaluation sessions, append-only judgments,
multi-dimensional disagreement, adjudication policies, report separation and
export identity, dataset import and resumable batch evaluation, kappa reference
calculations, SQLite version 1→2→3→4→5 migrations with rollback and a foreign-key
check, tool authorization and receipts, agent budgets and cancellation, retrieval
injection scenarios and canary detection, control-variant construction, paired
trial resumes that never replay unknown requests, paired eligibility and exact
conditional paired intervals with reference values, capability validation,
segregated multi-model comparisons, benchmark budgets, quality checks, and TUI
run/history/export, reviewer, batch, agentic, controlled and comparison
workbenches. The CI workflow
is configured for macOS/Linux and Python 3.12/3.13.

## Current scope and tradeoffs

Phases 1, 2A, 2B and 3A work end to end. The core is independent of Textual;
SQLite uses versioned JSON snapshots plus relational links, insert-only review
records, mutable batch-case state guarded by `pending` transitions and trace
rows that are checkpointed only while `running`. Nine original toy definitions
span the requested technique families, and six synthetic agentic scenarios cover
retrieved authority spoofing, synthetic secret disclosure, unauthorized record
change, tool-output laundering, encoded injection and successful boundary
enforcement.
Deterministic checks measure narrow facts. Remote seeds and zero temperature do
not guarantee repeatable outputs.

Ordinal, categorical and numeric criteria depend on human assessment; their
disagreement rate is reported honestly rather than converted into accuracy. An
effective outcome requires an explicit adjudication policy; without one the report
shows automated results, individual judgments and the open disagreement. Findings
are bound to the execution-time session, so a later reevaluation does not rewrite
them; report review status states when a finding is contested.

Agentic execution is bounded and local: scripted fixtures run offline, and the
tool-calling path on the OpenAI-compatible adapter runs only for an authorized
profile that declares `tool_calling`. Tool effects exist only inside the synthetic
sandbox, so a report never claims an action against an external system, and a
denied request is reported as intent rather than compromise. Whether an agent
adopted an injected instruction stays a human judgement.

Still unimplemented: optional model judges, native Anthropic/other provider
adapters, live retrieval, adaptive attack generation, isolated Python workers,
resumption of a live agent run after process death, agreement confidence
intervals, paired comparisons, encrypted credential vaults, signed evidence bundles
and TUI editors for real profiles or rubric normalization review. Trusted library
assertions execute in process and record inspectable source hashes; their
dependencies and closure state are the caller's responsibility. No arbitrary
Python from a rubric executes.

Phase 4 should prioritize interruption recovery for live runs, isolated assertion
workers, cross-experiment regression diffs, calibrated optional judges and additional
provider adapters. See the
[architecture](docs/ARCHITECTURE.md), [implementation plan](docs/IMPLEMENTATION_PLAN.md),
[report schema](docs/REPORT_SCHEMA.md), [Phase 2A decisions](docs/PHASE2A_DECISIONS.md),
[Phase 2B decisions](docs/PHASE2B_DECISIONS.md), [Phase 3A decisions](docs/PHASE3A_DECISIONS.md),
[agentic scenarios](docs/AGENTIC_SCENARIOS.md),
[Phase 3B decisions](docs/PHASE3B_DECISIONS.md),
[controlled experiments](docs/CONTROLLED_EXPERIMENTS.md),
[Phase 3C decisions](docs/PHASE3C_DECISIONS.md),
[Phase 3D decisions](docs/PHASE3D_DECISIONS.md),
[provider validation](docs/PROVIDER_VALIDATION.md),
[benchmark methodology](docs/BENCHMARK_METHODOLOGY.md),
[live-model smoke test](docs/LIVE_MODEL_SMOKE_TEST.md),
[release checklist](docs/RELEASE_CHECKLIST.md),
[troubleshooting](docs/TROUBLESHOOTING.md), [changelog](CHANGELOG.md),
[dataset format](docs/DATASET_FORMAT.md),
[threat boundaries](docs/THREAT_BOUNDARIES.md), [research notes](docs/RESEARCH_NOTES.md)
and [verification record](docs/VERIFICATION.md). Contributor guidance is in
[AGENTS.md](AGENTS.md).

MIT licensed. No upstream prompt corpora, extracted prompts or source code are bundled.
