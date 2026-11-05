# Faultline

A Python-first, local-first adversarial LLM evaluation workbench for authorized
targets. Execute controlled synthetic techniques, evaluate observable behavior,
review it with versioned rubrics, adjudicate human judgments, and export
reproducible findings with evidence. Current scope: Phase 1 plus Phase 2A.

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
- Ctrl+J: append the entered human judgment to the selected criterion.
- Ctrl+A: adjudicate the selected session with the chosen policy.
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

## Databases and migrations

State opens at SQLite schema version 2. A version 1 database is migrated in one
transaction that preserves every row, ID and snapshot; the migration derives one
`migration`-origin session per run that already carried evaluations. If anything
fails, the transaction rolls back, the database stays at version 1 and Faultline
reports a controlled error. `uv run faultline migrate` prints the active version.
Phase 1 report files still load and can be re-exported as format 2.0.0.

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
adjudication policies, report separation and export identity, SQLite version 1→2
migration with rollback, and TUI run/history/export plus the reviewer workbench.
The CI workflow is configured for macOS/Linux and Python 3.12/3.13.

## Current scope and tradeoffs

Phase 1 and Phase 2A work end to end. The core is independent of Textual; SQLite
uses versioned JSON snapshots plus relational links and insert-only review
records. Nine original toy definitions span the requested technique families.
Deterministic checks measure narrow facts. Remote seeds and zero temperature do
not guarantee repeatable outputs.

Ordinal, categorical and numeric criteria depend on human assessment; their
disagreement rate is reported honestly rather than converted into accuracy. An
effective outcome requires an explicit adjudication policy; without one the report
shows automated results, individual judgments and the open disagreement. Findings
are bound to the execution-time session, so a later reevaluation does not rewrite
them; report review status states when a finding is contested.

Still unimplemented: optional model judges, native Anthropic/other provider
adapters, live retrieval, adaptive multiturn generation, actual agent-tool
execution, isolated Python workers, batch statistics, agreement statistics,
cancellation/resumption, encrypted credential vaults, signed evidence bundles and
TUI editors for real profiles or rubric normalization review. Trusted library
assertions execute in process and record inspectable source hashes; their
dependencies and closure state are the caller's responsibility. No arbitrary
Python from a rubric executes.

Phase 2B should prioritize interruption recovery, isolated assertions and
instrumented toy tool receipts, then provider capability handling, calibrated
optional judges and agreement statistics. See the
[architecture](docs/ARCHITECTURE.md), [implementation plan](docs/IMPLEMENTATION_PLAN.md),
[report schema](docs/REPORT_SCHEMA.md), [Phase 2A decisions](docs/PHASE2A_DECISIONS.md),
[threat boundaries](docs/THREAT_BOUNDARIES.md), [research notes](docs/RESEARCH_NOTES.md)
and [verification record](docs/VERIFICATION.md). Contributor guidance is in
[AGENTS.md](AGENTS.md).

MIT licensed. No upstream prompt corpora, extracted prompts or source code are bundled.
