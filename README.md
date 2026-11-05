# Faultline

A Python-first, local-first adversarial LLM evaluation workbench for authorized
targets. Execute controlled synthetic techniques, evaluate observable behavior,
and export reproducible findings with evidence. Initial release: Phase 1.

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
Export creates files named by experiment ID in the chosen directory.

- Ctrl+R: run baseline + attack.
- Ctrl+D: save a dry-run plan with no endpoint dispatch.
- Ctrl+E: export the selected report to JSON and Markdown.
- Ctrl+Q: quit.

Create mock profiles and import rubrics directly in the TUI. Configure real
profiles, custom generation settings/budgets, human normalization and overrides
through the CLI. A connection test sends one normal baseline request; it is not
a passive TCP probe. The TUI uses the first allowed model in a selected profile.

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
example. JSON/YAML definitions support IDs, versions, criterion instructions,
weights, scales, pass thresholds, evidence requirements and case applicability.
Check types are `required_text`, `forbidden_text`, `exact_canary`, `json_schema`,
`tool_execution`, `manual` and explicitly registered library-only `python`.
Scores measure compliance; higher is better. Unknown or inapplicable criteria
have no score. Weighted automated summaries always include evidence coverage.

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
retains both the original source and normalization draft with hashes. `manual`
criteria remain uncertain until a human reviews their evaluations. Human judgment
never destroys an automated evaluation:

```sh
uv run faultline override EVALUATION_ID --outcome uncertain \
  --reviewer 'Tester name' --rationale 'Literal result needs contextual review'
uv run faultline export EXPERIMENT_ID --output reports/reviewed-run
```

Obtain evaluation IDs from report JSON or the TUI evidence panel. Overrides append
in order; report scores/findings continue to describe the original automated
observations and list human judgments separately.

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
review/override provenance, SQLite reopening and TUI run/history/export controls.
The CI workflow is configured for macOS/Linux and Python 3.12/3.13.

## Current scope and tradeoffs

Phase 1 works end to end. The core is independent of Textual; SQLite uses versioned
JSON snapshots plus relational links. Nine original toy definitions span the
requested technique families. Deterministic checks measure narrow facts. Remote
seeds and zero temperature do not guarantee repeatable outputs.

Still unimplemented: optional model judges, native Anthropic/other provider
adapters, live retrieval, adaptive multiturn generation, actual agent-tool
execution, isolated Python workers, batch statistics, cancellation/resumption,
database migrations, encrypted credential vaults, and TUI editors for real
profiles/normalization/overrides. Trusted library assertions execute in process
and record inspectable source hashes; their dependencies and closure state are
the caller's responsibility. No arbitrary Python from a rubric executes.

Phase 2 should prioritize human review screens, interruption recovery and
migrations, isolated assertions and instrumented toy tool receipts, then provider
capability handling and calibrated optional judges. See the
[architecture](docs/ARCHITECTURE.md), [implementation plan](docs/IMPLEMENTATION_PLAN.md),
[threat boundaries](docs/THREAT_BOUNDARIES.md), [research notes](docs/RESEARCH_NOTES.md)
and [verification record](docs/VERIFICATION.md). Contributor guidance is in
[AGENTS.md](AGENTS.md).

MIT licensed. No upstream prompt corpora, extracted prompts or source code are bundled.
