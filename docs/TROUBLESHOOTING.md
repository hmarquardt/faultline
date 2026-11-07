# Troubleshooting

Start with `uv run faultline version` and `uv run faultline doctor --json`. Neither
reads a credential value, and both are safe to paste into a report.

## Installation and startup

**`faultline: command not found`** — run through uv (`uv run faultline ...`) or activate
the environment (`uv sync --dev`).

**`ImportError` for `textual`, `pydantic` or `httpx`** — the environment is stale:
`uv sync --locked --dev`. Faultline requires Python 3.12 or newer.

**`doctor` reports `package-version-unresolved`** — the package is imported from a
source tree without installed metadata; run `uv sync` again.

**`doctor` reports `foreign-key-violation` or `database-integrity-check-failed`** — stop
writing to that database, copy it aside and restore from a backup. Never delete rows to
"fix" a check failure; review records and traces are append-only by design.

## Database and migrations

**`Database migration failed; the previous schema version was retained`** — the
migration rolled back and the file is unchanged. Copy the database, then report the
version it started from (`faultline migrate` prints the active version).

**`doctor` reports `schema-version-mismatch`** — the installed build expects a different
schema than the file holds; use the build that matches the database or migrate
deliberately with `faultline migrate`.

**A report destination exists** — exports never overwrite: choose a new `--output`
prefix.

## Endpoints and credentials

**`Credential environment variable is unset or empty`** — export the variable named in
the profile. The value is read only for the request (and, in validation, for scanning);
it is never stored.

**`HTTP 401/403: authorization rejected`** — the credential is wrong, expired or lacks
access to that model. Verify `allowed_models` and the scope string on the profile.

**`HTTP 429: endpoint rate limit or quota reached`** — Faultline does not retry. Wait,
then run the command again deliberately.

**`HTTP 400: context window or token budget exceeded`** — reduce the scenario, the
budget or `--max-output-tokens`.

**`HTTP 400: token-limit parameter rejected`** — the endpoint wants
`max_completion_tokens` instead of `max_tokens` (or the reverse). Change
`token_parameter` on the profile; Faultline never rewrites it for you.

**`Endpoint profile does not declare tool-calling capability`** — set
`tool_calling` on the profile only if the endpoint really supports tools; otherwise
experiments cannot represent that endpoint.

**`Missing capability: tool_calls unknown`** — the endpoint accepted the tool
declaration but returned no tool call, so support is unproven. Check the model, the
tool schema and the prompt; treat it as untested.

**`Real endpoint execution requires explicit network opt-in`** — add `--allow-network`
and, for experiments, the plan-level `allow_network` flag. This is deliberate.

## Experiments and statistics

**`complete_pairs` is 0 with completed trials** — inspect `excluded_trials`: strict
inference requires matching rubric and settings digests, verified integrity and no
blocking quality finding. `faultline experiment-quality <id>` lists the reason.

**`Paired difference interval is undefined`** — with no eligible pair or no discordant
pairs the conditional sensitivity interval cannot bound anything; the MOVER interval
remains available and no inference should be drawn from one or two pairs.

**Rates look extreme** — with fewer than five eligible pairs every rate is descriptive.
Add trials or report the interval instead of a conclusion.

**`Experiment is missing or already finalized`** — a completed experiment is immutable.
Plan a new one; only `planned`, `running`, `partial`, `failed` and `cancelled` plans
accept lifecycle updates.

## Reports and evidence

**`verify-report` reports `digest-mismatch`** — the JSON was edited after export. Do not
trust it; re-export from the database.

**`verify-report` reports `csv-formula-injection`** — a cell begins with `=`, `+`, `-`
or `@`. Faultline prefixes such cells with an apostrophe on export; a file that fails
this check was produced or edited elsewhere.

**`verify-report` reports `simulation-labelling-missing`** — a synthetic report must say
it is simulated. Re-export with the current build.

**`credential-pattern`** — a string shaped like a credential appears in the export. Do
not share it; re-run the workflow with the current build (which sanitizes) and report
the case.

## TUI

**A tab looks empty at 100x30** — widgets are scrollable; use Tab/Shift+Tab to reach
them and Enter to activate. The Controlled tab's trace panes scroll independently.

**`Export failed`** — the destination already holds a report with that name, or the
directory is not writable. Choose another directory.

**Nothing happens on Ctrl+R** — no experiment is selected, or a profile is out of
scope; the status line states the reason.

## When opening an issue

Include `faultline version` output, `faultline doctor --json`, the exact command, the
controlled error message and the commit you ran. Never include a credential value, and
prefer exporting a sanitized report over pasting raw database rows.
