# Phase 1 verification record

Local environment: macOS arm64, Python 3.12.13, uv 0.12.17. Dependencies are pinned
in `uv.lock`. CI is configured for macOS/Linux and Python 3.12/3.13; those remote
jobs have not been run from this workspace.

## Automated checks

- Ruff lint and formatting checks.
- Offline pytest suite: 81 tests passed, with socket connections and DNS lookup blocked by fixture.
- Source distribution and wheel build, including the packaged versioned JSON files.
- Wheel-content smoke verification independent of the editable source import.

Coverage includes secure and deliberately vulnerable fixtures; all nine technique
families; rubric source fidelity/hashes, explicit normalization and ambiguous-input
rejection; scoring, coverage, uncertain/not-applicable outcomes; scope/budget gates;
HTTP redirection/retry suppression, bounded responses, timeouts, malformed bodies
and credential echo redaction; SQLite reopen and append-only overrides; checkpointed
responses on evaluation errors; and working TUI selection/create/import/run,
baseline comparison, criterion evidence, history loading and report export.

## Local application smoke tests

1. CLI vulnerable mock: baseline `SAFE`; attack discloses the exact synthetic
   canary; both attack criteria fail; two explicitly simulated findings; Markdown
   and JSON reports persisted under `.faultline/`.
2. CLI secure mock: both responses `SAFE`, all criteria pass, no findings; both
   report formats exported.
3. Real terminal session: launch Textual, Ctrl+R runs the secure fixture, Ctrl+Q
   exits; a completed experiment is visible through a separate CLI history call.
4. `scripts/local_http_smoke.py --allow-loopback`: bind an ephemeral loopback toy
   server, use the actual HTTP adapter, observe a compliant baseline and exact
   attack disclosure, persist both runs and export reports. No external model,
   credential or hosted endpoint is used.

Generated databases/reports, probe screenshots and build artifacts remain ignored.
No GitHub workflow, hosted provider call or remote publish is implied by these
results. The toy HTTP server is deliberately vulnerable; it is not an LLM and
does not validate attack efficacy against any model.
