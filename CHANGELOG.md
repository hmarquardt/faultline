# Changelog

All notable changes to Faultline. Versions are workspace builds; the project has not
been published to an index.

## 0.4.0 (Phase 3D — operational validation and release readiness)

### Security
- Real credential-redaction verification (`redaction.py`): the configured secret is
  resolved for scanning only and searched in every retained probe artifact
  (structured and serialized), observation detail, provider error and exported
  document. Findings name locations, never the value. Validation fails on a leak.
- Provider error text, observation details and probe evidence are sanitized before
  storage, including endpoints that echo the credential back.
- HTTP failures are classified (authorization, rate limit, not found, too large,
  server error, context window, tool rejection, token parameter) with actionable
  messages that never embed provider text, so error bodies are still never persisted.

### Statistics
- Paired risk difference now uses Newcombe's MOVER score interval (approximate
  unconditional coverage). The previous exact conditional Clopper–Pearson interval is
  retained as a separately labelled conditional sensitivity interval and is no
  longer presented as unconditional.
- Strict inference identity: a pair enters paired statistics only when the trial
  belongs to the experiment, is completed, carries both observations with present and
  matching rubric-definition and settings digests, has verified trace integrity, has
  scored outcomes in both arms and has no unresolved blocking quality finding.
  Historical records without metadata stay visible as descriptive-only.

### Evidence and reporting
- `verify-report` audits an existing export offline: digest, denominators, transition
  totals, interval bounds, trace references, effect-without-execution claims,
  simulation labelling, orphan judgments/adjudications, credential-shaped strings and
  CSV formula injection. It never contacts a provider.
- Controlled-experiment reports print both intervals with their coverage labels and
  list excluded trials with reasons.

### Operations
- `smoke-plan`/`run-smoke`: bounded, explicitly authorized live-model verification
  with request, token, timeout and estimated-spend ceilings and a printed scope.
- `validate-endpoint` covers authorization, credential presence, capabilities, model
  identity, usage, tool round trip, sanitization, scenario execution, retrieval,
  multiturn, tool authorization, trace integrity, a one-trial experiment, quality and
  export.
- `version`, `doctor`, `verify-report`; package metadata, classifiers, project URLs and
  version 0.4.0.
- Batched session/judgment/adjudication reads removed per-trace query loops in
  comparison, benchmark and experiment reports.
- Offline performance baseline recorded in `docs/VERIFICATION.md`.

### Tests and docs
- 424 offline tests; new suites for redaction, interval reference values, strict
  identity, provider hardening, smoke workflow, report validation, end-to-end
  evaluator workflow and performance.
- New documents: `PHASE3D_DECISIONS.md`, `LIVE_MODEL_SMOKE_TEST.md`,
  `RELEASE_CHECKLIST.md`, `TROUBLESHOOTING.md`, this changelog.

## 0.3.0 (Phase 3C)

- Paired eligibility predicate; exact conditional paired interval (later relabelled).
- Provider capability validation with configured-versus-observed features and the
  `validate-endpoint` protocol.
- Segregated multi-model comparisons, packaged benchmark suites with explicit budgets,
  twelve experimental quality checks, schema version 6 and report format 2.3.0.

## 0.2.0 (Phase 3B)

- Controlled control/attack experiments, paired trials, resumable execution, paired
  statistics, controlled-experiment reports (2.2.0) and schema version 5.

## 0.1.0 (Phases 1–3A)

- Endpoint configuration, synthetic techniques, rubrics, deterministic evaluation,
  human review and adjudication, datasets and batches, agreement statistics,
  instrumented synthetic tools, agentic traces and report formats 2.0.0/2.1.0.
