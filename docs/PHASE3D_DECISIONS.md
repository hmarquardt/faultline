# Phase 3D decisions

Status: accepted for Phase 3D (operational validation, statistical correctness,
evidence security and release readiness). Baseline: Phase 3C (`ad7c5d7`).

## D1. Credential redaction is verified, not asserted

The previous sanitization step called `contains_credential(payload, "")`, which could
never detect anything. `redaction.py` now resolves the configured secret for scanning
only and searches every retained `provider-probe` artifact (structured walk plus
rendered string), every observation detail, every provider error and every exported
document. Findings name locations and counts; the value is never written to SQLite,
reports, logs, exceptions or test output. Validation runs the scan twice — on probe
evidence and on the exported files — and stops the protocol on a leak.

Defence in depth remains: probe evidence is sanitized before storage, provider error
messages are classified without embedding provider text, and the raw response snippet
used for classification is discarded. The scan exists so a future regression is
detected rather than trusted.

## D2. The paired interval states its coverage

Newcombe's MOVER score interval (method 10) is the reported paired-difference
interval: it combines the two arm Wilson intervals with the phi coefficient of the
2×2 paired table and has approximate **unconditional** coverage. The earlier exact
conditional Clopper–Pearson calculation is retained as `conditional_difference_interval`
with `coverage="conditional-exact"` because its coverage conditions on the observed
discordance count; it is a sensitivity analysis, not the headline interval. Zero
discordant pairs keep a MOVER interval (the shared marginal uncertainty, documented as
conservative) while the conditional interval stays undefined with a reason. Intervals
are never described as significance tests, and the exact McNemar calculation is
reported separately with its discordant counts.

## D3. Strict identity is the only inference path

`compare.eligibility` is the single predicate. In strict mode a pair needs a matching
experiment id, a completed trial, both observations, present-and-equal rubric and
settings digests, verified integrity, scored outcomes in both arms and no unresolved
blocking quality finding. Missing metadata excludes with a reason such as
`control-rubric-definition-missing`; nothing is inferred from an absent digest.
`summarize()` receives the current blocking check ids from the service, so a failing
experimental frame contributes no pairs. Historical observations without metadata stay
visible through `strict=False` descriptive summaries and are never silently promoted.

## D4. Provider diagnostics are classified, not echoed

`describe_http_error` maps a status and a sanitized body hint to a category:
authorization, rate limit, not found, too large, server error, context window, tool
rejection or token-parameter rejection. The returned message never contains provider
text, because error bodies are still not persisted; the sanitized body lives only in
the probe evidence artifact. A rejected parameter is never rewritten, no request is
retried, and an endpoint that accepts tool declarations but returns no tool call stays
`unknown`.

## D5. Reports are auditable after the fact

`reportcheck.py` validates an existing export with no provider contact: format version,
origin, export digest, criterion denominators, transition totals, interval bounds and
sample size, coverage mislabelling, simulation labelling, network claims without
opt-in, trace references, effects without execution, session evidence, orphan or
duplicate review records, credential-shaped strings and CSV formula injection. It
never rewrites a document; findings are the audit trail. `verify-report` exposes it
and the end-to-end workflow uses it as a gate.

## D6. Live-model work is bounded and opt-in at four layers

The smoke workflow requires an authorized profile with a scope string, a model inside
`allowed_models`, declared tool calling, `--allow-network`, an explicit authorization
note and an explicit estimated spending ceiling with a per-request estimate. Caps are
absolute (8 requests, 256 output tokens, 60 s) and the plan prints the exact commands.
Nothing runs automatically; there is no background campaign.

## D7. Performance is measured before it is constrained

The suite builds 300 recorded responses, evaluates a batch, generates a report, runs a
three-trial controlled experiment, records judgments from three reviewers, computes
agreement and reopens the database, printing each measurement. Ceilings are deliberately
generous so an order-of-magnitude regression fails while machine variance does not.
Report paths now batch session, judgment and adjudication reads instead of issuing one
query per trace.

## D8. Release without publishing

Version 0.4.0 with classifiers and project URLs, `version` and `doctor` commands, a
changelog and a release checklist. Nothing is published, no repository visibility is
changed and no hosted service is provisioned; publishing remains an explicit operator
decision.

## D9. Known limitations

- No hosted provider was contacted; live validation remains an operator action.
- MOVER is approximate; conditional intervals are conservative and conditional.
- Strict identity excludes legacy observations from inference by design.
- Report validation covers structural and labelling claims, not semantic truth.
- Performance numbers are one local baseline, not a benchmark of other machines.
