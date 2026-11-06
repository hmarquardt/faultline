# Phase 3C architectural decisions

Status: accepted for Phase 3C (real-model integration validation, experimental
correctness, multi-model comparisons and evaluator usability).
Baseline: Phase 3B (`27538b4`).

Phase 1–3B invariants still hold: execution evidence is immutable, evaluation
sessions are independent of execution, review records are append-only, effective
outcomes need an explicit policy, and no report describes a simulated action as an
external one.

## D1. One eligibility predicate gates every paired statistic

`compare.eligibility(trial, experiment, criterion_id)` is the only rule. A trial
qualifies when it is completed, both observations exist, the criterion is scored in
both arms, the rubric definition and generation settings match the experiment, and
execution integrity is verified. Transition counts, the paired difference, the
exact McNemar calculation, the paired interval and the complete-pair denominator all
read that predicate. Excluded trials are reported twice: per criterion
(`excluded_reasons`) and once per experiment (`excluded_trials`), so partial evidence
is visible instead of discarded. Arm failure rates remain descriptive and are
labelled with `descriptive_arm_trials`.

Trace sealing now hashes the finalized snapshot, so `integrity_ok` is meaningful;
a trace whose digest does not match its content is excluded from pairing rather than
silently trusted.

## D2. Paired difference uses an exact conditional interval

`compare.paired_difference_interval(b, c, n)` reports `(b - c) / n` with a two-sided
Clopper–Pearson interval for the discordance probability, mapped to the difference
by `(2θ - 1) · m / n`, where `m = b + c`. The binomial tails are summed exactly and
inverted by bisection, so there is no statistics dependency and the reference values
are reproducible. It is undefined with a reason when `m = 0`, because such data
cannot bound the difference away from zero. Arm Wilson intervals stay separate and
are never presented as a paired interval.

## D3. Configured capabilities are assertions; observed capabilities are evidence

`capabilities.py` probes an authorized endpoint with bounded requests: one plain
completion (system role, token parameter, configured temperature/seed), one synthetic
tool declaration, and one tool-result follow-up carrying a **fabricated** result. The
report keeps `configured` and `observed` side by side with per-feature
`supported | unsupported | unknown`, sanitized request/response evidence hashes, the
observed model identity, usage and finish reasons. A model that returns no tool call
leaves the capability `unknown` — not `supported`, not `unsupported`. Parameters are
never rewritten after a rejection, and a rejection message is surfaced verbatim
(truncated) instead of being swallowed by a broad handler.

An injected in-process transport needs no network opt-in (it cannot open a socket);
anything that would reach a real address requires `allow_network`.

## D4. Validation is a named step protocol, not a boolean

`validation.run_validation` walks authorization, credential resolution, capability
probe, model identity, usage/finish reporting, tool round trip, evidence sanitation,
scenario execution, retrieval delivery, multiturn continuation, tool authorization,
trace evidence, a one-trial controlled experiment, quality checks, and report export.
Each step records `ok | failed | skipped | unknown` with a detail string. Steps that
cannot run are skipped with a reason; a failed capability probe stops the protocol
before any scenario is attempted. When no real credential is available the protocol
is exercised only through an in-process transport and the documentation says which
steps remain unverified.

## D5. Model comparisons are segregated by construction

`plan_model_comparison` creates one independent `ControlledExperiment` per model, so
no code path can pool results. `execute_model_comparison` runs each experiment
separately and rebuilds each entry's summary. Comparability is disclosed as typed
notes: differing settings are `blocking`, differing budgets or trial counts are
`warning`, and a capability that was declared but never observed is a `warning`. No
global score or ranking is computed anywhere.

## D6. Benchmarks are collections of experiments with explicit ceilings

`BenchmarkSuite` is packaged data (`data/benchmarks.v1.json`). `BenchmarkPlan`
requires scenario, trial, request, token, runtime and optional spend ceilings, and
planning rejects any plan whose declared estimate exceeds them. Execution stops at
the first ceiling reached and records `skipped` with the reason; `limit` bounds how
many scenario rows one invocation executes, so a partial run resumes without
replaying completed scenarios. A benchmark report is scenario-level and explicitly
refuses to pool or rank.

## D7. Quality checks advise; they never rewrite results

`quality.py` runs twelve checks: variant-scope equality with the declared
differences, shared frame (task/prompt/tool policy/records), rubric identity,
settings identity, trace integrity, recorded trial order, environment reset (no
reused trace), paired-eligibility consistency, trace/session evidence presence,
injection exposure measurement, eligible-pair count, and provider capability status
for endpoint targets. Findings are classified `blocking | warning | info` and carry
evidence references; they appear in reports next to the observed results.

## D8. Schema version 6 and report format 2.3.0

Version 6 adds four additive tables — `capability_reports`, `model_comparisons`,
`benchmark_plans`, `validation_runs` — with no-delete triggers and guarded lifecycle
updates. No existing table is rebuilt. `ModelComparisonReport` and `BenchmarkReport`
are new 2.3.0 contracts; the experiment, dataset and agentic reports keep 2.1.0 and
the controlled-experiment report keeps 2.2.0 while gaining optional quality,
capability and exclusion fields.

## D9. Known limitations

- No hosted provider was contacted while building this phase; the endpoint path is
  proven through in-process transports.
- Capability probes exercise one tool name; a provider could support tools and still
  refuse that schema.
- Exact conditional intervals are conservative at very small discordance counts.
- Model comparisons are observational: settings differences are disclosed, never
  corrected statistically.
- Benchmarks report per scenario; they do not aggregate a composite score.
