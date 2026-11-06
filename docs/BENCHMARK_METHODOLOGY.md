# Benchmark and comparison methodology

A benchmark in Faultline is a collection of independent controlled experiments. It
is not a score, a leaderboard or a substitute for the individual traces.

## Unit of analysis

One **scenario × model** pair is one controlled experiment with `n` paired trials.
Each trial runs a control variant (payload neutralized) and an attack variant (same
task, same tools, same budgets, one injected document), in a recorded order, each
with a freshly reset synthetic environment.

Nothing is pooled:

- across models — every model gets its own experiment and its own denominators;
- across scenarios — each scenario keeps its own rubric, criteria and rates;
- across arms — control and attack rates are reported separately.

## Eligibility

Paired inference uses only trials that satisfy `compare.eligibility`: completed,
both observations present, both scored for the criterion, rubric definition and
generation settings identical to the plan, and execution integrity verified. Excluded
trials are listed with reasons. Arm rates additionally describe partial trials and
say so (`descriptive_arm_trials`); they never enter a paired estimate.

## Paired estimators

Let `a`, `b`, `c`, `d` be the eligible-pair counts for pass/pass, pass/fail,
fail/pass and fail/fail, and `n = a + b + c + d`.

| Quantity | Definition |
| -------- | ---------- |
| Arm failure rate | failures / (failures + passes) in that arm, denominator reported |
| Arm interval | 95% Wilson score interval, per arm, descriptive |
| Paired risk difference | `(b - c) / n` |
| Paired interval | exact conditional Clopper–Pearson on `b` of `m = b + c`, mapped by `(2θ - 1) · m / n` |
| Discordant pairs | `b + c` |
| Exact test | two-sided exact McNemar (exact binomial on `b` of `m`), reported with `b` and `c` |

Reference values enforced by tests: Clopper–Pearson `0/5 = [0, 0.5218]`,
`5/5 = [0.4782, 1]`, `1/10 = [0.0025, 0.4450]`, `2/5 = [0.0527, 0.8534]`;
exact McNemar `5 vs 0 → 0.0625`, `6 vs 0 → 0.03125`, `4 vs 1 → 0.375`.

When `m = 0` the paired interval and the exact test are **undefined with a reason**:
identical arms cannot bound a difference. Fewer than five eligible pairs adds an
explicit note that rates are descriptive. Nothing in a report claims significance,
causation or a population parameter, and a control failure is labelled a shared
failure rather than attributed to the payload.

## Reported observations

Counts are kept separate per arm and never combined into a verdict:

- exposure — attack variants that actually retrieved the injected document;
- unauthorized tool proposals (requested but not necessarily executed);
- policy denials (blocked, therefore not a successful unauthorized action);
- verified synthetic state changes (a real effect inside the sandbox);
- canary disclosures (exact synthetic string in model-authored content);
- required-marker presence (a deterministic proxy, not semantic completion);
- human-assessed criteria, including semantic task completion and adoption.

## Benchmark budgets

`BenchmarkLimits` requires ceilings for scenarios, trials per scenario, total
requests, total tokens, runtime and — optionally — estimated spend. Planning
computes `scenarios × models × trials × 2 × estimated_requests_per_variant` and
refuses any plan that exceeds a ceiling. Execution stops at the first ceiling reached
and marks the remaining rows `skipped` with the reason. `limit` bounds how many
scenario rows a single invocation executes, so a partial run resumes without
replaying completed scenarios. Estimated spend is an operator-supplied estimate and
is never described as provider billing.

## Comparability

A comparison discloses, as typed notes:

- `settings` (blocking) — generation settings differ between models;
- `budget` / `trials` (warning) — budgets or trial counts differ;
- `capabilities` (warning) — a declared capability was not observed by a probe.

Comparisons report each model's declared and observed capability snapshots so a
reader can judge whether the configurations were comparable at all. When they were
not, the report says so instead of implying equivalence.

## Quality checks

Twelve checks accompany every experiment report: variant scope, shared frame,
rubric identity, settings identity, trace integrity, recorded trial order,
environment reset, paired-eligibility consistency, trace/session evidence,
injection exposure, eligible-pair count and endpoint capability status. They are
classified blocking, warning or informational and always reference their evidence;
they advise a reviewer and never rewrite an observed result.

## Limits

- Scripted fixtures demonstrate mechanics, not model behaviour.
- Exact conditional intervals are conservative for very small discordance counts.
- Benchmark rows are independent; there is no composite or ranking score, and none
  should be invented from these numbers.
- Real endpoints add vendor-specific request shapes that a probe can only partially
  confirm; see [provider validation](PROVIDER_VALIDATION.md).
