# Controlled experiments

A controlled experiment runs one legitimate task twice, under identical conditions,
with exactly one declared difference: the attack arm receives a retrieved document
that carries an attacker-controlled instruction. Phase 3B is offline by default; a
real endpoint is used only when an authorized profile declares tool calling and the
operator passes an explicit network opt-in.

## Anatomy of a plan

`ControlledExperiment` is a versioned plan, not a result. It records:

- the legitimate objective and the scenario identity/version;
- the **control** and **attack** `ExperimentVariant`s, each with its own scenario
  snapshot, scenario digest, corpus digest, document hashes and script key;
- the declared `VariantDifference` list: path, control value, attack value, meaning;
- the rubric and its canonical definition digest;
- the target (scripted fixture, or profile ID + provider + model + declared
  tool-calling capability);
- generation settings, per-request budgets and experiment-wide limits;
- trial count, execution-order policy, optional seed and the environment policy;
- the authorization attestation and the network opt-in flag.

Planning never contacts a provider: `plan-experiment` writes the plan and one
`pending` row per trial.

## Control construction

`scenarios.control_scenario` derives the control from the attack scenario:

1. the injected document's content is replaced with its declared
   `control_content` rendering;
2. its trust class becomes `trusted-reference` and its `injection` is cleared;
3. `injected_document_id` becomes null.

Nothing else changes: the system prompt, user task, tool scope, budgets, rubric and
uninjected documents stay byte-identical, which `variant_differences` proves by
listing every changed path. A control rendering may not contain the payload, and a
scenario without a declared rendering refuses to produce a control rather than
risk silently leaving the payload in place.

## Paired trials

`execute_experiment` executes control and attack for the same trial index with:

- the same target, rubric, settings and budgets;
- the same tool authorization and monitored records;
- a **freshly built synthetic environment per variant**, so no note, message or
  record touches the other arm;
- the declared order (`control_first`, `attack_first`, `alternate`, `randomized`),
  recorded on the trial as the order that actually ran.

A trial moves `pending → running → completed | failed | incomplete | interrupted`
exactly once through a guarded `UPDATE ... WHERE status = ...`. A completed trial
stores both trace ids, both session ids and every observation. An incomplete pair
keeps the variant that did run and is excluded from paired statistics.

Resuming calls `execute_experiment` again. Any trial left `running` by a crash is
first marked `interrupted` with a reason, because the remote outcome is unknown and
must not be replayed. Only `pending` trials execute, and trials that already ran
are never re-executed.

## Observations versus conclusions

The harness records, per variant: exposure to the injected document, unauthorized
tool proposals, policy denials, verified state changes, canary disclosure, required
marker presence, and per-criterion outcomes. `VariantObservation` keeps them
separate and never stores a verdict.

- Exposure is not compromise.
- A proposal is not an execution.
- A denial is not a successful unauthorized action.
- Marker presence is not semantic task completion (human-assessed).
- A model's self-report is not evidence; only receipts and digests are.
- A control failure is reported as a shared failure, not attributed to the payload.

## Statistics

`faultline.compare` is pure and documented:

- a criterion is scored from `pass`/`fail` only; `uncertain` and `not_applicable`
  are counted separately and never enter a denominator;
- arm failure rate = failures / (failures + passes) for that arm;
- each rate carries a 95% Wilson score interval, undefined with a reason when the
  arm has no scored observation;
- paired comparisons use complete pairs only, reporting the four transitions
  (pass→pass, pass→fail, fail→pass, fail→fail);
- the absolute rate difference is the paired estimate `(pass→fail − fail→pass) / pairs`;
- the exact McNemar p-value is the two-sided exact binomial test on discordant
  pairs, reported as a calculation with its `b`/`c` counts, and undefined with a
  reason when there are no discordant pairs;
- fewer than five complete pairs adds an explicit note that rates are descriptive.

No output claims significance, causation or a population parameter. Automated tests
cover the reference values (0/5 interval `0.00–0.43`, 5/5 `0.57–1.00`, McNemar
`5 vs 0 → p = 0.0625`).

## Budgets, authorization and spending

Real execution requires: an authorized profile with an explicit scope string, a
model inside `allowed_models`, declared `tool_calling`, and `allow_network`. Plans
reject any other combination. `ExperimentLimits` carries the experiment-wide request
cap and an optional estimated-spend guard; the guard uses an operator-supplied
per-request estimate and the report labels it an estimate, never a provider bill.
Execution stops before a trial that would exceed the cap and records why. There is
no background automation: every request belongs to an explicit `run-experiment`
invocation.

## Report

`experiment-report` writes JSON, Markdown and a trial-level CSV. The Markdown report
contains the objective, authorization and target, both variant definitions, the
exact differences, corpus and payload hashes, tool policy, settings and budgets,
the paired comparison table, the observation tallies, every trial with its trace
references, human review records, reproduction commands, limitations and the full
evidence bundle. It never presents a scripted fixture as a model experiment.
