# Phase 3B architectural decisions

Status: accepted for Phase 3B (controlled real-model experiments, paired
comparisons, repeatability analysis and evidence-based reporting).
Baseline: Phase 3A (`117a111`).

Phase 1–3A invariants still hold: execution evidence is immutable, evaluation
sessions are independent of execution, review records are append-only, effective
outcomes need an explicit policy, and no report describes a simulated action as an
external one.

## D1. A control is a derived variant, not a second scenario

A control is built from the attack scenario by neutralizing exactly one injected
document: content replaced with its declared `control_content`, trust reset to
`trusted-reference`, payload cleared, `injected_document_id` removed. Everything
else — task, system prompt, tool scope, budgets, rubric, monitoring — is shared by
construction, and `variant_differences` enumerates the changed paths with hashes.
A scenario without a declared control rendering refuses to yield a control rather
than risk leaving the payload in place.

## D2. Trials are guarded, resumable and never replayed blindly

`paired_trials` rows move `pending → running → completed | failed | incomplete |
interrupted` exactly once through a compare-and-set `UPDATE`. Each variant receives
a freshly constructed `SyntheticEnvironment`, so mutable tool state never crosses an
arm or a trial. Resuming marks any still-`running` trial `interrupted` because a
process death leaves the remote status unknown: Phase 3B never re-dispatches such a
request. Completed traces and sessions stay stored and reevaluable.

## D3. Observations are stored; verdicts are not

`VariantObservation` records exposure, unauthorized proposals, denials, verified
state changes, canary disclosure, marker presence and per-criterion outcomes. It has
no verdict field, so a report cannot present a proxy as a finding. Adoption and
semantic task completion remain human assessments; the deterministic
`agent_task_completed` check is labelled a required-marker proxy everywhere.

## D4. Statistics stay descriptive and recomputable

`faultline.compare` is pure. Rates use `pass`/`fail` only, with explicit
denominators; `uncertain` and `not_applicable` are counted separately. Intervals are
95% Wilson scores per arm. Paired comparisons use complete pairs only and report the
four transitions; the difference is `(b − c) / pairs`; the exact McNemar p-value is
the two-sided exact binomial test with its discordant counts. Fewer than five pairs
produces an explicit descriptive-only note. Nothing claims significance or causation.

## D5. Real execution is opt-in twice

An endpoint experiment needs an authorized profile with a scope string, a model
inside `allowed_models`, `tool_calling=True`, and `allow_network=True`; the CLI also
requires `--allow-network` at run time. Planned requests must fit
`ExperimentLimits.max_total_requests` using the declared per-variant estimate, and an
optional estimated-spend guard rejects plans whose estimate exceeds the limit. The
report labels spending as an estimate, never a bill. Providers without declared tool
calling are rejected instead of having tool behaviour fabricated for them.

## D6. Schema version 5

Two additive tables: `controlled_experiments` (plan snapshot, status, plan digest)
and `paired_trials` (per-trial snapshot with a guarded status transition). Both are
protected by no-delete triggers; experiments update only while
`planned|running|partial|failed|cancelled`, so a completed plan is never rewritten.
The v4→v5 migration creates tables, indexes and triggers only — no table rebuild —
so Phase 1–3A rows, snapshots and IDs are untouched. Report format 2.2.0 is a new
contract; existing `Report`, `BatchReport` and `AgenticReport` documents stay 2.1.0.

## D7. Known limitations

- Real-endpoint behaviour is exercised through an in-process transport; no hosted
  provider was contacted while building this phase.
- Scripted fixtures demonstrate the mechanics; they are not evidence about a model.
- Provider seeds are advisory settings; identical output is not guaranteed.
- Five or fewer pairs cannot support inference, and the small-sample note says so.
- A cancelled or interrupted trial is not resumed automatically; the operator
  resumes explicitly and the interrupted trial stays excluded.
