# Verification record

## Phase 3D (current)

Local environment: macOS arm64, Python 3.12.13, uv 0.12.x, Textual 6.12,
Pydantic 2.14, SQLite 3.50.4, package version 0.4.0. CI is configured for
macOS/Linux and Python 3.12/3.13; a remote run is reported only when inspected.

### Automated checks

- `uv run ruff check .` and `uv run ruff format --check .`: clean (89 files).
- `uv run pytest -q`: 424 tests, fully offline (socket connect/connect_ex and DNS
  lookup raise inside every test; provider paths use in-process transports).
- `uv build`: `faultline_workbench-0.4.0.tar.gz` and `.whl`, containing
  `redaction.py`, `reportcheck.py`, `smoke.py`, `release.py` and the packaged
  scenario, benchmark, technique and rubric assets.
- `uv run python scripts/evaluator_workflow.py --output /tmp/wf`: 12 steps, ends with
  `verify-report origin=controlled_experiment errors=0 checks=13` and
  `reopen-and-verify ... judgments=4 digest=ok`.
- GitHub Actions run `42320583836` for commit `7b493c9` completed with
  `conclusion=success`; `gh run view --json jobs` reported `success` for
  `verify (macos-latest, 3.12)`, `verify (macos-latest, 3.13)`,
  `verify (ubuntu-latest, 3.12)` and `verify (ubuntu-latest, 3.13)`. Inspected, not
  assumed.

### Required proofs (Phase 3D)

| Requirement | Test |
| --- | --- |
| Credential leaks are detected and redacted | `tests/test_redaction.py::test_verify_redaction_detects_a_planted_secret_without_revealing_it`, `...::test_probe_response_echo_is_redacted_before_storage`, `...::test_provider_error_text_is_redacted` |
| Sanitized reports contain no secret values | `...::test_exported_reports_contain_no_credential`, `tests/test_reportcheck.py::test_credential_shaped_string_is_detected_without_echo` |
| Paired interval semantics are statistically correct | `tests/test_intervals.py` (MOVER reference derivation, asymptotic agreement with the paired Wald interval, antisymmetry, coverage labels) |
| Zero-discordance cases are handled appropriately | `...::test_all_concordant_pairs_use_marginal_uncertainty` |
| Missing identity hashes exclude pairs | `tests/test_strict_identity.py::test_missing_rubric_digest_excludes_the_pair`, `...::test_missing_settings_digest_excludes_the_pair` |
| Invalid integrity evidence excludes pairs | `...::test_integrity_failure_excludes_the_pair`, `...::test_inconsistent_digests_exclude_the_pair` |
| Historical records remain readable | `...::test_historical_observations_without_metadata_are_descriptive_only`, `tests/test_migration.py` |
| Provider errors are actionable and sanitized | `tests/test_provider_hardening.py` (ten classifications, no retry, no parameter rewrite) |
| Real-provider behavior is simulated accurately offline | `tests/test_provider_hardening.py`, `tests/test_validation.py`, `tests/test_smoke.py` |
| A complete professional evaluation workflow succeeds | `tests/test_workflow_e2e.py` |
| Human judgments survive database reopen | `...::test_the_documented_workflow_completes_and_verifies` |
| Adjudication remains explicit and append-only | `...::test_workflow_reports_a_disagreement_and_an_explicit_resolution` |
| Report validation detects unsupported claims | `tests/test_reportcheck.py` (digest, denominators, transitions, intervals, traces, effects, labelling, network claims, orphans, secrets, CSV) |
| CSV formula injection protection remains intact | `tests/test_reportcheck.py::test_neutralised_csv_is_accepted`, `...::test_csv_formula_injection_is_detected` |
| Interrupted batches and experiments preserve evidence | `tests/test_batch.py`, `tests/test_experiments.py::test_interrupted_execution_keeps_completed_evidence` |
| Performance tests produce reproducible measurements | `tests/test_performance.py` (prints every measurement) |
| All Textual tabs remain usable | `tests/test_tui.py::test_every_tab_is_usable_at_common_terminal_sizes` (100x30, 120x40, 150x60) |
| Existing tests remain green | full suite, 424 passing |

### Local performance baseline

`uv run pytest tests/test_performance.py -q -s` on the environment above:

| Measurement | Result |
| --- | --- |
| Import 300 recorded responses | 0.01 s |
| Batch evaluation (default 200-case budget) | 0.38 s (~800 cases/s) |
| Batch report generation | 0.66 s |
| Controlled experiment, 3 paired trials (scripted) | 0.08 s |
| Experiment summary | 0.004 s |
| Controlled-experiment report | 0.02 s |
| Agreement over 3 reviewers | 0.001 s |
| Database reopen | 0.001 s |
| Database size after the batch fixture | 1.8 MiB |

These are one local baseline, not a cross-machine benchmark. Test ceilings are
deliberately loose (10-60 s) so an order-of-magnitude regression fails while ordinary
variance does not.

### Local smoke tests

1. `version`, `doctor --json`, `verify-report` on a controlled-experiment export.
2. `demo` → `run-scenario` → `plan-comparison`/`run-comparison`/`comparison-report`
   → `plan-benchmark`/`run-benchmark`/`benchmark-report` → `verify-report`.
3. `smoke-plan` refusal paths (no authorization note, no network opt-in, no spending
   ceiling, caps above the smoke limits) and the offline `run-smoke` path through an
   in-process transport.
4. Textual: every tab at 100x30, 120x40 and 150x60; Controlled tab validation, run,
   side-by-side traces, comparison and export; Ctrl+E follows the active tab.

### Not verified

No hosted provider or real credential was used. Live-model validation, real model
identity strings, vendor tool schemas, rate limits, billing and whether a hosted model
calls the synthetic tools remain unverified; see
[live-model smoke test](LIVE_MODEL_SMOKE_TEST.md) and
[provider validation](PROVIDER_VALIDATION.md). Statistical output is descriptive at
small samples; MOVER intervals are approximate and the conditional interval is
conservative and conditional. No release was published.

## Phase 3C (historical)

Local environment: macOS arm64, Python 3.12.13, uv 0.12.x, Textual 6.12,
Pydantic 2.14. CI is configured for macOS/Linux and Python 3.12/3.13; a remote run
is reported only when it was actually inspected.

### Automated checks

- `uv run ruff check .`
- `uv run ruff format --check .`
- `uv run pytest -q`: 343 tests, fully offline (socket connect/connect_ex and DNS
  lookup raise inside every test; provider paths use in-process transports).
- `uv build`: sdist and wheel including `capabilities.py`, `quality.py`,
  `benchmark.py`, `validation.py` and `data/benchmarks.v1.json`.
- GitHub Actions run `42297998880` for commit `ae9a4b0` completed with
  `conclusion=success`; `gh run view --json jobs` reported `success` for
  `verify (macos-latest, 3.12)`, `verify (macos-latest, 3.13)`,
  `verify (ubuntu-latest, 3.12)` and `verify (ubuntu-latest, 3.13)`. Inspected, not
  assumed.

### Required proofs (Phase 3C)

| Requirement | Test |
| --- | --- |
| Only completed eligible pairs enter paired inference | `tests/test_eligibility.py` (completed pair, interrupted, failed, incomplete, missing observation, mixed sample) |
| Partial arm observations remain visible | `...::test_non_completed_trial_with_both_observations_is_excluded`, `...::test_mixed_complete_and_incomplete_samples_preserve_denominators` |
| Paired confidence intervals match references | `...::test_clopper_pearson_matches_published_reference_values`, `...::test_paired_interval_reference_examples`, `...::test_reference_calculations_for_transitions_and_mcnemar` |
| Capability validation distinguishes supported/unsupported/unknown | `tests/test_capabilities.py` (supporting, rejecting and silent endpoints) |
| Tool-calling capability tests use synthetic tools only | `...::test_supported_endpoint_records_observed_features` (fabricated tool result) |
| Provider error evidence is sanitized | `...::test_probe_evidence_is_sanitized`, `...::test_chat_rejection_distinguishes_parameter_problems` |
| The same benchmark can run across two scripted models | `tests/test_multimodel.py::test_benchmark_plans_every_scenario_and_model`, `tests/test_cli.py::test_cli_validation_comparison_and_benchmark_surface` |
| Model results stay segregated | `...::test_results_stay_segregated_per_model`, `...::test_comparison_creates_one_experiment_per_model` |
| Differences in model settings are disclosed | `...::test_non_comparable_settings_are_reported_not_hidden`, `...::test_capability_gaps_are_disclosed_as_notes` |
| Benchmark-wide budgets are enforced | `...::test_benchmark_budgets_are_enforced_at_planning`, `...::test_benchmark_resumes_without_replaying_completed_scenarios` |
| Quality-control checks detect variant mismatches | `...::test_quality_detects_variant_and_policy_mismatches`, `...::test_quality_flags_undeclared_variant_differences`, `...::test_quality_flags_missing_trace_evidence` |
| Injection exposure is measured, not assumed | `...::test_quality_checks_pass_for_a_clean_experiment` (`injection-exposure` check), `tests/test_compare.py::test_observation_tallies_keep_arms_separate` |
| Side-by-side traces preserve complete evidence | `tests/test_tui.py::test_controlled_tab_shows_side_by_side_traces_and_comparison` |
| Existing human review and adjudication still work | `tests/test_review_flow.py`, `tests/test_agentic_flow.py::test_judgments_and_adjudication_work_on_agentic_sessions` |
| Existing reports remain readable | `tests/test_workbench.py`, `tests/test_batch_reports.py`, `tests/test_agentic_flow.py::test_agentic_report_separates_simulation_from_observation` |
| Historical database migrations preserve data | `tests/test_migration.py` (v1→v6 chain, v4→v5 and v5→v6 additive migrations, foreign-key check) |
| CLI and TUI work without hosted credentials | `tests/test_cli.py::test_cli_validation_comparison_and_benchmark_surface`, `tests/test_tui.py` (Controlled tab) |
| All previous tests remain green | full suite, 343 passing |

### Endpoint validation coverage

`tests/test_validation.py` exercises the documented protocol through
`httpx.MockTransport`: authorization failure without probing, unresolved credential,
capability failure that stops before scenario execution, a full run with export, a
run without an export prefix, and proof that the probe never executes a tool. No
hosted credential or endpoint was contacted.

### Local smoke tests

1. `capabilities`/`validate-endpoint` through an in-process compatible transport.
2. `plan-comparison` → `run-comparison` → `comparison-report` (JSON/Markdown/CSV).
3. `plan-benchmark` → `run-benchmark` → `benchmark-status` → `benchmark-report`.
4. `experiment-quality` on a completed experiment.
5. Textual Controlled tab at 100x30: plan, run, side-by-side traces, comparison plan
   and run, export.

### Not verified

No hosted provider or real credential was used. Live-model validation, real model
identity strings, vendor tool-call schemas, rate limits, billing and whether a hosted
model actually calls the synthetic tools remain unverified; see
[provider validation](PROVIDER_VALIDATION.md). Statistical output is descriptive for
small samples and no significance or causation claim is made.

## Phase 3B (historical)

Local environment: macOS arm64, Python 3.12.13, uv 0.12.x, Textual 6.12,
Pydantic 2.14. CI is configured for macOS/Linux and Python 3.12/3.13; a remote run
is only reported when it was actually inspected (see below).

### Automated checks

- `uv run ruff check .`
- `uv run ruff format --check .`
- `uv run pytest -q`: 298 tests, fully offline (socket connect/connect_ex and DNS
  lookup raise inside every test; the only HTTP paths use in-process transports).
- `uv build`: sdist and wheel including `compare.py` and the updated packaged
  scenario data.
- GitHub Actions run `42283147300` for commit `e423e44` completed with
  `conclusion=success`; `gh run view --json jobs` reported `success` for
  `verify (macos-latest, 3.12)`, `verify (macos-latest, 3.13)`,
  `verify (ubuntu-latest, 3.12)` and `verify (ubuntu-latest, 3.13)`. Inspected,
  not assumed.

### Required proofs (Phase 3B)

| Requirement | Test |
| --- | --- |
| Missing protected-record evidence returns uncertain | `tests/test_agentic_eval.py::test_protected_record_check_needs_both_digests`, `...::test_protected_record_check_passes_when_digests_match_and_fails_when_they_differ` |
| Marker presence is not called verified semantic completion | `...::test_marker_presence_is_not_semantic_completion`, `...::test_agentic_result_reports_marker_basis_and_exposure` |
| Protected records are not implicitly writable | `tests/test_tooling.py::test_initial_records_are_not_implicitly_writable`, `...::test_scenario_separates_initial_monitored_and_writable_records` |
| Control and attack differ only where declared | `tests/test_variants.py::test_control_removes_only_the_injected_payload`, `...::test_variant_pair_declares_every_difference_with_hashes` |
| Each variant starts from an identical, independent environment | `tests/test_experiments.py::test_each_variant_starts_from_an_independent_environment` |
| A secure scripted model resists the injection | `...::test_secure_scripted_fixture_resists_the_injection` |
| A vulnerable scripted model behaves differently under attack | `...::test_vulnerable_scripted_fixture_behaves_differently_under_attack` |
| Unauthorized proposals are not counted as executed actions | `...::test_vulnerable_scripted_fixture_behaves_differently_under_attack`, `tests/test_compare.py::test_observation_tallies_keep_arms_separate` |
| Denied actions produce no state change | `...::test_protected_records_are_never_implicitly_writable_in_experiments` |
| Paired comparisons preserve all raw observations | `tests/test_compare.py::test_paired_summary_counts_denominators_and_transitions`, `...::test_flatten_preserves_raw_per_trial_observations` |
| Repeated trials report accurate denominators | `...::test_uncertain_and_not_applicable_are_separate_from_rates`, `tests/test_experiments.py::test_secure_scripted_fixture_resists_the_injection` |
| Incomplete pairs are excluded from paired statistics | `tests/test_compare.py::test_incomplete_pairs_are_excluded_and_counted` |
| Control failures are not attributed to injection | `...::test_control_failure_is_reported_as_shared_failure` |
| Interrupted runs preserve completed evidence | `tests/test_experiments.py::test_interrupted_execution_keeps_completed_evidence` |
| Resume never replays an unknown-status remote request | `...::test_resume_runs_only_pending_trials_and_never_replays_running_ones` |
| Reports preserve variant hashes and trace references | `...::test_report_preserves_hashes_traces_and_uncertainty` |
| Reevaluation of stored traces never contacts a provider | `...::test_reevaluation_of_experiment_traces_is_offline` |
| Existing Phase 1–3A workflows remain functional | `tests/test_workbench.py`, `tests/test_sessions.py`, `tests/test_batch.py`, `tests/test_agentic_flow.py`, `tests/test_tui.py`, `tests/test_cli.py` |
| Database migrations preserve all historical records | `tests/test_migration.py` (v1→v5 chain, v4→v5 additive migration, foreign-key check) |
| CLI and TUI operate without a real hosted provider | `tests/test_cli.py::test_cli_controlled_experiment_workflow`, `tests/test_tui.py::test_controlled_tab_plans_runs_and_exports` |

### Local smoke tests

1. `controlled-scenarios` → `plan-experiment --trials 2` → `experiments` →
   `run-experiment` → `experiment-status` → `experiment-summary` →
   `experiment-report` (JSON/Markdown/CSV).
2. Textual Controlled tab at 100x30: plan, run, criterion comparison, trial detail,
   export.
3. The Phase 3A agentic workflows and the Phase 1 demo still run unchanged.

### Not verified

Remote CI, hosted providers, real model endpoints, real tool execution and any
inference beyond these trials. Real-endpoint experiments were exercised only through
in-process HTTP transports; no hosted model was contacted.

## Phase 3A (historical)

Local environment: macOS arm64, Python 3.12.13, uv 0.12.x, Textual 6.12,
Pydantic 2.14. CI is configured for macOS/Linux and Python 3.12/3.13; a remote run
is only reported when it was actually inspected (see below).

### Automated checks

- `uv run ruff check .`
- `uv run ruff format --check .`
- `uv run pytest -q`: 253 tests, fully offline (socket connect/connect_ex and DNS
  lookup raise inside every test).
- `uv build`: sdist and wheel including `tooling.py`, `agents.py`, `scenarios.py`,
  `agentic_eval.py` and `data/scenarios.v1.json`.
- GitHub Actions run `42244123576` for commit `cad9b6d` completed with
  `conclusion=success`; `gh run view --json jobs` reported `success` for
  `verify (macos-latest, 3.12)`, `verify (macos-latest, 3.13)`,
  `verify (ubuntu-latest, 3.12)` and `verify (ubuntu-latest, 3.13)`. The result was
  inspected, not assumed.

### Required proofs (Phase 3A)

| Requirement | Test |
| --- | --- |
| Secure scripted agent ignores an injected instruction | `tests/test_scenarios.py::test_secure_agent_passes_and_vulnerable_agent_fails`, `tests/test_agent_loop.py::test_retrieved_content_never_becomes_a_system_instruction` |
| Vulnerable scripted agent requests an unauthorized synthetic action | `tests/test_scenarios.py` (spoof, record-change and encoded families) |
| Policy blocks a forbidden action and records the decision | `tests/test_tooling.py::test_policy_denies_tools_outside_the_authorized_set`, `tests/test_agentic_eval.py::test_policy_blocked_check_requires_an_observed_denial` |
| Allowed toy tool executes with a verified receipt | `tests/test_tooling.py::test_allowed_tool_executes_and_returns_a_verified_receipt`, `...::test_message_is_queued_not_delivered` |
| Denied tool produces no state change | `tests/test_tooling.py::test_denied_call_produces_no_state_change`, `tests/test_scenarios.py::test_blocked_attempt_is_reported_as_denied_not_compromise` |
| Requested tools are distinguishable from executed tools | `tests/test_agentic_eval.py::test_forbidden_request_and_execution_are_distinct_checks`, `tests/test_agentic_flow.py::test_agentic_report_separates_simulation_from_observation` |
| Synthetic canary disclosure is detected | `tests/test_scenarios.py::test_canary_disclosure_is_detected`, `tests/test_agentic_eval.py::test_canary_check_ignores_tool_and_document_text` |
| Retrieved content never becomes a system instruction | `tests/test_agent_loop.py::test_retrieved_content_never_becomes_a_system_instruction` |
| Multiturn ordering is preserved exactly | `tests/test_agent_loop.py::test_turns_keep_exact_order_with_tool_correlation`, `...::test_denied_tool_is_recorded_as_a_tool_message` |
| Request and tool budgets terminate execution | `tests/test_agent_loop.py` (requests, turns, tools, tokens, bytes, deadline, provider error) |
| Interrupted runs preserve committed evidence | `tests/test_agent_loop.py::test_cancellation_keeps_committed_evidence`, `tests/test_agentic_flow.py::test_cancelled_trace_preserves_partial_evidence` |
| Stored traces support offline re-evaluation | `tests/test_agentic_flow.py::test_stored_trace_supports_offline_reevaluation`, CLI `reevaluate-trace` test |
| Reports distinguish simulated findings from observations | `tests/test_agentic_flow.py::test_agentic_report_separates_simulation_from_observation` |
| Phase 1/2A/2B databases migrate without record loss | `tests/test_migration.py` (v1→v4, v2→v4, v3→v4, reopen, foreign-key check) |
| Existing single-run and dataset-batch workflows still work | `tests/test_workbench.py`, `tests/test_sessions.py`, `tests/test_batch.py`, `tests/test_cli.py` |
| Applicability and graded agreement corrections | `tests/test_agreement.py` (dispute attribution, definition digest grouping, numeric levels, missing labels, out-of-level ratings, weighted-kappa reasons) |

### Local smoke tests

1. `scenarios` → `scenario` → `run-scenario --dry-run` → `run-scenario` (secure and
   vulnerable) → `traces` → `trace` → `trace-turns` → `trace-tools` →
   `agentic-report` (JSON/Markdown/CSV).
2. `judge` on a trace session, `reevaluate-trace`, `agreement --trace`.
3. Textual Agentic tab at 100x30: scenario inspection, dry run, secure and
   vulnerable runs, timeline, receipts, rubric outcomes, export.

### Not verified

Remote CI, hosted providers, real model endpoints, real tool execution and any
claim that deterministic checks resolve instruction adoption. Scenario outcomes
describe synthetic scripted fixtures and say nothing about a specific real model.

## Phase 2B (historical)

Local environment: macOS arm64, Python 3.12.13, uv 0.12.x, Textual 6.12,
Pydantic 2.14. CI is configured for macOS/Linux and Python 3.12/3.13; those
remote jobs were not observed from this workspace.

### Automated checks

- `uv run ruff check .`
- `uv run ruff format --check .`
- `uv run pytest -q`: 186 tests, fully offline (socket connect/connect_ex and DNS
  lookup are patched to raise inside every test).
- `uv build`: sdist and wheel, including the new modules and packaged data.
- GitHub Actions run `42134152633` for commit `5c0bb24` completed with
  `conclusion=success` for `macos-latest` and `ubuntu-latest` on Python 3.12 and
  3.13 (inspected with `gh run view`, not inferred).

### Required proofs (Phase 2B)

| Requirement | Test |
| --- | --- |
| Unfamiliar structured rubric imports without semantic loss | `tests/test_conformance.py` (six packs, preservation of wording, labels, weights, thresholds) |
| Imported response evaluated without a provider call | `tests/test_batch.py::test_execution_never_contacts_a_provider_or_creates_a_run`, `tests/test_datasets.py` |
| Batch evaluation handles mixed rubric outcomes | `tests/test_batch.py`, `tests/test_review_flow.py` |
| Partial batch resumes without duplicate results | `tests/test_batch.py::test_partial_execution_resumes_without_duplicates` |
| Disagreements survive persistence and export | `tests/test_review_flow.py` |
| Different categorical labels are a disagreement | `tests/test_disagreement.py`, `tests/test_review_flow.py::test_categorical_labels_differing_with_identical_outcome_are_a_disagreement` |
| Different ordinal scores stay distinguishable | `tests/test_review_flow.py::test_ordinal_scores_stay_distinguishable_through_export` |
| Cohen's kappa matches reference calculations | `tests/test_agreement.py` (2x2 reference, perfect agreement, weighted reference) |
| Undefined statistics are reported, not fabricated | `tests/test_agreement.py::test_undefined_statistics_state_why`, report assertions on `reason` |
| Historical Phase 1 and Phase 2A databases stay compatible | `tests/test_migration.py` (6 tests incl. v2→v3 rebuild and foreign-key check) |
| Batch reports carry complete provenance and evidence | `tests/test_batch_reports.py` |
| Existing single-run workflows still work | `tests/test_workbench.py`, `tests/test_sessions.py`, `tests/test_tui.py` |
| Reviewer workbench batch flow | `tests/test_tui.py::test_tui_batch_import_run_review_and_export` |
| CLI dataset/batch/agreement/conformance surface | `tests/test_cli.py::test_cli_dataset_batch_agreement_and_conformance` |

### Fixtures

- `tests/fixtures/conformance/*.json`: six rubric packs with known responses for
  full, partial, failing, ambiguous, not-applicable and conflicting-reviewer cases.
- `tests/fixtures/datasets/reviewed-batch.jsonl` and `.json`: imported-response
  datasets in both supported formats, including an empty response and an attack case.
- `tests/fixtures/phase1/*`: unchanged Phase 1 database dump and report (used by the
  chained v1→v3 migration test).

### Local smoke tests

1. `import-dataset` → `create-batch` → `run-batch --dry-run` → `run-batch --limit`
   → `run-batch` (resume) → `batch-status` → `batch-report` (JSON/Markdown/CSV).
2. `judge`/`adjudicate` on a dataset session, then `agreement --batch` JSON output.
3. `rubric-conformance --pack` over the six packs: zero errors, notes for every
   human-assessed criterion.
4. Textual: Batch tab at 100x30 (import, plan, run, review, adjudicate, export) and
   at 110x40 in the automated pilot test.

### Not verified

Remote CI, hosted providers, real model endpoints, and any claim that deterministic
checks resolve subjective criteria. Agreement statistics describe the reviewers and
items in the fixture, not a population.

## Phase 2A (historical)

Local environment: macOS arm64, Python 3.12.13, uv 0.12.x, Textual 6.12,
Pydantic 2.14. CI is configured for macOS/Linux and Python 3.12/3.13; those
remote jobs were not run from this workspace.

### Automated checks (Phase 2A)

- `uv run ruff check .` and `uv run ruff format --check .`.
- `uv run pytest -q`: 113 tests, fully offline (socket connect/connect_ex and DNS
  lookup are patched to raise inside every test).
- `uv build` (sdist + wheel) and a wheel-content smoke import.

Coverage added in Phase 2A:

| Requirement | Test |
| --- | --- |
| One saved response, two distinct rubric evaluations | `tests/test_sessions.py::test_one_saved_response_supports_two_independent_rubric_evaluations` |
| Reevaluation never calls the model endpoint | `...::test_reevaluation_never_contacts_the_model` |
| Ordinal partial credit keeps its meaning | `...::test_ordinal_partial_credit_keeps_its_original_meaning`, `tests/test_evaluation.py::test_partial_credit_keeps_its_fractional_compliance` |
| Categorical results are not binary | `...::test_categorical_assessment_is_not_converted_to_binary`, `tests/test_evaluation.py::test_non_binary_scales_never_become_binary_observations` |
| Two reviewers disagree without data loss | `...::test_two_reviewers_can_disagree_without_losing_records` |
| Adjudication without destroying evidence | `...::test_adjudication_produces_an_effective_outcome_without_destroying_evidence` |
| Reports distinguish original and adjudicated results | `...::test_report_separates_automated_human_and_adjudicated_results`, `...::test_overridden_failure_is_reported_as_contested` |
| Append-only review records | `...::test_review_records_are_append_only_in_storage` |
| Explicit adjudication policy only | `...::test_adjudication_policy_requires_an_explicit_choice`, `...::test_judgment_validation_rejects_contradictions` |
| Deterministic digests, distinct export identity | `...::test_digests_are_deterministic_and_keep_identities_separate` |
| Phase 1 database migration | `tests/test_migration.py` (5 tests: preserve records, new workflows, rollback, reopen, historical report) |
| Reviewer workbench | `tests/test_tui.py::test_tui_reviewer_workbench_records_review_and_adjudication` |
| CLI review surface | `tests/test_cli.py::test_cli_reevaluate_review_adjudicate_and_migrate` |

### Fixtures

- `tests/fixtures/rubrics/graded-disclosure.v2.json`: ordinal levels with verbatim
  descriptions, a categorical criterion with explicit outcomes, and a numeric
  criterion (partial credit, disagreement, reevaluation).
- `tests/fixtures/phase1/database.json` and `report.v1.json`: a real Phase 1
  database dump and a real Phase 1 report export, both generated from the
  committed Phase 1 code (`ac4e180`) and stored as reviewable JSON.

### Local application smoke tests

1. `faultline demo --behavior vulnerable`: two execution sessions, two simulated
   findings, report format 2.0.0 with every documented section.
2. `faultline reevaluate RUN_ID --rubric RUBRIC_ID`: third session with rubric
   2.0.0, unchanged run snapshot, no network access.
3. `faultline judge` / `faultline adjudicate` / `faultline disagreements`:
   judgment appended, adjudication recorded, effective result confirmed,
   overridden or `human_assessed`.
4. `faultline export`: Markdown and JSON contain source hashes, canonical digests,
   automated evaluations, human judgments, adjudications, disagreement status and
   the full evidence bundle; the export digest verifies.
5. `faultline migrate` against a Phase 1 database: reports schema version 2 with
   all rows, IDs and overrides intact.

### Not verified

Remote CI, hosted providers, real model endpoints, cryptographic signing, and any
claim about attack efficacy against a real model. The toy HTTP server remains
deliberately vulnerable and is not an LLM.

## Phase 1 (historical)

Local environment: macOS arm64, Python 3.12.13, uv 0.12.17. Dependencies are pinned
in `uv.lock`. CI is configured for macOS/Linux and Python 3.12/3.13; those remote
jobs have not been run from this workspace.

## Automated checks (Phase 1)

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
