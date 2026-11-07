"""CLI use cases; offline by default, real endpoint IO requires explicit opt-in."""

import argparse
import asyncio
import json
import sqlite3
from pathlib import Path

import yaml
from platformdirs import user_data_path
from pydantic import ValidationError

from faultline import domain
from faultline.conformance import check_pack, check_rubric
from faultline.domain import (
    AdjudicationPolicy,
    AgentBudget,
    BatchBudget,
    BenchmarkLimits,
    DatasetLimits,
    EndpointProfile,
    ExecutionBudget,
    ExecutionSettings,
    ExperimentLimits,
    HumanOverride,
)
from faultline.release import build_facts, diagnose
from faultline.reportcheck import validate_export
from faultline.reports import export_report
from faultline.rubrics import import_rubric, review_normalization, sample_rubric
from faultline.scenarios import variant_pair
from faultline.service import Workbench
from faultline.smoke import execute_smoke, plan_smoke
from faultline.storage import Store
from faultline.techniques import techniques


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Faultline authorized LLM evaluation workbench")
    p.add_argument("--db", type=Path, default=user_data_path("faultline") / "history.sqlite3")
    commands = p.add_subparsers(dest="command", required=True)
    commands.add_parser("tui", help="Launch the Textual workbench")
    commands.add_parser("history", help="List local experiments")
    commands.add_parser("profiles", help="List endpoint profiles (credential references only)")
    commands.add_parser("rubrics", help="List imported rubrics and review states")
    t = commands.add_parser("techniques", help="Inspect versioned synthetic technique definitions")
    t.add_argument("id", nargs="?")
    d = commands.add_parser("demo", help="Execute offline baseline and attack and export reports")
    d.add_argument("--behavior", choices=["secure", "vulnerable"], default="secure")
    d.add_argument("--output", type=Path, default=Path("reports/demo"))
    profile = commands.add_parser("add-profile", help="Create an immutable scoped endpoint profile")
    profile.add_argument("name")
    profile.add_argument("--provider", choices=["mock", "openai-compatible"], default="mock")
    profile.add_argument("--base-url")
    profile.add_argument("--credential-env", help="Environment variable NAME, never the key itself")
    profile.add_argument("--model", action="append", help="Allowed model ID; repeat for more")
    profile.add_argument(
        "--authorize", action="store_true", help="Attest authorization for this target"
    )
    profile.add_argument("--scope", default="Local synthetic mock evaluation")
    profile.add_argument("--behavior", choices=["secure", "vulnerable"], default="secure")
    profile.add_argument(
        "--token-parameter", choices=["max_tokens", "max_completion_tokens"], default="max_tokens"
    )
    imp = commands.add_parser(
        "import-rubric", help="Import JSON/YAML, or stage text/Markdown for review"
    )
    imp.add_argument("source", type=Path)
    review = commands.add_parser(
        "review-rubric", help="Approve human normalization as a new rubric"
    )
    review.add_argument("rubric_id")
    review.add_argument("draft", type=Path)
    review.add_argument("--reviewer", required=True)
    review.add_argument("--rationale", required=True)
    for command in ("run", "test-endpoint"):
        run = commands.add_parser(
            command, help="Run authorized cases; connection test sends one baseline"
        )
        run.add_argument("profile_id")
        run.add_argument("--rubric", help="Imported rubric ID; default is packaged sample")
        run.add_argument("--technique", choices=list(techniques()), default="authority-spoof")
        run.add_argument("--model")
        run.add_argument("--canary")
        run.add_argument("--allow-network", action="store_true")
        run.add_argument("--dry-run", action="store_true")
        run.add_argument("--max-requests", type=int, default=2)
        run.add_argument("--max-output-tokens", type=int, default=128)
        run.add_argument("--total-output-tokens", type=int, default=256)
        run.add_argument("--timeout", type=float, default=30)
        run.add_argument("--omit-seed", action="store_true")
        run.add_argument("--omit-temperature", action="store_true")
        run.add_argument("--output", type=Path)
    export = commands.add_parser("export", help="Export complete evidence as Markdown and JSON")
    export.add_argument("experiment_id")
    export.add_argument("--output", type=Path, required=True)
    override = commands.add_parser(
        "override", help="Append a legacy Phase 1 human override without replacing the original"
    )
    override.add_argument("evaluation_id")
    override.add_argument(
        "--outcome", choices=["pass", "fail", "uncertain", "not_applicable"], required=True
    )
    override.add_argument("--reviewer", required=True)
    override.add_argument("--rationale", required=True)
    reevaluate = commands.add_parser(
        "reevaluate", help="Score a stored response again with another rubric; no model call"
    )
    reevaluate.add_argument("run_id")
    reevaluate.add_argument("--rubric", required=True)
    reevaluate.add_argument("--output", type=Path)
    review = commands.add_parser(
        "start-review", help="Open a human review session for a stored response"
    )
    review.add_argument("run_id")
    review.add_argument("--rubric", required=True)
    sessions = commands.add_parser("sessions", help="List evaluation sessions")
    sessions.add_argument("--experiment")
    sessions.add_argument("--run")
    judge = commands.add_parser("judge", help="Append one reviewer judgment")
    judge.add_argument("session_id")
    judge.add_argument("criterion_id")
    judge.add_argument(
        "--outcome", choices=["pass", "fail", "uncertain", "not_applicable"], required=True
    )
    judge.add_argument("--reviewer", required=True)
    judge.add_argument("--rationale", required=True)
    judge.add_argument("--label", help="Rubric level or category label for ordered scales")
    judge.add_argument("--score", type=float, help="Numeric score within the rubric scale")
    judge.add_argument("--confidence", choices=["low", "medium", "high"])
    judge.add_argument("--supersedes", help="ID of this reviewer's earlier judgment")
    adjudicate = commands.add_parser(
        "adjudicate", help="Record an explicit adjudication policy outcome"
    )
    adjudicate.add_argument("session_id")
    adjudicate.add_argument(
        "--policy",
        choices=["single_reviewer", "unanimous", "majority", "first_reviewer"],
        required=True,
    )
    adjudicate.add_argument(
        "--designated-reviewer", help="Reviewer whose judgment wins under single_reviewer"
    )
    adjudicate.add_argument("--reviewer", required=True, help="Adjudicator identity")
    adjudicate.add_argument("--rationale", required=True)
    disputes = commands.add_parser(
        "disagreements", help="List unresolved disagreements for an experiment"
    )
    disputes.add_argument("experiment_id")
    dataset = commands.add_parser(
        "import-dataset", help="Import prerecorded responses from JSON or JSONL"
    )
    dataset.add_argument("source", type=Path)
    dataset.add_argument("--title")
    dataset.add_argument("--version")
    dataset.add_argument("--provenance")
    dataset.add_argument("--max-records", type=int)
    commands.add_parser("datasets", help="List imported datasets")
    records = commands.add_parser("dataset-records", help="List dataset case identifiers")
    records.add_argument("dataset_id")
    records.add_argument("--limit", type=int, default=20)
    batch = commands.add_parser("create-batch", help="Plan a batch over an imported dataset")
    batch.add_argument("dataset_id")
    batch.add_argument("--rubric", required=True)
    batch.add_argument("--max-cases", type=int)
    batch.add_argument("--per-run", type=int)
    run_batch = commands.add_parser(
        "run-batch", help="Evaluate or resume a batch offline; never contacts a model"
    )
    run_batch.add_argument("batch_id")
    run_batch.add_argument("--limit", type=int)
    run_batch.add_argument(
        "--dry-run", action="store_true", help="Validate the plan without evaluating"
    )
    run_batch.add_argument("--output", type=Path)
    status = commands.add_parser("batch-status", help="Show batch progress counts")
    status.add_argument("batch_id")
    report = commands.add_parser("batch-report", help="Export the batch report (JSON/Markdown/CSV)")
    report.add_argument("batch_id")
    report.add_argument("--output", type=Path, required=True)
    agreement = commands.add_parser(
        "agreement", help="Inter-rater agreement statistics for experiment or batch reviews"
    )
    agreement.add_argument("--experiment")
    agreement.add_argument("--batch")
    agreement.add_argument("--trace")
    conformance = commands.add_parser(
        "rubric-conformance", help="Validate an unfamiliar rubric without executing a model"
    )
    conformance.add_argument("--pack", type=Path, help="Conformance pack with known responses")
    conformance.add_argument("--path", type=Path, help="Rubric JSON/YAML file")
    conformance.add_argument("--rubric", help="Stored rubric ID")
    commands.add_parser("scenarios", help="List packaged synthetic agentic scenarios")
    scenario = commands.add_parser("scenario", help="Show one scenario definition")
    scenario.add_argument("scenario_id")
    run_scenario = commands.add_parser(
        "run-scenario", help="Run one synthetic agentic scenario (offline by default)"
    )
    run_scenario.add_argument("scenario_id")
    run_scenario.add_argument("--rubric")
    run_scenario.add_argument(
        "--agent",
        choices=["scripted-secure", "scripted-vulnerable", "endpoint"],
        default="scripted-secure",
    )
    run_scenario.add_argument("--profile")
    run_scenario.add_argument("--allow-network", action="store_true")
    run_scenario.add_argument("--dry-run", action="store_true")
    run_scenario.add_argument("--max-requests", type=int)
    run_scenario.add_argument("--max-turns", type=int)
    run_scenario.add_argument("--max-tool-invocations", type=int)
    run_scenario.add_argument("--max-output-tokens", type=int)
    run_scenario.add_argument("--timeout", type=float)
    run_scenario.add_argument("--output", type=Path)
    commands.add_parser("traces", help="List stored agentic traces")
    trace = commands.add_parser("trace", help="Summarise one agentic trace")
    trace.add_argument("trace_id")
    turns = commands.add_parser("trace-turns", help="Print the ordered conversation timeline")
    turns.add_argument("trace_id")
    tools = commands.add_parser("trace-tools", help="Print tool requests and receipts")
    tools.add_argument("trace_id")
    agentic_report = commands.add_parser(
        "agentic-report", help="Export the agentic report (JSON/Markdown/CSV)"
    )
    agentic_report.add_argument("trace_id")
    agentic_report.add_argument("--output", type=Path, required=True)
    reevaluate_trace = commands.add_parser(
        "reevaluate-trace", help="Re-score a stored trace without re-running the agent"
    )
    reevaluate_trace.add_argument("trace_id")
    reevaluate_trace.add_argument("--rubric", required=True)
    controlled = commands.add_parser(
        "controlled-scenarios", help="List scenarios that support a control/attack pair"
    )
    controlled.add_argument("--agent", default="scripted-vulnerable")
    plan = commands.add_parser(
        "plan-experiment", help="Plan a paired control/attack experiment (no execution)"
    )
    plan.add_argument("scenario_id")
    plan.add_argument(
        "--agent",
        choices=["scripted-secure", "scripted-vulnerable", "endpoint"],
        default="scripted-vulnerable",
    )
    plan.add_argument("--profile")
    plan.add_argument("--model")
    plan.add_argument("--rubric")
    plan.add_argument("--trials", type=int, default=5)
    plan.add_argument(
        "--order",
        choices=["control_first", "attack_first", "alternate", "randomized"],
        default="control_first",
    )
    plan.add_argument("--seed", type=int)
    plan.add_argument("--max-requests", type=int)
    plan.add_argument("--max-tool-invocations", type=int)
    plan.add_argument("--max-turns", type=int)
    plan.add_argument("--max-output-tokens", type=int)
    plan.add_argument("--total-requests", type=int)
    plan.add_argument("--estimated-cost-per-request", type=float)
    plan.add_argument("--max-estimated-spend", type=float)
    plan.add_argument(
        "--authorization",
        default="Synthetic scenario evaluation with synthetic tools only",
    )
    plan.add_argument("--allow-network", action="store_true")
    plan.add_argument("--name")
    plans = commands.add_parser("experiments", help="List controlled experiments")
    plans.add_argument("--scenario")
    run_experiment = commands.add_parser(
        "run-experiment", help="Run or safely resume pending paired trials"
    )
    run_experiment.add_argument("experiment_id")
    run_experiment.add_argument("--limit", type=int)
    run_experiment.add_argument("--allow-network", action="store_true")
    experiment_status = commands.add_parser(
        "experiment-status", help="Show trial counts for a controlled experiment"
    )
    experiment_status.add_argument("experiment_id")
    summary = commands.add_parser("experiment-summary", help="Print the paired comparison as JSON")
    summary.add_argument("experiment_id")
    experiment_report = commands.add_parser(
        "experiment-report", help="Export the controlled-experiment report"
    )
    experiment_report.add_argument("experiment_id")
    experiment_report.add_argument("--output", type=Path, required=True)
    validate = commands.add_parser(
        "validate-endpoint", help="Validate an authorized endpoint end to end"
    )
    validate.add_argument("--profile", required=True)
    validate.add_argument("--model")
    validate.add_argument("--scenario", default="retrieved-authority-spoof")
    validate.add_argument("--trials", type=int, default=1)
    validate.add_argument("--allow-network", action="store_true")
    validate.add_argument("--output", type=Path)
    capabilities = commands.add_parser(
        "capabilities", help="Probe an endpoint's configured versus observed features"
    )
    capabilities.add_argument("--profile", required=True)
    capabilities.add_argument("--model")
    capabilities.add_argument("--allow-network", action="store_true")
    commands.add_parser("capability-reports", help="List stored capability reports")
    validation = commands.add_parser("validation-runs", help="List endpoint validation runs")
    validation.add_argument("--profile")
    comparison = commands.add_parser(
        "plan-comparison", help="Plan a segregated multi-model comparison"
    )
    comparison.add_argument("scenario_id")
    comparison.add_argument("--profile", action="append", default=[])
    comparison.add_argument("--model", action="append", default=[])
    comparison.add_argument(
        "--agent", action="append", default=[], help="scripted-secure or scripted-vulnerable"
    )
    comparison.add_argument("--trials", type=int, default=2)
    comparison.add_argument("--rubric")
    comparison.add_argument("--authorization", default=None)
    comparison.add_argument("--allow-network", action="store_true")
    comparison.add_argument("--name")
    run_comparison = commands.add_parser(
        "run-comparison", help="Run or resume each model's experiment separately"
    )
    run_comparison.add_argument("comparison_id")
    run_comparison.add_argument("--limit", type=int)
    run_comparison.add_argument("--allow-network", action="store_true")
    comparison_report = commands.add_parser(
        "comparison-report", help="Export the multi-model comparison report"
    )
    comparison_report.add_argument("comparison_id")
    comparison_report.add_argument("--output", type=Path, required=True)
    commands.add_parser("comparisons", help="List model comparisons")
    commands.add_parser("benchmarks", help="List packaged benchmark suites")
    plan_benchmark = commands.add_parser(
        "plan-benchmark", help="Plan a benchmark suite across authorized models"
    )
    plan_benchmark.add_argument("suite_id")
    plan_benchmark.add_argument("--profile", action="append", default=[])
    plan_benchmark.add_argument("--model", action="append", default=[])
    plan_benchmark.add_argument(
        "--agent", action="append", default=[], help="scripted-secure or scripted-vulnerable"
    )
    plan_benchmark.add_argument("--trials", type=int, default=2)
    plan_benchmark.add_argument("--max-scenarios", type=int)
    plan_benchmark.add_argument("--max-trials", type=int)
    plan_benchmark.add_argument("--max-requests", type=int)
    plan_benchmark.add_argument("--max-tokens", type=int)
    plan_benchmark.add_argument("--max-runtime", type=float)
    plan_benchmark.add_argument("--max-spend", type=float)
    plan_benchmark.add_argument("--estimated-cost-per-request", type=float)
    plan_benchmark.add_argument(
        "--authorization", default="Authorized benchmark with synthetic tools only"
    )
    plan_benchmark.add_argument("--allow-network", action="store_true")
    run_benchmark = commands.add_parser("run-benchmark", help="Run or resume a planned benchmark")
    run_benchmark.add_argument("plan_id")
    run_benchmark.add_argument("--limit", type=int)
    run_benchmark.add_argument("--allow-network", action="store_true")
    benchmark_status = commands.add_parser(
        "benchmark-status", help="Show benchmark scenario status counts"
    )
    benchmark_status.add_argument("plan_id")
    benchmark_report = commands.add_parser("benchmark-report", help="Export the benchmark report")
    benchmark_report.add_argument("plan_id")
    benchmark_report.add_argument("--output", type=Path, required=True)
    commands.add_parser("benchmark-plans", help="List benchmark plans")
    experiment_quality = commands.add_parser(
        "experiment-quality", help="Run the experimental quality checks"
    )
    experiment_quality.add_argument("experiment_id")
    verify_report = commands.add_parser(
        "verify-report", help="Audit an exported report against its own evidence"
    )
    verify_report.add_argument("path", type=Path)
    verify_report.add_argument("--json", action="store_true")
    smoke = commands.add_parser(
        "smoke-plan", help="Show the exact bounded live-model smoke plan and ceilings"
    )
    smoke.add_argument("--profile", required=True)
    smoke.add_argument("--model")
    smoke.add_argument("--scenario", default="retrieved-authority-spoof")
    smoke.add_argument("--allow-network", action="store_true")
    smoke.add_argument("--authorization", default="")
    smoke.add_argument("--max-requests", type=int, default=4)
    smoke.add_argument("--max-output-tokens", type=int, default=64)
    smoke.add_argument("--timeout", type=float, default=20.0)
    smoke.add_argument("--max-spend", type=float)
    smoke.add_argument("--estimated-cost-per-request", type=float)
    run_smoke = commands.add_parser(
        "run-smoke", help="Validate and run the planned bounded smoke experiment"
    )
    run_smoke.add_argument("--profile", required=True)
    run_smoke.add_argument("--model")
    run_smoke.add_argument("--scenario", default="retrieved-authority-spoof")
    run_smoke.add_argument("--allow-network", action="store_true")
    run_smoke.add_argument("--authorization", default="")
    run_smoke.add_argument("--max-requests", type=int, default=4)
    run_smoke.add_argument("--max-output-tokens", type=int, default=64)
    run_smoke.add_argument("--timeout", type=float, default=20.0)
    run_smoke.add_argument("--max-spend", type=float)
    run_smoke.add_argument("--estimated-cost-per-request", type=float)
    run_smoke.add_argument("--output", type=Path)
    commands.add_parser("version", help="Print the Faultline version and build facts")
    doctor = commands.add_parser("doctor", help="Check the local installation, database and assets")
    doctor.add_argument("--json", action="store_true")
    commands.add_parser("migrate", help="Apply pending database migrations explicitly")
    schema = commands.add_parser("schemas", help="Export domain JSON Schema contracts")
    schema.add_argument("directory", type=Path)
    return p


def comparison_targets(args, store):
    """Resolve --profile/--model/--agent triples into comparison targets."""
    profiles = list(args.profile or [])
    models = list(args.model or [])
    agents = list(args.agent or [])
    if not profiles and not agents:
        raise ValueError("Supply at least one --profile or --agent target")
    targets = []
    for index, profile_id in enumerate(profiles):
        targets.append(
            {
                "profile": store.profile(profile_id),
                "model": models[index] if index < len(models) else None,
            }
        )
    offset = len(profiles)
    for index, agent in enumerate(agents):
        model = models[offset + index] if offset + index < len(models) else None
        targets.append({"agent": agent, "model": model})
    return targets


def dispatch(args: argparse.Namespace) -> None:
    if args.command == "schemas":
        args.directory.mkdir(parents=True, exist_ok=True)
        for name in dir(domain):
            cls = getattr(domain, name)
            if isinstance(cls, type) and issubclass(cls, domain.Contract):
                (args.directory / f"{name}.json").write_text(
                    json.dumps(cls.model_json_schema(), indent=2) + "\n",
                    encoding="utf-8",
                )
        print(args.directory)
        return
    if args.command == "techniques":
        registry = techniques()
        if args.id:
            if args.id not in registry:
                raise ValueError("Unknown technique")
            print(registry[args.id].model_dump_json(indent=2))
        else:
            for item in registry.values():
                print(f"{item.id}\t{item.version}\t{item.family}\t{item.name}")
        return
    store = Store(args.db)
    workbench = Workbench(store)
    if args.command == "tui":
        from faultline.tui import FaultlineApp

        FaultlineApp(workbench).run()
    elif args.command == "demo":
        profile = EndpointProfile(
            name=f"Demo / {args.behavior}",
            mock_behavior=args.behavior,
            authorized=True,
        )
        store.add_profile(profile)
        rubric = sample_rubric()
        store.add_rubric(rubric)
        report = asyncio.run(workbench.execute(workbench.prepare(profile, rubric)))
        paths = export_report(report, args.output)
        print(
            f"{report.experiment.id}\t{report.experiment.status}\t{len(report.findings)} findings"
        )
        for path in paths:
            print(path)
    elif args.command == "add-profile":
        if args.provider != "mock" and (
            not args.scope.strip() or args.scope == "Local synthetic mock evaluation"
        ):
            raise ValueError("Supply an explicit --scope describing the authorized real target")
        profile = EndpointProfile(
            name=args.name,
            provider=args.provider,
            base_url=args.base_url,
            credential_env=args.credential_env,
            allowed_models=args.model or ["toy-model"],
            authorized=args.authorize,
            authorization=args.scope,
            mock_behavior=args.behavior,
            token_parameter=args.token_parameter,
        )
        store.add_profile(profile)
        print(profile.id)
    elif args.command == "profiles":
        for profile in store.profiles():
            print(profile.model_dump_json())
    elif args.command == "import-rubric":
        rubric = import_rubric(args.source)
        store.add_rubric(rubric)
        print(f"{rubric.id}\t{rubric.review_status}\t{rubric.source.sha256}")
    elif args.command == "review-rubric":
        rubric = review_normalization(
            store.rubric(args.rubric_id), args.draft, args.reviewer, args.rationale
        )
        store.add_rubric(rubric)
        print(rubric.id)
    elif args.command == "rubrics":
        for rubric in store.rubrics():
            title = rubric.definition.title if rubric.definition else rubric.source.provenance
            print(f"{rubric.id}\t{rubric.review_status}\t{title}")
    elif args.command in {"run", "test-endpoint"}:
        rubric = store.rubric(args.rubric) if args.rubric else sample_rubric()
        experiment = workbench.prepare(
            store.profile(args.profile_id),
            rubric,
            args.technique,
            model=args.model,
            parameters={"canary": args.canary} if args.canary else None,
            settings=ExecutionSettings(
                max_output_tokens=args.max_output_tokens,
                timeout_seconds=args.timeout,
                seed=None if args.omit_seed else 42,
                temperature=None if args.omit_temperature else 0,
            ),
            budget=ExecutionBudget(
                max_requests=args.max_requests, max_total_output_tokens=args.total_output_tokens
            ),
            dry_run=args.dry_run,
            allow_network=args.allow_network,
            connection_test=args.command == "test-endpoint",
        )
        report = asyncio.run(workbench.execute(experiment))
        print(
            f"{report.experiment.id}\t{report.experiment.status}\t{len(report.findings)} findings"
        )
        if args.output:
            for path in export_report(report, args.output):
                print(path)
        if report.experiment.status == "failed":
            raise ValueError(report.runs[-1].error or "Experiment failed")
    elif args.command == "history":
        for experiment in store.history():
            print(
                f"{experiment.id}\t{experiment.status}\t{experiment.name}\t{experiment.created_at}"
            )
    elif args.command == "export":
        for path in export_report(workbench.report(args.experiment_id), args.output):
            print(path)
    elif args.command == "override":
        value = HumanOverride(
            evaluation_id=args.evaluation_id,
            reviewer=args.reviewer,
            outcome=args.outcome,
            rationale=args.rationale,
        )
        store.add_override(value)
        print(value.id)
    elif args.command == "import-dataset":
        dataset = workbench.import_dataset(
            args.source,
            title=args.title,
            version=args.version,
            provenance=args.provenance,
            limits=DatasetLimits(max_records=args.max_records) if args.max_records else None,
        )
        print(f"{dataset.id}\t{dataset.record_count}\t{dataset.version}\t{dataset.dataset_sha256}")
    elif args.command == "datasets":
        for dataset in workbench.datasets():
            print(
                f"{dataset.id}\t{dataset.record_count}\t{dataset.version}\t"
                f"{dataset.title}\t{dataset.source_format}"
            )
    elif args.command == "dataset-records":
        for record in store.dataset_records_page(args.dataset_id, limit=args.limit):
            print(f"{record.id}\t{record.source_sha256}\t{record.provenance}")
    elif args.command == "create-batch":
        batch = workbench.create_batch(
            args.dataset_id,
            store.rubric(args.rubric),
            max_cases=args.max_cases,
            budget=BatchBudget(max_cases_per_run=args.per_run) if args.per_run else None,
        )
        print(f"{batch.id}\t{batch.status}\t{batch.budget.max_cases}")
    elif args.command == "run-batch":
        if args.dry_run:
            planned = workbench.pending_batch_cases(args.batch_id, limit=args.limit)
            batch = workbench.batch(args.batch_id)
            print(f"{batch.id}	dry_run	pending={len(planned)}")
            return
        batch = workbench.execute_batch(args.batch_id, limit=args.limit)
        counts = store.batch_case_counts(batch.id)
        print(
            f"{batch.id}\t{batch.status}\t"
            + "\t".join(
                f"{key}={counts.get(key, 0)}"
                for key in ("completed", "failed", "skipped", "pending")
            )
        )
        if args.output:
            for path in export_report(workbench.batch_report(batch.id), args.output):
                print(path)
    elif args.command == "batch-status":
        batch = workbench.batch(args.batch_id)
        counts = store.batch_case_counts(batch.id)
        print(f"{batch.id}\t{batch.status}\t{batch.dataset_id}\t{batch.rubric_id}")
        for key in ("completed", "failed", "skipped", "pending"):
            print(f"{key}\t{counts.get(key, 0)}")
    elif args.command == "batch-report":
        for path in export_report(workbench.batch_report(args.batch_id), args.output):
            print(path)
    elif args.command == "scenarios":
        for scenario in workbench.scenarios().values():
            print(
                f"{scenario.id}	{scenario.version}	{scenario.family}	"
                f"{scenario.injected_document_id or 'none'}	{scenario.title}"
            )
    elif args.command == "scenario":
        print(workbench.scenario(args.scenario_id).model_dump_json(indent=2))
    elif args.command == "run-scenario":
        rubric = store.rubric(args.rubric) if args.rubric else None
        profile = store.profile(args.profile) if args.profile else None
        trace = asyncio.run(
            workbench.run_scenario(
                args.scenario_id,
                rubric=rubric,
                agent=args.agent,
                profile=profile,
                allow_network=args.allow_network,
                dry_run=args.dry_run,
                budget=AgentBudget(
                    **{
                        key: value
                        for key, value in {
                            "max_requests": args.max_requests,
                            "max_turns": args.max_turns,
                            "max_tool_invocations": args.max_tool_invocations,
                            "max_output_tokens": args.max_output_tokens,
                            "overall_timeout_seconds": args.timeout,
                        }.items()
                        if value is not None
                    }
                ),
            )
        )
        result = workbench.agentic_result(trace)
        print(
            f"{trace.id}	{trace.status}	{trace.termination}	{result.verdict}	"
            f"requests={len(trace.invocations)}	turns={len(trace.turns)}"
        )
        if args.output and trace.status != "dry_run":
            for path in export_report(workbench.agentic_report(trace.id), args.output):
                print(path)
    elif args.command == "traces":
        for trace in workbench.traces():
            print(
                f"{trace.id}	{trace.status}	{trace.termination}	"
                f"{trace.scenario.id}@{trace.scenario.version}	{trace.agent}	"
                f"requests={len(trace.invocations)}"
            )
    elif args.command == "trace":
        trace = workbench.trace(args.trace_id)
        print(workbench.agentic_result(trace).model_dump_json(indent=2))
    elif args.command == "trace-turns":
        for turn in workbench.trace(args.trace_id).turns:
            content = turn.content.replace("\n", " ")[:200]
            print(
                f"{turn.index}	{turn.role}	{turn.source}	{turn.trust}	"
                f"{turn.tool_request_id or ''}	{content}"
            )
    elif args.command == "trace-tools":
        for invocation in workbench.trace(args.trace_id).invocations:
            decision = invocation.decision.decision if invocation.decision else "unrecorded"
            executed = bool(invocation.receipt and invocation.receipt.executed)
            print(
                f"{invocation.request_id}	{invocation.tool}	{decision}	"
                f"executed={executed}	{invocation.arguments}"
            )
    elif args.command == "agentic-report":
        for path in export_report(workbench.agentic_report(args.trace_id), args.output):
            print(path)
    elif args.command == "reevaluate-trace":
        session = asyncio.run(
            workbench.reevaluate_agentic(args.trace_id, store.rubric(args.rubric))
        )
        print(f"{session.id}	{session.rubric.definition.version}	{session.execution_sha256}")
    elif args.command == "controlled-scenarios":
        for scenario in workbench.scenarios().values():
            if not scenario.injected_document_id:
                continue
            control, attack = variant_pair(scenario, args.agent)
            injected = next(
                document
                for document in scenario.documents
                if document.id == scenario.injected_document_id
            )
            print(
                f"{scenario.id}	{scenario.version}	{scenario.family}	"
                f"control={control.corpus_sha256[:12]}	"
                f"attack={attack.corpus_sha256[:12]}	"
                f"payload={'yes' if injected.injection else 'no'}"
            )
    elif args.command == "plan-experiment":
        profile = store.profile(args.profile) if args.profile else None
        rubric = store.rubric(args.rubric) if args.rubric else None
        experiment = workbench.plan_experiment(
            args.scenario_id,
            agent=args.agent,
            profile=profile,
            model=args.model,
            rubric=rubric,
            trial_count=args.trials,
            budget=AgentBudget(
                **{
                    key: value
                    for key, value in {
                        "max_requests": args.max_requests,
                        "max_tool_invocations": args.max_tool_invocations,
                        "max_turns": args.max_turns,
                        "max_output_tokens": args.max_output_tokens,
                    }.items()
                    if value is not None
                }
            ),
            limits=ExperimentLimits(
                **{
                    key: value
                    for key, value in {
                        "max_total_requests": args.total_requests,
                        "estimated_cost_per_request_usd": args.estimated_cost_per_request,
                        "max_estimated_spend_usd": args.max_estimated_spend,
                    }.items()
                    if value is not None
                }
            ),
            order=args.order,
            seed=args.seed,
            authorization=args.authorization,
            allow_network=args.allow_network,
            name=args.name,
        )
        print(
            f"{experiment.id}	{experiment.status}	trials={experiment.trial_count}	"
            f"order={experiment.order}	target={experiment.target.agent}"
        )
        for difference in experiment.differences:
            print(f"  difference	{difference.path}	{difference.description}")
    elif args.command == "experiments":
        for experiment in store.controlled_experiments():
            if args.scenario and experiment.scenario_id != args.scenario:
                continue
            counts = store.trial_counts(experiment.id)
            print(
                f"{experiment.id}	{experiment.status}	{experiment.scenario_id}	"
                f"trials={experiment.trial_count}	"
                + "	".join(
                    f"{key}={counts.get(key, 0)}"
                    for key in ("pending", "running", "completed", "failed", "interrupted")
                )
            )
    elif args.command == "run-experiment":
        experiment = store.controlled_experiment(args.experiment_id)
        if experiment.allow_network and not args.allow_network:
            raise ValueError("This experiment requires --allow-network to execute")
        finished = asyncio.run(workbench.execute_experiment(args.experiment_id, limit=args.limit))
        counts = store.trial_counts(finished.id)
        print(
            f"{finished.id}	{finished.status}	"
            + "	".join(
                f"{key}={counts.get(key, 0)}"
                for key in ("pending", "running", "completed", "failed", "interrupted")
            )
        )
    elif args.command == "experiment-status":
        experiment = store.controlled_experiment(args.experiment_id)
        counts = store.trial_counts(experiment.id)
        print(
            f"{experiment.id}	{experiment.status}	{experiment.scenario_id}	"
            f"{experiment.target.agent}	trials={experiment.trial_count}"
        )
        for key in ("pending", "running", "completed", "failed", "interrupted"):
            print(f"{key}	{counts.get(key, 0)}")
    elif args.command == "experiment-summary":
        summary_value = workbench.experiment_summary(args.experiment_id)
        print(summary_value.model_dump_json(indent=2))
    elif args.command == "experiment-report":
        for path in export_report(workbench.experiment_report(args.experiment_id), args.output):
            print(path)
    elif args.command == "capabilities":
        profile = store.profile(args.profile)
        report = asyncio.run(
            workbench.validate_provider(
                profile,
                model=args.model,
                allow_network=args.allow_network,
            )
        )
        print(report.model_dump_json(indent=2))
    elif args.command == "capability-reports":
        for report in workbench.capability_reports():
            print(
                f"{report.id}\t{report.profile_id}\t{report.model}\t"
                f"chat={report.observed.chat_completions}\ttools={report.observed.tool_calls}\t"
                f"tool_results={report.observed.tool_result_messages}"
            )
    elif args.command == "validate-endpoint":
        profile = store.profile(args.profile)
        run = asyncio.run(
            workbench.run_validation(
                profile,
                model=args.model,
                scenario_id=args.scenario,
                trials=args.trials,
                allow_network=args.allow_network,
                output_prefix=args.output,
            )
        )
        for step in run.steps:
            print(f"{step.name}\t{step.status}\t{step.detail}")
        print(f"validation\t{run.id}\t{'ok' if run.ok else 'failed'}")
        if run.failed_steps:
            raise ValueError("Validation failed at: " + ", ".join(run.failed_steps))
    elif args.command == "validation-runs":
        for run in workbench.validation_runs():
            if args.profile and run.profile_id != args.profile:
                continue
            failed = ",".join(run.failed_steps) or "none"
            print(f"{run.id}\t{run.profile_id}\t{run.model}\t{failed}")
    elif args.command == "plan-comparison":
        targets = comparison_targets(args, store)
        chosen = workbench.plan_model_comparison(
            args.scenario_id,
            targets,
            trials=args.trials,
            rubric=store.rubric(args.rubric) if args.rubric else None,
            authorization=args.authorization
            or "Synthetic scenario comparison with synthetic tools only",
            allow_network=args.allow_network,
            name=args.name,
        )
        print(f"{chosen.id}\t{chosen.status}\tmodels={len(chosen.entries)}")
        for entry in chosen.entries:
            print(f"  model\t{entry.provider}/{entry.model or entry.agent}\t{entry.experiment_id}")
        for note in chosen.notes:
            print(f"  note\t{note.kind}\t{note.severity}\t{note.message}")
    elif args.command == "comparisons":
        for chosen in workbench.model_comparisons():
            print(
                f"{chosen.id}\t{chosen.status}\t{chosen.scenario_id}\tmodels={len(chosen.entries)}"
            )
    elif args.command == "run-comparison":
        chosen = store.model_comparison(args.comparison_id)
        if chosen.allow_network and not args.allow_network:
            raise ValueError("This comparison requires --allow-network to execute")
        finished = asyncio.run(
            workbench.execute_model_comparison(args.comparison_id, limit=args.limit)
        )
        print(f"{finished.id}\t{finished.status}\tmodels={len(finished.entries)}")
        for entry in finished.entries:
            print(
                f"  model\t{entry.provider}/{entry.model or entry.agent}\t"
                f"pairs={entry.summary.complete_pairs}\ttrials={entry.trial_count}"
            )
    elif args.command == "comparison-report":
        for path in export_report(workbench.comparison_report(args.comparison_id), args.output):
            print(path)
    elif args.command == "benchmarks":
        for suite in workbench.benchmarks().values():
            print(f"{suite.id}\t{suite.version}\t{len(suite.scenario_ids)}\t{suite.title}")
    elif args.command == "plan-benchmark":
        targets = comparison_targets(args, store)
        plan_value = workbench.plan_benchmark(
            args.suite_id,
            targets,
            trials=args.trials,
            limits=BenchmarkLimits(
                **{
                    key: value
                    for key, value in {
                        "max_scenarios": args.max_scenarios,
                        "max_trials_per_scenario": args.max_trials,
                        "max_total_requests": args.max_requests,
                        "max_total_tokens": args.max_tokens,
                        "max_runtime_seconds": args.max_runtime,
                        "max_estimated_spend_usd": args.max_spend,
                        "estimated_cost_per_request_usd": args.estimated_cost_per_request,
                    }.items()
                    if value is not None
                }
            ),
            authorization=args.authorization,
            allow_network=args.allow_network,
        )
        print(
            f"{plan_value.id}\t{plan_value.status}\tscenarios={len(plan_value.results)}\t"
            f"models={len(plan_value.model_labels)}"
        )
    elif args.command == "benchmark-plans":
        for plan_value in workbench.benchmark_plans():
            print(
                f"{plan_value.id}\t{plan_value.status}\t{plan_value.suite.id}\t"
                f"rows={len(plan_value.results)}"
            )
    elif args.command == "run-benchmark":
        plan_value = store.benchmark_plan(args.plan_id)
        if plan_value.allow_network and not args.allow_network:
            raise ValueError("This benchmark requires --allow-network to execute")
        finished = asyncio.run(workbench.execute_benchmark(args.plan_id, limit=args.limit))
        counts: dict[str, int] = {}
        for row in finished.results:
            counts[row.status] = counts.get(row.status, 0) + 1
        print(
            f"{finished.id}\t{finished.status}\t"
            + "\t".join(f"{key}={value}" for key, value in sorted(counts.items()))
        )
    elif args.command == "benchmark-status":
        plan_value = store.benchmark_plan(args.plan_id)
        print(f"{plan_value.id}\t{plan_value.status}\t{plan_value.suite.id}")
        for row in plan_value.results:
            print(
                f"{row.scenario_id}\t{row.model_label}\t{row.status}\t"
                f"{row.experiment_id or '-'}\t{row.skipped_reason or row.error or ''}"
            )
    elif args.command == "benchmark-report":
        for path in export_report(workbench.benchmark_report(args.plan_id), args.output):
            print(path)
    elif args.command == "version":
        facts = build_facts()
        for key, value in facts.items():
            print(f"{key}	{value}")
    elif args.command == "doctor":
        report = diagnose(store)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            for key, value in report.items():
                print(f"{key}	{value}")
            if report["problems"]:
                raise ValueError("Doctor found problems: " + ", ".join(report["problems"]))
    elif args.command == "verify-report":
        finding = validate_export(args.path)
        if args.json:
            print(finding.model_dump_json(indent=2))
        else:
            print(
                f"{finding.path}	{finding.origin}	{finding.report_format_version}	"
                f"checks={finding.checks_run}	errors={len(finding.errors)}"
            )
            for issue in finding.issues:
                print(f"{issue.severity}	{issue.code}	{issue.location}	{issue.message}")
        if not finding.ok:
            raise ValueError(
                "Report validation found blocking issues: "
                + ", ".join(sorted({issue.code for issue in finding.errors}))
            )
    elif args.command in {"smoke-plan", "run-smoke"}:
        profile = store.profile(args.profile)
        plan_value = plan_smoke(
            profile,
            args.scenario,
            model=args.model,
            allow_network=args.allow_network,
            authorization=args.authorization,
            max_output_tokens=args.max_output_tokens,
            max_requests=args.max_requests,
            timeout_seconds=args.timeout,
            max_estimated_spend_usd=args.max_spend,
            estimated_cost_per_request_usd=args.estimated_cost_per_request,
        )
        print(plan_value.model_dump_json(indent=2))
        if args.command == "smoke-plan":
            print("No request was sent. To execute this plan exactly as printed:")
            for command in plan_value.commands:
                print(f"  {command}")
        else:
            run = asyncio.run(
                execute_smoke(
                    workbench,
                    plan_value,
                    output_prefix=args.output,
                )
            )
            for step in run.steps:
                print(f"{step.name}	{step.status}	{step.detail}")
            print(f"validation	{run.id}	{'ok' if run.ok else 'failed'}")
            if run.failed_steps:
                raise ValueError("Smoke test failed at: " + ", ".join(run.failed_steps))
    elif args.command == "experiment-quality":
        quality = workbench.experiment_quality(args.experiment_id)
        print(quality.model_dump_json(indent=2))
    elif args.command == "agreement":
        report = workbench.agreement(
            experiment_id=args.experiment, batch_id=args.batch, trace_id=args.trace
        )
        print(report.model_dump_json(indent=2))
    elif args.command == "rubric-conformance":
        if args.pack:
            result = check_pack(args.pack)
        elif args.path:
            result = check_rubric(import_rubric(args.path))
        elif args.rubric:
            result = check_rubric(store.rubric(args.rubric))
        else:
            raise ValueError("Choose a conformance pack, a rubric file or a stored rubric")
        print(result.summary())
        print(result.model_dump_json(indent=2))
    elif args.command == "migrate":
        print(f"schema_version\t{store.schema_version}")
    elif args.command == "reevaluate":
        session = workbench.reevaluate(args.run_id, store.rubric(args.rubric))
        print(f"{session.id}\t{session.rubric.definition.version}\t{session.execution_sha256}")
        if args.output:
            run = store.run(args.run_id)
            for path in export_report(workbench.report(run.experiment_id), args.output):
                print(path)
    elif args.command == "start-review":
        session = workbench.start_human_session(args.run_id, store.rubric(args.rubric))
        print(f"{session.id}\t{session.status}")
    elif args.command == "sessions":
        for session in store.sessions(experiment_id=args.experiment, run_id=args.run):
            assert session.rubric.definition is not None
            definition = session.rubric.definition
            print(
                f"{session.id}\t{session.origin}\t{session.status}\t"
                f"{definition.id}@{definition.version}\t{session.run_id}"
            )
    elif args.command == "judge":
        judgment = workbench.record_judgment(
            args.session_id,
            args.criterion_id,
            reviewer=args.reviewer,
            outcome=args.outcome,
            rationale=args.rationale,
            label=args.label,
            score=args.score,
            confidence=args.confidence,
            supersedes_id=args.supersedes,
        )
        print(judgment.id)
    elif args.command == "adjudicate":
        recorded = workbench.adjudicate(
            args.session_id,
            policy=AdjudicationPolicy(kind=args.policy, reviewer=args.designated_reviewer),
            reviewer=args.reviewer,
            rationale=args.rationale,
        )
        for value in recorded:
            outcome = value.outcome or "unresolved"
            print(f"{value.id}\t{value.criterion_id}\t{value.status}\t{outcome}")
    elif args.command == "disagreements":
        for item in workbench.report(args.experiment_id).disagreements:
            print(item.model_dump_json())


def main() -> None:
    p = parser()
    args = p.parse_args()
    try:
        dispatch(args)
    except (ValidationError, OSError, sqlite3.Error, yaml.YAMLError, UnicodeError):
        # Validation errors may include input values. Print controlled context only.
        p.exit(
            2,
            "Faultline could not complete the operation. Check scope, budgets, rubric schema, "
            "IDs, credential environment and file paths; inspect history for partial runs.\n",
        )
    except ValueError as exc:
        # Application policy errors contain controlled messages, never input snapshots.
        p.exit(2, f"Faultline: {exc}\n")


if __name__ == "__main__":
    main()
