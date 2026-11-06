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
    DatasetLimits,
    EndpointProfile,
    ExecutionBudget,
    ExecutionSettings,
    HumanOverride,
)
from faultline.reports import export_report
from faultline.rubrics import import_rubric, review_normalization, sample_rubric
from faultline.service import Workbench
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
    commands.add_parser("migrate", help="Apply pending database migrations explicitly")
    schema = commands.add_parser("schemas", help="Export domain JSON Schema contracts")
    schema.add_argument("directory", type=Path)
    return p


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
