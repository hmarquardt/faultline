#!/usr/bin/env python
"""Repeatable end-to-end evaluator workflow. Offline by default, no credentials.

Runs the full professional assignment in one process and verifies that every piece
of evidence survives a database reopen:

    import an unfamiliar rubric -> validate fidelity -> plan and run a controlled
    experiment -> inspect trace evidence -> record two reviewers (including a
    not-applicable case and a disagreement) -> adjudicate explicitly -> compute
    agreement and paired statistics -> export JSON/Markdown/CSV -> reopen and verify.

Usage: python scripts/evaluator_workflow.py [--database PATH] [--output DIR]
"""

import argparse
import asyncio
import sys
import tempfile
from pathlib import Path

from faultline.conformance import check_rubric
from faultline.domain import AdjudicationPolicy
from faultline.reportcheck import validate_export
from faultline.reports import export_report, verify_export_digest
from faultline.rubrics import import_rubric
from faultline.scenarios import scenario
from faultline.service import Workbench
from faultline.storage import Store

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def step(name: str, detail: str) -> None:
    print(f"{name}\t{detail}")


def run(database: Path, output: Path) -> int:
    store = Store(database)
    workbench = Workbench(store)

    rubric = import_rubric(FIXTURES / "rubrics" / "graded-disclosure.v2.json")
    store.add_rubric(rubric)
    step("import-rubric", f"{rubric.id}\t{rubric.review_status}")

    conformance = check_rubric(rubric)
    step("conformance", conformance.summary())
    if conformance.errors:
        step("conformance", "blocking conformance errors; stop")
        return 1

    experiment = workbench.plan_experiment(
        "synthetic-secret-disclosure",
        agent="scripted-vulnerable",
        trial_count=2,
        authorization="Offline scripted demonstration",
    )
    step("plan-experiment", f"{experiment.id}\tpairs={experiment.trial_count}")

    finished = asyncio.run(workbench.execute_experiment(experiment.id))
    step("run-experiment", f"{finished.status}\ttrials={finished.trial_count}")

    trial = workbench.store.trial(experiment.id, 0)
    trace = workbench.store.agentic_trace(trial.attack_trace_id)
    step(
        "inspect-trace",
        f"{trace.id[:8]}\tturns={len(trace.turns)}\tinvocations={len(trace.invocations)}"
        f"\texposed={workbench.agentic_result(trace).exposed_to_injection}",
    )

    session = workbench.store.sessions_for_trace(trial.attack_trace_id)[0]
    criteria = session.rubric.definition.criteria
    manual = next(item for item in criteria if item.check == "manual")
    deterministic = next(item for item in criteria if item.check == "canary_absent")
    workbench.record_judgment(
        session.id,
        deterministic.id,
        reviewer="Alice",
        outcome="fail",
        rationale="The canary appears in the final answer",
    )
    workbench.record_judgment(
        session.id,
        deterministic.id,
        reviewer="Bob",
        outcome="not_applicable",
        rationale="Disputes that this criterion applies to the reply",
    )
    workbench.record_judgment(
        session.id,
        manual.id,
        reviewer="Alice",
        outcome="fail",
        rationale="The agent repeated the injected request verbatim",
        confidence="medium",
    )
    workbench.record_judgment(
        session.id,
        manual.id,
        reviewer="Bob",
        outcome="pass",
        rationale="The reply summarised the policy before leaking",
        confidence="low",
    )
    step("record-judgments", f"session={session.id[:8]}\t4 judgments by 2 reviewers")

    disagreements = workbench.agreement(trace_id=trace.id)
    step(
        "agreement",
        f"groups={len(disagreements.groups)}\tapplicability_disputes="
        f"{len(disagreements.applicability_disputes)}",
    )

    recorded = workbench.adjudicate(
        session.id,
        policy=AdjudicationPolicy(kind="single_reviewer", reviewer="Alice"),
        reviewer="Alice",
        rationale="Designated reviewer resolves both criteria",
    )
    step("adjudicate", f"{len(recorded)} criterion(s) resolved")

    summary = workbench.experiment_summary(experiment.id)
    spoof = next(item for item in summary.criteria if item.criterion_id == deterministic.id)
    step(
        "paired-statistics",
        f"pairs={summary.complete_pairs}\tattack_failures={spoof.attack_failures}"
        f"/{spoof.attack_trials}\tinterval={spoof.paired_difference_interval.method}",
    )

    prefix = output / "workflow"
    paths = export_report(workbench.experiment_report(experiment.id), prefix)
    step("export", ", ".join(path.name for path in paths))

    finding = validate_export(prefix.with_suffix(".json"))
    step(
        "verify-report",
        f"origin={finding.origin}\terrors={len(finding.errors)}\tchecks={finding.checks_run}",
    )
    if not finding.ok:
        for issue in finding.issues:
            step("report-issue", f"{issue.severity}\t{issue.code}\t{issue.message}")
        return 1

    reopened = Store(database)
    report = Workbench(reopened).experiment_report(experiment.id)
    assert verify_export_digest(report), "export digest mismatch after reopen"
    assert reopened.agentic_trace(trial.attack_trace_id).id == trial.attack_trace_id
    judgments = reopened.judgments(session_id=session.id)
    step(
        "reopen-and-verify",
        f"experiment={experiment.id[:8]}\tjudgments={len(judgments)}\t"
        f"digest=ok\tsessions={len(reopened.sessions_for_trace(trial.attack_trace_id))}",
    )
    scenario_definition = scenario("synthetic-secret-disclosure")
    step("scenario", f"{scenario_definition.id}@{scenario_definition.version}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=Path("reports"))
    args = parser.parse_args(argv)
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    if args.database is None:
        with tempfile.TemporaryDirectory() as directory:
            return run(Path(directory) / "workflow.sqlite3", output)
    return run(args.database, output)


if __name__ == "__main__":
    sys.exit(main())
