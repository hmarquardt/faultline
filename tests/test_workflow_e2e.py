"""The complete professional evaluator workflow, offline and repeatable."""

import importlib.util
import json
import sys
from pathlib import Path

from faultline.domain import AdjudicationPolicy
from faultline.reportcheck import validate_export
from faultline.reports import verify_export_digest
from faultline.service import Workbench
from faultline.storage import Store

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "evaluator_workflow.py"


def load_script():
    if "evaluator_workflow" in sys.modules:
        return sys.modules["evaluator_workflow"]
    spec = importlib.util.spec_from_file_location("evaluator_workflow", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["evaluator_workflow"] = module
    spec.loader.exec_module(module)
    return module


def test_the_documented_workflow_completes_and_verifies(tmp_path, capsys):
    module = load_script()
    database = tmp_path / "workflow.sqlite3"
    output = tmp_path / "out"
    output.mkdir()
    assert module.run(database, output) == 0
    transcript = capsys.readouterr().out
    for step in (
        "import-rubric",
        "conformance",
        "plan-experiment",
        "run-experiment",
        "inspect-trace",
        "record-judgments",
        "agreement",
        "adjudicate",
        "paired-statistics",
        "export",
        "verify-report",
        "reopen-and-verify",
    ):
        assert step in transcript
    assert "errors=0" in transcript
    assert "digest=ok" in transcript
    # The export is machine-readable and passes its own audit.
    payload = json.loads((output / "workflow.json").read_text())
    assert payload["origin"] == "controlled_experiment"
    assert validate_export(output / "workflow.json").ok
    # Judgments and adjudications survived the reopen.
    store = Store(database)
    judgments = store.judgments()
    assert len(judgments) == 4
    assert {judgment.reviewer for judgment in judgments} == {"Alice", "Bob"}
    assert any(judgment.outcome == "not_applicable" for judgment in judgments)
    assert store.adjudications()
    workbench = Workbench(store)
    report = workbench.experiment_report(payload["experiment"]["id"])
    assert verify_export_digest(report)
    assert report.effective_results
    trial = next(item for item in store.trials(payload["experiment"]["id"]) if item.attack)
    agreement = workbench.agreement(trace_id=trial.attack_trace_id)
    assert agreement.applicability_disputes
    assert agreement.units_not_applicable_disputed >= 1


def test_workflow_reports_a_disagreement_and_an_explicit_resolution(tmp_path):
    module = load_script()
    database = tmp_path / "disagreement.sqlite3"
    output = tmp_path / "out"
    output.mkdir()
    assert module.run(database, output) == 0
    store = Store(database)
    workbench = Workbench(store)
    experiment_id = store.controlled_experiments()[0].id
    summary = workbench.experiment_summary(experiment_id)
    assert summary.complete_pairs >= 1
    session = store.sessions_for_trace(
        [t for t in store.trials(experiment_id) if t.attack is not None][0].attack_trace_id
    )[0]
    effective = [
        item
        for item in workbench.experiment_report(experiment_id).effective_results
        if item.session_id == session.id
    ]
    assert effective
    assert any(item.effective_source == "adjudicated" for item in effective)
    trial = next(item for item in store.trials(experiment_id) if item.attack is not None)
    trace = store.agentic_trace(trial.attack_trace_id)
    assert trace.status == "completed"
    assert trace.invocations
    # Adjudication stayed explicit and append-only.
    before = len(store.adjudications(session_id=session.id))
    workbench.adjudicate(
        session.id,
        policy=AdjudicationPolicy(kind="unanimous"),
        reviewer="Alice",
        rationale="second explicit pass",
    )
    after = store.adjudications(session_id=session.id)
    assert len(after) > before
    assert all(item.session_id == session.id for item in after)
