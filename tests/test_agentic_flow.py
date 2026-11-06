"""Agentic persistence, offline re-evaluation, review, reporting and migration."""

import asyncio
import sqlite3

import pytest

from faultline.domain import AdjudicationPolicy
from faultline.reports import csv_export, markdown, verify_export_digest, with_export_digest
from faultline.scenarios import rubric_for, scenario


def run(workbench, scenario_id="retrieved-authority-spoof", agent="scripted-secure", **kwargs):
    return asyncio.run(workbench.run_scenario(scenario_id, agent=agent, **kwargs))


def test_trace_is_persisted_with_an_evaluation_session(tmp_path, workbench):
    trace = run(workbench)
    assert trace.status == "completed"
    stored = workbench.trace(trace.id)
    assert stored.execution_sha256 == trace.execution_sha256
    assert stored.turns == trace.turns
    assert [item.id for item in workbench.traces()] == [trace.id]
    (session,) = workbench.trace_sessions(trace.id)
    assert session.evidence_kind == "agentic"
    assert session.agentic_trace_id == trace.id
    assert session.run_id is None and session.experiment_id is None
    assert session.origin == "agentic_execution"
    assert {artifact.kind for artifact in session.evidence} == {
        "scenario-source",
        "agentic-trace",
    }


def test_stored_trace_supports_offline_reevaluation(workbench):
    trace = run(workbench)
    alternative = rubric_for(scenario("retrieved-authority-spoof"))
    assert alternative.definition is not None
    revised = alternative.definition.model_copy(
        update={
            "criteria": [
                alternative.definition.criteria[0].model_copy(
                    update={"instructions": "Re-worded criterion"}
                ),
                *alternative.definition.criteria[1:],
            ]
        }
    )
    alternative = alternative.model_copy(update={"definition": revised})
    session = asyncio.run(workbench.reevaluate_agentic(trace.id, alternative))
    assert session.origin == "reevaluation"
    assert session.agentic_trace_id == trace.id
    assert session.execution_sha256 == trace.execution_sha256
    # Re-evaluation never re-runs the agent: the trace is unchanged.
    assert workbench.trace(trace.id).turns == trace.turns
    assert len(workbench.trace_sessions(trace.id)) == 2


def test_judgments_and_adjudication_work_on_agentic_sessions(workbench):
    trace = run(workbench)
    (session,) = workbench.trace_sessions(trace.id)
    workbench.record_judgment(
        session.id, "MANUAL-001", reviewer="Alice", outcome="fail", rationale="Adopted memo"
    )
    workbench.record_judgment(
        session.id, "MANUAL-001", reviewer="Bob", outcome="pass", rationale="Ignored memo"
    )
    recorded = workbench.adjudicate(
        session.id,
        policy=AdjudicationPolicy(kind="single_reviewer", reviewer="Alice"),
        reviewer="Alice",
        rationale="Humans disagree about adoption",
    )
    assert recorded[0].criterion_id == "MANUAL-001"
    agreement = workbench.agreement(trace_id=trace.id)
    assert agreement.scope == "agentic_trace"
    assert agreement.reviewers == ["Alice", "Bob"]


def test_agentic_report_separates_simulation_from_observation(workbench):
    trace = run(workbench, "tool-output-laundering", "scripted-vulnerable")
    report = workbench.agentic_report(trace.id)
    assert report.origin == "agentic"
    assert report.result.verdict == "compromised"
    text = markdown(report)
    assert "synthetic, simulated" in text
    assert "No external system, mailbox or record store was touched" in text
    assert "A denied request is evidence of intent, not of a compromise" in text
    assert report.export_digest is not None
    exported = with_export_digest(report)
    assert verify_export_digest(exported)
    rows = csv_export(exported).splitlines()
    assert len(rows) == 1 + len(exported.evaluation_sessions[0].evaluations)
    assert rows[1].startswith("agentic,")


def test_dry_run_stores_a_plan_without_a_conversation(workbench):
    trace = run(workbench, dry_run=True)
    assert trace.status == "dry_run"
    assert trace.turns == [] and trace.invocations == []
    assert workbench.trace_sessions(trace.id) == []
    assert workbench.trace(trace.id).status == "dry_run"


def test_finished_trace_cannot_be_rewritten_or_deleted(workbench):
    trace = run(workbench)
    finished = workbench.trace(trace.id)
    with pytest.raises(ValueError):
        workbench.store.save_agentic_trace(finished)
    with pytest.raises(sqlite3.IntegrityError), workbench.store.connect() as db:
        db.execute("DELETE FROM agentic_traces WHERE id=?", (trace.id,))
    assert workbench.store.agentic_trace(trace.id).status == "completed"


def test_cancelled_trace_preserves_partial_evidence(workbench):
    state = {"calls": 0}

    def cancel() -> bool:
        state["calls"] += 1
        return state["calls"] >= 2

    trace = run(workbench, should_cancel=cancel)
    assert trace.status == "cancelled"
    assert trace.termination == "cancelled"
    assert trace.turns  # everything recorded before cancellation survives
    stored = workbench.trace(trace.id)
    assert stored.status == "cancelled"
    assert len(stored.turns) == len(trace.turns)
    assert workbench.trace_sessions(trace.id) == []


def test_missing_capability_and_scope_are_rejected(workbench, profile):
    with pytest.raises(ValueError, match="authorized profile"):
        run(workbench, agent="endpoint")
    workbench.store.add_profile(profile)
    with pytest.raises(ValueError, match="tool-calling"):
        run(workbench, agent="endpoint", profile=profile)


def test_agentic_trace_survives_reopening_the_database(tmp_path, workbench):
    trace = run(workbench)
    from faultline.storage import Store

    reopened = Store(workbench.store.path)
    assert reopened.agentic_trace(trace.id).execution_sha256 == trace.execution_sha256
    assert len(reopened.sessions_for_trace(trace.id)) == 1


def test_phase2b_database_migrates_and_keeps_agentic_sessions(tmp_path, workbench):
    trace = run(workbench)
    (session,) = workbench.trace_sessions(trace.id)
    from faultline.storage import SCHEMA_VERSION, Store

    assert workbench.store.schema_version == SCHEMA_VERSION == 6
    with workbench.store.connect() as db:
        db.execute("PRAGMA user_version=3")
    downgraded = Store(workbench.store.path)
    assert downgraded.schema_version == 6
    assert downgraded.session(session.id).id == session.id
    assert downgraded.agentic_trace(trace.id).id == trace.id
    with downgraded.connect() as db:
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
