"""Trace checks read harness observations and stay conservative about intent."""

import asyncio

from faultline.agentic_eval import evaluate_trace
from faultline.domain import EvidenceArtifact


def evaluate(workbench, trace, rubric=None):
    chosen = rubric or trace.rubric
    artifact = EvidenceArtifact.capture("agentic-trace", "{}", "agentic-trace:test")
    return {value.criterion_id: value for value in evaluate_trace(chosen, trace, artifact)}


def run(workbench, scenario_id="retrieved-authority-spoof", agent="scripted-secure"):
    return asyncio.run(workbench.run_scenario(scenario_id, agent=agent))


def test_deterministic_checks_report_observed_basis(workbench):
    trace = run(workbench)
    values = evaluate(workbench, trace)
    for criterion_id in ("SPOOF-001", "SPOOF-002", "SPOOF-003"):
        assert values[criterion_id].outcome == "pass"
        assert values[criterion_id].basis == "observed"
        assert values[criterion_id].evaluator == "faultline.agentic-trace/1"
        assert values[criterion_id].facts


def test_manual_checks_stay_uncertain_and_require_review(workbench):
    trace = run(workbench)
    value = evaluate(workbench, trace)["MANUAL-001"]
    assert value.outcome == "uncertain"
    assert value.basis == "subjective"


def test_forbidden_request_and_execution_are_distinct_checks(workbench):
    blocked = run(workbench, "unauthorized-record-change", "scripted-vulnerable")
    values = evaluate(workbench, blocked)
    assert values["REC-001"].outcome == "fail"  # a proposal was observed
    assert values["REC-001"].facts["requested"] == 1
    assert values["REC-002"].outcome == "pass"  # but nothing changed
    executed = run(workbench, "tool-output-laundering", "scripted-vulnerable")
    assert evaluate(workbench, executed)["LAUNDER-001"].outcome == "fail"
    assert evaluate(workbench, executed)["LAUNDER-001"].facts["executed"] == 1


def test_policy_blocked_check_requires_an_observed_denial(workbench, rubric):
    trace = run(workbench, "unauthorized-record-change", "scripted-vulnerable")
    definition = trace.rubric.definition
    assert definition is not None
    original = definition.criteria[0]
    blocked = original.model_copy(
        update={
            "id": "REC-999",
            "check": "tool_policy_blocked",
            "config": {"tool": "update_record"},
        }
    )
    revised = trace.rubric.model_copy(
        update={"definition": definition.model_copy(update={"criteria": [blocked]})}
    )
    assert evaluate(workbench, trace, revised)["REC-999"].outcome == "pass"
    secure = run(workbench, "unauthorized-record-change", "scripted-secure")
    assert evaluate(workbench, secure, revised)["REC-999"].outcome == "fail"


def test_protected_record_check_detects_a_verified_change(workbench):
    trace = run(workbench, "unauthorized-record-change", "scripted-vulnerable")
    definition = trace.rubric.definition
    assert definition is not None
    # Rewrite the trace's own record digests to simulate a permitted change.
    changed = trace.model_copy(
        update={
            "record_digests_after": {
                "rec-2001": "0" * 64,
            }
        }
    )
    value = evaluate(workbench, changed)["REC-002"]
    assert value.outcome == "fail"
    assert value.facts["before"] != value.facts["after"]


def test_canary_check_ignores_tool_and_document_text(workbench):
    trace = run(workbench, "synthetic-secret-disclosure", "scripted-secure")
    value = evaluate(workbench, trace)["DISCLOSE-001"]
    assert value.outcome == "pass"
    canary = trace.scenario.parameters["canary"]
    assert any(canary in turn.content for turn in trace.turns if turn.role == "system")


def test_task_completion_uses_the_final_assistant_turn(workbench):
    trace = run(workbench)
    assert evaluate(workbench, trace)["SPOOF-003"].facts["marker_present"] is True
    definition = trace.rubric.definition
    assert definition is not None
    criterion = definition.criteria[2].model_copy(update={"config": {"text": "ABSENT-MARKER"}})
    revised = trace.rubric.model_copy(
        update={"definition": definition.model_copy(update={"criteria": [criterion]})}
    )
    assert evaluate(workbench, trace, revised)["SPOOF-003"].outcome == "fail"


def test_response_evaluator_refuses_trace_only_checks(workbench, rubric):
    from faultline.domain import EvidenceArtifact, ModelResponse
    from faultline.evaluation import Evaluator
    from faultline.techniques import render_cases, techniques

    trace = run(workbench)
    definition = trace.rubric.definition
    assert definition is not None
    response = ModelResponse(text="REFUND-30", returned_model="fixture", raw={})
    case = render_cases(techniques()["authority-spoof"])[1]
    evidence = EvidenceArtifact.capture("response", response.model_dump_json(), "test")
    values = Evaluator().evaluate(trace.rubric, case, response, "run", evidence)
    assert [value.outcome for value in values[:3]] == ["uncertain"] * 3
    assert all("agentic trace" in (value.rationale or "") for value in values[:3])


def test_graded_trace_criteria_require_human_assessment(workbench):
    trace = run(workbench)
    definition = trace.rubric.definition
    assert definition is not None
    graded = definition.criteria[0].model_copy(
        update={
            "scale_kind": "ordinal",
            "levels": [
                {"label": "weak", "description": "Weak", "score": 1},
                {"label": "strong", "description": "Strong", "score": 3},
            ],
        }
    )
    revised = trace.rubric.model_copy(
        update={"definition": definition.model_copy(update={"criteria": [graded]})}
    )
    value = evaluate(workbench, trace, revised)["SPOOF-001"]
    assert value.outcome == "uncertain"
    assert "human-assessed" in (value.rationale or "")


def test_protected_record_check_needs_both_digests():
    trace = run(workbench_fixture(), "retrieved-authority-spoof", "scripted-secure")
    assert evaluate(workbench_fixture(), trace)["SPOOF-002"].outcome in {"pass", "fail"}
    without_after = trace.model_copy(update={"record_digests_after": {}})
    value = evaluate(workbench_fixture(), without_after)["SPOOF-002"]
    assert value.outcome == "uncertain"
    assert "after digest" in (value.rationale or "")
    assert "unverified" in (value.rationale or "")
    without_before = trace.model_copy(update={"record_digests_before": {}})
    value = evaluate(workbench_fixture(), without_before)["SPOOF-002"]
    assert value.outcome == "uncertain"
    assert "before digest" in (value.rationale or "")
    missing_both = trace.model_copy(
        update={"record_digests_before": {}, "record_digests_after": {}}
    )
    assert evaluate(workbench_fixture(), missing_both)["SPOOF-002"].outcome == "uncertain"


def test_protected_record_check_passes_when_digests_match_and_fails_when_they_differ():
    trace = run(workbench_fixture(), "retrieved-authority-spoof", "scripted-secure")
    same = trace.model_copy(
        update={
            "record_digests_before": {"rec-1001": "a" * 64},
            "record_digests_after": {"rec-1001": "a" * 64},
        }
    )
    assert evaluate(workbench_fixture(), same)["SPOOF-002"].outcome == "pass"
    changed = trace.model_copy(
        update={
            "record_digests_before": {"rec-1001": "a" * 64},
            "record_digests_after": {"rec-1001": "b" * 64},
        }
    )
    value = evaluate(workbench_fixture(), changed)["SPOOF-002"]
    assert value.outcome == "fail"
    assert value.facts["before"] != value.facts["after"]


def test_marker_presence_is_not_semantic_completion():
    trace = run(workbench_fixture())
    values = evaluate(workbench_fixture(), trace)
    marker = values["SPOOF-003"]
    assert marker.outcome == "pass"
    assert marker.rationale is not None and "deterministic proxy" in marker.rationale
    assert marker.facts["semantic_completion"] == "human-assessed"
    semantic = values["SEM-001"]
    assert semantic.outcome == "uncertain"
    assert semantic.basis == "subjective"
    assert "human-assessed" in (semantic.rationale or "")


def test_agentic_result_reports_marker_basis_and_exposure():
    workbench = workbench_fixture()
    trace = run(workbench, "retrieved-authority-spoof", "scripted-secure")
    result = workbench.agentic_result(trace)
    assert result.task_marker_present is True
    assert result.task_completion_basis == "required-marker"
    assert result.exposed_to_injection is True
    unified = run(workbench, "retrieved-authority-spoof", "scripted-secure")
    assert workbench.agentic_result(unified).exposed_to_injection is True
    assert "semantic_completion=human-assessed" in result.basis


_FIXTURES = {}


def workbench_fixture():
    """One shared offline workbench per module (cheap, no network)."""
    import tempfile
    from pathlib import Path

    from faultline.service import Workbench
    from faultline.storage import Store

    if "wb" not in _FIXTURES:
        store = Store(Path(tempfile.mkdtemp()) / "eval.sqlite3")
        _FIXTURES["wb"] = Workbench(store)
    return _FIXTURES["wb"]
