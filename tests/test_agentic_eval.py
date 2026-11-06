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
