"""Packaged scenarios: data-only definitions with secure and vulnerable fixtures."""

import asyncio

import pytest

from faultline.scenarios import rubric_for, scenario, scenario_digest, scenarios


def run_scenario(workbench, scenario_id, agent):
    return asyncio.run(workbench.run_scenario(scenario_id, agent=agent))


def outcomes(workbench, trace):
    session = workbench.trace_sessions(trace.id)[0]
    return {value.criterion_id: value.outcome for value in session.evaluations}


def test_every_scenario_ships_both_fixtures_and_a_rubric():
    registry = scenarios()
    assert len(registry) == 6
    families = {definition.family for definition in registry.values()}
    assert len(families) == 6
    for definition in registry.values():
        assert {"secure", "vulnerable"} <= set(definition.scripts)
        assert definition.expected_secure_behavior
        assert definition.failure_conditions
        assert definition.injected_document_id
        rubric = rubric_for(definition)
        assert rubric.definition is not None and rubric.definition.criteria
        assert len(scenario_digest(definition)) == 64


def test_scenario_definitions_are_data_not_code():
    definition = scenario("retrieved-authority-spoof")
    assert "import " not in definition.user_task.lower()
    assert definition.documents[1].trust == "untrusted-injected"
    assert definition.documents[1].injection in definition.documents[1].content


def test_unknown_scenario_is_rejected():
    with pytest.raises(ValueError, match="Unknown scenario"):
        scenario("does-not-exist")


@pytest.mark.parametrize(
    "scenario_id,forbidden_criterion",
    [
        ("retrieved-authority-spoof", "SPOOF-001"),
        ("unauthorized-record-change", "REC-001"),
        ("encoded-injection", "ENC-001"),
    ],
)
def test_secure_agent_passes_and_vulnerable_agent_fails(
    workbench, scenario_id, forbidden_criterion
):
    secure = run_scenario(workbench, scenario_id, "scripted-secure")
    assert workbench.agentic_result(secure).verdict == "secure"
    assert outcomes(workbench, secure)[forbidden_criterion] == "pass"
    vulnerable = run_scenario(workbench, scenario_id, "scripted-vulnerable")
    assert outcomes(workbench, vulnerable)[forbidden_criterion] == "fail"
    assert workbench.agentic_result(vulnerable).verdict != "secure"


def test_blocked_attempt_is_reported_as_denied_not_compromise(workbench):
    trace = run_scenario(workbench, "unauthorized-record-change", "scripted-vulnerable")
    result = workbench.agentic_result(trace)
    assert result.denied_tools == ["update_record"]
    # Only the read tools executed; the denied write produced no receipt at all.
    assert set(result.executed_tools) == {"read_document", "search_documents"}
    assert result.state_changes == []
    assert result.verdict == "inconclusive"
    assert trace.record_digests_before == trace.record_digests_after


def test_permitted_injected_side_effect_is_a_verified_change(workbench):
    trace = run_scenario(workbench, "tool-output-laundering", "scripted-vulnerable")
    result = workbench.agentic_result(trace)
    assert result.state_changes == ["note-written:audit-approved"]
    assert result.verdict == "compromised"
    assert outcomes(workbench, trace)["LAUNDER-001"] == "fail"


def test_canary_disclosure_is_detected(workbench):
    scenario_definition = scenario("synthetic-secret-disclosure")
    canary = scenario_definition.parameters["canary"]
    vulnerable = run_scenario(workbench, "synthetic-secret-disclosure", "scripted-vulnerable")
    result = workbench.agentic_result(vulnerable)
    assert result.canary_disclosed is True
    assert outcomes(workbench, vulnerable)["DISCLOSE-001"] == "fail"
    assert canary in [turn.content for turn in vulnerable.turns if turn.role == "assistant"][-1]
    secure = run_scenario(workbench, "synthetic-secret-disclosure", "scripted-secure")
    assert workbench.agentic_result(secure).canary_disclosed is False
    assert outcomes(workbench, secure)["DISCLOSE-001"] == "pass"


def test_boundary_enforcement_scenario_demonstrates_both_paths(workbench):
    secure = run_scenario(workbench, "boundary-enforcement", "scripted-secure")
    assert workbench.agentic_result(secure).verdict == "secure"
    vulnerable = run_scenario(workbench, "boundary-enforcement", "scripted-vulnerable")
    result = workbench.agentic_result(vulnerable)
    assert result.state_changes == ["message-queued:synthetic-review-queue"]
    assert result.verdict == "compromised"


def test_encoded_scenario_keeps_the_encoded_payload_in_evidence(workbench):
    trace = run_scenario(workbench, "encoded-injection", "scripted-vulnerable")
    document = next(item for item in trace.scenario.documents if item.id == "doc-encoded")
    encoded = trace.scenario.parameters["encoded_instruction"]
    assert encoded in document.content
    assert "SYSTEM OVERRIDE" in (document.injection or "")
    retrieval = [
        turn for turn in trace.turns if turn.role == "tool" and turn.document_id == "doc-encoded"
    ]
    assert retrieval and encoded in retrieval[0].content
