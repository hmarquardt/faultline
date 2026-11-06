"""Endpoint validation workflow: explicit steps, sanitized evidence, no fabrication."""

import asyncio
import json

import httpx
import pytest

from faultline.domain import EndpointProfile, ExecutionSettings, TargetModel
from faultline.providers import AgentEndpointProvider, CompatibleProvider


def profile(**changes):
    values = dict(
        name="Validation fixture",
        provider="openai-compatible",
        base_url="https://toy.invalid/v1",
        allowed_models=["toy-model"],
        authorized=True,
        authorization="Owner-approved validation fixture",
        tool_calling=True,
    )
    values.update(changes)
    return EndpointProfile(**values)


def tool_call_response():
    return {
        "model": "toy-model",
        "choices": [
            {
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": "read_document",
                                "arguments": json.dumps({"document_id": "doc-handbook"}),
                            },
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"completion_tokens": 5},
    }


def chat_response(content="REFUND-30"):
    return {
        "model": "toy-model",
        "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
        "usage": {"completion_tokens": 3},
    }


def handler_for_flow():
    seen = {"requests": 0}

    def handler(request):
        body = json.loads(request.content)
        seen["requests"] += 1
        roles = [message["role"] for message in body.get("messages", [])]
        if body.get("tools") and "tool" not in roles:
            return httpx.Response(200, json=tool_call_response())
        return httpx.Response(200, json=chat_response())

    return handler, seen


@pytest.fixture
def endpoint(workbench, monkeypatch):
    """Install an in-process transport for every endpoint call in the run."""
    prof = profile()
    workbench.store.add_profile(prof)
    handler, seen = handler_for_flow()
    transport = httpx.MockTransport(handler)

    def patched(
        scenario_definition,
        agent,
        target_profile,
        allow_network,
        script_key=None,
        settings=None,
    ):
        return AgentEndpointProvider(
            CompatibleProvider(target_profile, transport=transport),
            TargetModel(endpoint_id=prof.id, requested_model="toy-model"),
            settings or ExecutionSettings(),
        )

    monkeypatch.setattr(workbench, "_agent_provider", patched)
    return workbench, prof, seen, transport


def test_validation_records_every_step_and_persists(endpoint, tmp_path):
    workbench, prof, _, transport = endpoint
    # allow_network=True is the operator attestation; the transport stays in-process,
    # so no socket is ever opened (the offline fixture would fail otherwise).
    run = asyncio.run(
        workbench.run_validation(
            prof,
            scenario_id="retrieved-authority-spoof",
            trials=1,
            allow_network=True,
            transport=transport,
            output_prefix=tmp_path / "validation",
        )
    )
    statuses = {step.name: step.status for step in run.steps}
    assert statuses["authorization"] == "ok"
    assert statuses["capabilities"] == "ok"
    assert statuses["model_identity"] == "ok"
    assert statuses["tool_round_trip"] == "ok"
    assert statuses["evidence_sanitization"] == "ok"
    assert statuses["scenario_execution"] == "ok"
    assert statuses["tool_authorization"] == "ok"
    assert statuses["trace_evidence"] == "ok"
    assert statuses["controlled_experiment"] == "ok"
    assert statuses["report_export"] == "ok"
    assert run.ok
    assert run.capability_report_id and run.trace_id and run.experiment_id
    stored = workbench.store.validation_run(run.id)
    assert [step.name for step in stored.steps] == [step.name for step in run.steps]
    assert workbench.capability_report(run.capability_report_id).observed.chat_completions == (
        "supported"
    )


def test_validation_reports_missing_authorization_without_probing(workbench):
    prof = profile(authorized=False)
    workbench.store.add_profile(prof)
    run = asyncio.run(workbench.run_validation(prof))
    assert [step.name for step in run.steps] == ["authorization"]
    assert run.steps[0].status == "failed"
    assert run.failed_steps == ["authorization"]
    assert workbench.capability_reports() == []


def test_validation_reports_unresolved_credential(workbench, monkeypatch):
    monkeypatch.delenv("FAULTLINE_VALIDATION_KEY", raising=False)
    prof = profile(credential_env="FAULTLINE_VALIDATION_KEY")
    workbench.store.add_profile(prof)
    run = asyncio.run(workbench.run_validation(prof))
    statuses = {step.name: step.status for step in run.steps}
    assert statuses["authorization"] == "ok"
    assert statuses["credential"] == "failed"
    assert "FAULTLINE_VALIDATION_KEY" in run.steps[1].detail
    assert not run.ok


def test_validation_reports_capability_failure_as_failed_step(endpoint):
    workbench, prof, _, _ = endpoint

    def broken(request):
        return httpx.Response(400, json={"error": {"message": "model not found"}})

    run = asyncio.run(
        workbench.run_validation(
            prof,
            transport=httpx.MockTransport(broken),
            scenario_id="retrieved-authority-spoof",
            allow_network=True,
        )
    )
    statuses = {step.name: step.status for step in run.steps}
    assert statuses["capabilities"] == "failed"
    assert "model not found" in run.steps[-1].detail
    assert not run.ok
    # Later steps were never attempted.
    assert "scenario_execution" not in statuses


def test_validation_skips_export_without_an_output_prefix(endpoint):
    workbench, prof, _, transport = endpoint
    run = asyncio.run(workbench.run_validation(prof, transport=transport, allow_network=True))
    statuses = {step.name: step.status for step in run.steps}
    assert statuses["report_export"] == "skipped"
    assert run.ok


def test_validation_never_fabricates_a_tool_execution(endpoint):
    workbench, prof, _, transport = endpoint
    run = asyncio.run(workbench.run_validation(prof, transport=transport, allow_network=True))
    trace = workbench.trace(run.trace_id)
    # Tool activity comes from the scenario fixture, not from the probe.
    assert all(
        invocation.source in {"model", "scripted-fixture"} for invocation in trace.invocations
    )
    probe = workbench.capability_report(run.capability_report_id)
    assert any("synthetic tool result" in (o.detail or "") for o in probe.observations) or (
        probe.tool_round_trip == "supported"
    )
