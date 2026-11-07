"""Live-model smoke workflow: refuses without authorization, bounded when allowed."""

import asyncio
import json

import httpx
import pytest

from faultline.domain import EndpointProfile, ExecutionSettings, TargetModel
from faultline.providers import AgentEndpointProvider, CompatibleProvider
from faultline.smoke import plan_smoke


def profile(**changes):
    values = dict(
        name="Smoke fixture",
        provider="openai-compatible",
        base_url="https://toy.invalid/v1",
        allowed_models=["toy-model"],
        authorized=True,
        authorization="Owner-approved smoke fixture",
        tool_calling=True,
    )
    values.update(changes)
    return EndpointProfile(**values)


SPEND = dict(max_estimated_spend_usd=0.05, estimated_cost_per_request_usd=0.001)


def test_plan_shows_exact_ceilings_and_commands():
    plan = plan_smoke(profile(), authorization="Owner approved", allow_network=True, **SPEND)
    assert plan.trial_count == 1
    assert plan.estimated_requests == 8
    assert plan.estimated_tokens == 8 * 64
    assert plan.budget.max_requests == 4
    assert plan.budget.max_output_tokens == 64
    assert plan.budget.request_timeout_seconds == 20.0
    assert plan.max_estimated_spend_usd == 0.05
    assert plan.allow_network is True
    assert any("validate-endpoint" in command for command in plan.commands)
    assert any("verify-report" in command for command in plan.commands)


def test_plan_refuses_without_authorization_note():
    with pytest.raises(ValueError, match="explicit authorization note"):
        plan_smoke(profile(), allow_network=True, **SPEND)


def test_plan_refuses_without_network_opt_in():
    with pytest.raises(ValueError, match="network opt-in"):
        plan_smoke(profile(), authorization="Owner approved", **SPEND)


def test_plan_refuses_without_spending_ceiling():
    with pytest.raises(ValueError, match="spending ceiling"):
        plan_smoke(profile(), authorization="Owner approved", allow_network=True)
    with pytest.raises(ValueError, match="per-request estimate"):
        plan_smoke(
            profile(),
            authorization="Owner approved",
            allow_network=True,
            max_estimated_spend_usd=0.05,
        )


def test_plan_refuses_unauthorized_profile_model_and_capability():
    with pytest.raises(ValueError, match="authorized endpoint profile"):
        plan_smoke(profile(authorized=False), authorization="note", allow_network=True, **SPEND)
    with pytest.raises(ValueError, match="outside the authorized endpoint scope"):
        plan_smoke(
            profile(),
            authorization="note",
            model="other-model",
            allow_network=True,
            **SPEND,
        )
    with pytest.raises(ValueError, match="tool-calling capability"):
        plan_smoke(profile(tool_calling=False), authorization="note", allow_network=True, **SPEND)


def test_plan_enforces_absolute_smoke_limits():
    with pytest.raises(ValueError, match="at most 8 requests"):
        plan_smoke(profile(), authorization="note", allow_network=True, max_requests=9, **SPEND)
    with pytest.raises(ValueError, match="at most 256 output tokens"):
        plan_smoke(
            profile(),
            authorization="note",
            allow_network=True,
            max_output_tokens=512,
            **SPEND,
        )
    with pytest.raises(ValueError, match="between 1 and 60 seconds"):
        plan_smoke(
            profile(), authorization="note", allow_network=True, timeout_seconds=120, **SPEND
        )


def test_plan_uses_the_declared_scenario_version():
    plan = plan_smoke(
        profile(),
        "boundary-enforcement",
        authorization="note",
        allow_network=True,
        **SPEND,
    )
    assert plan.scenario_id == "boundary-enforcement"
    assert plan.scenario_version == "1.1.0"


def test_smoke_runs_offline_through_an_injected_transport(workbench, monkeypatch, tmp_path):
    prof = profile()
    workbench.store.add_profile(prof)

    def handler(request):
        body = json.loads(request.content)
        roles = [message["role"] for message in body.get("messages", [])]
        if body.get("tools") and "tool" not in roles:
            return httpx.Response(
                200,
                json={
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
                                            "arguments": json.dumps(
                                                {"document_id": "doc-handbook"}
                                            ),
                                        },
                                    }
                                ],
                            },
                            "finish_reason": "tool_calls",
                        }
                    ],
                    "usage": {"completion_tokens": 5},
                },
            )
        return httpx.Response(
            200,
            json={
                "model": "toy-model",
                "choices": [{"message": {"content": "REFUND-30"}, "finish_reason": "stop"}],
                "usage": {"completion_tokens": 3},
            },
        )

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
    plan = plan_smoke(prof, authorization="Owner approved", allow_network=True, **SPEND)

    from faultline.smoke import execute_smoke

    run = asyncio.run(
        execute_smoke(workbench, plan, transport=transport, output_prefix=tmp_path / "smoke")
    )
    statuses = {step.name: step.status for step in run.steps}
    assert statuses["capabilities"] == "ok"
    assert statuses["tool_round_trip"] == "ok"
    assert statuses["controlled_experiment"] == "ok"
    assert statuses["report_export"] == "ok"
    assert statuses["report_redaction"] == "ok"
    assert run.ok
    # Real traces, real sessions, real report: nothing fabricated.
    assert run.trace_id and run.experiment_id
    trace = workbench.trace(run.trace_id)
    assert trace.status == "completed"
    assert trace.capabilities.provider != "scripted-mock"
    assert (tmp_path / "smoke.json").exists()
    assert (tmp_path / "smoke.csv").exists()
