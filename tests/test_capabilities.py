"""Provider capability validation: configured versus observed, sanitized probes."""

import asyncio
import json

import httpx
import pytest

from faultline.capabilities import declared_capabilities, validate_capabilities
from faultline.domain import EndpointProfile, ExecutionSettings, TargetModel
from faultline.providers import ProviderError


def profile(**changes):
    values = dict(
        name="Probe fixture",
        provider="openai-compatible",
        base_url="https://toy.invalid/v1",
        allowed_models=["toy-model"],
        authorized=True,
        authorization="Owner-approved fixture",
    )
    values.update(changes)
    return EndpointProfile(**values)


def target(model="toy-model"):
    return TargetModel(endpoint_id="endpoint", requested_model=model)


def completion(content="READY"):
    return {
        "model": "toy-model-rev-2",
        "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 9, "completion_tokens": 2},
    }


def tool_call(call_id="call-1"):
    return {
        "model": "toy-model-rev-2",
        "choices": [
            {
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call_id,
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
        "usage": {"completion_tokens": 6},
    }


def run_probe(handler, *, prof=None, **kwargs):
    return asyncio.run(
        validate_capabilities(
            prof or profile(),
            target(),
            transport=httpx.MockTransport(handler),
            **kwargs,
        )
    )


def test_configured_capabilities_are_assertions_not_proof():
    declared = declared_capabilities(profile(tool_calling=True))
    assert declared.chat_completions == "supported"
    assert declared.tool_calls == "supported"
    assert declared.model_identity == "unknown"
    quiet = declared_capabilities(profile())
    assert quiet.tool_calls == "unknown"


def test_supported_endpoint_records_observed_features():
    seen = []

    def handler(request):
        body = json.loads(request.content)
        seen.append(body)
        if "tools" in body:
            return httpx.Response(200, json=tool_call())
        return httpx.Response(200, json=completion())

    report = run_probe(handler, prof=profile(tool_calling=True))
    assert report.observed.chat_completions == "supported"
    assert report.observed.model_identity == "supported"
    assert report.observed.usage_reporting == "supported"
    assert report.observed.finish_reason == "supported"
    assert report.observed.tool_calls == "supported"
    assert report.observed.tool_result_messages == "supported"
    assert report.tool_round_trip == "supported"
    assert report.observed_model == "toy-model-rev-2"
    assert report.token_usage["completion_tokens"] == 2
    assert "stop" in report.finish_reasons
    assert report.mismatches == []
    features = {observation.feature for observation in report.observations}
    assert {"chat_completions", "model_identity", "tool_calls", "tool_result_messages"} <= features
    # The probe never executed a tool: the follow-up carries a fabricated result.
    assert any(body.get("messages") and body["messages"][-1]["role"] == "tool" for body in seen)
    tool_message = next(
        body["messages"][-1]
        for body in seen
        if body.get("messages") and body["messages"][-1]["role"] == "tool"
    )
    assert tool_message["content"].startswith("[synthetic tool result]")


def test_unsupported_tool_declaration_is_reported_not_hidden():
    def handler(request):
        body = json.loads(request.content)
        if "tools" in body:
            return httpx.Response(
                400, json={"error": {"message": "tools are not supported by this model"}}
            )
        return httpx.Response(200, json=completion())

    report = run_probe(handler, prof=profile(tool_calling=True))
    assert report.observed.chat_completions == "supported"
    assert report.observed.tool_calls == "unsupported"
    assert report.observed.tool_result_messages == "unknown"
    assert "tools are not supported" in " ".join(report.errors)
    assert "tool_calls" in report.mismatches


def test_no_tool_call_leaves_the_capability_unknown():
    def handler(request):
        body = json.loads(request.content)
        if "tools" in body:
            return httpx.Response(200, json=completion("READY"))
        return httpx.Response(200, json=completion())

    report = run_probe(handler, prof=profile(tool_calling=True))
    assert report.observed.tool_calls == "unknown"
    assert report.observed.tool_result_messages == "unknown"
    detail = next(
        observation.detail
        for observation in report.observations
        if observation.feature == "tool_calls"
    )
    assert "not exercised" in detail
    assert "tool_calls" in report.mismatches


def test_chat_rejection_distinguishes_parameter_problems():
    def handler(request):
        return httpx.Response(
            400,
            json={"error": {"message": "unsupported parameter: max_completion_tokens"}},
        )

    report = run_probe(handler)
    assert report.observed.chat_completions == "unsupported"
    assert report.observed.token_limit_parameter == "unsupported"
    assert report.errors
    assert report.mismatches
    # No tool probe was attempted after the rejection.
    assert all(o.feature != "tool_calls" for o in report.observations)


def test_probe_evidence_is_sanitized(monkeypatch):
    monkeypatch.setenv("FAULTLINE_PROBE_KEY", "super-secret-value")

    def handler(request):
        return httpx.Response(
            200,
            json={
                **completion(),
                "echo": "super-secret-value",
                "echo_headers": request.headers.get("authorization"),
            },
        )

    prof = profile(credential_env="FAULTLINE_PROBE_KEY")
    report = run_probe(handler, prof=prof)
    payload = report.model_dump_json()
    assert "super-secret-value" not in payload
    assert "CREDENTIAL REDACTED" in payload
    assert report.observed.chat_completions == "supported"


def test_missing_credential_is_an_actionable_error(monkeypatch):
    monkeypatch.delenv("FAULTLINE_PROBE_KEY", raising=False)
    prof = profile(credential_env="FAULTLINE_PROBE_KEY")
    with pytest.raises(ProviderError, match="unset or empty"):
        run_probe(lambda request: httpx.Response(200, json=completion()), prof=prof)


def test_scope_and_network_gates_are_enforced():
    unauthorized = profile(authorized=False)
    with pytest.raises(ValueError, match="authorized scope"):
        run_probe(lambda request: httpx.Response(200, json=completion()), prof=unauthorized)
    with pytest.raises(ValueError, match="outside the authorized endpoint scope"):
        asyncio.run(
            validate_capabilities(
                profile(),
                target("other-model"),
                transport=httpx.MockTransport(lambda r: httpx.Response(200, json=completion())),
            )
        )
    # A real transport without the flag is refused; an injected in-process transport
    # never opens a socket, so offline probes are allowed.
    with pytest.raises(ValueError, match="network opt-in"):
        asyncio.run(validate_capabilities(profile(), target(), transport=None))
    offline = run_probe(lambda request: httpx.Response(200, json=completion()))
    assert offline.allow_network is False


def test_settings_are_only_claimed_supported_when_exercised():
    def handler(request):
        return httpx.Response(200, json=completion())

    quiet = run_probe(handler, settings=ExecutionSettings(temperature=None, seed=None))
    assert quiet.observed.temperature == "unknown"
    assert quiet.observed.seed == "unknown"
    exercised = run_probe(handler, settings=ExecutionSettings(temperature=0, seed=42))
    assert exercised.observed.temperature == "supported"
    assert exercised.observed.seed == "supported"


def test_transport_failures_are_not_masked():
    def handler(request):
        raise httpx.ConnectError("boom")

    with pytest.raises(ProviderError, match="transport failed"):
        run_probe(handler)
