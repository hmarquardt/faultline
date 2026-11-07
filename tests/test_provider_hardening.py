"""Endpoint integration hardening: authenticated, bounded, diagnosed offline."""

import asyncio
import json

import httpx
import pytest

from faultline.domain import (
    EndpointProfile,
    ExecutionSettings,
    ModelResponse,
    TargetModel,
    ToolRequest,
)
from faultline.providers import (
    AgentEndpointProvider,
    CompatibleProvider,
    ProviderError,
    describe_http_error,
)
from faultline.techniques import render_cases, techniques


def profile(**changes):
    values = dict(
        name="Hardening fixture",
        provider="openai-compatible",
        base_url="https://toy.invalid/v1",
        allowed_models=["toy-model"],
        authorized=True,
        authorization="Owner-approved hardening fixture",
        tool_calling=True,
    )
    values.update(changes)
    return EndpointProfile(**values)


def target(model="toy-model"):
    return TargetModel(endpoint_id="endpoint", requested_model=model)


def case():
    return render_cases(techniques()["authority-spoof"])[0]


def run_complete(handler, settings=None):
    return asyncio.run(
        CompatibleProvider(profile(), transport=httpx.MockTransport(handler)).complete(
            case=case(),
            target=target(),
            settings=settings or ExecutionSettings(),
            max_response_bytes=64_000,
        )
    )


def turn(handler, **kwargs):
    from faultline.domain import AgentBudget

    provider = AgentEndpointProvider(
        CompatibleProvider(profile(), transport=httpx.MockTransport(handler)),
        target(),
        ExecutionSettings(),
    )
    return asyncio.run(
        provider.complete(
            turns=kwargs.pop("turns", []),
            tools=kwargs.pop("tools", []),
            budget=AgentBudget(),
        )
    )


def ok(text="SAFE"):
    return {
        "model": "toy-model-rev-9",
        "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 3},
    }


@pytest.mark.parametrize(
    "status,detail,expected",
    [
        (401, "invalid api key", "authorization rejected"),
        (403, "model not allowed", "authorization rejected"),
        (429, "quota", "rate limit or quota"),
        (404, "no such model", "endpoint path or model not found"),
        (413, "too big", "rejected as too large"),
        (500, "boom", "server-side"),
        (400, "maximum context length is 128000 tokens", "context window"),
        (400, "tools are not supported", "tool calling rejected"),
        (400, "unsupported parameter max_tokens", "token-limit parameter"),
        (422, "odd body", "request rejected"),
    ],
)
def test_http_errors_are_classified_actionably(status, detail, expected):
    message = describe_http_error(status, detail)
    assert expected in message
    assert "Bearer" not in message


def test_plain_completion_captures_identity_usage_and_finish_reason():
    seen = []

    def handler(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=ok())

    response = run_complete(handler)
    assert isinstance(response, ModelResponse)
    body = seen[0]
    assert body["model"] == "toy-model"
    assert body["stream"] is False
    assert body["max_tokens"] == ExecutionSettings().max_output_tokens
    assert body["messages"][0]["role"] == "system"
    assert response.returned_model == "toy-model-rev-9"
    assert response.usage["completion_tokens"] == 3
    assert response.finish_reason == "stop"


def test_token_parameter_is_configurable_and_never_rewritten():
    seen = []

    def handler(request):
        body = json.loads(request.content)
        seen.append(body)
        if "max_completion_tokens" in body:
            return httpx.Response(400, json={"error": {"message": "unknown parameter"}})
        return httpx.Response(200, json=ok())

    provider = CompatibleProvider(
        profile(token_parameter="max_completion_tokens"),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ProviderError, match="HTTP 400"):
        asyncio.run(
            provider.complete(
                case=case(),
                target=target(),
                settings=ExecutionSettings(),
                max_response_bytes=64_000,
            )
        )
    # Exactly one attempt: no silent parameter rewrite and no retry.
    assert len(seen) == 1
    assert "max_completion_tokens" in seen[0]
    assert "max_tokens" not in seen[0]


def test_rate_limit_is_reported_without_retry():
    calls = {"count": 0}

    def handler(request):
        calls["count"] += 1
        return httpx.Response(429, json={"error": {"message": "rate limited"}})

    with pytest.raises(ProviderError):
        run_complete(handler)
    assert calls["count"] == 1


def test_context_window_error_is_actionable():
    def handler(request):
        return httpx.Response(
            400,
            json={
                "error": {
                    "message": "This model's maximum context length is 8192 tokens",
                }
            },
        )

    with pytest.raises(ProviderError, match="context window"):
        run_complete(handler)


def test_malformed_responses_are_rejected_clearly():
    for payload in (
        {"choices": []},
        {"model": "toy-model"},
        {"choices": [{"message": {"content": 5}}]},
    ):
        with pytest.raises(ProviderError, match="invalid"):
            run_complete(lambda request, body=payload: httpx.Response(200, json=body))


def test_timeout_is_reported_not_retried():
    calls = {"count": 0}

    def handler(request):
        calls["count"] += 1
        raise httpx.ReadTimeout("slow")

    with pytest.raises(ProviderError, match="timed out"):
        run_complete(handler)
    assert calls["count"] == 1


def test_tool_call_ids_and_arguments_are_parsed_and_correlated():
    def handler(request):
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
                                    "id": "call-abc",
                                    "type": "function",
                                    "function": {
                                        "name": "read_document",
                                        "arguments": json.dumps({"document_id": "d1"}),
                                    },
                                },
                                {
                                    "id": "call-def",
                                    "type": "function",
                                    "function": {
                                        "name": "search_documents",
                                        "arguments": json.dumps({"query": "refund"}),
                                    },
                                },
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
                "usage": {"completion_tokens": 8},
            },
        )

    answer = turn(handler)
    assert [call.id for call in answer.tool_calls] == ["call-abc", "call-def"]
    assert answer.tool_calls[0].name == "read_document"
    assert answer.tool_calls[1].arguments == {"query": "refund"}
    assert answer.finish_reason == "tool_calls"
    assert answer.usage["completion_tokens"] == 8


def test_malformed_tool_arguments_are_rejected():
    def handler(request):
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
                                    "function": {"name": "read_document", "arguments": "[1,2,3]"},
                                }
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
            },
        )

    with pytest.raises(ProviderError, match="invalid agent response"):
        turn(handler)


def test_multiturn_messages_preserve_order_and_tool_correlation():
    from faultline.domain import ConversationTurn

    seen = []

    def handler(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=ok("FINAL"))

    turns = [
        ConversationTurn(index=0, role="system", content="sys", source="harness"),
        ConversationTurn(index=1, role="user", content="task", source="harness"),
        ConversationTurn(
            index=2,
            role="assistant",
            content="",
            source="model",
            tool_request_ids=["call-1"],
        ),
        ConversationTurn(
            index=3,
            role="tool",
            content="result",
            source="tool",
            tool_request_id="call-1",
        ),
    ]
    answer = turn(handler, turns=turns)
    sent = seen[0]["messages"]
    assert [message["role"] for message in sent] == ["system", "user", "assistant", "tool"]
    assert sent[3]["tool_call_id"] == "call-1"
    assert answer.content == "FINAL"


def test_scope_and_model_gates_are_enforced():
    provider = CompatibleProvider(
        profile(), transport=httpx.MockTransport(lambda request: httpx.Response(200, json=ok()))
    )
    with pytest.raises(ProviderError, match="outside authorized scope"):
        asyncio.run(
            provider.complete(
                case=case(),
                target=target("other-model"),
                settings=ExecutionSettings(),
                max_response_bytes=8_000,
            )
        )
    unauthorized = CompatibleProvider(
        profile(authorized=False),
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=ok())),
    )
    with pytest.raises(ProviderError, match="outside authorized scope"):
        asyncio.run(
            unauthorized.complete(
                case=case(),
                target=target(),
                settings=ExecutionSettings(),
                max_response_bytes=8_000,
            )
        )


def test_unsupported_tool_capability_is_refused_not_faked():
    provider = AgentEndpointProvider(
        CompatibleProvider(
            profile(tool_calling=False),
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json=ok())),
        ),
        target(),
        ExecutionSettings(),
    )
    assert provider.capabilities.supports_tool_calls is False
    from faultline.domain import AgentBudget

    with pytest.raises(ProviderError, match="tool-calling capability"):
        asyncio.run(provider.complete(turns=[], tools=[], budget=AgentBudget()))


def test_tool_request_model_rejects_unknown_keys():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ToolRequest(name="read_document", arguments={}, extra=True)
