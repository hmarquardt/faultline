"""Explicit, bounded IO adapters. Provider tool calls are never executed."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Protocol

import httpx

from faultline.documents import load_json
from faultline.domain import (
    AttackCase,
    EndpointProfile,
    ExecutionSettings,
    ModelResponse,
    TargetModel,
)


class ProviderError(Exception):
    """Controlled text only; never include credentials, headers or provider error bodies."""


class Provider(Protocol):
    async def complete(
        self,
        case: AttackCase,
        target: TargetModel,
        settings: ExecutionSettings,
        max_response_bytes: int,
    ) -> ModelResponse: ...


class MockProvider:
    def __init__(self, behavior: str = "secure") -> None:
        self.behavior = behavior

    async def complete(
        self,
        case: AttackCase,
        target: TargetModel,
        settings: ExecutionSettings,
        max_response_bytes: int,
    ) -> ModelResponse:
        text = (
            case.parameters["canary"]
            if self.behavior == "vulnerable" and case.kind == "attack"
            else "SAFE"
        )
        raw = {
            "model": target.requested_model,
            "simulated": True,
            "choices": [
                {"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}
            ],
        }
        if len(json.dumps(raw).encode()) > max_response_bytes:
            raise ProviderError("Mock response exceeds response-byte budget")
        return ModelResponse(
            text=text,
            returned_model=target.requested_model,
            raw=raw,
            finish_reason="stop",
            tool_receipts=[],
        )


def _redact(value: Any, secret: str) -> Any:
    if isinstance(value, str):
        return value.replace(secret, "[CREDENTIAL REDACTED]")
    if isinstance(value, list):
        return [_redact(v, secret) for v in value]
    if isinstance(value, dict):
        return {_redact(k, secret): _redact(v, secret) for k, v in value.items()}
    return value


def contains_credential(value: Any, secret: str) -> bool:
    return _redact(value, secret) != value if secret else False


def protect_response(response: ModelResponse, secret: str) -> ModelResponse:
    """Central redaction also covers trusted library-supplied adapters."""
    if not secret:
        return response
    original = response.model_dump(mode="json")
    protected = _redact(original, secret)
    if protected != original:
        protected["credential_redacted"] = True
    return ModelResponse.model_validate(protected)


class CompatibleProvider:
    def __init__(
        self,
        profile: EndpointProfile,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.profile = profile
        self.transport = transport

    async def complete(
        self,
        case: AttackCase,
        target: TargetModel,
        settings: ExecutionSettings,
        max_response_bytes: int,
    ) -> ModelResponse:
        profile = self.profile
        if not profile.authorized or target.requested_model not in profile.allowed_models:
            raise ProviderError("Endpoint or model is outside authorized scope")
        secret = os.environ.get(profile.credential_env, "") if profile.credential_env else ""
        if profile.credential_env and not secret:
            raise ProviderError("Credential environment variable is unset or empty")
        headers = {"Authorization": f"Bearer {secret}"} if secret else {}
        body: dict[str, Any] = {
            "model": target.requested_model,
            "messages": [{"role": m.role, "content": m.content} for m in case.messages],
            profile.token_parameter: settings.max_output_tokens,
            "stream": False,
        }
        if settings.temperature is not None:
            body["temperature"] = settings.temperature
        if settings.seed is not None:
            body["seed"] = settings.seed
        try:
            async with asyncio.timeout(settings.timeout_seconds):
                async with (
                    httpx.AsyncClient(
                        transport=self.transport,
                        timeout=settings.timeout_seconds,
                        follow_redirects=False,
                        trust_env=False,
                    ) as client,
                    client.stream(
                        "POST",
                        profile.request_url,
                        headers=headers,
                        json=body,
                    ) as response,
                ):
                    if response.status_code != 200:
                        raise ProviderError(f"Endpoint returned HTTP {response.status_code}")
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(data) + len(chunk) > max_response_bytes:
                            raise ProviderError("Endpoint exceeded response-byte budget")
                        data.extend(chunk)
            raw = load_json(data)
            redacted = contains_credential(raw, secret)
            if secret:
                raw = _redact(raw, secret)
            message = raw["choices"][0]["message"]
            text = message.get("content")
            if text is None:
                text = message.get("refusal") or ""
            if not isinstance(text, str) or not isinstance(raw.get("model"), str):
                raise ValueError("Malformed response")
            return ModelResponse(
                text=text,
                returned_model=raw["model"],
                raw=raw,
                finish_reason=raw["choices"][0].get("finish_reason"),
                tool_requests=message.get("tool_calls") or [],
                usage=raw.get("usage") or {},
                credential_redacted=redacted,
            )
        except ProviderError:
            raise
        except (httpx.TimeoutException, TimeoutError):
            raise ProviderError("Endpoint request timed out") from None
        except httpx.HTTPError:
            raise ProviderError(
                "Endpoint transport failed; verify address, TLS and connectivity"
            ) from None
        except (ValueError, KeyError, IndexError, TypeError, RecursionError):
            raise ProviderError("Endpoint returned an invalid compatible response") from None
