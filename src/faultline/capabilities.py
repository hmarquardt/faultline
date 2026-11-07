"""Configured versus observed provider capabilities.

A profile's declared capabilities are a configuration assertion, never proof. These
probes send bounded, harmless requests, exercise one synthetic tool round trip when
the profile declares tool calling, and record exactly what was supported,
unsupported or left unknown. No external tool is ever executed, no credential is
stored or exported, and a rejected parameter is never silently rewritten.
"""

import asyncio
import json
import os
from typing import Any

import httpx

from faultline.domain import (
    CapabilityObservation,
    EndpointProfile,
    EvidenceArtifact,
    ExecutionSettings,
    ProviderCapabilities,
    ProviderCapabilityReport,
    TargetModel,
    ToolRequest,
    canonical_digest,
)
from faultline.providers import ProviderError, describe_http_error
from faultline.tooling import registry, tool_specifications

PROBE_MAX_BYTES = 32_000
SYNTHETIC_TOOL_RESULT = (
    "[synthetic tool result] document doc-handbook: refunds are allowed within 30 "
    "days. This result was produced by the capability probe, not by a real tool."
)


def declared_capabilities(profile: EndpointProfile) -> ProviderCapabilities:
    """Translate a profile's configuration assertion into capability statuses."""
    declared = "supported" if profile.tool_calling else "unknown"
    return ProviderCapabilities(
        chat_completions="supported" if profile.authorized else "unknown",
        tool_calls=declared,
        tool_result_messages=declared,
        token_limit_parameter="supported",
        temperature="supported",
        seed="supported",
        system_role="supported",
        model_identity="unknown",
        usage_reporting="unknown",
        finish_reason="unknown",
        token_parameter_name=profile.token_parameter,
    )


def _sanitize(value: Any, secret: str, limit: int = 400) -> Any:
    """Strip the credential and truncate before anything is stored as evidence."""
    if isinstance(value, str):
        cleaned = value.replace(secret, "[CREDENTIAL REDACTED]") if secret else value
        return cleaned[:limit] + ("…" if len(cleaned) > limit else "")
    if isinstance(value, list):
        return [_sanitize(item, secret, limit) for item in value[:20]]
    if isinstance(value, dict):
        return {str(key): _sanitize(item, secret, limit) for key, item in list(value.items())[:40]}
    return value


def _evidence(
    feature: str,
    request_body: dict[str, Any],
    response_status: int | None,
    response_body: Any,
    secret: str,
) -> tuple[EvidenceArtifact, str, str]:
    request_payload = json.dumps(_sanitize(request_body, secret), sort_keys=True)
    response_payload = json.dumps(_sanitize(response_body, secret), sort_keys=True, default=str)
    request_sha = canonical_digest(request_payload)
    response_sha = canonical_digest(response_payload)
    artifact = EvidenceArtifact.capture(
        "provider-probe",
        json.dumps(
            {
                "feature": feature,
                "status_code": response_status,
                "request": json.loads(request_payload),
                "response": json.loads(response_payload),
            },
            indent=2,
            sort_keys=True,
        ),
        f"provider-probe:{feature}",
    )
    return artifact, request_sha, response_sha


class _Probe:
    """One bounded HTTP probe with sanitized evidence."""

    def __init__(self, profile: EndpointProfile, transport, settings: ExecutionSettings) -> None:
        self.profile = profile
        self.transport = transport
        self.settings = settings
        self.secret = os.environ.get(profile.credential_env, "") if profile.credential_env else ""
        self.observations: list[CapabilityObservation] = []
        self.errors: list[str] = []

    async def post(self, body: dict[str, Any]) -> tuple[int | None, Any]:
        headers = {"Authorization": f"Bearer {self.secret}"} if self.secret else {}
        try:
            async with asyncio.timeout(self.settings.timeout_seconds):
                async with (
                    httpx.AsyncClient(
                        transport=self.transport,
                        timeout=self.settings.timeout_seconds,
                        follow_redirects=False,
                        trust_env=False,
                    ) as client,
                    client.stream(
                        "POST", self.profile.request_url, headers=headers, json=body
                    ) as response,
                ):
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(data) + len(chunk) > PROBE_MAX_BYTES:
                            raise ProviderError("Probe response exceeded the byte budget")
                        data.extend(chunk)
                    status = response.status_code
        except (httpx.TimeoutException, TimeoutError):
            raise ProviderError("Probe request timed out") from None
        except httpx.HTTPError:
            raise ProviderError(
                "Probe transport failed; verify address, TLS and connectivity"
            ) from None
        try:
            return status, json.loads(data)
        except ValueError:
            return status, {"raw_truncated": bytes(data[:400]).decode("utf-8", "replace")}

    def record(
        self,
        feature: str,
        status: str,
        detail: str,
        *,
        configured: str = "unknown",
        request_body: dict[str, Any] | None = None,
        response_status: int | None = None,
        response_body: Any = None,
    ) -> None:
        artifact = None
        request_sha = response_sha = None
        if request_body is not None:
            artifact, request_sha, response_sha = _evidence(
                feature, request_body, response_status, response_body, self.secret
            )
        self.observations.append(
            CapabilityObservation(
                feature=feature,
                status=status,
                configured=configured,
                detail=str(_sanitize(detail, self.secret, limit=400)),
                request_sha256=request_sha,
                response_sha256=response_sha,
                evidence=artifact,
            )
        )


def _error_message(body: Any, secret: str = "") -> str:
    """Short, sanitized provider error text; never contains the credential."""
    message = "no provider message"
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            candidate = error.get("message") or error.get("type") or error.get("code")
            if isinstance(candidate, str):
                message = candidate
        elif isinstance(error, str):
            message = error
        else:
            candidate = body.get("message")
            if isinstance(candidate, str):
                message = candidate
    return str(_sanitize(message, secret, limit=200))


def _mentions(body: Any, needles: tuple[str, ...]) -> bool:
    text = json.dumps(_sanitize(body, ""), default=str).lower()
    return any(needle in text for needle in needles)


async def validate_capabilities(
    profile: EndpointProfile,
    target: TargetModel,
    *,
    transport=None,
    settings: ExecutionSettings | None = None,
    allow_network: bool = False,
    exercise_tools: bool | None = None,
) -> ProviderCapabilityReport:
    """Probe an authorized endpoint and record configured versus observed features."""
    settings = settings or ExecutionSettings()
    if not profile.authorized or not profile.authorization.strip():
        raise ValueError("Endpoint profile requires an authorized scope")
    if target.requested_model not in profile.allowed_models:
        raise ValueError("Model is outside the authorized endpoint scope")
    # An injected in-process transport never opens a socket, so it needs no network
    # opt-in; anything that would reach a real address requires the flag.
    if profile.provider != "mock" and transport is None and not allow_network:
        raise ValueError("Real endpoint probing requires explicit network opt-in")
    if profile.credential_env and not os.environ.get(profile.credential_env):
        raise ProviderError(
            "Credential environment variable is unset or empty; set it before probing"
        )
    configured = declared_capabilities(profile)
    probe = _Probe(profile, transport, settings)
    observed: dict[str, object] = {
        "token_parameter_name": profile.token_parameter,
    }
    base = {
        "model": target.requested_model,
        "messages": [
            {"role": "system", "content": "You are a capability probe. Reply in one word."},
            {"role": "user", "content": "Reply with the single word READY."},
        ],
        profile.token_parameter: min(16, settings.max_output_tokens),
        "stream": False,
    }
    if settings.temperature is not None:
        base["temperature"] = settings.temperature
    if settings.seed is not None:
        base["seed"] = settings.seed
    status, body = await probe.post(base)
    chat_supported = status == 200
    observed["chat_completions"] = "supported" if chat_supported else "unsupported"
    observed["system_role"] = "supported" if chat_supported else "unknown"
    observed["token_limit_parameter"] = "supported" if chat_supported else "unknown"
    observed["temperature"] = (
        "supported" if chat_supported and settings.temperature is not None else "unknown"
    )
    observed["seed"] = "supported" if chat_supported and settings.seed is not None else "unknown"
    detail = (
        "Chat completion accepted with a system message"
        if chat_supported
        else "Chat completion rejected: "
        + describe_http_error(status or 0, _error_message(body, probe.secret))
    )
    probe.record(
        "chat_completions",
        observed["chat_completions"],
        detail,
        configured=configured.chat_completions,
        request_body=base,
        response_status=status,
        response_body=body,
    )
    if not chat_supported:
        if _mentions(body, ("system",)):
            observed["system_role"] = "unsupported"
        if _mentions(body, ("max_tokens", "max_completion_tokens", "token")):
            observed["token_limit_parameter"] = "unsupported"
        if _mentions(body, ("temperature",)):
            observed["temperature"] = "unsupported"
        if _mentions(body, ("seed",)):
            observed["seed"] = "unsupported"
        probe.errors.append(_error_message(body, probe.secret))
        return _report(profile, target, configured, observed, probe, allow_network)
    choices = body.get("choices") or [{}]
    returned_model = body.get("model")
    observed["model_identity"] = "supported" if returned_model else "unsupported"
    observed["usage_reporting"] = "supported" if body.get("usage") else "unsupported"
    observed["finish_reason"] = "supported" if choices[0].get("finish_reason") else "unsupported"
    probe.record(
        "model_identity",
        observed["model_identity"],
        f"Endpoint reported model {returned_model!r}",
        configured=configured.model_identity,
        request_body={"model": target.requested_model},
        response_status=status,
        response_body={"model": returned_model},
    )
    probe.record(
        "usage_reporting",
        observed["usage_reporting"],
        "Usage block present" if body.get("usage") else "No usage block in the response",
        configured=configured.usage_reporting,
        response_body={"usage": body.get("usage")},
    )
    if exercise_tools is None:
        exercise_tools = profile.tool_calling
    if exercise_tools:
        await _tool_round_trip(probe, profile, target, configured, observed, settings)
    return _report(profile, target, configured, observed, probe, allow_network)


async def _tool_round_trip(
    probe: _Probe,
    profile: EndpointProfile,
    target: TargetModel,
    configured: ProviderCapabilities,
    observed: dict,
    settings: ExecutionSettings,
) -> None:
    """Exercise one tool call and one tool-result message; never execute the tool."""
    specifications = tool_specifications(registry())
    request: dict[str, Any] = {
        "model": target.requested_model,
        "messages": [
            {
                "role": "user",
                "content": (
                    "Call the synthetic tool read_document with document_id "
                    "'doc-handbook', then stop."
                ),
            }
        ],
        "tools": specifications,
        "tool_choice": "auto",
        profile.token_parameter: min(64, settings.max_output_tokens),
        "stream": False,
    }
    status, body = await probe.post(request)
    if status != 200:
        observed["tool_calls"] = "unsupported"
        observed["tool_result_messages"] = "unknown"
        detail = (
            f"Tool declaration rejected with HTTP {status}: {_error_message(body, probe.secret)}"
        )
        probe.record(
            "tool_calls",
            "unsupported",
            detail,
            configured=configured.tool_calls,
            request_body=request,
            response_status=status,
            response_body=body,
        )
        probe.errors.append(_error_message(body, probe.secret))
        return
    choices = body.get("choices") or [{}]
    calls = (choices[0].get("message") or {}).get("tool_calls") or []
    parsed: list[ToolRequest] = []
    for index, call in enumerate(calls):
        function = call.get("function") or {}
        arguments = function.get("arguments")
        try:
            parsed_arguments = json.loads(arguments) if isinstance(arguments, str) else arguments
        except ValueError:
            parsed_arguments = None
        if not isinstance(parsed_arguments, dict):
            continue
        parsed.append(
            ToolRequest(
                id=str(call.get("id") or f"probe-{index}"),
                name=str(function.get("name") or ""),
                arguments=parsed_arguments,
            )
        )
    if not parsed:
        observed["tool_calls"] = "unknown"
        observed["tool_result_messages"] = "unknown"
        probe.record(
            "tool_calls",
            "unknown",
            "Endpoint accepted tool declarations but returned no tool call; capability "
            "was not exercised",
            configured=configured.tool_calls,
            request_body=request,
            response_status=status,
            response_body=body,
        )
        return
    observed["tool_calls"] = "supported"
    probe.record(
        "tool_calls",
        "supported",
        f"Endpoint returned {len(parsed)} tool call(s) in the declared schema",
        configured=configured.tool_calls,
        request_body=request,
        response_status=status,
        response_body={"tool_calls": calls},
    )
    call = parsed[0]
    follow_up: dict[str, Any] = {
        "model": target.requested_model,
        "messages": [
            request["messages"][0],
            {
                "role": "assistant",
                "content": "",
                "tool_calls": calls,
            },
            {
                "role": "tool",
                "tool_call_id": call.id,
                "name": call.name,
                "content": SYNTHETIC_TOOL_RESULT,
            },
        ],
        "tools": specifications,
        profile.token_parameter: min(64, settings.max_output_tokens),
        "stream": False,
    }
    status, body = await probe.post(follow_up)
    if status == 200:
        observed["tool_result_messages"] = "supported"
        detail = "Tool-result message accepted and the conversation continued"
    else:
        observed["tool_result_messages"] = "unsupported"
        detail = (
            f"Tool-result message rejected with HTTP {status}: {_error_message(body, probe.secret)}"
        )
        probe.errors.append(_error_message(body, probe.secret))
    probe.record(
        "tool_result_messages",
        observed["tool_result_messages"],
        detail,
        configured=configured.tool_result_messages,
        request_body=follow_up,
        response_status=status,
        response_body=body,
    )


def _observed_model(probe: "_Probe") -> str | None:
    """The model identity the endpoint actually reported, if it reported one."""
    for observation in probe.observations:
        if observation.feature != "model_identity" or observation.evidence is None:
            continue
        response = json.loads(observation.evidence.content).get("response") or {}
        if isinstance(response, dict):
            candidate = response.get("model")
            if isinstance(candidate, str) and candidate:
                return candidate
    return None


def _report(
    profile: EndpointProfile,
    target: TargetModel,
    configured: ProviderCapabilities,
    observed: dict,
    probe: _Probe,
    allow_network: bool,
) -> ProviderCapabilityReport:
    resolved = ProviderCapabilities(**observed)
    usage: dict[str, Any] = {}
    finish_reasons: list[str] = []
    for observation in probe.observations:
        if observation.evidence is None:
            continue
        payload = json.loads(observation.evidence.content)
        response = payload.get("response") or {}
        if isinstance(response, dict):
            if isinstance(response.get("usage"), dict):
                # Keep the first observed usage block (the plain completion) so a
                # later tool round trip cannot overwrite it.
                for key, value in response["usage"].items():
                    usage.setdefault(key, value)
            for choice in response.get("choices") or []:
                reason = choice.get("finish_reason") if isinstance(choice, dict) else None
                if reason and reason not in finish_reasons:
                    finish_reasons.append(reason)
    return ProviderCapabilityReport(
        profile_id=profile.id,
        provider=profile.provider,
        model=target.requested_model,
        observed_model=_observed_model(probe),
        configured=configured,
        observed=resolved,
        observations=probe.observations,
        tool_round_trip=str(observed.get("tool_calls", "unknown")),
        token_usage=usage,
        finish_reasons=finish_reasons,
        errors=probe.errors,
        allow_network=allow_network,
    )
