"""Credential redaction: detected without ever revealing the value."""

import asyncio
import json

import httpx

from faultline.capabilities import validate_capabilities
from faultline.domain import EndpointProfile, ExecutionSettings, TargetModel
from faultline.redaction import resolve_secret, verify_redaction

SECRET = "sk-faultline-synthetic-7Q2"


def profile(**changes):
    values = dict(
        name="Redaction fixture",
        provider="openai-compatible",
        base_url="https://toy.invalid/v1",
        allowed_models=["toy-model"],
        authorized=True,
        authorization="Owner-approved redaction fixture",
        credential_env="FAULTLINE_REDACTION_KEY",
        tool_calling=True,
    )
    values.update(changes)
    return EndpointProfile(**values)


def completion(**extra):
    return {
        "model": "toy-model",
        "choices": [{"message": {"content": "READY"}, "finish_reason": "stop"}],
        "usage": {"completion_tokens": 2},
        **extra,
    }


def probe(handler, secret=SECRET, monkeypatch=None):
    if monkeypatch is not None:
        monkeypatch.setenv("FAULTLINE_REDACTION_KEY", secret)
    return asyncio.run(
        validate_capabilities(
            profile(),
            TargetModel(endpoint_id="endpoint", requested_model="toy-model"),
            transport=httpx.MockTransport(handler),
            settings=ExecutionSettings(),
        )
    )


def test_secret_is_resolved_without_being_stored(monkeypatch):
    monkeypatch.setenv("FAULTLINE_REDACTION_KEY", SECRET)
    assert resolve_secret(profile()) == SECRET
    assert resolve_secret(profile(credential_env=None)) == ""


def test_verify_redaction_detects_a_planted_secret_without_revealing_it(monkeypatch):
    monkeypatch.setenv("FAULTLINE_REDACTION_KEY", SECRET)
    report = probe(lambda request: httpx.Response(200, json=completion()), monkeypatch=monkeypatch)
    # Defence in depth: plant the secret in a copy of the retained evidence.
    tampered = report.observations[0].evidence.model_copy(
        update={"content": report.observations[0].evidence.content + SECRET}
    )
    broken = report.model_copy(
        update={
            "observations": [
                report.observations[0].model_copy(update={"evidence": tampered}),
                *report.observations[1:],
            ]
        }
    )
    finding = verify_redaction(SECRET, capability_report=broken)
    assert finding.leaked is True
    assert finding.secret_configured is True
    assert finding.locations
    assert SECRET not in finding.detail
    assert SECRET not in "".join(finding.locations)
    assert SECRET not in finding.model_dump_json()


def test_verify_redaction_detects_a_secret_in_an_exported_document(monkeypatch):
    monkeypatch.setenv("FAULTLINE_REDACTION_KEY", SECRET)
    report = probe(lambda request: httpx.Response(200, json=completion()), monkeypatch=monkeypatch)
    clean = verify_redaction(SECRET, capability_report=report)
    assert clean.leaked is False
    dirty = verify_redaction(
        SECRET,
        capability_report=report,
        documents=[("report.md", f"# report\n{json.dumps({'token': SECRET})}\n")],
    )
    assert dirty.leaked is True
    assert dirty.documents_checked == 1
    assert SECRET not in dirty.detail


def test_probe_response_echo_is_redacted_before_storage(monkeypatch):
    def handler(request):
        return httpx.Response(
            200,
            json=completion(echo=SECRET, echo_header=request.headers.get("authorization")),
        )

    report = probe(handler, monkeypatch=monkeypatch)
    payload = report.model_dump_json()
    assert SECRET not in payload
    assert "[CREDENTIAL REDACTED]" in payload
    finding = verify_redaction(SECRET, capability_report=report)
    assert finding.leaked is False
    assert finding.observations_checked >= 1


def test_provider_error_text_is_redacted(monkeypatch):
    def handler(request):
        return httpx.Response(
            400,
            json={"error": {"message": f"invalid key {SECRET} for model toy-model"}},
        )

    report = probe(handler, monkeypatch=monkeypatch)
    joined = " ".join(report.errors) + report.model_dump_json()
    assert SECRET not in joined
    assert "CREDENTIAL REDACTED" in joined
    assert "invalid key" in " ".join(report.errors)
    assert report.observed.chat_completions == "unsupported"
    finding = verify_redaction(SECRET, capability_report=report)
    assert finding.leaked is False


def test_no_configured_secret_is_reported_as_such(monkeypatch):
    monkeypatch.delenv("FAULTLINE_REDACTION_KEY", raising=False)
    finding = verify_redaction("", capability_report=None)
    assert finding.secret_configured is False
    assert finding.leaked is False
    assert "nothing to redact" in finding.detail


def test_validation_fails_when_a_leak_is_detected(workbench, monkeypatch):
    """End-to-end: a leaked credential fails the validation step, without echo."""
    monkeypatch.setenv("FAULTLINE_REDACTION_KEY", SECRET)
    prof = profile()
    workbench.store.add_profile(prof)

    def handler(request):
        return httpx.Response(200, json=completion())

    transport = httpx.MockTransport(handler)
    # Force a leak by pointing the verification at a tampered capability report.
    import faultline.validation as validation_module

    original = validation_module.verify_redaction

    def leaking(secret, *, capability_report=None, documents=()):
        finding = original(secret, capability_report=capability_report, documents=documents)
        return finding.model_copy(
            update={
                "leaked": True,
                "locations": ["evidence:provider-probe:planted"],
                "detail": "A configured credential value was found in retained evidence at "
                "1 location(s): evidence:provider-probe:planted. The value is not "
                "reproduced here",
            }
        )

    monkeypatch.setattr(validation_module, "verify_redaction", leaking)
    run = asyncio.run(
        workbench.run_validation(
            prof, transport=transport, allow_network=True, scenario_id="retrieved-authority-spoof"
        )
    )
    statuses = {step.name: step.status for step in run.steps}
    assert statuses["evidence_sanitization"] == "failed"
    assert run.ok is False
    # The protocol stops before any scenario execution or experiment.
    assert "scenario_execution" not in statuses
    assert SECRET not in run.model_dump_json()
    stored = workbench.store.validation_run(run.id)
    assert SECRET not in stored.model_dump_json()


def test_exported_reports_contain_no_credential(workbench, monkeypatch, tmp_path):
    monkeypatch.setenv("FAULTLINE_REDACTION_KEY", SECRET)
    prof = profile()
    workbench.store.add_profile(prof)

    def handler(request):
        return httpx.Response(200, json=completion(echo=SECRET))

    from faultline.providers import AgentEndpointProvider, CompatibleProvider
    from faultline.service import Workbench as _Workbench  # noqa: F401

    transport = httpx.MockTransport(handler)

    def patched(
        scenario_definition, agent, target_profile, allow_network, script_key=None, settings=None
    ):
        return AgentEndpointProvider(
            CompatibleProvider(target_profile, transport=transport),
            TargetModel(endpoint_id=prof.id, requested_model="toy-model"),
            settings or ExecutionSettings(),
        )

    monkeypatch.setattr(workbench, "_agent_provider", patched)
    run = asyncio.run(
        workbench.run_validation(
            prof,
            transport=transport,
            allow_network=True,
            output_prefix=tmp_path / "validation",
        )
    )
    statuses = {step.name: step.status for step in run.steps}
    assert statuses["evidence_sanitization"] == "ok"
    assert statuses["report_redaction"] == "ok"
    for path in tmp_path.iterdir():
        assert SECRET not in path.read_text(encoding="utf-8", errors="replace")
