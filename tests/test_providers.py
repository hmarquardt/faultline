import json

import httpx
import pytest
from pydantic import ValidationError

from faultline.domain import EndpointProfile, ExecutionBudget, ExecutionSettings
from faultline.providers import CompatibleProvider, MockProvider
from faultline.reports import export_report


def real_profile(**changes):
    return EndpointProfile(
        name="Authorized fixture",
        provider="openai-compatible",
        base_url="https://toy.invalid/v1",
        allowed_models=["toy-model"],
        authorized=True,
        authorization="Owner-approved toy evaluation",
        **changes,
    )


def response(text="SAFE", **changes):
    return {
        "model": "toy-model-revision-2",
        "choices": [
            {"message": {"content": text}, "finish_reason": "stop"},
        ],
        "usage": {"completion_tokens": 3},
        **changes,
    }


async def test_compatible_request_and_raw_evidence(workbench, rubric):
    seen = []
    profile = real_profile(token_parameter="max_completion_tokens")

    def handle(request):
        seen.append(request)
        return httpx.Response(200, json=response())

    provider = CompatibleProvider(profile, transport=httpx.MockTransport(handle))
    experiment = workbench.prepare(profile, rubric, allow_network=True)
    report = await workbench.execute(experiment, provider=provider)
    assert len(seen) == 2
    assert all(str(r.url) == "https://toy.invalid/v1/chat/completions" for r in seen)
    body = json.loads(seen[0].content)
    assert body["messages"][0]["role"] == "system"
    assert body["max_completion_tokens"] == 128
    assert "max_tokens" not in body
    assert body["seed"] == 42 and body["temperature"] == 0
    assert report.runs[0].response.raw == response()
    assert report.runs[0].response.returned_model == "toy-model-revision-2"
    assert report.runs[0].response.usage == {"completion_tokens": 3}


@pytest.mark.parametrize("secret", ["test-only-credential", 'key-"quoted"-\\value'])
async def test_credentials_are_redacted_from_response_keys_values_and_exports(
    workbench,
    rubric,
    tmp_path,
    monkeypatch,
    secret,
):
    monkeypatch.setenv("FAULTLINE_TEST_KEY", secret)
    profile = real_profile(credential_env="FAULTLINE_TEST_KEY")
    seen_headers = []

    def handle(request):
        seen_headers.append(request.headers["Authorization"])
        return httpx.Response(200, json=response(secret, **{secret: [secret]}))

    report = await workbench.execute(
        workbench.prepare(profile, rubric, allow_network=True),
        provider=CompatibleProvider(profile, transport=httpx.MockTransport(handle)),
    )
    assert seen_headers == [f"Bearer {secret}", f"Bearer {secret}"]
    assert all(r.response.credential_redacted for r in report.runs)
    assert all(r.evaluations[0].outcome == "uncertain" for r in report.runs)
    for path in export_report(report, tmp_path / "redacted"):
        # No export format ever contains the credential value.
        assert secret not in path.read_text()
        # The redaction marker appears wherever response evidence is rendered.
        if path.suffix != ".csv":
            assert "CREDENTIAL REDACTED" in path.read_text()
    with workbench.store.connect() as db:
        all_data = "\n".join(db.iterdump())
    assert secret not in all_data


@pytest.mark.parametrize("status", [302, 401, 429, 500])
async def test_no_redirect_retry_or_error_body_persistence(workbench, rubric, status):
    seen = []
    profile = real_profile()

    def handle(request):
        seen.append(request)
        return httpx.Response(
            status, headers={"Location": "https://other.invalid"}, text="sensitive-provider-error"
        )

    report = await workbench.execute(
        workbench.prepare(profile, rubric, allow_network=True),
        provider=CompatibleProvider(profile, transport=httpx.MockTransport(handle)),
    )
    assert len(seen) == 1
    assert report.experiment.status == "failed"
    assert report.runs[0].error == f"Endpoint returned HTTP {status}"
    assert "sensitive-provider-error" not in report.model_dump_json()


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"choices": []},
        {"model": "x", "choices": None},
        {"model": "x", "choices": [{"message": {"content": []}}]},
    ],
)
async def test_malformed_responses_are_saved_as_errors(workbench, rubric, data):
    profile = real_profile()
    report = await workbench.execute(
        workbench.prepare(profile, rubric, allow_network=True),
        provider=CompatibleProvider(
            profile,
            transport=httpx.MockTransport(
                lambda _: httpx.Response(200, json=data),
            ),
        ),
    )
    assert report.experiment.status == "failed"
    assert not report.runs[0].evaluations
    assert "invalid compatible response" in report.runs[0].error


async def test_response_byte_budget_and_timeout(workbench, rubric):
    profile = real_profile()
    report = await workbench.execute(
        workbench.prepare(
            profile, rubric, allow_network=True, budget=ExecutionBudget(max_response_bytes=8)
        ),
        provider=CompatibleProvider(
            profile,
            transport=httpx.MockTransport(
                lambda _: httpx.Response(200, text="x" * 100),
            ),
        ),
    )
    assert "response-byte budget" in report.runs[0].error

    async def stalled(request):
        raise httpx.ReadTimeout("sensitive details", request=request)

    report = await workbench.execute(
        workbench.prepare(profile, rubric, allow_network=True),
        provider=CompatibleProvider(profile, transport=httpx.MockTransport(stalled)),
    )
    assert report.runs[0].error == "Endpoint request timed out"


async def test_scope_network_and_missing_credentials_reject_before_io(
    workbench, rubric, monkeypatch
):
    profile = real_profile()
    for experiment, reason in [
        (workbench.prepare(profile, rubric), "allow_network"),
        (workbench.prepare(profile, rubric, model="other", allow_network=True), "allowed scope"),
        (
            workbench.prepare(
                profile.model_copy(update={"authorized": False}), rubric, allow_network=True
            ),
            "authorized scope",
        ),
    ]:
        with pytest.raises(ValueError, match=reason):
            await workbench.execute(experiment)
    monkeypatch.delenv("FAULTLINE_MISSING_KEY", raising=False)
    profile = real_profile(credential_env="FAULTLINE_MISSING_KEY")
    with pytest.raises(ValueError, match="unset"):
        await workbench.execute(workbench.prepare(profile, rubric, allow_network=True))
    assert not workbench.store.history()
    report = await workbench.execute(workbench.prepare(profile, rubric, dry_run=True))
    assert report.experiment.status == "dry_run"


async def test_credential_in_source_rejected_before_persistence(workbench, rubric, monkeypatch):
    secret = "FAULTLINE_SYNTHETIC_ACCIDENTALLY_A_KEY_12345"
    monkeypatch.setenv("FAULTLINE_TEST_KEY", secret)
    profile = real_profile(credential_env="FAULTLINE_TEST_KEY")
    experiment = workbench.prepare(
        profile, rubric, parameters={"canary": secret}, allow_network=True
    )
    with pytest.raises(ValueError, match="Credential value"):
        await workbench.execute(experiment)
    assert not workbench.store.history()


async def test_custom_adapter_cannot_leak_configured_credential(workbench, rubric, monkeypatch):
    secret = "test-only-secret"
    monkeypatch.setenv("FAULTLINE_TEST_KEY", secret)
    profile = real_profile(credential_env="FAULTLINE_TEST_KEY")

    class Leaky(MockProvider):
        async def complete(self, *args):
            value = await super().complete(*args)
            return value.model_copy(update={"text": secret, "raw": {"echo": secret}})

    report = await workbench.execute(
        workbench.prepare(profile, rubric, allow_network=True),
        provider=Leaky(),
    )
    assert secret not in report.model_dump_json()
    assert report.runs[0].response.credential_redacted


@pytest.mark.parametrize(
    "url",
    [
        "https://user:password@example.com/v1",
        "https://example.com?key=secret",
        "https://example.com/#secret",
        "http://example.com/v1",
        "file:///tmp/foo",
    ],
)
def test_unsafe_endpoint_addresses_are_rejected(url):
    with pytest.raises(ValidationError):
        EndpointProfile(name="bad", provider="openai-compatible", base_url=url)


async def test_generation_parameters_can_be_omitted(workbench, rubric):
    profile = real_profile()
    seen = []

    def handle(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=response())

    await workbench.execute(
        workbench.prepare(
            profile,
            rubric,
            allow_network=True,
            settings=ExecutionSettings(seed=None, temperature=None),
        ),
        provider=CompatibleProvider(profile, transport=httpx.MockTransport(handle)),
    )
    assert all("seed" not in b and "temperature" not in b for b in seen)
