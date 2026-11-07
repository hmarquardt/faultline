"""Credential redaction verification. Never reveals the value, only the finding.

A credential is resolved from the environment for the sole purpose of searching for
it. The value is never stored, logged, raised or written into an evidence artifact;
findings name the *location* (artifact/feature/field) where a leak was detected.
"""

import json
import os
from collections.abc import Iterable

from faultline.domain import (
    EndpointProfile,
    EvidenceArtifact,
    ProviderCapabilityReport,
    RedactionFinding,
)

SENSITIVE_KEY_HINTS = ("authorization", "api-key", "api_key", "apikey", "token", "secret")


def resolve_secret(profile: EndpointProfile, environ: dict | None = None) -> str:
    """Read the configured credential for scanning only; caller must not persist it."""
    if not profile.credential_env:
        return ""
    source = os.environ if environ is None else environ
    return source.get(profile.credential_env, "") or ""


def _walk(value, trail: str) -> Iterable[tuple[str, str]]:
    """Yield (location, text) pairs for every retained scalar in a structure."""
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and any(hint in key.lower() for hint in SENSITIVE_KEY_HINTS):
                yield f"{trail}.{key}", "<sensitive-key-present>"
            yield from _walk(item, f"{trail}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk(item, f"{trail}[{index}]")
    elif isinstance(value, str):
        yield trail, value


def scan_text(secret: str, text: str, location: str) -> list[str]:
    """Return the locations where the secret appears; never returns the secret."""
    if not secret or secret not in text:
        return []
    return [location]


def scan_evidence(secret: str, artifact: EvidenceArtifact) -> list[str]:
    """Inspect structured content and rendered serialization of one artifact."""
    found = scan_text(secret, artifact.content, f"evidence:{artifact.kind}:{artifact.id}")
    found.extend(scan_text(secret, artifact.provenance, f"evidence:{artifact.id}:provenance"))
    try:
        parsed = json.loads(artifact.content)
    except ValueError:
        return found
    for location, text in _walk(parsed, f"evidence:{artifact.id}"):
        found.extend(scan_text(secret, text, location))
    return found


def scan_report_payload(secret: str, payload: str, label: str) -> list[str]:
    return scan_text(secret, payload, f"document:{label}")


def scan_capability_report(secret: str, report: ProviderCapabilityReport) -> tuple[list[str], int]:
    """Check every retained probe artifact and the rendered report itself."""
    found: list[str] = []
    for observation in report.observations:
        if observation.evidence is not None:
            found.extend(scan_evidence(secret, observation.evidence))
        found.extend(
            scan_text(secret, observation.detail, f"observation:{observation.feature}:detail")
        )
    rendered = report.model_dump_json()
    found.extend(scan_text(secret, rendered, "capability-report:serialized"))
    for error in report.errors:
        found.extend(scan_text(secret, error, "capability-report:error"))
    return sorted(set(found)), len(report.observations)


def verify_redaction(
    secret: str,
    *,
    capability_report: ProviderCapabilityReport | None = None,
    documents: Iterable[tuple[str, str]] = (),
) -> RedactionFinding:
    """Verify that no retained evidence or document contains the credential."""
    locations: list[str] = []
    observations = 0
    if capability_report is not None:
        found, observations = scan_capability_report(secret, capability_report)
        locations.extend(found)
    checked_documents = 0
    for label, payload in documents:
        checked_documents += 1
        locations.extend(scan_report_payload(secret, payload, label))
    unique = sorted(set(locations))
    if not secret:
        return RedactionFinding(
            secret_configured=False,
            observations_checked=observations,
            documents_checked=checked_documents,
            leaked=False,
            detail=(
                "No credential is configured for this profile, so there is nothing to "
                "redact; no credential value is retained anywhere in the evidence"
            ),
        )
    if unique:
        return RedactionFinding(
            secret_configured=True,
            observations_checked=observations,
            documents_checked=checked_documents,
            leaked=True,
            locations=unique[:20],
            detail=(
                "A configured credential value was found in retained evidence at "
                f"{len(unique)} location(s): {', '.join(unique[:10])}. The value is not "
                "reproduced here"
            ),
        )
    return RedactionFinding(
        secret_configured=True,
        observations_checked=observations,
        documents_checked=checked_documents,
        leaked=False,
        detail=(
            "A configured credential is resolved and absent from every retained probe "
            f"artifact ({observations} observation(s)) and document "
            f"({checked_documents} checked); the value is never stored"
        ),
    )
