"""Reusable rubric conformance checks. No model, no network, no subjective claims.

A conformance run answers three questions about an unfamiliar rubric:

1. Is the rubric structurally complete and unambiguous?
2. Does import, evaluation and serialization preserve its wording, labels,
   weights, thresholds and scale semantics byte-for-byte?
3. Does the deterministic evaluator stay conservative: only binary criteria with
   observable evidence produce pass/fail, and subjective criteria stay uncertain?

It never scores a rubric for quality and never claims that deterministic checks
resolve subjective criteria.
"""

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from faultline.documents import load_json
from faultline.domain import (
    AttackCase,
    EvidenceArtifact,
    Message,
    ModelResponse,
    Rubric,
    RubricCriterion,
    RubricDefinition,
    canonical_digest,
)
from faultline.evaluation import Evaluator

SUPPORTED_EVIDENCE = {"raw_response", "exact_match_offset", "tool_receipt"}
DETERMINISTIC_CHECKS = {
    "required_text",
    "forbidden_text",
    "exact_canary",
    "json_schema",
    "tool_execution",
}
Severity = Literal["error", "warning", "note"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class ConformanceSample(StrictModel):
    """One known response used to exercise a rubric."""

    id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    prompt: str = Field(min_length=1)
    response: str
    system_context: str | None = None
    expected_behavior: str | None = None
    reference_answer: str | None = None
    case_kind: Literal["baseline", "attack"] = "baseline"
    parameters: dict[str, str] = Field(default_factory=dict)
    expect: dict[str, str] = Field(default_factory=dict)
    judgments: list[dict] = Field(default_factory=list)


class ConformancePack(StrictModel):
    """A rubric plus the known responses and expectations that exercise it."""

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    version: str = Field(default="1.0.0")
    domain: str = Field(default="")
    rubric: dict
    responses: list[ConformanceSample] = Field(default_factory=list)


class ConformanceFinding(StrictModel):
    code: str
    severity: Severity
    criterion_id: str | None = None
    sample_id: str | None = None
    message: str


class ConformanceReport(StrictModel):
    rubric_id: str
    rubric_version: str
    rubric_source_sha256: str
    pack_id: str | None = None
    criteria: int
    samples: int
    findings: list[ConformanceFinding] = Field(default_factory=list)

    @property
    def errors(self) -> list[ConformanceFinding]:
        return [finding for finding in self.findings if finding.severity == "error"]

    @property
    def warnings(self) -> list[ConformanceFinding]:
        return [finding for finding in self.findings if finding.severity == "warning"]

    def summary(self) -> str:
        return (
            f"{self.rubric_id}@{self.rubric_version}: {self.criteria} criteria, "
            f"{self.samples} samples, {len(self.errors)} error(s), "
            f"{len(self.warnings)} warning(s), "
            f"{len(self.findings) - len(self.errors) - len(self.warnings)} note(s)"
        )


def load_pack(path: Path) -> ConformancePack:
    """Load a conformance pack; the rubric definition is embedded data, never code."""
    with path.open("rb") as stream:
        raw = stream.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError("Conformance pack exceeds 2 MB")
    document = load_json(raw.decode("utf-8"))
    return ConformancePack.model_validate(document)


def _rubric(pack: ConformancePack, source: str) -> Rubric:
    text = json.dumps(pack.rubric, indent=2, ensure_ascii=False)
    return Rubric(
        source=EvidenceArtifact.capture("rubric-source", text, source),
        definition=RubricDefinition.model_validate(pack.rubric),
        review_status="structured",
    )


def _case(sample: ConformanceSample) -> AttackCase:
    messages = []
    if sample.system_context:
        messages.append(Message(role="system", content=sample.system_context))
    messages.append(Message(role="user", content=sample.prompt))
    return AttackCase(
        kind=sample.case_kind,
        technique_id="conformance-sample",
        technique_version="1",
        parameters=sample.parameters,
        messages=messages,
    )


def _response(sample: ConformanceSample) -> ModelResponse:
    return ModelResponse(
        text=sample.response,
        returned_model="conformance-fixture",
        raw={"faultline_conformance_sample": sample.id},
    )


def is_subjective(criterion: RubricCriterion) -> bool:
    """Criteria that a deterministic evaluator must never decide."""
    return criterion.check == "manual" or criterion.scale_kind != "binary"


def _structure(rubric: Rubric) -> list[ConformanceFinding]:
    assert rubric.definition is not None
    findings: list[ConformanceFinding] = []
    for criterion in rubric.definition.criteria:
        unsupported = set(criterion.evidence_requirements) - SUPPORTED_EVIDENCE
        if unsupported:
            findings.append(
                ConformanceFinding(
                    code="unsupported-evidence",
                    severity="warning",
                    criterion_id=criterion.id,
                    message=(
                        f"Evidence requirement(s) {sorted(unsupported)} are not produced "
                        "by this evaluator; the criterion will stay uncertain"
                    ),
                )
            )
        if is_subjective(criterion):
            findings.append(
                ConformanceFinding(
                    code="subjective-criterion",
                    severity="note",
                    criterion_id=criterion.id,
                    message=(
                        f"{criterion.scale_kind} scale with a {criterion.check} check is "
                        "human-assessed; the deterministic evaluator reports uncertain"
                    ),
                )
            )
        elif criterion.check not in DETERMINISTIC_CHECKS:
            findings.append(
                ConformanceFinding(
                    code="unexecutable-check",
                    severity="warning",
                    criterion_id=criterion.id,
                    message=f"Check {criterion.check} has no deterministic implementation",
                )
            )
    return findings


def _declared_source(rubric: Rubric) -> dict | None:
    """The rubric's own source document, when it is a JSON object."""
    try:
        document = json.loads(rubric.source.content)
    except (ValueError, TypeError):
        return None
    return document if isinstance(document, dict) else None


def _preservation(rubric: Rubric, source: dict) -> list[ConformanceFinding]:
    """Everything the rubric states must survive a serialization round trip."""
    assert rubric.definition is not None
    findings: list[ConformanceFinding] = []
    reloaded = RubricDefinition.model_validate_json(rubric.definition.model_dump_json())
    if canonical_digest(reloaded) != canonical_digest(rubric.definition):
        findings.append(
            ConformanceFinding(
                code="definition-loss",
                severity="error",
                message="Rubric definition does not survive serialization unchanged",
            )
        )
    original = {criterion["id"]: criterion for criterion in source.get("criteria", [])}
    for criterion in rubric.definition.criteria:
        declared = original.get(criterion.id, {})
        checks = {
            "instructions": (criterion.instructions, declared.get("instructions")),
            "weight": (criterion.weight, declared.get("weight", 1)),
            "threshold": (criterion.pass_threshold, declared.get("pass_threshold", 1)),
        }
        for field, (actual, expected) in checks.items():
            if expected is not None and actual != expected:
                findings.append(
                    ConformanceFinding(
                        code="value-drift",
                        severity="error",
                        criterion_id=criterion.id,
                        message=f"Criterion {field} changed during import",
                    )
                )
        levels = [
            {"label": level.label, "description": level.description, "score": level.score}
            for level in criterion.levels
        ]
        declared_levels = [
            {
                "label": entry.get("label"),
                "description": entry.get("description"),
                "score": entry.get("score"),
            }
            for entry in declared.get("levels", [])
        ]
        if levels != declared_levels:
            findings.append(
                ConformanceFinding(
                    code="level-drift",
                    severity="error",
                    criterion_id=criterion.id,
                    message="Criterion levels changed during import",
                )
            )
        categories = [
            {
                "label": category.label,
                "description": category.description,
                "outcome": category.outcome,
            }
            for category in criterion.categories
        ]
        declared_categories = [
            {
                "label": entry.get("label"),
                "description": entry.get("description"),
                "outcome": entry.get("outcome"),
            }
            for entry in declared.get("categories", [])
        ]
        if categories != declared_categories:
            findings.append(
                ConformanceFinding(
                    code="category-drift",
                    severity="error",
                    criterion_id=criterion.id,
                    message="Criterion categories changed during import",
                )
            )
    return findings


def _behaviour(rubric: Rubric, samples: list[ConformanceSample]) -> list[ConformanceFinding]:
    """Check conservative evaluator behaviour against known responses."""
    assert rubric.definition is not None
    findings: list[ConformanceFinding] = []
    evaluator = Evaluator()
    for sample in samples:
        response = _response(sample)
        evidence = EvidenceArtifact.capture(
            "response", response.model_dump_json(), f"conformance:{sample.id}"
        )
        values = {
            value.criterion_id: value
            for value in evaluator.evaluate(rubric, _case(sample), response, sample.id, evidence)
        }
        for criterion in rubric.definition.criteria:
            value = values[criterion.id]
            if is_subjective(criterion) and value.outcome in {"pass", "fail"}:
                findings.append(
                    ConformanceFinding(
                        code="subjective-auto-scored",
                        severity="error",
                        criterion_id=criterion.id,
                        sample_id=sample.id,
                        message="A human-assessed criterion produced an automatic verdict",
                    )
                )
            expected = sample.expect.get(criterion.id)
            if expected is not None and value.outcome != expected:
                findings.append(
                    ConformanceFinding(
                        code="expectation-mismatch",
                        severity="error",
                        criterion_id=criterion.id,
                        sample_id=sample.id,
                        message=(
                            f"Expected {expected} for sample {sample.label} but the "
                            f"evaluator reported {value.outcome}"
                        ),
                    )
                )
    return findings


def check_rubric(
    rubric: Rubric,
    *,
    samples: list[ConformanceSample] | None = None,
    pack: ConformancePack | None = None,
) -> ConformanceReport:
    """Run every conformance check for one rubric and optional known responses."""
    if rubric.definition is None:
        raise ValueError("Conformance requires an executable rubric definition")
    findings = [*_structure(rubric)]
    declared = _declared_source(rubric)
    if declared is None:
        findings.append(
            ConformanceFinding(
                code="source-not-json",
                severity="note",
                message=(
                    "Source document is not JSON, so only the definition round trip "
                    "could be verified"
                ),
            )
        )
    else:
        findings.extend(_preservation(rubric, declared))
    findings.extend(_behaviour(rubric, samples or []))
    return ConformanceReport(
        rubric_id=rubric.definition.id,
        rubric_version=rubric.definition.version,
        rubric_source_sha256=rubric.source.sha256,
        pack_id=pack.id if pack else None,
        criteria=len(rubric.definition.criteria),
        samples=len(samples or []),
        findings=findings,
    )


def check_pack(path: Path) -> ConformanceReport:
    """Load and check one conformance pack."""
    pack = load_pack(path)
    rubric = _rubric(pack, f"conformance-pack:{path.name}")
    return check_rubric(rubric, samples=pack.responses, pack=pack)
