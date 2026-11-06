"""Rubric conformance: semantic preservation and conservative evaluation."""

from pathlib import Path

import pytest

from faultline.conformance import (
    ConformanceSample,
    check_pack,
    check_rubric,
    is_subjective,
    load_pack,
)
from faultline.domain import EvidenceArtifact, Rubric, RubricDefinition
from faultline.rubrics import import_document

PACKS = Path(__file__).parent / "fixtures" / "conformance"
NAMES = [
    "instruction-adherence",
    "response-quality",
    "factual-accuracy",
    "safety-privacy",
    "structured-output",
    "prompt-injection",
]


def rubric_from_pack(pack):
    return Rubric(
        source=EvidenceArtifact.capture(
            "rubric-source", __import__("json").dumps(pack.rubric, indent=2), "test"
        ),
        definition=RubricDefinition.model_validate(pack.rubric),
        review_status="structured",
    )


@pytest.mark.parametrize("name", NAMES)
def test_every_conformance_pack_passes_without_errors(name):
    report = check_pack(PACKS / f"{name}.json")
    assert report.errors == [], [finding.model_dump() for finding in report.errors]
    assert report.criteria >= 2
    assert report.samples >= 4


@pytest.mark.parametrize("name", NAMES)
def test_known_responses_are_exercised(name):
    pack = load_pack(PACKS / f"{name}.json")
    labels = {sample.label for sample in pack.responses}
    assert {
        "full compliance",
        "partial compliance",
        "clear failure",
        "ambiguous result",
    } <= labels
    expectations = [sample.expect for sample in pack.responses if sample.expect]
    assert expectations, f"{name} must declare at least one deterministic expectation"


@pytest.mark.parametrize("name", NAMES)
def test_import_preserves_wording_labels_weights_and_thresholds(name):
    pack = load_pack(PACKS / f"{name}.json")
    imported = import_document(
        __import__("json").dumps(pack.rubric, ensure_ascii=False).encode(),
        ".json",
        f"conformance:{name}",
    )
    assert imported.review_status == "structured"
    for criterion in imported.definition.criteria:
        declared = next(item for item in pack.rubric["criteria"] if item["id"] == criterion.id)
        assert criterion.instructions == declared["instructions"]
        assert criterion.weight == declared.get("weight", 1)
        assert criterion.pass_threshold == declared.get("pass_threshold", 1)
        assert [level.label for level in criterion.levels] == [
            level["label"] for level in declared.get("levels", [])
        ]
        assert [level.description for level in criterion.levels] == [
            level["description"] for level in declared.get("levels", [])
        ]
        assert [category.label for category in criterion.categories] == [
            category["label"] for category in declared.get("categories", [])
        ]
    # Nothing in the definition changes when serialized and reloaded.
    reloaded = RubricDefinition.model_validate_json(imported.definition.model_dump_json())
    assert reloaded == imported.definition


def test_conformance_detects_a_wrong_expectation():
    pack = load_pack(PACKS / "structured-output.json")
    rubric = rubric_from_pack(pack)
    samples = [
        ConformanceSample(
            id="wrong",
            label="deliberately wrong expectation",
            prompt="Return the JSON envelope.",
            response='{"status": "ok", "confidence": 0.9}',
            expect={"SO-001": "fail"},
        )
    ]
    report = check_rubric(rubric, samples=samples)
    codes = {finding.code for finding in report.errors}
    assert "expectation-mismatch" in codes


def test_conformance_detects_semantic_drift():
    pack = load_pack(PACKS / "instruction-adherence.json")
    rubric = rubric_from_pack(pack)
    # Change the definition without changing the retained source document.
    definition = rubric.definition.model_copy(deep=True)
    changed = definition.criteria[0].model_copy(update={"weight": 99})
    drifted = definition.model_copy(update={"criteria": [changed, *definition.criteria[1:]]})
    report = check_rubric(rubric.model_copy(update={"definition": drifted}))
    codes = {finding.code for finding in report.errors}
    assert "value-drift" in codes


def test_conformance_never_scores_subjective_criteria():
    pack = load_pack(PACKS / "response-quality.json")
    rubric = rubric_from_pack(pack)
    subjective = [c for c in rubric.definition.criteria if is_subjective(c)]
    assert subjective, "the graded fixture must contain a subjective criterion"
    report = check_rubric(rubric, samples=pack.responses)
    assert not any(finding.code == "subjective-auto-scored" for finding in report.findings)


def test_unexecutable_evidence_requirement_is_a_warning():
    rubric = import_document(
        b'{"id":"x","version":"1","title":"T","criteria":[{"id":"C","instructions":"i",'
        b'"check":"manual","config":{},"evidence_requirements":["screenshot"]}]}',
        ".json",
        "test",
    )
    report = check_rubric(rubric)
    codes = {(finding.code, finding.severity) for finding in report.findings}
    assert ("unsupported-evidence", "warning") in codes


def test_pack_loading_is_strict_about_unknown_fields(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"id": "x", "title": "y", "rubric": {}, "unknown": 1}')
    with pytest.raises(ValueError):
        load_pack(path)


@pytest.mark.parametrize(
    "name",
    [
        "instruction-adherence",
        "response-quality",
        "factual-accuracy",
        "safety-privacy",
        "prompt-injection",
    ],
)
def test_subjective_criteria_are_reported_as_human_assessed(name):
    report = check_pack(PACKS / f"{name}.json")
    assert any(finding.code == "subjective-criterion" for finding in report.findings)
