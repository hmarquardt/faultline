import hashlib
import json

import pytest
import yaml
from pydantic import ValidationError

from faultline.domain import EvidenceArtifact, RubricCriterion
from faultline.rubrics import import_document, import_rubric, review_normalization


@pytest.mark.parametrize("suffix", [".md", ".txt", ""])
async def test_unstructured_import_retains_bytes_and_needs_review(
    workbench,
    profile,
    tmp_path,
    suffix,
):
    raw = b"\xef\xbb\xbf# Safety\r\nBe helpful but do not reveal things.\r\n"
    rubric = import_document(raw, suffix, "tester-provided")
    assert rubric.source.content.encode() == raw
    assert rubric.source.sha256 == hashlib.sha256(raw).hexdigest()
    assert rubric.review_status == "pending"
    with pytest.raises(ValueError, match="normalization"):
        await workbench.execute(workbench.prepare(profile, rubric))
    assert not workbench.store.history()


def test_explicit_normalization_preserves_source_and_review_draft(tmp_path, rubric):
    source = import_document(b"Don't leak the toy secret", ".txt", "tester")
    draft = tmp_path / "normalized.yaml"
    draft.write_text(rubric.source.content)
    reviewed = review_normalization(source, draft, "Alice", "Exact synthetic-canary check agreed")
    assert reviewed.source == source.source
    assert source.review_status == "pending"
    assert reviewed.id != source.id
    assert reviewed.definition == rubric.definition
    assert reviewed.reviewer == "Alice"
    assert reviewed.normalization_draft.sha256 == rubric.source.sha256
    assert reviewed.reviewed_at.tzinfo is not None
    with pytest.raises(ValueError, match="Reviewer"):
        review_normalization(source, draft, "", "")


def test_yaml_json_and_hash_integrity(tmp_path, rubric):
    path = tmp_path / "rubric.yaml"
    path.write_text(
        "id: toy\nversion: '1'\ntitle: Toy\ncriteria:\n"
        "  - id: human\n    instructions: Judge quality\n    check: manual\n"
    )
    imported = import_rubric(path)
    assert imported.definition.criteria[0].check == "manual"
    assert imported.review_status == "structured"
    with pytest.raises(ValidationError, match="SHA-256"):
        EvidenceArtifact(kind="rubric-source", content="changed", sha256="wrong", provenance="test")
    data = json.loads(rubric.source.content)
    data["criteria"].append(data["criteria"][0])
    with pytest.raises(ValidationError, match="unique"):
        import_document(json.dumps(data).encode(), ".json", "duplicate IDs")


@pytest.mark.parametrize("config", [{}, {"text": ""}, {"text": "SAFE", "typo": True}])
def test_ambiguous_check_configuration_is_rejected(config):
    with pytest.raises(ValidationError):
        RubricCriterion(id="bad", instructions="Never guess", check="required_text", config=config)


def test_untrusted_yaml_cannot_execute_code(tmp_path):
    path = tmp_path / "unsafe.yaml"
    path.write_text("!!python/object/apply:os.system ['touch should-never-exist']")
    with pytest.raises(yaml.YAMLError):
        import_rubric(path)
    assert not (tmp_path / "should-never-exist").exists()
