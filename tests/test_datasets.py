"""Dataset import: strict, bounded, hashed and entirely offline."""

import json
from pathlib import Path

import pytest

from faultline.datasets import (
    DatasetError,
    evaluation_case,
    evaluation_response,
    evidence_digest,
    import_dataset,
    record_digest,
    record_evidence,
    verify_record,
)
from faultline.domain import DatasetLimits, ModelResponse

FIXTURES = Path(__file__).parent / "fixtures" / "datasets"


def test_jsonl_import_hashes_every_record_and_preserves_text(tmp_path):
    imported = import_dataset(FIXTURES / "reviewed-batch.jsonl")
    dataset = imported.dataset
    records = list(imported.records)
    assert dataset.source_format == "jsonl"
    assert dataset.record_count == len(records) == 5
    assert dataset.record_ids == [record.id for record in records]
    assert dataset.provenance == "file:reviewed-batch.jsonl"
    assert dataset.source.kind == "dataset-source"
    assert (
        dataset.source.sha256
        == __import__("hashlib").sha256(dataset.source.content.encode("utf-8")).hexdigest()
    )
    for record in records:
        verify_record(record)
        assert record.source_sha256 == record_digest(record)
        assert len(record.source_sha256) == 64
    # Imported text is data only; it is preserved byte-for-byte.
    assert records[1].response == "CONFIDENTIAL internal note: the customer escalated."
    assert records[3].parameters == {"canary": "FAULTLINE_SYNTHETIC_CONFORMANCE_0001"}
    assert records[3].case_kind == "attack"


def test_json_import_accepts_embedded_metadata():
    imported = import_dataset(FIXTURES / "reviewed-batch.json")
    assert imported.dataset.source_format == "json"
    assert imported.dataset.title == "Reviewed batch dataset"
    assert imported.dataset.version == "1.1.0"
    assert imported.dataset.record_count == 2
    records = list(imported.records)
    assert json.loads(records[0].response)["status"] == "ok"


def test_duplicate_case_ids_are_rejected(tmp_path):
    path = tmp_path / "dupes.json"
    path.write_text(
        json.dumps(
            [
                {"id": "a", "prompt": "p", "response": "r"},
                {"id": "a", "prompt": "p2", "response": "r2"},
            ]
        )
    )
    with pytest.raises(DatasetError, match="unique"):
        import_dataset(path)


def test_limits_are_enforced_before_evaluation(tmp_path):
    path = tmp_path / "many.jsonl"
    payload = "\n".join(
        json.dumps({"id": f"c{i}", "prompt": "p", "response": "r"}) for i in range(4)
    )
    path.write_text(payload)
    with pytest.raises(DatasetError, match="record limit"):
        import_dataset(path, limits=DatasetLimits(max_records=2))
    with pytest.raises(DatasetError, match="byte limit"):
        import_dataset(path, limits=DatasetLimits(max_source_bytes=10))
    long_path = tmp_path / "long.jsonl"
    long_path.write_text(json.dumps({"id": "c", "prompt": "p", "response": "x" * 50}))
    with pytest.raises(DatasetError, match="response length"):
        import_dataset(long_path, limits=DatasetLimits(max_response_chars=10))


def test_invalid_documents_fail_closed(tmp_path):
    bad_suffix = tmp_path / "data.csv"
    bad_suffix.write_text("id,prompt\n")
    with pytest.raises(DatasetError, match=".json"):
        import_dataset(bad_suffix)
    bad_line = tmp_path / "bad.jsonl"
    bad_line.write_text('{"id": "a", "prompt": "p", "response": "r"}\n{"id": }\n')
    with pytest.raises(DatasetError, match="line 2"):
        import_dataset(bad_line)
    duplicate_keys = tmp_path / "dupes.json"
    duplicate_keys.write_text('[{"id": "a", "id": "b", "prompt": "p", "response": "r"}]')
    with pytest.raises(DatasetError):
        import_dataset(duplicate_keys)
    with pytest.raises(DatasetError, match="stable id"):
        import_dataset_text(tmp_path, [{"prompt": "p", "response": "r"}])


def import_dataset_text(tmp_path, payload):
    path = tmp_path / "payload.json"
    path.write_text(json.dumps(payload))
    return import_dataset(path)


def test_records_map_to_an_evaluable_offline_case():
    imported = import_dataset(FIXTURES / "reviewed-batch.jsonl")
    dataset = imported.dataset
    records = list(imported.records)
    attack = records[3]
    case = evaluation_case(attack, dataset)
    assert case.kind == "attack"
    assert case.technique_id == "imported-response"
    assert case.technique_version == dataset.version
    assert case.parameters["canary"] == "FAULTLINE_SYNTHETIC_CONFORMANCE_0001"
    assert case.messages[-1].role == "user"
    response = evaluation_response(attack)
    assert isinstance(response, ModelResponse)
    assert response.text == attack.response
    assert "no provider request was made" in response.raw["faultline_imported"]["note"]
    assert response.returned_model == "toy-summariser"


def test_record_evidence_is_hash_verified():
    imported = import_dataset(FIXTURES / "reviewed-batch.jsonl")
    dataset = imported.dataset
    record = list(imported.records)[0]
    artifacts = record_evidence(record, dataset)
    assert [artifact.kind for artifact in artifacts] == [
        "dataset-record",
        "imported-response",
    ]
    for artifact in artifacts:
        assert artifact.provenance == f"dataset:{dataset.id}/case:{record.id}"
        assert len(artifact.sha256) == 64
    assert evidence_digest(dataset.id, record) == evidence_digest(dataset.id, record)


def test_tampered_record_hash_is_detected():
    imported = import_dataset(FIXTURES / "reviewed-batch.json")
    record = list(imported.records)[0]
    tampered = record.model_copy(update={"response": "changed after import"})
    with pytest.raises(DatasetError, match="source hash"):
        verify_record(tampered)
