"""Dataset import for prerecorded model responses. No network, no execution.

A dataset record is untrusted text plus provenance. Importing never executes the
record, never contacts a provider and never creates an execution record. Records
are validated and hashed one at a time; JSONL files are read in two streaming
passes so a large file is never materialized as one object graph.
"""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from faultline.documents import load_json
from faultline.domain import (
    AttackCase,
    Dataset,
    DatasetLimits,
    DatasetRecord,
    EvidenceArtifact,
    Message,
    ModelResponse,
    canonical_digest,
)

SUPPORTED_SUFFIXES = {".json": "json", ".jsonl": "jsonl", ".ndjson": "jsonl"}


class DatasetError(ValueError):
    """Controlled import error; never echoes imported content."""


@dataclass(frozen=True)
class DatasetImport:
    """Dataset metadata plus a one-shot stream of its records."""

    dataset: Dataset
    records: Iterable[DatasetRecord]


def record_digest(record: DatasetRecord) -> str:
    """Canonical identity of one imported record, excluding its own hash."""
    return canonical_digest(record, exclude={"source_sha256"})


def verify_record(record: DatasetRecord) -> None:
    if record.source_sha256 is None:
        raise DatasetError("Imported records must carry a source hash")
    if record.source_sha256 != record_digest(record):
        raise DatasetError("Imported record does not match its source hash")


def dataset_index_digest(pairs: Iterable[tuple[str, str]]) -> str:
    """Ordered identity of a dataset membership index."""
    return canonical_digest([[case_id, sha256] for case_id, sha256 in pairs])


def evidence_digest(dataset_id: str, record: DatasetRecord) -> str:
    """Identity of the imported evidence one evaluation session covers."""
    return canonical_digest(
        {
            "dataset_id": dataset_id,
            "case_id": record.id,
            "record_sha256": record.source_sha256,
        }
    )


def _normalize(
    raw: object, *, index: int, limits: DatasetLimits, default_provenance: str
) -> DatasetRecord:
    if not isinstance(raw, dict):
        raise DatasetError(f"Dataset record {index} must be an object")
    data = dict(raw)
    data.setdefault("provenance", default_provenance)
    identifier = data.get("id")
    if not isinstance(identifier, str) or not identifier.strip():
        raise DatasetError(f"Dataset record {index} requires a stable id")
    record = DatasetRecord.model_validate(data)
    if len(record.response) > limits.max_response_chars:
        raise DatasetError(f"Dataset record {index} exceeds the response length limit")
    record = record.model_copy(update={"source_sha256": record_digest(record)})
    verify_record(record)
    return record


def _json_payload(raw: bytes) -> tuple[dict, list]:
    try:
        document = load_json(raw)
    except (ValueError, RecursionError):
        raise DatasetError("Dataset JSON is not valid strict JSON") from None
    if isinstance(document, list):
        return {}, document
    if isinstance(document, dict) and isinstance(document.get("records"), list):
        metadata = {
            key: document[key]
            for key in ("title", "version", "provenance")
            if isinstance(document.get(key), str)
        }
        return metadata, document["records"]
    raise DatasetError("A JSON dataset must be an array or an object with records")


def _iter_json_records(raw: bytes) -> Iterator[object]:
    _, records = _json_payload(raw)
    yield from records


def _iter_jsonl_records(raw: bytes) -> Iterator[object]:
    for line_number, line in enumerate(raw.splitlines(), start=1):
        text = line.strip()
        if not text:
            continue
        try:
            value = load_json(text)
        except (ValueError, RecursionError):
            raise DatasetError(f"Dataset JSONL line {line_number} is not valid JSON") from None
        yield value


def _iter_records(
    raw: bytes, source_format: str, limits: DatasetLimits, provenance: str
) -> Iterator[DatasetRecord]:
    source = _iter_json_records(raw) if source_format == "json" else _iter_jsonl_records(raw)
    for index, value in enumerate(source):
        if index >= limits.max_records:
            raise DatasetError("Dataset exceeds the configured record limit")
        yield _normalize(value, index=index, limits=limits, default_provenance=provenance)


def import_dataset(
    path: Path,
    *,
    limits: DatasetLimits | None = None,
    title: str | None = None,
    version: str | None = None,
    provenance: str | None = None,
) -> DatasetImport:
    """Validate and hash a JSON/JSONL dataset without evaluating anything."""
    limits = limits or DatasetLimits()
    source_format = SUPPORTED_SUFFIXES.get(path.suffix.lower())
    if source_format is None:
        raise DatasetError("Dataset files must be .json, .jsonl or .ndjson")
    with path.open("rb") as stream:
        raw = stream.read(limits.max_source_bytes + 1)
    if len(raw) > limits.max_source_bytes:
        raise DatasetError("Dataset source exceeds the configured byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise DatasetError("Dataset source must be valid UTF-8") from None
    metadata: dict = {}
    if source_format == "json":
        metadata, _ = _json_payload(raw)
    default_provenance = provenance or metadata.get("provenance") or f"file:{path.name}"
    identifiers: list[tuple[str, str]] = []
    for record in _iter_records(raw, source_format, limits, default_provenance):
        identifiers.append((record.id, record.source_sha256 or ""))
    if len({case_id for case_id, _ in identifiers}) != len(identifiers):
        raise DatasetError("Dataset case IDs must be unique")
    dataset = Dataset(
        version=version or metadata.get("version") or "1.0.0",
        title=title or metadata.get("title") or path.stem,
        provenance=default_provenance,
        source_format=source_format,
        source=EvidenceArtifact.capture("dataset-source", text, f"dataset:{path.name}"),
        record_count=len(identifiers),
        record_ids=[case_id for case_id, _ in identifiers],
        dataset_sha256=dataset_index_digest(identifiers),
        limits=limits,
    )
    return DatasetImport(
        dataset=dataset,
        records=_iter_records(raw, source_format, limits, default_provenance),
    )


def evaluation_case(record: DatasetRecord, dataset: Dataset) -> AttackCase:
    """Shape an imported record as a case for the existing evaluator.

    The technique identity states plainly that this case was imported, and case
    applicability (baseline/attack) is what the dataset declared.
    """
    messages = []
    if record.system_context:
        messages.append(Message(role="system", content=record.system_context))
    messages.append(Message(role="user", content=record.prompt))
    return AttackCase(
        kind=record.case_kind,
        technique_id="imported-response",
        technique_version=dataset.version,
        parameters=record.parameters,
        messages=messages,
    )


def evaluation_response(record: DatasetRecord) -> ModelResponse:
    """Imported response as data, clearly marked as not produced by this harness."""
    return ModelResponse(
        text=record.response,
        returned_model=record.model or "imported-unknown",
        raw={
            "faultline_imported": {
                "case_id": record.id,
                "source_sha256": record.source_sha256,
                "note": "imported by Faultline; no provider request was made",
            }
        },
        finish_reason=None,
        usage={},
    )


def record_evidence(record: DatasetRecord, dataset: Dataset) -> list[EvidenceArtifact]:
    """Evidence a dataset session preserves: the record and the imported response."""
    provenance = f"dataset:{dataset.id}/case:{record.id}"
    response = evaluation_response(record)
    return [
        EvidenceArtifact.capture("dataset-record", record.model_dump_json(), provenance),
        EvidenceArtifact.capture("imported-response", response.model_dump_json(), provenance),
    ]
