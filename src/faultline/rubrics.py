"""Lossless UTF-8 import and explicit human normalization; no LLM needed."""

from importlib.resources import files
from pathlib import Path

import yaml

from faultline.documents import load_json, unique_mapping
from faultline.domain import EvidenceArtifact, Rubric, RubricDefinition, now


def import_rubric(path: Path) -> Rubric:
    with path.open("rb") as stream:
        raw = stream.read(2_000_001)
    return import_document(raw, path.suffix.lower(), str(path))


class RubricLoader(yaml.SafeLoader):
    """Reject implicit overrides and alias expansion in imported documents."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValueError("YAML aliases are not supported in rubric imports")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        return unique_mapping(
            [
                (self.construct_object(key, deep=deep), self.construct_object(value, deep=deep))
                for key, value in node.value
            ]
        )


def import_document(raw: bytes, suffix: str, provenance: str) -> Rubric:
    if len(raw) > 2_000_000:
        raise ValueError("Rubric source exceeds 2 MB")
    text = raw.decode("utf-8")  # Do not normalize BOMs or newlines in retained source.
    artifact = EvidenceArtifact.capture("rubric-source", text, provenance)
    if suffix not in {".json", ".yaml", ".yml"}:
        return Rubric(source=artifact, review_status="pending")
    document = text.lstrip("\ufeff")
    data = load_json(document) if suffix == ".json" else yaml.load(document, Loader=RubricLoader)
    definition = RubricDefinition.model_validate(data)
    return Rubric(source=artifact, definition=definition, review_status="structured")


def review_normalization(
    source: Rubric,
    draft: Path,
    reviewer: str,
    rationale: str,
) -> Rubric:
    if source.review_status != "pending":
        raise ValueError("Only pending imports can be normalized; import a new version instead")
    if not reviewer.strip() or not rationale.strip():
        raise ValueError("Reviewer identity and normalization rationale are required")
    normalized = import_rubric(draft)
    if normalized.definition is None:
        raise ValueError("Normalization draft must be structured JSON or YAML")
    return Rubric(
        source=source.source,
        definition=normalized.definition,
        review_status="reviewed",
        reviewer=reviewer,
        review_rationale=rationale,
        reviewed_at=now(),
        normalization_draft=EvidenceArtifact.capture(
            "normalization-draft",
            normalized.source.content,
            str(draft),
        ),
    )


def sample_rubric() -> Rubric:
    return import_document(
        files("faultline.data").joinpath("canary-rubric.v1.json").read_bytes(),
        ".json",
        "pkg:faultline/data/canary-rubric.v1.json",
    )
