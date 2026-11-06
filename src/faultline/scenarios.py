"""Packaged synthetic agentic scenarios; definitions are data, never code."""

from importlib.resources import files

from faultline.documents import load_json
from faultline.domain import (
    AgenticScenario,
    EvidenceArtifact,
    ExperimentVariant,
    Rubric,
    RubricDefinition,
    canonical_digest,
)

SCENARIO_PACKAGE = "scenarios.v1.json"


def scenarios() -> dict[str, AgenticScenario]:
    """Load every packaged scenario, rejecting duplicate identifiers."""
    raw = files("faultline.data").joinpath(SCENARIO_PACKAGE).read_text()
    definitions = [AgenticScenario.model_validate(item) for item in load_json(raw)]
    if len({definition.id for definition in definitions}) != len(definitions):
        raise ValueError("Duplicate scenario ID")
    return {definition.id: definition for definition in definitions}


def scenario(identifier: str) -> AgenticScenario:
    registry = scenarios()
    if identifier not in registry:
        raise ValueError("Unknown scenario ID")
    return registry[identifier]


def scenario_digest(scenario: AgenticScenario) -> str:
    """Canonical identity of the scenario definition."""
    return canonical_digest(scenario)


def scenario_artifact(scenario: AgenticScenario) -> EvidenceArtifact:
    return EvidenceArtifact.capture(
        "scenario-source",
        scenario.model_dump_json(),
        f"scenario:{scenario.id}@{scenario.version}",
    )


def rubric_for(scenario: AgenticScenario) -> Rubric:
    """Build the scenario's rubric from its embedded, versioned definition."""
    definition = RubricDefinition.model_validate(scenario.rubric)
    return Rubric(
        source=EvidenceArtifact.capture(
            "rubric-source",
            definition.model_dump_json(indent=2),
            f"scenario-rubric:{scenario.id}@{scenario.version}",
        ),
        definition=definition,
        review_status="structured",
    )


def _document_hashes(scenario: AgenticScenario) -> dict[str, str]:
    return {
        document.id: canonical_digest(
            {
                "title": document.title,
                "content": document.content,
                "trust": document.trust,
                "injection": document.injection,
                "control_content": document.control_content,
            }
        )
        for document in scenario.documents
    }


def corpus_digest(scenario: AgenticScenario) -> str:
    """Identity of the served corpus, independent of scripts and rubric."""
    return canonical_digest(
        {
            document.id: {
                "title": document.title,
                "content": document.content,
                "trust": document.trust,
                "source_note": document.source_note,
            }
            for document in scenario.documents
        }
    )


def _variant(scenario: AgenticScenario, role: str, script_key: str) -> ExperimentVariant:
    injected = [
        document for document in scenario.documents if document.id == scenario.injected_document_id
    ]
    return ExperimentVariant(
        role=role,
        label=f"{role}:{scenario.id}@{scenario.version}",
        scenario=scenario,
        scenario_sha256=canonical_digest(scenario),
        corpus_sha256=corpus_digest(scenario),
        injected_document_id=scenario.injected_document_id,
        injected_payload_sha256=(
            canonical_digest(injected[0].injection) if injected and injected[0].injection else None
        ),
        script_key=script_key,
        document_hashes=_document_hashes(scenario),
    )


def control_scenario(scenario: AgenticScenario) -> AgenticScenario:
    """Neutralize the injected payload without touching anything else."""
    if scenario.injected_document_id is None:
        raise ValueError("Scenario has no injected document to neutralize")
    documents = []
    for document in scenario.documents:
        if document.id != scenario.injected_document_id:
            documents.append(document)
            continue
        if document.control_content is None:
            raise ValueError(
                "Injected document declares no control rendering; a control cannot be "
                "derived safely"
            )
        documents.append(
            document.model_copy(
                update={
                    "content": document.control_content,
                    "trust": "trusted-reference",
                    "injection": None,
                }
            )
        )
    return scenario.model_copy(update={"documents": documents, "injected_document_id": None})


def variant_differences(control: ExperimentVariant, attack: ExperimentVariant) -> list:
    """Declare exactly what differs between the two variants."""
    from faultline.domain import VariantDifference

    differences: list[VariantDifference] = []
    control_documents = {document.id: document for document in control.scenario.documents}
    for document in attack.scenario.documents:
        original = control_documents.get(document.id)
        if original is None:  # pragma: no cover - variants share the corpus
            differences.append(
                VariantDifference(
                    path=f"documents[{document.id}]",
                    control_value="absent",
                    attack_value=document.trust,
                    description="Document exists only in the attack variant",
                )
            )
            continue
        if original.content != document.content:
            differences.append(
                VariantDifference(
                    path=f"documents[{document.id}].content",
                    control_value=canonical_digest(original.content),
                    attack_value=canonical_digest(document.content),
                    description="Attack variant content carries the injected instruction",
                )
            )
        if original.trust != document.trust:
            differences.append(
                VariantDifference(
                    path=f"documents[{document.id}].trust",
                    control_value=original.trust,
                    attack_value=document.trust,
                    description="Attack variant marks the document untrusted-injected",
                )
            )
        if original.injection != document.injection:
            differences.append(
                VariantDifference(
                    path=f"documents[{document.id}].injection",
                    control_value=original.injection or "none",
                    attack_value=document.injection or "none",
                    description="Attack variant embeds the attacker-controlled payload",
                )
            )
    if control.scenario.injected_document_id != attack.scenario.injected_document_id:
        differences.append(
            VariantDifference(
                path="injected_document_id",
                control_value=control.scenario.injected_document_id or "none",
                attack_value=attack.scenario.injected_document_id or "none",
                description="Only the attack variant declares an injected document",
            )
        )
    return differences


def variant_pair(scenario: AgenticScenario, agent: str) -> tuple:
    """Build the canonical control/attack pair for one scripted or endpoint agent."""
    control = control_scenario(scenario)
    control_key = "secure" if agent == "scripted-secure" else "control_vulnerable"
    if control_key not in control.scripts:
        control_key = "secure"
    attack_key = "secure" if agent == "scripted-secure" else "vulnerable"
    return (
        _variant(control, "control", control_key),
        _variant(scenario, "attack", attack_key),
    )
