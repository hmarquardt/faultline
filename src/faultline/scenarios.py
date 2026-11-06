"""Packaged synthetic agentic scenarios; definitions are data, never code."""

from importlib.resources import files

from faultline.documents import load_json
from faultline.domain import (
    AgenticScenario,
    EvidenceArtifact,
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
