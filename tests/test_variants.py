"""Control construction: only declared differences may separate the arms."""

import pytest

from faultline.domain import AgenticScenario, ScenarioDocument
from faultline.scenarios import (
    control_scenario,
    scenario,
    scenarios,
    variant_differences,
    variant_pair,
)


@pytest.mark.parametrize("scenario_id", sorted(scenarios()))
def test_control_removes_only_the_injected_payload(scenario_id):
    attack = scenario(scenario_id)
    control = control_scenario(attack)
    injected = next(
        document for document in attack.documents if document.id == attack.injected_document_id
    )
    assert control.injected_document_id is None
    assert injected.injection not in str(control.model_dump(mode="json"))
    # Everything that defines the legitimate task is untouched.
    assert control.user_task == attack.user_task
    assert control.system_prompt == attack.system_prompt
    assert control.allowed_tools == attack.allowed_tools
    assert control.writable_records == attack.writable_records
    assert control.protected_records == attack.protected_records
    assert control.rubric == attack.rubric
    # Unrelated documents keep identical content.
    for original, cleaned in zip(attack.documents, control.documents, strict=True):
        if original.id == attack.injected_document_id:
            assert cleaned.trust == "trusted-reference"
            assert cleaned.injection is None
            assert cleaned.content == original.control_content
        else:
            assert cleaned == original


def test_variant_pair_declares_every_difference_with_hashes():
    attack = scenario("retrieved-authority-spoof")
    control, injected = variant_pair(attack, "scripted-vulnerable")
    assert control.role == "control" and injected.role == "attack"
    assert control.corpus_sha256 != injected.corpus_sha256
    assert control.scenario_sha256 != injected.scenario_sha256
    assert injected.injected_document_id == "doc-memo"
    assert control.injected_document_id is None
    assert len(injected.injected_payload_sha256 or "") == 64
    assert control.script_key == "control_vulnerable"
    assert injected.script_key == "vulnerable"
    paths = {difference.path for difference in variant_differences(control, injected)}
    assert paths == {
        "documents[doc-memo].content",
        "documents[doc-memo].trust",
        "documents[doc-memo].injection",
        "injected_document_id",
    }
    # Secure fixtures differ only in the corpus, never in the script.
    secure_control, secure_attack = variant_pair(attack, "scripted-secure")
    assert secure_control.script_key == secure_attack.script_key == "secure"


def test_control_requires_a_declared_clean_rendering():
    attack = scenario("boundary-enforcement")
    payload = attack.model_dump(mode="json")
    for document in payload["documents"]:
        document.pop("control_content", None)
    stripped = AgenticScenario.model_validate(payload)
    with pytest.raises(ValueError, match="no control rendering"):
        control_scenario(stripped)


def test_control_rendering_may_not_contain_the_payload():
    attack = scenario("tool-output-laundering")
    injected = next(
        document for document in attack.documents if document.id == attack.injected_document_id
    )
    with pytest.raises(ValueError, match="must not contain the injected payload"):
        ScenarioDocument.model_validate(
            {
                **injected.model_dump(mode="json"),
                "control_content": injected.content,
            }
        )
