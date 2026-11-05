import pytest
from pydantic import ValidationError

from faultline.domain import RubricCriterion
from faultline.rubrics import import_document
from tests.test_evaluation import evaluate


@pytest.mark.parametrize(
    "suffix, document",
    [
        (".json", '{"id":"first","id":"second"}'),
        (".yaml", "id: first\nid: second\n"),
        (".yaml", "id: &alias toy\nversion: *alias\n"),
    ],
)
def test_ambiguous_duplicate_keys_and_yaml_aliases_are_rejected(suffix, document):
    with pytest.raises(ValueError):
        import_document(document.encode(), suffix, "test")


def test_invalid_json_schema_is_a_validation_error():
    with pytest.raises(ValidationError, match="Invalid JSON Schema"):
        RubricCriterion(
            id="bad",
            instructions="Invalid schema",
            check="json_schema",
            config={"schema": {"type": "not-a-real-type"}},
        )


def test_schema_remote_references_cannot_trigger_network(rubric):
    criterion = RubricCriterion(
        id="remote",
        instructions="Remote schema is unavailable",
        check="json_schema",
        config={
            "schema": {
                "$ref": "https://example.invalid/schema.json",
            }
        },
    )
    value, score = evaluate(rubric, criterion, "{}")
    assert value.outcome == "uncertain"
    assert "locally" in value.rationale
    assert score.coverage == 0


def test_local_schema_references_work(rubric):
    criterion = RubricCriterion(
        id="local",
        instructions="Local boolean",
        check="json_schema",
        config={"schema": {"$defs": {"flag": {"type": "boolean"}}, "$ref": "#/$defs/flag"}},
    )
    value, _ = evaluate(rubric, criterion, "true")
    assert value.outcome == "pass"


def test_threshold_cannot_mark_a_failed_check_as_passing():
    with pytest.raises(ValidationError, match="Threshold"):
        RubricCriterion(
            id="bad", instructions="Not a valid threshold", check="manual", pass_threshold=0
        )


@pytest.mark.parametrize("response", ["NaN", '{"ok":true,"ok":false}'])
def test_nonstandard_or_ambiguous_json_is_noncompliant(rubric, response):
    criterion = RubricCriterion(
        id="json",
        instructions="Standard JSON only",
        check="json_schema",
        config={"schema": {}},
    )
    value, _ = evaluate(rubric, criterion, response)
    assert value.outcome == "fail"
