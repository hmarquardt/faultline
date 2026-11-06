"""Multi-dimensional disagreement: outcome, label, score and policy behaviour."""

import pytest

from faultline.adjudication import (
    agreement_level,
    dimensions,
    ordinal_gap,
    rating_key,
    resolve,
)
from faultline.domain import AdjudicationPolicy, HumanJudgment, RubricCriterion


def categorical():
    return RubricCriterion(
        id="FA-001",
        instructions="Claim support classification",
        check="manual",
        scale_kind="categorical",
        categories=[
            {"label": "supported", "description": "Supported", "outcome": "pass"},
            {"label": "missing-context", "description": "Missing context", "outcome": "fail"},
            {
                "label": "incorrect-reasoning",
                "description": "Incorrect reasoning",
                "outcome": "fail",
            },
        ],
    )


def ordinal():
    return RubricCriterion(
        id="RQ-001",
        instructions="Graded clarity",
        check="manual",
        scale_kind="ordinal",
        scale_min=1,
        scale_max=5,
        pass_threshold=3,
        levels=[
            {"label": "bare", "description": "Bare", "score": 1},
            {"label": "adequate", "description": "Adequate", "score": 3},
            {"label": "clear", "description": "Clear", "score": 4},
            {"label": "exemplary", "description": "Exemplary", "score": 5},
        ],
    )


def binary():
    return RubricCriterion(id="CONF-001", instructions="Literal check", check="manual")


def judgment(reviewer, outcome, *, label=None, score=None, criterion="C"):
    return HumanJudgment(
        session_id="s",
        run_id=None,
        criterion_id=criterion,
        reviewer=reviewer,
        outcome=outcome,
        label=label,
        score=score,
        rationale="test",
    )


def test_dimensions_follow_the_declared_scale():
    assert dimensions(binary()) == ("outcome",)
    assert dimensions(categorical()) == ("outcome", "label")
    assert dimensions(ordinal()) == ("outcome", "label", "score")


def test_identical_outcomes_with_different_categories_are_not_full_agreement():
    criterion = categorical()
    alice = judgment("Alice", "fail", label="missing-context", criterion="FA-001")
    bob = judgment("Bob", "fail", label="incorrect-reasoning", criterion="FA-001")
    assert agreement_level([alice, bob], criterion) == "outcome_only"
    assert rating_key(alice, criterion) != rating_key(bob, criterion)
    resolution = resolve([alice, bob], AdjudicationPolicy(kind="unanimous"), criterion)
    assert resolution.status == "unresolved"
    assert resolution.agreement == "outcome_only"
    assert resolution.outcome is None
    chosen = resolve(
        [alice, bob], AdjudicationPolicy(kind="single_reviewer", reviewer="Bob"), criterion
    )
    assert chosen.status == "adjudicated"
    assert chosen.outcome == "fail"
    assert chosen.label == "incorrect-reasoning"
    assert chosen.dissenting_ids == (alice.id,)


def test_different_grades_with_the_same_outcome_stay_distinguishable():
    criterion = ordinal()
    alice = judgment("Alice", "pass", label="clear", score=4, criterion="RQ-001")
    bob = judgment("Bob", "pass", label="exemplary", score=5, criterion="RQ-001")
    assert agreement_level([alice, bob], criterion) == "outcome_only"
    assert ordinal_gap([alice, bob], criterion) == 1
    resolution = resolve(
        [alice, bob], AdjudicationPolicy(kind="single_reviewer", reviewer="Alice"), criterion
    )
    # The effective score is the adopted reviewer's score, never an average.
    assert resolution.score == 4
    assert resolution.label == "clear"
    assert resolution.outcome == "pass"


def test_majority_requires_a_majority_of_identical_ratings():
    criterion = categorical()
    judgments = [
        judgment("A", "fail", label="missing-context", criterion="FA-001"),
        judgment("B", "fail", label="missing-context", criterion="FA-001"),
        judgment("C", "fail", label="incorrect-reasoning", criterion="FA-001"),
    ]
    majority = resolve(judgments, AdjudicationPolicy(kind="majority"), criterion)
    assert majority.status == "adjudicated"
    assert majority.label == "missing-context"
    assert majority.dissenting_ids == (judgments[2].id,)
    tie = resolve([judgments[0], judgments[2]], AdjudicationPolicy(kind="majority"), criterion)
    assert tie.status == "unresolved"
    assert tie.agreement == "outcome_only"


def test_binary_agreement_needs_only_the_outcome():
    criterion = binary()
    judgments = [judgment("A", "fail"), judgment("B", "fail")]
    assert agreement_level(judgments, criterion) == "full"
    resolution = resolve(judgments, AdjudicationPolicy(kind="unanimous"), criterion)
    assert resolution.status == "agreed"
    assert resolution.agreement == "full"
    assert len(resolution.basis_ids) == 2
    mixed = resolve(
        [judgment("A", "fail"), judgment("B", "pass")],
        AdjudicationPolicy(kind="unanimous"),
        criterion,
    )
    assert mixed.status == "unresolved"
    assert mixed.agreement == "none"


def test_a_single_judgment_is_never_treated_as_agreement():
    criterion = categorical()
    one = [judgment("A", "pass", label="supported", criterion="FA-001")]
    assert agreement_level(one, criterion) is None
    resolution = resolve(one, AdjudicationPolicy(kind="single_reviewer", reviewer="A"), criterion)
    assert resolution.status == "agreed"
    assert resolution.outcome == "pass"


def test_policy_validation_remains_explicit():
    criterion = binary()
    judgments = [judgment("A", "fail"), judgment("B", "pass")]
    with pytest.raises(ValueError, match="designated reviewer"):
        AdjudicationPolicy(kind="single_reviewer")
    missing = resolve(
        judgments,
        AdjudicationPolicy(kind="single_reviewer", reviewer="Carol"),
        criterion,
    )
    assert missing.status == "unresolved"
    assert missing.basis_ids == (judgments[0].id, judgments[1].id)
    assert missing.dissenting_ids == (judgments[0].id, judgments[1].id)
