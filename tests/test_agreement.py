"""Inter-rater agreement: reference calculations and explicit undefined cases."""

import pytest

from faultline.agreement import AgreementUnit, build_report, cohen_kappa, rating_of
from faultline.domain import HumanJudgment, RubricCriterion


def binary_criterion():
    return RubricCriterion(id="CONF-001", instructions="Literal check", check="manual")


def ordinal_criterion():
    return RubricCriterion(
        id="RQ-001",
        instructions="Graded quality",
        check="manual",
        scale_kind="ordinal",
        scale_min=0,
        scale_max=1,
        pass_threshold=0.6,
        levels=[
            {"label": "unusable", "description": "Unusable", "score": 0},
            {"label": "partial", "description": "Partial", "score": 0.5},
            {"label": "excellent", "description": "Excellent", "score": 1},
        ],
    )


def categorical_criterion():
    return RubricCriterion(
        id="FA-001",
        instructions="Claim support",
        check="manual",
        scale_kind="categorical",
        categories=[
            {"label": "supported", "description": "Supported", "outcome": "pass"},
            {"label": "unsupported", "description": "Unsupported", "outcome": "fail"},
        ],
    )


def judgment(reviewer, outcome="pass", *, label=None, score=None, session="s1", criterion="C"):
    return HumanJudgment(
        session_id=session,
        criterion_id=criterion,
        reviewer=reviewer,
        outcome=outcome,
        label=label,
        score=score,
        rationale="test",
    )


def unit(criterion, judgments, *, session="s1", rubric_version="1.0.0", digest="c" * 64):
    return AgreementUnit(
        session_id=session,
        rubric_id="rubric",
        rubric_version=rubric_version,
        rubric_definition_sha256=digest,
        criterion=criterion,
        judgments=judgments,
    )


def test_cohen_kappa_matches_reference_two_by_two():
    # Classic 2x2 table: 20/5/10/15, po=0.7, pe=0.5, kappa=0.4
    pairs = [("a", "a")] * 20 + [("a", "b")] * 5 + [("b", "a")] * 10 + [("b", "b")] * 15
    result = cohen_kappa(pairs, ["a", "b"])
    assert result.defined
    assert result.value == pytest.approx(0.4)
    assert result.observed_agreement == pytest.approx(0.7)
    assert result.expected_agreement == pytest.approx(0.5)
    assert result.n == 50


def test_cohen_kappa_perfect_agreement_is_one():
    pairs = [("pass", "pass")] * 3 + [("fail", "fail")] * 2
    result = cohen_kappa(pairs, ["pass", "fail"])
    assert result.defined
    assert result.value == pytest.approx(1.0)


def test_weighted_kappa_matches_reference_calculation():
    categories = ["a", "b", "c"]
    pairs = [("a", "a"), ("a", "b"), ("b", "b"), ("b", "c"), ("c", "c")]
    weighted = cohen_kappa(pairs, categories, weighting="linear")
    unweighted = cohen_kappa(pairs, categories)
    # po_w=0.8, pe_w=0.56 -> 0.5454...; po=0.6, pe=0.32 -> 0.4117...
    assert weighted.value == pytest.approx(0.24 / 0.44, abs=1e-9)
    assert unweighted.value == pytest.approx(0.28 / 0.68, abs=1e-9)
    assert weighted.weighting == "linear"
    assert unweighted.weighting == "none"


def test_undefined_statistics_state_why():
    single = cohen_kappa([("pass", "pass")], ["pass", "fail"])
    assert not single.defined and "Fewer than two" in single.reason
    one_category = cohen_kappa([("pass", "pass")] * 4, ["pass", "fail"])
    assert not one_category.defined and "chance correction" in one_category.reason
    with pytest.raises(ValueError, match="linear"):
        cohen_kappa([("a", "b")] * 2, ["a", "b"], weighting="quadratic")


def test_group_measures_outcome_label_and_score_separately():
    criterion = ordinal_criterion()
    units = [
        unit(
            criterion,
            [
                judgment("Alice", "pass", label="excellent", score=1, criterion="RQ-001"),
                judgment("Bob", "pass", label="partial", score=0.5, criterion="RQ-001"),
            ],
            session="s1",
        ),
        unit(
            criterion,
            [
                judgment("Alice", "pass", label="excellent", score=1, criterion="RQ-001"),
                judgment("Bob", "pass", label="excellent", score=1, criterion="RQ-001"),
            ],
            session="s2",
        ),
    ]
    report = build_report(units, scope="batch", scope_id="b")
    group = report.groups[0]
    assert group.scale_kind == "ordinal"
    assert group.units_compared == 2
    assert group.exact_agreement == pytest.approx(0.5)
    assert group.outcome_agreement == pytest.approx(1.0)
    assert group.label_agreement == pytest.approx(0.5)
    assert group.mean_absolute_score_difference == pytest.approx(0.25)
    assert group.max_ordinal_gap == 1
    # Both reviewers used only the pass outcome, so outcome kappa is undefined;
    # the graded dimension is still measurable with weighted kappa.
    assert not group.kappa.defined
    assert "chance correction" in group.kappa.reason
    assert group.weighted_kappa.defined
    pair = group.pairwise[0]
    assert (pair.reviewer_a, pair.reviewer_b) == ("Alice", "Bob")
    assert pair.n == 2
    assert pair.contingency and sum(row.count for row in pair.contingency) == 2


def test_units_without_two_reviewers_or_not_applicable_are_excluded_and_counted():
    criterion = binary_criterion()
    units = [
        unit(criterion, [judgment("Alice", "pass"), judgment("Bob", "pass")], session="s1"),
        unit(criterion, [judgment("Alice", "pass")], session="s2"),
        unit(
            criterion,
            [judgment("Alice", "not_applicable"), judgment("Bob", "pass")],
            session="s3",
        ),
        unit(criterion, [], session="s4"),
    ]
    report = build_report(units, scope="experiment", scope_id="e")
    group = report.groups[0]
    assert report.units_total == 4
    assert group.units_compared == 1
    assert group.units_excluded_incomplete == 2
    assert group.units_excluded_not_applicable == 1
    assert report.units_excluded_incomplete == 2
    assert report.units_excluded_not_applicable == 1
    assert any("not_applicable" in note for note in group.notes)


def test_statistics_never_mix_criteria_or_scale_kinds():
    binary = binary_criterion()
    categorical = categorical_criterion()
    units = [
        unit(binary, [judgment("A", "pass"), judgment("B", "fail")], session="s1"),
        unit(categorical, [judgment("A", "pass"), judgment("B", "pass")], session="s1"),
        unit(
            binary,
            [judgment("A", "pass"), judgment("B", "pass")],
            session="s2",
            rubric_version="2.0.0",
        ),
    ]
    report = build_report(units, scope="experiment", scope_id="e")
    keys = {(g.criterion_id, g.rubric_version) for g in report.groups}
    assert keys == {("CONF-001", "1.0.0"), ("FA-001", "1.0.0"), ("CONF-001", "2.0.0")}
    for group in report.groups:
        assert group.units_compared == 1


def test_empty_report_explains_that_statistics_are_undefined():
    report = build_report([], scope="batch", scope_id="empty")
    assert report.units_total == 0
    assert report.groups == []
    assert any("undefined" in note or "No rubric criterion" in note for note in report.notes)


def test_rating_category_prefers_label_then_score():
    assert rating_of(judgment("A", "pass", label="excellent", score=1)).category == "excellent"
    assert rating_of(judgment("A", "pass", score=0.5)).category == "0.5"
    assert rating_of(judgment("A", "fail")).category == "fail"


def test_applicability_disagreement_is_retained_with_attribution():
    criterion = binary_criterion()
    units = [
        unit(
            criterion,
            [judgment("Alice", "not_applicable"), judgment("Bob", "fail")],
            session="s1",
        ),
        unit(criterion, [judgment("Alice", "pass"), judgment("Bob", "pass")], session="s2"),
    ]
    report = build_report(units, scope="batch", scope_id="b")
    assert report.units_total == 2
    assert report.units_compared == 1
    assert report.units_excluded_not_applicable == 1
    assert report.units_not_applicable_disputed == 1
    (dispute,) = report.applicability_disputes
    assert dispute.session_id == "s1"
    assert dispute.criterion_id == "CONF-001"
    assert dispute.reviewers_not_applicable == ["Alice"]
    assert dispute.reviewers_with_rating == ["Bob"]
    assert dispute.reviewer_outcomes == {"Alice": "not_applicable", "Bob": "fail"}
    group = report.groups[0]
    assert group.units_not_applicable_disputed == 1
    assert any("applicability dispute" in note for note in group.notes)
    # The dispute is excluded from kappa, not silently merged into it.
    assert group.units_compared == 1


def test_disputes_need_both_sides_to_be_reported():
    criterion = binary_criterion()
    units = [
        unit(
            criterion,
            [judgment("Alice", "not_applicable"), judgment("Bob", "not_applicable")],
            session="s1",
        )
    ]
    report = build_report(units, scope="batch", scope_id="b")
    assert report.applicability_disputes == []
    assert report.units_excluded_not_applicable == 1
    assert report.units_not_applicable_disputed == 0


def test_distinct_definitions_sharing_identifiers_are_never_combined():
    criterion = binary_criterion()
    units = [
        unit(
            criterion,
            [judgment("A", "pass"), judgment("B", "fail")],
            session="s1",
            rubric_version="1.0.0",
            digest="a" * 64,
        ),
        unit(
            criterion,
            [judgment("A", "pass"), judgment("B", "pass")],
            session="s2",
            rubric_version="1.0.0",
            digest="b" * 64,
        ),
    ]
    report = build_report(units, scope="experiment", scope_id="e")
    assert len(report.groups) == 2
    digests = {group.rubric_definition_sha256 for group in report.groups}
    assert digests == {"a" * 64, "b" * 64}
    assert all(group.units_compared == 1 for group in report.groups)
    assert sum(group.units_compared for group in report.groups) == 2


def numeric_criterion(levels=None):
    return RubricCriterion(
        id="CLARITY-101",
        instructions="Clarity 1-5",
        check="manual",
        scale_kind="numeric",
        scale_min=1,
        scale_max=5,
        pass_threshold=3,
        levels=levels or [],
    )


def test_numeric_criterion_uses_declared_levels_not_inferred_order():
    levels = [
        {"label": "bare", "description": "Bare", "score": 1},
        {"label": "adequate", "description": "Adequate", "score": 3},
        {"label": "clear", "description": "Clear", "score": 5},
    ]
    criterion = numeric_criterion(levels)
    units = [
        unit(
            criterion,
            [
                judgment("A", "pass", label="clear", score=5, criterion="CLARITY-101"),
                judgment("B", "pass", label="adequate", score=3, criterion="CLARITY-101"),
            ],
            session="s1",
        ),
        unit(
            criterion,
            [
                judgment("A", "pass", label="clear", score=5, criterion="CLARITY-101"),
                judgment("B", "pass", label="clear", score=5, criterion="CLARITY-101"),
            ],
            session="s2",
        ),
    ]
    report = build_report(units, scope="batch", scope_id="b")
    group = report.groups[0]
    assert group.scale_kind == "numeric"
    assert group.units_outside_declared_levels == 0
    assert group.weighted_kappa is not None and group.weighted_kappa.defined
    assert group.weighted_kappa.weighting == "linear"
    assert group.weighted_kappa.categories == ["bare", "adequate", "clear"]
    assert group.max_ordinal_gap == 1


def test_numeric_scores_that_match_a_declared_level_are_orderable():
    levels = [
        {"label": "bare", "description": "Bare", "score": 1},
        {"label": "clear", "description": "Clear", "score": 5},
    ]
    criterion = numeric_criterion(levels)
    units = [
        unit(
            criterion,
            [
                judgment("A", "pass", score=5, criterion="CLARITY-101"),
                judgment("B", "pass", score=1, criterion="CLARITY-101"),
            ],
            session="s1",
        )
    ]
    group = build_report(units, scope="batch", scope_id="b").groups[0]
    assert group.units_outside_declared_levels == 0
    assert group.max_ordinal_gap == 1


def test_numeric_criteria_must_declare_levels_instead_of_inferring_order():
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="at least two described levels"):
        numeric_criterion()


def test_declared_levels_drive_weighting_not_raw_score_distance():
    levels = [
        {"label": "bare", "description": "Bare", "score": 1},
        {"label": "clear", "description": "Clear", "score": 5},
    ]
    criterion = numeric_criterion(levels)
    units = [
        unit(
            criterion,
            [
                judgment("A", "pass", label="bare", score=1, criterion="CLARITY-101"),
                judgment("B", "pass", label="clear", score=5, criterion="CLARITY-101"),
            ],
            session="s1",
        ),
        unit(
            criterion,
            [
                judgment("A", "pass", label="clear", score=5, criterion="CLARITY-101"),
                judgment("B", "pass", label="clear", score=5, criterion="CLARITY-101"),
            ],
            session="s2",
        ),
    ]
    group = build_report(units, scope="batch", scope_id="b").groups[0]
    assert group.weighted_kappa.defined
    # Linear weights over two declared levels: a one-level gap is total disagreement.
    assert group.weighted_kappa.categories == ["bare", "clear"]
    assert group.mean_absolute_score_difference == pytest.approx(2.0)


def test_ratings_outside_declared_levels_are_reported_not_silently_weighted():
    levels = [
        {"label": "bare", "description": "Bare", "score": 1},
        {"label": "clear", "description": "Clear", "score": 5},
    ]
    criterion = numeric_criterion(levels)
    units = [
        unit(
            criterion,
            [
                judgment("A", "pass", score=5, criterion="CLARITY-101"),
                judgment("B", "pass", score=4, criterion="CLARITY-101"),
            ],
            session="s1",
        )
    ]
    units.append(
        unit(
            criterion,
            [
                judgment("A", "pass", score=5, criterion="CLARITY-101"),
                judgment("B", "pass", score=4, criterion="CLARITY-101"),
            ],
            session="s2",
        )
    )
    group = build_report(units, scope="batch", scope_id="b").groups[0]
    assert group.units_outside_declared_levels == 2
    assert group.units_compared == 2
    assert group.weighted_kappa is not None
    assert not group.weighted_kappa.defined
    assert "do not map to a declared level" in group.weighted_kappa.reason
    # Exact/outcome agreement is still reported; only ordering is unavailable.
    assert group.outcome_agreement == 1.0
    assert group.exact_agreement == 0.0


def test_missing_category_labels_are_counted():
    criterion = categorical_criterion()
    units = [
        unit(
            criterion,
            [judgment("A", "fail", label="unsupported"), judgment("B", "fail")],
            session="s1",
        )
    ]
    group = build_report(units, scope="batch", scope_id="b").groups[0]
    assert group.units_missing_labels == 1
    assert any("without a category label" in note for note in group.notes)
    assert group.label_agreement == 0.0
    assert group.outcome_agreement == 1.0
