"""Inter-rater agreement statistics. Pure: no storage, UI, clock or network.

Statistics are only ever computed inside one comparable group: the same rubric
version, criterion and scale. Missing ratings are excluded rather than counted as
disagreements, ``not_applicable`` units are excluded and counted, and undefined
estimates state why. Kappa is chance-corrected agreement, not accuracy and not
ground truth.
"""

from collections import Counter
from dataclasses import dataclass, field
from itertools import combinations

from faultline.domain import (
    AgreementGroup,
    AgreementReport,
    ApplicabilityDisagreement,
    ContingencyRow,
    HumanJudgment,
    KappaResult,
    PairwiseAgreement,
    RubricCriterion,
    ScaleKind,
)

OUTCOME_CATEGORIES = ["pass", "fail", "uncertain"]
EXCLUDED_OUTCOMES = {"not_applicable"}
ORDERED_SCALES: set[ScaleKind] = {"ordinal", "numeric"}
LABEL_SCALES: set[ScaleKind] = {"categorical", "ordinal"}


@dataclass(frozen=True)
class Rating:
    outcome: str
    label: str | None
    score: float | None

    @property
    def category(self) -> str:
        if self.label is not None:
            return self.label
        if self.score is not None:
            return f"{self.score:g}"
        return self.outcome


@dataclass(frozen=True)
class AgreementUnit:
    """One reviewable criterion of one session with its reviewer judgments."""

    session_id: str
    rubric_id: str
    rubric_version: str
    criterion: RubricCriterion
    rubric_definition_sha256: str = ""
    judgments: list[HumanJudgment] = field(default_factory=list)

    @property
    def scale_kind(self) -> ScaleKind:
        return self.criterion.scale_kind


def latest_per_reviewer(judgments: list[HumanJudgment]) -> list[HumanJudgment]:
    latest: dict[str, HumanJudgment] = {}
    for judgment in judgments:
        latest[judgment.reviewer] = judgment
    return list(latest.values())


def rating_of(judgment: HumanJudgment) -> Rating:
    return Rating(outcome=judgment.outcome, label=judgment.label, score=judgment.score)


def ordered_categories(criterion: RubricCriterion) -> list[str]:
    """Declared level order, used for weighted statistics on one criterion."""
    return [level.label for level in criterion.levels]


def undefined(reason: str, n: int = 0, *, weighting: str = "none") -> KappaResult:
    return KappaResult(defined=False, reason=reason, weighting=weighting, n=n)


def _matrix(pairs: list[tuple[str, str]], categories: list[str]) -> list[list[int]]:
    index = {category: position for position, category in enumerate(categories)}
    matrix = [[0 for _ in categories] for _ in categories]
    for first, second in pairs:
        matrix[index[first]][index[second]] += 1
    return matrix


def _linear_weight(first: int, second: int, size: int) -> float:
    return 1.0 - abs(first - second) / (size - 1)


def cohen_kappa(
    pairs: list[tuple[str, str]],
    categories: list[str],
    *,
    weighting: str = "none",
) -> KappaResult:
    """Cohen's kappa for two raters, optionally with linear weights."""
    if weighting not in {"none", "linear"}:
        raise ValueError("Only unweighted and linear-weighted kappa are supported")
    n = len(pairs)
    if n < 2:
        return undefined("Fewer than two compared items", n, weighting=weighting)
    labels = list(dict.fromkeys([*categories, *[category for pair in pairs for category in pair]]))
    if len(labels) < 2:
        return undefined("All ratings fall into one category", n, weighting=weighting)
    if weighting == "linear" and len(categories) < 2:
        return undefined(
            "Weighted kappa needs an ordered criterion with declared levels",
            n,
            weighting=weighting,
        )
    if weighting == "linear":
        undeclared = sorted({label for pair in pairs for label in pair} - set(categories))
        if undeclared:
            return undefined(
                "Some ratings do not map to a declared level: " + ", ".join(undeclared[:3]),
                n,
                weighting=weighting,
            )
    matrix = _matrix(pairs, labels)
    size = len(labels)
    rows = [sum(row) for row in matrix]
    columns = [sum(matrix[row][column] for row in range(size)) for column in range(size)]
    if weighting == "none":
        observed = sum(matrix[i][i] for i in range(size)) / n
        expected = sum(rows[i] * columns[i] for i in range(size)) / (n * n)
    else:
        order = {label: position for position, label in enumerate(categories)}
        ranks = [order.get(label) for label in labels]
        weights = [
            [
                _linear_weight(ranks[i], ranks[j], len(categories))
                if ranks[i] is not None and ranks[j] is not None
                else 0.0
                for j in range(size)
            ]
            for i in range(size)
        ]
        observed = sum(weights[i][j] * matrix[i][j] for i in range(size) for j in range(size)) / n
        expected = sum(
            weights[i][j] * rows[i] * columns[j] for i in range(size) for j in range(size)
        ) / (n * n)
    if abs(1.0 - expected) < 1e-12:
        return undefined(
            "Expected agreement is 1.0; chance correction is undefined",
            n,
            weighting=weighting,
        )
    return KappaResult(
        value=(observed - expected) / (1.0 - expected),
        defined=True,
        observed_agreement=observed,
        expected_agreement=expected,
        weighting=weighting,
        categories=labels,
        n=n,
    )


def _mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _pairwise(
    compared: list[dict[str, Rating]], criterion: RubricCriterion, reviewers: list[str]
) -> list[PairwiseAgreement]:
    ordered = ordered_categories(criterion)
    results: list[PairwiseAgreement] = []
    for first, second in combinations(reviewers, 2):
        shared = [
            (ratings[first], ratings[second])
            for ratings in compared
            if first in ratings and second in ratings
        ]
        if not shared:
            continue
        n = len(shared)
        outcome_pairs = [(left.outcome, right.outcome) for left, right in shared]
        label_pairs = [
            (left.label or left.outcome, right.label or right.outcome) for left, right in shared
        ]
        weighted = None
        if criterion.scale_kind in ORDERED_SCALES:
            weighted = (
                cohen_kappa(label_pairs, ordered, weighting="linear")
                if ordered
                else undefined("Criterion declares no ordered levels", n, weighting="linear")
            )
        differences = [
            abs(left.score - right.score)
            for left, right in shared
            if left.score is not None and right.score is not None
        ]
        contingency = Counter((left.category, right.category) for left, right in shared)
        results.append(
            PairwiseAgreement(
                reviewer_a=first,
                reviewer_b=second,
                n=n,
                exact_agreement=sum(float(left == right) for left, right in shared) / n,
                outcome_agreement=(
                    sum(float(left.outcome == right.outcome) for left, right in shared) / n
                ),
                label_agreement=(
                    sum(float(left.label == right.label) for left, right in shared) / n
                    if criterion.scale_kind in LABEL_SCALES
                    else None
                ),
                kappa=cohen_kappa(outcome_pairs, OUTCOME_CATEGORIES),
                weighted_kappa=weighted,
                mean_absolute_score_difference=_mean(differences),
                contingency=[
                    ContingencyRow(rater_a=a, rater_b=b, count=count)
                    for (a, b), count in sorted(contingency.items())
                ],
            )
        )
    return results


def _declared_label(
    rating: Rating, by_label: dict[str, int], by_score: dict[float, str]
) -> str | None:
    """Map a rating onto a declared level without inventing an order."""
    if rating.label is not None:
        return rating.label if rating.label in by_label else None
    if rating.score is not None:
        return by_score.get(rating.score)
    return None


def _group(
    key: tuple[str, str, str, str], units: list[AgreementUnit]
) -> tuple[AgreementGroup, list[ApplicabilityDisagreement]]:
    rubric_id, rubric_version, definition_sha256, criterion_id = key
    criterion = units[0].criterion
    reviewers = sorted({j.reviewer for unit in units for j in unit.judgments})
    compared: list[dict[str, Rating]] = []
    excluded_not_applicable = 0
    excluded_incomplete = 0
    partial_coverage = 0
    missing_labels = 0
    outside_levels = 0
    disputes: list[ApplicabilityDisagreement] = []
    level_by_label = {level: index for index, level in enumerate(ordered_categories(criterion))}
    level_by_score = {level.score: level.label for level in criterion.levels}
    for unit in units:
        ratings = {j.reviewer: rating_of(j) for j in latest_per_reviewer(unit.judgments)}
        if len(ratings) < 2:
            excluded_incomplete += 1
            continue
        not_applicable = sorted(
            reviewer for reviewer, rating in ratings.items() if rating.outcome in EXCLUDED_OUTCOMES
        )
        with_rating = sorted(reviewer for reviewer in ratings if reviewer not in not_applicable)
        if not_applicable:
            excluded_not_applicable += 1
            if with_rating:
                disputes.append(
                    ApplicabilityDisagreement(
                        session_id=unit.session_id,
                        rubric_id=rubric_id,
                        rubric_version=rubric_version,
                        rubric_definition_sha256=definition_sha256,
                        criterion_id=criterion_id,
                        scale_kind=criterion.scale_kind,
                        reviewer_outcomes={
                            reviewer: ratings[reviewer].outcome for reviewer in ratings
                        },
                        reviewers_not_applicable=not_applicable,
                        reviewers_with_rating=with_rating,
                    )
                )
            continue
        if len(ratings) != len(reviewers):
            partial_coverage += 1
        if criterion.scale_kind == "categorical" and any(
            rating.label is None for rating in ratings.values()
        ):
            missing_labels += 1
        if (
            criterion.scale_kind in ORDERED_SCALES
            and criterion.levels
            and any(
                _declared_label(rating, level_by_label, level_by_score) is None
                for rating in ratings.values()
            )
        ):
            outside_levels += 1
        compared.append(ratings)

    exact: list[float] = []
    outcomes: list[float] = []
    labels: list[float] = []
    spreads: list[float] = []
    gaps: list[int] = []
    for ratings in compared:
        values = list(ratings.values())
        exact.append(float(len({(r.outcome, r.label, r.score) for r in values}) == 1))
        outcomes.append(float(len({r.outcome for r in values}) == 1))
        if criterion.scale_kind in LABEL_SCALES:
            labels.append(float(len({r.label for r in values}) == 1))
        scores = [r.score for r in values if r.score is not None]
        if len(scores) >= 2:
            spreads.append(max(scores) - min(scores))
        positions = [
            level_by_label[label]
            for label in (
                _declared_label(rating, level_by_label, level_by_score) for rating in values
            )
            if label is not None
        ]
        if len(positions) >= 2:
            gaps.append(max(positions) - min(positions))

    pairwise = _pairwise(compared, criterion, reviewers)
    notes: list[str] = []
    if len(reviewers) == 2:
        kappa = pairwise[0].kappa if pairwise else None
        weighted_kappa = pairwise[0].weighted_kappa if pairwise else None
    elif len(reviewers) > 2:
        kappa = undefined("Kappa is defined for two raters; see pairwise results")
        weighted_kappa = undefined(
            "Weighted kappa is defined for two raters; see pairwise results",
            weighting="linear",
        )
    else:
        kappa = undefined("Fewer than two reviewers rated this criterion")
        weighted_kappa = undefined(
            "Fewer than two reviewers rated this criterion", weighting="linear"
        )
    if not compared:
        notes.append("No criterion instance has two comparable reviewer ratings")
    if excluded_not_applicable:
        notes.append(
            f"{excluded_not_applicable} unit(s) excluded from kappa because a reviewer "
            "marked not_applicable"
        )
    if disputes:
        notes.append(f"{len(disputes)} applicability dispute(s) retained with reviewer attribution")
    if partial_coverage:
        notes.append(
            f"{partial_coverage} unit(s) were rated by a subset of reviewers; "
            "pairs use only the reviewers who rated them"
        )
    if missing_labels:
        notes.append(f"{missing_labels} unit(s) had a reviewer without a category label")
    if outside_levels:
        weight_state = (
            "weighted kappa is undefined"
            if weighted_kappa is not None and not weighted_kappa.defined
            else "some comparisons are not orderable"
        )
        notes.append(
            f"{outside_levels} unit(s) contained ratings that do not map to a declared "
            f"level; {weight_state}"
        )
    if criterion.scale_kind == "binary":
        notes.append("Binary criteria have no label or score dimension")
    if criterion.scale_kind == "categorical":
        notes.append("Categorical labels are unordered; no weighted kappa is reported")
    return (
        AgreementGroup(
            rubric_id=rubric_id,
            rubric_version=rubric_version,
            rubric_definition_sha256=definition_sha256,
            criterion_id=criterion_id,
            scale_kind=criterion.scale_kind,
            reviewers=reviewers,
            units_compared=len(compared),
            units_excluded_not_applicable=excluded_not_applicable,
            units_excluded_incomplete=excluded_incomplete,
            units_not_applicable_disputed=len(disputes),
            units_missing_labels=missing_labels,
            units_outside_declared_levels=outside_levels,
            exact_agreement=_mean(exact),
            outcome_agreement=_mean(outcomes),
            label_agreement=_mean(labels),
            kappa=kappa,
            weighted_kappa=weighted_kappa,
            mean_absolute_score_difference=_mean(spreads),
            max_ordinal_gap=max(gaps) if gaps else None,
            pairwise=pairwise,
            notes=notes,
        ),
        disputes,
    )


def build_report(units: list[AgreementUnit], *, scope: str, scope_id: str) -> AgreementReport:
    """Build one agreement report from reviewable units, never mixing definitions."""
    grouped: dict[tuple[str, str, str, str], list[AgreementUnit]] = {}
    for unit in units:
        grouped.setdefault(
            (
                unit.rubric_id,
                unit.rubric_version,
                unit.rubric_definition_sha256,
                unit.criterion.id,
            ),
            [],
        ).append(unit)
    built = [_group(key, value) for key, value in grouped.items()]
    groups = [group for group, _ in built]
    disputes = [dispute for _, found in built for dispute in found]
    compared = sum(group.units_compared for group in groups)
    notes: list[str] = []
    if not groups:
        notes.append("No rubric criterion has human judgments to compare")
    elif compared == 0:
        notes.append("Statistics are undefined: no criterion has two reviewer ratings")
    if disputes:
        notes.append(
            f"{len(disputes)} applicability dispute(s) are reported separately and "
            "excluded from chance-corrected statistics"
        )
    return AgreementReport(
        scope=scope,
        scope_id=scope_id,
        units_total=len(units),
        units_compared=compared,
        units_excluded_not_applicable=sum(group.units_excluded_not_applicable for group in groups),
        units_excluded_incomplete=sum(group.units_excluded_incomplete for group in groups),
        units_not_applicable_disputed=len(disputes),
        reviewers=sorted({r for group in groups for r in group.reviewers}),
        groups=groups,
        applicability_disputes=disputes,
        notes=notes,
    )
