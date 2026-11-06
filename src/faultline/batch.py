"""Batch aggregation for imported-response evaluation. Pure: no IO, no UI.

Progress, coverage and case-level summaries are derived from stored records; the
service owns persistence and the report exporter owns rendering.
"""

from faultline.domain import (
    BatchCase,
    BatchCoverage,
    BatchProgress,
    Disagreement,
    EffectiveResult,
    ScoreSummary,
)

DEFINITE = {"pass", "fail"}


def counts(cases: list[BatchCase]) -> dict[str, int]:
    total = {"pending": 0, "completed": 0, "failed": 0, "skipped": 0}
    for case in cases:
        total[case.status] = total.get(case.status, 0) + 1
    return total


def progress(cases: list[BatchCase], scores: list[ScoreSummary]) -> BatchProgress:
    """Case progress plus aggregate compliance over completed cases only."""
    totals = counts(cases)
    acceptable = [
        score.weighted_compliance for score in scores if score.weighted_compliance is not None
    ]
    return BatchProgress(
        cases_total=len(cases),
        cases_completed=totals.get("completed", 0),
        cases_failed=totals.get("failed", 0),
        cases_skipped=totals.get("skipped", 0),
        cases_pending=totals.get("pending", 0),
        cases_with_results=totals.get("completed", 0),
        mean_weighted_compliance=(sum(acceptable) / len(acceptable) if acceptable else None),
        min_weighted_compliance=min(acceptable) if acceptable else None,
        max_weighted_compliance=max(acceptable) if acceptable else None,
        criteria_total=sum(score.criteria_total for score in scores),
        criteria_scored=sum(score.criteria_scored for score in scores),
        criteria_uncertain=sum(score.criteria_uncertain for score in scores),
    )


def coverage(
    cases: list[BatchCase],
    results: list[EffectiveResult],
    unresolved: list[Disagreement],
) -> BatchCoverage:
    """State exactly which cases produced results and which did not."""
    totals = counts(cases)
    total = len(results)
    automated = [r for r in results if r.automated_outcome in DEFINITE]
    reviewed = [r for r in results if r.judgment_ids]
    adjudicated = [r for r in results if r.adjudication_id is not None]
    awaiting = [r for r in results if r.status == "awaiting_human_review"]
    unresolved_results = [r for r in results if r.status == "unresolved"]
    definite = [r for r in results if r.effective_outcome in DEFINITE]
    excluded = [case.case_id for case in cases if case.status == "skipped"]
    notes: list[str] = []
    if totals.get("pending"):
        notes.append(f"{totals['pending']} case(s) have not been evaluated yet")
    if totals.get("failed"):
        notes.append(f"{totals['failed']} case(s) failed evaluation and preserve their evidence")
    if excluded:
        notes.append(f"{len(excluded)} case(s) were skipped and are neither pass nor fail")
    if total and len(automated) < total:
        notes.append(f"{total - len(automated)} criterion evaluation(s) have no definite outcome")
    if awaiting:
        notes.append(f"{len(awaiting)} criterion evaluation(s) await an explicit adjudication")
    if unresolved_results:
        notes.append(f"{len(unresolved_results)} criterion evaluation(s) remain unresolved")
    if unresolved:
        notes.append(f"{len(unresolved)} recorded disagreement(s) await resolution")
    if not cases:
        notes.append("The batch contains no cases")
    return BatchCoverage(
        cases_total=len(cases),
        cases_completed=totals.get("completed", 0),
        cases_failed=totals.get("failed", 0),
        cases_skipped=totals.get("skipped", 0),
        cases_pending=totals.get("pending", 0),
        excluded_case_ids=excluded,
        session_criteria_total=total,
        session_criteria_automated=len(automated),
        session_criteria_with_human_judgment=len(reviewed),
        session_criteria_adjudicated=len(adjudicated),
        session_criteria_awaiting=len(awaiting),
        session_criteria_unresolved=len(unresolved_results),
        automated_coverage=len(automated) / total if total else 0.0,
        effective_coverage=len(definite) / total if total else 0.0,
        notes=notes,
    )
