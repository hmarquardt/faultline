"""Policy math for human judgment. Pure: no storage, UI, clock or network.

A reviewer's own revisions collapse to their latest record. Nothing here ever
promotes the most recent cross-reviewer judgment to authoritative status: an
effective outcome exists only because an explicit adjudication record does.
"""

from dataclasses import dataclass, field

from faultline.domain import (
    Adjudication,
    AdjudicationPolicy,
    CoverageSummary,
    Disagreement,
    EffectiveResult,
    EvaluationSession,
    ExecutionRun,
    HumanJudgment,
    Outcome,
)

DEFINITE = {"pass", "fail"}


@dataclass(frozen=True)
class Resolution:
    status: str
    outcome: Outcome | None = None
    label: str | None = None
    score: float | None = None
    basis_ids: tuple[str, ...] = ()
    dissenting_ids: tuple[str, ...] = field(default_factory=tuple)


def latest_per_reviewer(judgments: list[HumanJudgment]) -> list[HumanJudgment]:
    """Collapse one reviewer's revisions, preserving first-seen reviewer order."""
    latest: dict[str, HumanJudgment] = {}
    for judgment in judgments:
        latest[judgment.reviewer] = judgment
    return list(latest.values())


def _adopt(judgment: HumanJudgment, others: list[HumanJudgment], status: str) -> Resolution:
    return Resolution(
        status=status,
        outcome=judgment.outcome,
        label=judgment.label,
        score=judgment.score,
        basis_ids=(judgment.id,),
        dissenting_ids=tuple(o.id for o in others if o.outcome != judgment.outcome),
    )


def resolve(judgments: list[HumanJudgment], policy: AdjudicationPolicy) -> Resolution:
    """Apply one explicit policy to the latest judgment of each reviewer."""
    latest = latest_per_reviewer(judgments)
    if not latest:
        return Resolution(status="insufficient")
    outcomes = {j.outcome for j in latest}
    if len(outcomes) == 1:
        first = latest[0]
        labels = {j.label for j in latest}
        return Resolution(
            status="agreed",
            outcome=first.outcome,
            label=labels.pop() if len(labels) == 1 else None,
            score=first.score if len({j.score for j in latest}) == 1 else None,
            basis_ids=tuple(j.id for j in latest),
        )
    if policy.kind == "single_reviewer":
        chosen = next((j for j in latest if j.reviewer == policy.reviewer), None)
        if chosen is None:
            return Resolution(
                status="unresolved",
                basis_ids=tuple(j.id for j in latest),
                dissenting_ids=tuple(j.id for j in latest),
            )
        return _adopt(chosen, [j for j in latest if j is not chosen], "adjudicated")
    if policy.kind == "first_reviewer":
        ordered = sorted(latest, key=lambda j: (j.created_at, j.id))
        return _adopt(ordered[0], ordered[1:], "adjudicated")
    counts: dict[str, int] = {}
    for judgment in latest:
        counts[judgment.outcome] = counts.get(judgment.outcome, 0) + 1
    winner, count = max(counts.items(), key=lambda item: (item[1], item[0]))
    if policy.kind == "majority" and count * 2 > len(latest):
        chosen = [j for j in latest if j.outcome == winner]
        return _adopt(chosen[0], [j for j in latest if j.outcome != winner], "adjudicated")
    return Resolution(
        status="unresolved",
        basis_ids=tuple(j.id for j in latest),
        dissenting_ids=tuple(j.id for j in latest if j.outcome != winner),
    )


def latest_adjudications(adjudications: list[Adjudication]) -> dict[tuple[str, str], Adjudication]:
    latest: dict[tuple[str, str], Adjudication] = {}
    for adjudication in adjudications:
        latest[(adjudication.session_id, adjudication.criterion_id)] = adjudication
    return latest


def effective_results(
    sessions: list[EvaluationSession],
    judgments: list[HumanJudgment],
    adjudications: list[Adjudication],
) -> list[EffectiveResult]:
    """Derive one effective result per session criterion, never mutating inputs."""
    resolved = latest_adjudications(adjudications)
    results: list[EffectiveResult] = []
    for session in sessions:
        definition = session.rubric.definition
        if definition is None:
            continue
        for criterion in definition.criteria:
            automated = next(
                (e for e in session.evaluations if e.criterion_id == criterion.id), None
            )
            reviewers = latest_per_reviewer(
                [
                    j
                    for j in judgments
                    if j.session_id == session.id and j.criterion_id == criterion.id
                ]
            )
            adjudication = resolved.get((session.id, criterion.id))
            result = EffectiveResult(
                session_id=session.id,
                run_id=session.run_id,
                criterion_id=criterion.id,
                rubric_id=definition.id,
                rubric_version=definition.version,
                scale_kind=criterion.scale_kind,
                automated_outcome=automated.outcome if automated else None,
                automated_label=automated.label if automated else None,
                automated_score=automated.score if automated else None,
                reviewer_outcomes={j.reviewer: j.outcome for j in reviewers},
                judgment_ids=[j.id for j in reviewers],
                adjudication_id=adjudication.id if adjudication else None,
            )
            results.append(_apply_effective(result, adjudication))
    return results


def _apply_effective(result: EffectiveResult, adjudication: Adjudication | None) -> EffectiveResult:
    automated = result.automated_outcome
    if adjudication is not None and adjudication.status in {"agreed", "adjudicated"}:
        # An uncertain or absent automated outcome is supplied, not overridden.
        if automated not in DEFINITE:
            status = "human_assessed"
        else:
            status = "confirmed" if automated == adjudication.outcome else "overridden"
        return result.model_copy(
            update={
                "effective_outcome": adjudication.outcome,
                "effective_label": adjudication.label,
                "effective_score": adjudication.score,
                "effective_source": "adjudicated",
                "status": status,
            }
        )
    if adjudication is not None:
        return result.model_copy(update={"status": "unresolved", "effective_source": "none"})
    if result.judgment_ids:
        return result.model_copy(
            update={"status": "awaiting_human_review", "effective_source": "none"}
        )
    return result.model_copy(
        update={
            "effective_outcome": automated,
            "effective_label": result.automated_label,
            "effective_score": result.automated_score,
            "effective_source": "automated",
            "status": "automated_only",
        }
    )


def _distinct_outcomes(result: EffectiveResult) -> set[str]:
    values = set(result.reviewer_outcomes.values())
    if result.automated_outcome in DEFINITE:
        values.add(result.automated_outcome)
    return values


def disagreements(
    results: list[EffectiveResult], adjudications: list[Adjudication]
) -> list[Disagreement]:
    """Criteria where automated and/or reviewer outcomes conflict without resolution."""
    resolved = latest_adjudications(adjudications)
    found: list[Disagreement] = []
    for result in results:
        contested = result.status == "unresolved" or (
            result.status == "awaiting_human_review" and len(_distinct_outcomes(result)) > 1
        )
        if not contested:
            continue
        adjudication = resolved.get((result.session_id, result.criterion_id))
        humans = ", ".join(
            f"{reviewer}={outcome}" for reviewer, outcome in result.reviewer_outcomes.items()
        )
        automated = result.automated_outcome or "no automated outcome"
        found.append(
            Disagreement(
                session_id=result.session_id,
                run_id=result.run_id,
                criterion_id=result.criterion_id,
                rubric_id=result.rubric_id,
                rubric_version=result.rubric_version,
                automated_outcome=result.automated_outcome,
                reviewer_outcomes=result.reviewer_outcomes,
                adjudication_id=adjudication.id if adjudication else None,
                resolved=False,
                summary=f"Automated {automated}; human {humans or 'none'}",
            )
        )
    return found


def coverage(
    runs: list[ExecutionRun],
    sessions: list[EvaluationSession],
    results: list[EffectiveResult],
    unresolved: list[Disagreement],
) -> CoverageSummary:
    """State explicitly what was evaluated, reviewed and left undecided."""
    total = len(results)
    automated = [r for r in results if r.automated_outcome in DEFINITE]
    reviewed = [r for r in results if r.judgment_ids]
    adjudicated = [r for r in results if r.adjudication_id is not None]
    awaiting = [r for r in results if r.status == "awaiting_human_review"]
    unresolved_results = [r for r in results if r.status == "unresolved"]
    definite = [r for r in results if r.effective_outcome in DEFINITE]
    without_session = [r for r in runs if not any(s.run_id == r.id for s in sessions)]
    notes: list[str] = []
    if without_session:
        notes.append(
            f"{len(without_session)} execution(s) have no evaluation session "
            "(dry run, failure or migration gap)"
        )
    if total and len(automated) < total:
        notes.append(f"{total - len(automated)} criterion evaluation(s) have no definite outcome")
    if awaiting:
        notes.append(f"{len(awaiting)} criterion evaluation(s) await an explicit adjudication")
    if unresolved_results:
        notes.append(f"{len(unresolved_results)} criterion evaluation(s) remain unresolved")
    if unresolved:
        notes.append(f"{len(unresolved)} recorded disagreement(s) await resolution")
    if not sessions:
        notes.append("No evaluation session exists for this experiment")
    return CoverageSummary(
        runs_total=len(runs),
        runs_without_session=len(without_session),
        sessions_total=len(sessions),
        sessions_failed=len([s for s in sessions if s.status == "failed"]),
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
