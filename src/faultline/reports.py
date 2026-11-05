"""Portable, versioned report exports; never publish or fetch remote content."""

import json
import re
from pathlib import Path

from faultline.domain import EvidenceDigest, Report, canonical_digest
from faultline.techniques import technique_hash


def fenced(content: str, language: str = "text") -> str:
    longest = max((len(m.group()) for m in re.finditer(r"`+", content)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{content}\n{fence}\n"


def with_export_digest(report: Report) -> Report:
    """Attach the identity of this export artifact, distinct from source evidence."""
    sha256 = canonical_digest(report, exclude={"export_digest"})
    digest = EvidenceDigest(kind="report-export", source_id=report.id, sha256=sha256)
    return report.model_copy(update={"export_digest": digest})


def verify_export_digest(report: Report) -> bool:
    """True when the recorded export digest describes this report's content."""
    if report.export_digest is None:
        return False
    return report.export_digest.sha256 == canonical_digest(report, exclude={"export_digest"})


def _metadata(report: Report) -> dict:
    e = report.experiment
    return {
        "report_id": report.id,
        "report_format_version": report.report_format_version,
        "experiment_id": e.id,
        "name": e.name,
        "status": e.status,
        "generated_at": report.generated_at.isoformat(),
        "requested_model": e.target.requested_model,
        "provider": e.endpoint.provider,
        "technique": f"{e.technique.id}@{e.technique.version}",
        "technique_sha256": technique_hash(e.technique),
        "execution_rubric_source_sha256": e.rubric.source.sha256,
        "export_sha256": report.export_digest.sha256 if report.export_digest else None,
        "sessions": len(report.evaluation_sessions),
        "human_judgments": len(report.human_judgments),
        "adjudications": len(report.adjudications),
    }


def _execution_evidence(report: Report) -> list[str]:
    lines = ["## Execution evidence\n"]
    lines.append(
        "Immutable responses exactly as received and preserved. Source sha256 values hash "
        "the retained bytes; canonical digests identify typed records.\n"
    )
    digests = {d.source_id: d.sha256 for d in report.evidence_digests if d.kind == "execution"}
    for run in report.runs:
        lines.append(f"### {run.case.kind.title()} · run {run.id}\n")
        lines.append(
            fenced(
                f"Status: {run.status}\n"
                f"Case: {run.case.technique_id}@{run.case.technique_version}\n"
                f"Started: {run.started_at.isoformat()}\n"
                f"Completed: {run.completed_at.isoformat() if run.completed_at else 'n/a'}\n"
                f"Execution sha256: {digests.get(run.id)}\n"
                f"Returned model: {run.response.returned_model if run.response else 'n/a'}"
            )
        )
        if run.response:
            lines.append(fenced(run.response.text))
        if run.error:
            lines.append(fenced(run.error))
        for artifact in run.evidence:
            lines.append(
                fenced(
                    f"Artifact {artifact.id} ({artifact.kind})\n"
                    f"Source sha256: {artifact.sha256}\nProvenance: {artifact.provenance}"
                )
            )
    return lines


def _sessions(report: Report) -> list[str]:
    lines = ["## Rubric identity and evaluation sessions\n"]
    if not report.evaluation_sessions:
        lines.append("No evaluation session is stored for this experiment.\n")
    for session in report.evaluation_sessions:
        definition = session.rubric.definition
        assert definition is not None
        lines.append(f"### Session {session.id} · {session.origin}\n")
        lines.append(
            fenced(
                f"Rubric: {definition.id}@{definition.version} — {definition.title}\n"
                f"Rubric source sha256: {session.rubric.source.sha256}\n"
                f"Rubric definition sha256: {session.rubric_definition_sha256}\n"
                f"Review status: {session.rubric.review_status}"
                f" (reviewer: {session.rubric.reviewer or 'n/a'})\n"
                f"Evaluator: {session.evaluator}\n"
                f"Evaluator settings: {json.dumps(session.evaluator_settings, sort_keys=True)}\n"
                f"Execution sha256: {session.execution_sha256}\n"
                f"Status: {session.status}"
            )
        )
        for criterion in definition.criteria:
            detail = [
                f"{criterion.id} · scale={criterion.scale_kind} · weight={criterion.weight} "
                f"· threshold={criterion.pass_threshold} "
                f"(range {criterion.scale_min}–{criterion.scale_max})",
                criterion.instructions,
            ]
            for level in criterion.levels:
                detail.append(f"  level {level.label!r} = {level.score}: {level.description}")
            for category in criterion.categories:
                detail.append(
                    f"  category {category.label!r} → {category.outcome}: {category.description}"
                )
            lines.append(fenced("\n".join(detail)))
    return lines


def _automated(report: Report) -> list[str]:
    lines = ["## Automated evaluations\n"]
    lines.append("Deterministic observations only; never rewritten by human review.\n")
    for score in report.automated_scores:
        lines.append(
            fenced(
                f"Run: {score.run_id}\nSession: {score.session_id or 'n/a'}\n"
                f"Weighted compliance: {score.weighted_compliance}\n"
                f"Coverage: {score.coverage:.1%}\n"
                f"Criteria: {score.criteria_total} total, {score.criteria_scored} scored, "
                f"{score.criteria_uncertain} uncertain, "
                f"{score.criteria_not_applicable} not applicable"
            )
        )
    for session in report.evaluation_sessions:
        for value in session.evaluations:
            label = f", label={value.label}" if value.label else ""
            lines.append(
                fenced(
                    f"{value.criterion_id} [{value.scale_kind}]: {value.outcome} "
                    f"(score={value.score}{label}, {value.basis}, {value.evaluator})\n"
                    f"{value.rationale}\nEvidence: {', '.join(value.evidence_ids)}"
                )
            )
    return lines


def _human(report: Report) -> list[str]:
    lines = ["## Human judgments (append-only)\n"]
    if not report.human_judgments:
        lines.append("No human judgment is recorded for this experiment.\n")
    for judgment in report.human_judgments:
        lines.append(
            fenced(
                f"Reviewer: {judgment.reviewer}\nSession: {judgment.session_id}\n"
                f"Criterion: {judgment.criterion_id}\nOutcome: {judgment.outcome}"
                f"{f' · label={judgment.label}' if judgment.label else ''}"
                f"{f' · score={judgment.score}' if judgment.score is not None else ''}\n"
                f"Supersedes: {judgment.supersedes_id or 'none'}\n"
                f"Confidence: {judgment.confidence or 'unspecified'}\n"
                f"Recorded: {judgment.created_at.isoformat()}\n"
                f"Rationale: {judgment.rationale}"
            )
        )
    return lines


def _effective(report: Report) -> list[str]:
    lines = ["## Adjudication and effective results\n"]
    lines.append(
        "Automated observations above are unchanged. An effective outcome exists only where an "
        "explicit adjudication policy was recorded; a lone human judgment is not authoritative.\n"
    )
    for adjudication in report.adjudications:
        designated = f" ({adjudication.policy.reviewer})" if adjudication.policy.reviewer else ""
        label = f" · label={adjudication.label}" if adjudication.label else ""
        lines.append(
            fenced(
                f"Criterion: {adjudication.criterion_id} · session {adjudication.session_id}\n"
                f"Policy: {adjudication.policy.kind}{designated}\n"
                f"Result: {adjudication.status}"
                f"{f' → {adjudication.outcome}' if adjudication.outcome else ''}{label}\n"
                f"Basis judgments: {', '.join(adjudication.basis_judgment_ids)}\n"
                f"Dissenting judgments: "
                f"{', '.join(adjudication.dissenting_judgment_ids) or 'none'}\n"
                f"Adjudicator: {adjudication.reviewer}\n"
                f"Supersedes: {adjudication.supersedes_id or 'none'}\n"
                f"Rationale: {adjudication.rationale}"
            )
        )
    if not report.effective_results:
        lines.append("No session criterion is available for an effective result.\n")
    for result in report.effective_results:
        humans = ", ".join(f"{k}={v}" for k, v in result.reviewer_outcomes.items()) or "none"
        lines.append(
            fenced(
                f"{result.rubric_id}@{result.rubric_version} · {result.criterion_id} "
                f"[{result.scale_kind}] · run {result.run_id}\n"
                f"Automated: {result.automated_outcome or 'none'}\n"
                f"Human: {humans}\n"
                f"Effective: {result.effective_outcome or 'none'} "
                f"(source: {result.effective_source})\n"
                f"Status: {result.status}"
            )
        )
    return lines


def _disagreements(report: Report) -> list[str]:
    lines = ["## Unresolved disagreements\n"]
    if not report.disagreements:
        lines.append("No unresolved disagreement is recorded.\n")
    for item in report.disagreements:
        lines.append(
            fenced(
                f"{item.rubric_id}@{item.rubric_version} · {item.criterion_id} "
                f"· run {item.run_id}\n{item.summary}\n"
                f"Adjudication: {item.adjudication_id or 'none'}"
            )
        )
    return lines


def _findings(report: Report) -> list[str]:
    lines = ["## Findings (automated observations with review status)\n"]
    if not report.findings:
        lines.append("No failed automated checks recorded. Inspect coverage and run status.\n")
    reviews = {review.finding_id: review for review in report.finding_reviews}
    for finding in report.findings:
        review = reviews.get(finding.id)
        status = review.effective_status if review else "automated_only"
        note = review.note if review else "No review status recorded"
        contested = (
            "" if status in {"automated_only", "confirmed", "human_assessed"} else " · CONTESTED"
        )
        lines.append(
            fenced(
                f"[{finding.classification}] {finding.title}\n{finding.claim}\n"
                f"Run: {finding.run_id}\nEvaluation: {finding.evaluation_id}\n"
                f"Evidence: {', '.join(finding.evidence_ids)}\n"
                f"Review status: {status}{contested}\n{note}"
            )
        )
    return lines


def _coverage(report: Report) -> list[str]:
    lines = ["## Coverage, uncertainty and limitations\n"]
    summary = report.coverage
    if summary is not None:
        lines.append(
            fenced(
                f"Runs: {summary.runs_total} ({summary.runs_without_session} without a session)\n"
                f"Sessions: {summary.sessions_total} ({summary.sessions_failed} failed)\n"
                f"Session criteria: {summary.session_criteria_total} total, "
                f"{summary.session_criteria_automated} with a definite automated outcome\n"
                f"Human reviewed: {summary.session_criteria_with_human_judgment}; "
                f"adjudicated: {summary.session_criteria_adjudicated}; "
                f"awaiting: {summary.session_criteria_awaiting}; "
                f"unresolved: {summary.session_criteria_unresolved}\n"
                f"Automated coverage: {summary.automated_coverage:.1%}\n"
                f"Effective coverage: {summary.effective_coverage:.1%}"
            )
        )
        for note in summary.notes:
            lines.append(f"- {note}\n")
    lines.extend(f"- {limit}\n" for limit in report.limitations)
    return lines


def markdown(report: Report) -> str:
    lines = [
        "# Faultline evaluation report\n",
        fenced(json.dumps(_metadata(report), indent=2), "json"),
        *_execution_evidence(report),
        *_sessions(report),
        *_automated(report),
        *_human(report),
        *_effective(report),
        *_disagreements(report),
        *_findings(report),
    ]
    if report.human_overrides:
        lines.append("## Legacy Phase 1 overrides (retained verbatim)\n")
        lines.append(
            "These append-only records predate evaluation sessions. They are preserved and "
            "never reinterpreted as adjudications.\n"
        )
        for override in report.human_overrides:
            lines.append(fenced(override.model_dump_json(indent=2), "json"))
    lines.extend(_coverage(report))
    lines.append("\n## Complete reproducibility and evidence bundle\n")
    lines.append(
        "Contains full rendered requests, raw decoded responses, source documents, rubric "
        "definitions, identities, timestamps, settings, judgments, adjudications and hashes.\n"
    )
    lines.append(fenced(report.model_dump_json(indent=2), "json"))
    return "\n".join(lines)


def export_report(report: Report, prefix: Path) -> tuple[Path, Path]:
    """Create two reports without overwriting an existing artifact."""
    prefix.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    json_path = Path(f"{prefix}.json")
    md_path = Path(f"{prefix}.md")
    if json_path.exists() or md_path.exists():
        raise ValueError("Report destination exists; choose a new output prefix")
    exported = with_export_digest(report)
    for path, content in [
        (json_path, exported.model_dump_json(indent=2)),
        (md_path, markdown(exported)),
    ]:
        # Exclusive creation prevents accidental evidence replacement and symlink following.
        with path.open("x", encoding="utf-8") as stream:
            path.chmod(0o600)
            stream.write(content + "\n")
    return json_path, md_path
