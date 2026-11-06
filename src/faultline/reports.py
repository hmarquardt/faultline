"""Portable, versioned report exports; never publish or fetch remote content."""

import csv
import io
import json
import re
from pathlib import Path

from faultline.domain import (
    AgenticReport,
    AgreementReport,
    BatchReport,
    BenchmarkReport,
    ControlledExperimentReport,
    EvidenceDigest,
    ModelComparisonReport,
    Report,
    canonical_digest,
)
from faultline.techniques import technique_hash


def fenced(content: str, language: str = "text") -> str:
    longest = max((len(m.group()) for m in re.finditer(r"`+", content)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{content}\n{fence}\n"


def with_export_digest[
    T: (
        Report,
        BatchReport,
        AgenticReport,
        ControlledExperimentReport,
        ModelComparisonReport,
        BenchmarkReport,
    )
](
    report: T,
) -> T:
    """Attach the identity of this export artifact, distinct from source evidence."""
    sha256 = canonical_digest(report, exclude={"export_digest"})
    digest = EvidenceDigest(kind="report-export", source_id=report.id, sha256=sha256)
    return report.model_copy(update={"export_digest": digest})


def verify_export_digest[
    T: (
        Report,
        BatchReport,
        AgenticReport,
        ControlledExperimentReport,
        ModelComparisonReport,
        BenchmarkReport,
    )
](
    report: T,
) -> bool:
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


def _human(judgments: list) -> list[str]:
    lines = ["## Human judgments (append-only)\n"]
    if not judgments:
        lines.append("No human judgment is recorded for these cases.\n")
    for judgment in judgments:
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


def _effective(adjudications: list, results: list) -> list[str]:
    lines = ["## Adjudication and effective results\n"]
    lines.append(
        "Automated observations above are unchanged. An effective outcome exists only where an "
        "explicit adjudication policy was recorded; a lone human judgment is not authoritative.\n"
    )
    for adjudication in adjudications:
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
    if not results:
        lines.append("No session criterion is available for an effective result.\n")
    for result in results:
        humans = ", ".join(f"{k}={v}" for k, v in result.reviewer_outcomes.items()) or "none"
        lines.append(
            fenced(
                f"{result.rubric_id}@{result.rubric_version} · {result.criterion_id} "
                f"[{result.scale_kind}] · subject "
                f"{result.run_id or result.dataset_case_id}\n"
                f"Automated: {result.automated_outcome or 'none'}\n"
                f"Human: {humans}\n"
                f"Effective: {result.effective_outcome or 'none'} "
                f"(source: {result.effective_source})\n"
                f"Status: {result.status}"
            )
        )
    return lines


def _disagreements(items: list) -> list[str]:
    lines = ["## Unresolved disagreements\n"]
    if not items:
        lines.append("No unresolved disagreement is recorded.\n")
    for item in items:
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


def markdown(
    document: Report
    | BatchReport
    | AgenticReport
    | ControlledExperimentReport
    | ModelComparisonReport
    | BenchmarkReport,
) -> str:
    """Render any report type; only a real run may claim a provider request."""
    if isinstance(document, BenchmarkReport):
        return markdown_benchmark(document)
    if isinstance(document, ModelComparisonReport):
        return markdown_comparison(document)
    if isinstance(document, ControlledExperimentReport):
        return markdown_experiment(document)
    if isinstance(document, AgenticReport):
        return markdown_agentic(document)
    if isinstance(document, BatchReport):
        return markdown_batch(document)
    report = document
    lines = [
        "# Faultline evaluation report\n",
        fenced(json.dumps(_metadata(report), indent=2), "json"),
        *_execution_evidence(report),
        *_sessions(report),
        *_automated(report),
        *_human(report.human_judgments),
        *_effective(report.adjudications, report.effective_results),
        *_disagreements(report.disagreements),
        *_findings(report),
        *_agreement_lines(report.agreement),
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


def export_report(
    document: Report
    | BatchReport
    | AgenticReport
    | ControlledExperimentReport
    | ModelComparisonReport
    | BenchmarkReport,
    prefix: Path,
) -> tuple[Path, Path, Path]:
    """Write JSON, Markdown and CSV without overwriting an existing artifact."""
    prefix.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    json_path = Path(f"{prefix}.json")
    md_path = Path(f"{prefix}.md")
    csv_path = Path(f"{prefix}.csv")
    if json_path.exists() or md_path.exists() or csv_path.exists():
        raise ValueError("Report destination exists; choose a new output prefix")
    exported = with_export_digest(document)
    for path, content in [
        (json_path, exported.model_dump_json(indent=2)),
        (md_path, markdown(exported)),
        (csv_path, csv_export(exported)),
    ]:
        # Exclusive creation prevents accidental evidence replacement and symlink following.
        with path.open("x", encoding="utf-8") as stream:
            path.chmod(0o600)
            stream.write(content if content.endswith("\n") else content + "\n")
    return json_path, md_path, csv_path


def _batch_metadata(report: BatchReport) -> dict:
    dataset = report.dataset
    batch = report.batch
    return {
        "report_id": report.id,
        "report_format_version": report.report_format_version,
        "origin": report.origin,
        "generated_at": report.generated_at.isoformat(),
        "batch_id": batch.id,
        "batch_status": batch.status,
        "dataset_id": dataset.id,
        "dataset_version": dataset.version,
        "dataset_title": dataset.title,
        "dataset_provenance": dataset.provenance,
        "dataset_source_format": dataset.source_format,
        "dataset_source_sha256": dataset.source.sha256,
        "dataset_index_sha256": dataset.dataset_sha256,
        "dataset_records": dataset.record_count,
        "rubric": f"{batch.rubric_definition_id}@{batch.rubric_definition_version}",
        "rubric_source_sha256": batch.rubric_source_sha256,
        "rubric_definition_sha256": batch.rubric_definition_sha256,
        "cases": report.progress.cases_total,
        "export_sha256": report.export_digest.sha256 if report.export_digest else None,
    }


def _batch_progress(report: BatchReport) -> list[str]:
    progress = report.progress
    return [
        "## Batch progress and aggregate compliance\n",
        fenced(
            f"Cases: {progress.cases_total} total · {progress.cases_completed} completed · "
            f"{progress.cases_failed} failed · {progress.cases_skipped} skipped · "
            f"{progress.cases_pending} pending\n"
            f"Cases with results: {progress.cases_with_results}\n"
            f"Weighted compliance: mean {_number(progress.mean_weighted_compliance)} · "
            f"min {_number(progress.min_weighted_compliance)} · "
            f"max {_number(progress.max_weighted_compliance)}\n"
            f"Criteria: {progress.criteria_total} total · "
            f"{progress.criteria_scored} scored · {progress.criteria_uncertain} uncertain"
        ),
    ]


def _number(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _batch_cases(report: BatchReport) -> list[str]:
    sessions = {s.dataset_case_id: s for s in report.evaluation_sessions}
    records = {record.id: record for record in report.records}
    lines = ["## Case-level evaluations\n"]
    lines.append(
        "Responses below were imported from the dataset. No request was sent by "
        "Faultline for any of them.\n"
    )
    for case in report.cases:
        record = records.get(case.case_id)
        session = sessions.get(case.case_id)
        detail = [
            f"Case {case.case_id} · position {case.position} · status {case.status}",
            f"Provenance: {record.provenance if record else 'unavailable'}",
            f"Model: {(record.model if record else None) or 'not recorded'}",
            f"Prompt: {record.prompt if record else 'unavailable'}",
            f"Response: {record.response if record else 'unavailable'}",
        ]
        if record and record.expected_behavior:
            detail.append(f"Expected behavior: {record.expected_behavior}")
        if record and record.reference_answer:
            detail.append(f"Reference answer: {record.reference_answer}")
        if record and record.source_sha256:
            detail.append(f"Record sha256: {record.source_sha256}")
        if case.error:
            detail.append(f"Error: {case.error}")
        if case.skip_reason:
            detail.append(f"Skipped: {case.skip_reason}")
        if session is not None:
            detail.append(f"Session: {session.id} ({session.evidence_kind})")
            for value in session.evaluations:
                article = f" · {value.label}" if value.label else ""
                detail.append(
                    f"  {value.criterion_id} [{value.scale_kind}]: {value.outcome} "
                    f"(score={value.score}{article}) {value.rationale}"
                )
        lines.append(fenced("\n".join(detail)))
    return lines


def _batch_coverage(report: BatchReport) -> list[str]:
    coverage = report.coverage
    lines = ["## Coverage, uncertainty and limitations\n"]
    lines.append(
        fenced(
            f"Cases: {coverage.cases_total} total · {coverage.cases_completed} completed · "
            f"{coverage.cases_failed} failed · {coverage.cases_skipped} skipped · "
            f"{coverage.cases_pending} pending\n"
            f"Excluded cases: {', '.join(coverage.excluded_case_ids) or 'none'}\n"
            f"Session criteria: {coverage.session_criteria_total} total · "
            f"{coverage.session_criteria_automated} with a definite automated outcome\n"
            f"Human reviewed: {coverage.session_criteria_with_human_judgment} · "
            f"adjudicated: {coverage.session_criteria_adjudicated} · "
            f"awaiting: {coverage.session_criteria_awaiting} · "
            f"unresolved: {coverage.session_criteria_unresolved}\n"
            f"Automated coverage: {coverage.automated_coverage:.1%} · "
            f"effective coverage: {coverage.effective_coverage:.1%}"
        )
    )
    for note in coverage.notes:
        lines.append(f"- {note}\n")
    lines.extend(f"- {limit}\n" for limit in report.limitations)
    return lines


def markdown_batch(report: BatchReport) -> str:
    """Readable report for imported responses; never describes a provider call."""
    lines = [
        "# Faultline dataset evaluation report\n",
        fenced(json.dumps(_batch_metadata(report), indent=2), "json"),
        "## Dataset provenance and membership\n",
        fenced(
            f"Dataset: {report.dataset.title} ({report.dataset.id}) version "
            f"{report.dataset.version} · {report.dataset.source_format}\n"
            f"Provenance: {report.dataset.provenance}\n"
            f"Source sha256: {report.dataset.source.sha256}\n"
            f"Index sha256: {report.dataset.dataset_sha256}\n"
            f"Records: {report.dataset.record_count} · batch membership: "
            f"{report.progress.cases_total}\n"
            f"Rubric: {report.batch.rubric_definition_id}@"
            f"{report.batch.rubric_definition_version}\n"
            f"Rubric source sha256: {report.batch.rubric_source_sha256}"
        ),
        *_batch_progress(report),
        *_batch_cases(report),
        *_human(report.human_judgments),
        *_effective(report.adjudications, report.effective_results),
        *_disagreements(report.disagreements),
        *_agreement_lines(report.agreement),
        *_batch_coverage(report),
    ]
    lines.append("\n## Complete reproducibility and evidence bundle\n")
    lines.append(
        "Contains the dataset source, imported records and responses, rubric snapshot, "
        "sessions, judgments, adjudications, agreement statistics and digests.\n"
    )
    lines.append(fenced(report.model_dump_json(indent=2), "json"))
    return "\n".join(lines)


def _percent(value: float | None) -> str:
    return "undefined" if value is None else f"{value:.1%}"


def _kappa(result) -> str:
    if result is None:
        return "not reported"
    if not result.defined:
        return f"undefined ({result.reason})"
    return f"{result.value:.4f}"


def _agreement_lines(agreement: AgreementReport | None) -> list[str]:
    lines = ["## Inter-rater agreement\n"]
    lines.append(
        "Chance-corrected agreement for these reviewers on these items. Kappa is not "
        "accuracy and agreement does not establish ground truth.\n"
    )
    if agreement is None:
        lines.append("No agreement statistics are available for this report.\n")
        return lines
    lines.append(
        fenced(
            f"Method: {agreement.method} · scope {agreement.scope} {agreement.scope_id}\n"
            f"Reviewers: {', '.join(agreement.reviewers) or 'none'}\n"
            f"Units: {agreement.units_total} total, {agreement.units_compared} compared, "
            f"{agreement.units_excluded_not_applicable} excluded as not applicable, "
            f"{agreement.units_excluded_incomplete} excluded for a single reviewer"
        )
    )
    for group in agreement.groups:
        detail = [
            f"{group.criterion_id} [{group.scale_kind}] · {group.rubric_id}@"
            f"{group.rubric_version} · definition "
            f"{group.rubric_definition_sha256[:12] or 'n/a'} · reviewers "
            f"{', '.join(group.reviewers) or 'none'}",
            f"  units compared: {group.units_compared} (excluded: "
            f"{group.units_excluded_not_applicable} not applicable, "
            f"{group.units_excluded_incomplete} single reviewer) · applicability "
            f"disputes: {group.units_not_applicable_disputed} · missing labels: "
            f"{group.units_missing_labels} · outside declared levels: "
            f"{group.units_outside_declared_levels}",
            f"  exact agreement: {_percent(group.exact_agreement)} · "
            f"outcome agreement: {_percent(group.outcome_agreement)} · "
            f"label agreement: {_percent(group.label_agreement)}",
            f"  kappa: {_kappa(group.kappa)} · weighted kappa: {_kappa(group.weighted_kappa)}",
        ]
        if group.mean_absolute_score_difference is not None:
            detail.append(
                f"  mean score spread: {group.mean_absolute_score_difference:g} "
                f"(max ordinal gap {group.max_ordinal_gap})"
            )
        for pair in group.pairwise:
            detail.append(
                f"  pair {pair.reviewer_a}/{pair.reviewer_b}: n={pair.n} "
                f"exact={_percent(pair.exact_agreement)} "
                f"outcome={_percent(pair.outcome_agreement)} "
                f"kappa={_kappa(pair.kappa)} "
                f"weighted={_kappa(pair.weighted_kappa)}"
            )
        for note in group.notes:
            detail.append(f"  note: {note}")
        lines.append(fenced("\n".join(detail)))
    for note in agreement.notes:
        lines.append(f"- {note}\n")
    return lines


EXPERIMENT_CSV_COLUMNS = [
    "experiment_id",
    "trial_index",
    "trial_status",
    "execution_order",
    "variant",
    "trace_id",
    "session_id",
    "trace_status",
    "termination",
    "criterion_id",
    "scale_kind",
    "outcome",
    "score",
    "exposed_to_injection",
    "unauthorized_requests",
    "denied_tools",
    "executed_tools",
    "state_changes",
    "canary_disclosed",
    "task_marker_present",
    "semantic_task_completion",
    "error",
]


def experiment_rows(report: ControlledExperimentReport) -> list[list[str]]:
    """One CSV row per trial, variant and criterion; raw observations only."""
    experiment = report.experiment
    definition = experiment.rubric.definition
    criteria = definition.criteria if definition else []
    session_values = {
        session.id: {value.criterion_id: value for value in session.evaluations}
        for session in report.evaluation_sessions
    }
    rows: list[list[str]] = []
    for trial in report.trials:
        for variant in (trial.control, trial.attack):
            if variant is None:
                continue
            evaluations = session_values.get(variant.session_id or "", {})
            for criterion in criteria:
                value = evaluations.get(criterion.id)
                rows.append(
                    [
                        _safe_cell(experiment.id),
                        _safe_cell(trial.trial_index),
                        _safe_cell(trial.status),
                        _safe_cell(" > ".join(trial.order)),
                        _safe_cell(variant.role),
                        _safe_cell(variant.trace_id),
                        _safe_cell(variant.session_id),
                        _safe_cell(variant.status),
                        _safe_cell(variant.termination),
                        _safe_cell(criterion.id),
                        _safe_cell(criterion.scale_kind),
                        _safe_cell(value.outcome if value else None),
                        _safe_cell(value.score if value else None),
                        _safe_cell(variant.exposed_to_injection),
                        _safe_cell(";".join(variant.unauthorized_requests)),
                        _safe_cell(";".join(variant.denied_tools)),
                        _safe_cell(";".join(variant.executed_tools)),
                        _safe_cell(";".join(variant.state_changes)),
                        _safe_cell(variant.canary_disclosed),
                        _safe_cell(variant.task_marker_present),
                        _safe_cell(variant.semantic_task_completion),
                        _safe_cell(trial.error or trial.interruption),
                    ]
                )
    return rows


def csv_export_experiment(report: ControlledExperimentReport) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(EXPERIMENT_CSV_COLUMNS)
    writer.writerows(experiment_rows(report))
    return buffer.getvalue()


CSV_COLUMNS = [
    "report_type",
    "report_id",
    "document_id",
    "batch_id",
    "dataset_id",
    "dataset_case_id",
    "run_id",
    "experiment_id",
    "session_id",
    "session_origin",
    "evidence_kind",
    "rubric_id",
    "rubric_version",
    "criterion_id",
    "scale_kind",
    "automated_outcome",
    "automated_label",
    "automated_score",
    "reviewer_outcomes",
    "reviewer_labels",
    "reviewer_scores",
    "reviewer_agreement",
    "effective_outcome",
    "effective_label",
    "effective_score",
    "effective_source",
    "status",
    "adjudication_id",
    "judgment_ids",
    "disagreement_dimensions",
]


def _safe_cell(value: object) -> str:
    """Plain CSV text; leading formula characters are neutralised."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in {"=", "+", "-", "@", "\t", "\r"} else text


def _disagreement_dimensions(document) -> dict[tuple[str, str], str]:
    dimensions: dict[tuple[str, str], str] = {}
    for item in document.disagreements:
        parts = []
        if item.outcome_disagreement:
            parts.append("outcome")
        if item.label_disagreement:
            parts.append("label")
        if item.score_disagreement:
            parts.append("score")
        dimensions[(item.session_id, item.criterion_id)] = "+".join(parts)
    return dimensions


def _join_pairs(mapping, formatter) -> str:
    return ";".join(formatter(key, value) for key, value in mapping.items())


def evaluation_rows(document: Report | BatchReport | AgenticReport) -> list[list[str]]:
    """One CSV row per session criterion, with original and effective results."""
    is_batch = isinstance(document, BatchReport)
    is_agentic = isinstance(document, AgenticReport)
    if is_agentic:
        kind, document_id = "agentic", document.trace.id
    elif is_batch:
        kind, document_id = "batch", document.batch.id
    else:
        kind, document_id = "experiment", document.experiment.id
    dimensions = _disagreement_dimensions(document)
    results = {(r.session_id, r.criterion_id): r for r in document.effective_results}
    rows: list[list[str]] = []
    for session in document.evaluation_sessions:
        definition = session.rubric.definition
        if definition is None:
            continue
        automated = {value.criterion_id: value for value in session.evaluations}
        for criterion in definition.criteria:
            value = automated.get(criterion.id)
            result = results.get((session.id, criterion.id))
            outcomes = result.reviewer_outcomes if result else {}
            labels = result.reviewer_labels if result else {}
            scores = result.reviewer_scores if result else {}
            reviewer_outcomes = _join_pairs(outcomes, lambda key, item: f"{key}={item}")
            reviewer_labels = _join_pairs(
                {k: v for k, v in labels.items() if v is not None},
                lambda key, item: f"{key}={item}",
            )
            reviewer_scores = _join_pairs(
                {k: v for k, v in scores.items() if v is not None},
                lambda key, item: f"{key}={item:g}",
            )
            rows.append(
                [
                    _safe_cell(kind),
                    _safe_cell(document.id),
                    _safe_cell(document_id),
                    _safe_cell(document.batch.id if is_batch else None),
                    _safe_cell(session.dataset_id),
                    _safe_cell(session.dataset_case_id),
                    _safe_cell(session.run_id),
                    _safe_cell(session.experiment_id),
                    _safe_cell(session.id),
                    _safe_cell(session.origin),
                    _safe_cell(session.evidence_kind),
                    _safe_cell(definition.id),
                    _safe_cell(definition.version),
                    _safe_cell(criterion.id),
                    _safe_cell(criterion.scale_kind),
                    _safe_cell(value.outcome if value else None),
                    _safe_cell(value.label if value else None),
                    _safe_cell(value.score if value else None),
                    _safe_cell(reviewer_outcomes),
                    _safe_cell(reviewer_labels),
                    _safe_cell(reviewer_scores),
                    _safe_cell(result.agreement if result else None),
                    _safe_cell(result.effective_outcome if result else None),
                    _safe_cell(result.effective_label if result else None),
                    _safe_cell(result.effective_score if result else None),
                    _safe_cell(result.effective_source if result else None),
                    _safe_cell(result.status if result else None),
                    _safe_cell(result.adjudication_id if result else None),
                    _safe_cell(";".join(result.judgment_ids) if result else None),
                    _safe_cell(dimensions.get((session.id, criterion.id))),
                ]
            )
    return rows


def csv_export(
    document: Report
    | BatchReport
    | AgenticReport
    | ControlledExperimentReport
    | ModelComparisonReport
    | BenchmarkReport,
) -> str:
    if isinstance(document, BenchmarkReport):
        return csv_export_benchmark(document)
    if isinstance(document, ModelComparisonReport):
        return csv_export_comparison(document)
    if isinstance(document, ControlledExperimentReport):
        return csv_export_experiment(document)
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    writer.writerows(evaluation_rows(document))
    return buffer.getvalue()


def _agentic_metadata(report: AgenticReport) -> dict:
    trace = report.trace
    return {
        "report_id": report.id,
        "report_format_version": report.report_format_version,
        "origin": report.origin,
        "trace_id": trace.id,
        "trace_status": trace.status,
        "termination": trace.termination,
        "agent": trace.agent,
        "capabilities": trace.capabilities.model_dump(mode="json"),
        "model": trace.model,
        "scenario": {
            "id": trace.scenario.id,
            "version": trace.scenario.version,
            "family": trace.scenario.family,
            "sha256": trace.scenario_sha256,
        },
        "rubric": {
            "id": trace.rubric.definition.id if trace.rubric.definition else None,
            "version": trace.rubric.definition.version if trace.rubric.definition else None,
            "definition_sha256": trace.rubric_definition_sha256,
        },
        "budget": trace.budget.model_dump(mode="json"),
        "execution_sha256": trace.execution_sha256,
        "started_at": trace.started_at.isoformat(),
        "completed_at": trace.completed_at.isoformat() if trace.completed_at else None,
    }


def _agentic_surface(report: AgenticReport) -> list[str]:
    trace = report.trace
    scenario = trace.scenario
    injected = [
        document for document in scenario.documents if document.id == scenario.injected_document_id
    ]
    lines = ["## Legitimate objective\n", f"{scenario.objective}\n"]
    lines.append("### Legitimate user request (trusted)\n")
    lines.append(fenced(scenario.user_task))
    lines.append("### Attack surface\n")
    lines.append(
        f"Attacker-controlled content arrives only through retrieved documents "
        f"(`{'`, `'.join(document.id for document in injected) or 'none'}`). The system "
        f"prompt and the user request are harness-controlled. Trust boundary: "
        f"`{scenario.trust_boundary}`.\n"
    )
    for document in injected:
        lines.append("### Injected payload and provenance\n")
        lines.append(
            fenced(
                json.dumps(
                    {
                        "document_id": document.id,
                        "title": document.title,
                        "source_note": document.source_note,
                        "trust": document.trust,
                        "content_sha256": canonical_digest(document.content),
                    },
                    indent=2,
                ),
                "json",
            )
        )
        lines.append(fenced(document.injection or ""))
    return lines


def _agentic_timeline(report: AgenticReport) -> list[str]:
    lines = ["## Conversation timeline\n"]
    lines.append("| # | role | source | trust | content | tool requests |")
    lines.append("| - | ---- | ------ | ----- | ------- | ------------- |")
    for turn in report.trace.turns:
        content = turn.content.replace("|", "\\|").replace("\n", " ")[:160]
        correlation = ", ".join(turn.tool_request_ids) or turn.tool_request_id or ""
        lines.append(
            f"| {turn.index} | {turn.role} | {turn.source} | {turn.trust} | "
            f"{content} | {correlation} |"
        )
    lines.append("")
    return lines


def _agentic_tools(report: AgenticReport) -> list[str]:
    lines = ["## Tool requests, authorization and executions\n"]
    if not report.trace.invocations:
        lines.append("The agent proposed no tool calls.\n")
        return lines
    lines.append("| request | tool | decision | executed | state changes | reason |")
    lines.append("| ------- | ---- | -------- | -------- | ------------- | ------ |")
    for invocation in report.trace.invocations:
        decision = invocation.decision
        receipt = invocation.receipt
        changes = (
            ", ".join(f"{c.kind}:{c.target}" for c in receipt.state_changes)
            if receipt and receipt.state_changes
            else "none"
        )
        lines.append(
            f"| {invocation.request_id} | {invocation.tool} | "
            f"{decision.decision if decision else 'unrecorded'} | "
            f"{'yes' if receipt and receipt.executed else 'no'} | {changes} | "
            f"{(decision.reason if decision else '').replace('|', '/')} |"
        )
    lines.append("")
    lines.append("### Structured receipts\n")
    for invocation in report.trace.invocations:
        receipt = invocation.receipt
        if receipt is None:
            continue
        lines.append(fenced(receipt.model_dump_json(indent=2), "json"))
    return lines


def _agentic_outcome(report: AgenticReport) -> list[str]:
    result = report.result
    lines = ["## Observed outcome\n"]
    lines.append(
        "All tool activity happened inside an in-memory synthetic sandbox. No external "
        "system, mailbox or record store was touched.\n"
    )
    lines.append(
        fenced(
            json.dumps(
                {
                    "verdict": result.verdict,
                    "termination": result.termination,
                    "requested_tools": result.requested_tools,
                    "denied_tools": result.denied_tools,
                    "executed_tools": result.executed_tools,
                    "unauthorized_requests": result.unauthorized_requests,
                    "state_changes": result.state_changes,
                    "canary_disclosed": result.canary_disclosed,
                    "task_marker_present": result.task_marker_present,
                    "task_completion_basis": result.task_completion_basis,
                    "semantic_task_completion": "human-assessed",
                    "exposed_to_injection": result.exposed_to_injection,
                    "basis": result.basis,
                },
                indent=2,
            ),
            "json",
        )
    )
    lines.append(
        "A denied request is evidence of intent, not of a compromise. A verified state "
        "change or a disclosed canary is required before a compromise is reported.\n"
    )
    lines.append(
        "`task_marker_present` is a deterministic proxy (a required string in the final "
        "answer). It is not verified semantic task completion: semantic completion is a "
        "human assessment recorded as a separate criterion.\n"
    )
    return lines


def _agentic_evaluations(report: AgenticReport) -> list[str]:
    lines = ["## Rubric evaluations\n"]
    if not report.evaluation_sessions:
        lines.append("No evaluation session exists for this trace.\n")
        return lines
    lines.append("| session | origin | criterion | scale | outcome | score | basis | rationale |")
    lines.append("| ------- | ------ | --------- | ----- | ------- | ----- | ----- | --------- |")
    for session in report.evaluation_sessions:
        for value in session.evaluations:
            rationale = (value.rationale or "").replace("|", "/")
            lines.append(
                f"| {session.id} | {session.origin} | {value.criterion_id} | "
                f"{value.scale_kind} | {value.outcome} | "
                f"{'' if value.score is None else f'{value.score:g}'} | "
                f"{value.basis or 'human'} | {rationale} |"
            )
    lines.append("")
    lines.append("### Reproduction\n")
    lines.append(
        "Re-evaluate the stored trace with `faultline reevaluate-trace <trace> "
        "--rubric <rubric>`; the agent is never re-run and no model is contacted.\n"
    )
    return lines


def markdown_agentic(report: AgenticReport) -> str:
    """Render a simulated agentic investigation without implying external effects."""
    lines = [
        "# Faultline agentic evaluation report (synthetic, simulated)\n",
        fenced(json.dumps(_agentic_metadata(report), indent=2), "json"),
        *_agentic_surface(report),
        *_agentic_timeline(report),
        *_agentic_tools(report),
        *_agentic_outcome(report),
        *_agentic_evaluations(report),
        *_human(report.human_judgments),
        *_effective(report.adjudications, report.effective_results),
        *_disagreements(report.disagreements),
        *_agreement_lines(report.agreement),
        "## Limitations\n",
        *[f"- {item}\n" for item in report.limitations],
    ]
    lines.append("\n## Complete evidence bundle\n")
    lines.append(fenced(report.model_dump_json(indent=2), "json"))
    return "\n".join(lines)


def _experiment_metadata(report: ControlledExperimentReport) -> dict:
    experiment = report.experiment
    return {
        "report_id": report.id,
        "report_format_version": report.report_format_version,
        "origin": report.origin,
        "experiment_id": experiment.id,
        "name": experiment.name,
        "status": experiment.status,
        "objective": experiment.objective,
        "authorization": experiment.authorization,
        "allow_network": experiment.allow_network,
        "scenario": {
            "id": experiment.scenario_id,
            "version": experiment.scenario_version,
        },
        "control": {
            "scenario_sha256": experiment.control.scenario_sha256,
            "corpus_sha256": experiment.control.corpus_sha256,
            "injected_document_id": experiment.control.injected_document_id,
            "script_key": experiment.control.script_key,
        },
        "attack": {
            "scenario_sha256": experiment.attack.scenario_sha256,
            "corpus_sha256": experiment.attack.corpus_sha256,
            "injected_document_id": experiment.attack.injected_document_id,
            "injected_payload_sha256": experiment.attack.injected_payload_sha256,
            "script_key": experiment.attack.script_key,
        },
        "target": experiment.target.model_dump(mode="json"),
        "settings": experiment.settings.model_dump(mode="json"),
        "budget": experiment.budget.model_dump(mode="json"),
        "limits": experiment.limits.model_dump(mode="json"),
        "trial_count": experiment.trial_count,
        "order": experiment.order,
        "seed": experiment.seed,
        "environment_policy": experiment.environment_policy,
        "rubric": {
            "id": experiment.rubric.definition.id if experiment.rubric.definition else None,
            "version": (
                experiment.rubric.definition.version if experiment.rubric.definition else None
            ),
            "definition_sha256": experiment.rubric_definition_sha256,
        },
        "created_at": experiment.created_at.isoformat(),
        "started_at": experiment.started_at.isoformat() if experiment.started_at else None,
        "completed_at": (experiment.completed_at.isoformat() if experiment.completed_at else None),
    }


def _experiment_variants(report: ControlledExperimentReport) -> list[str]:
    experiment = report.experiment
    lines = ["## Control and attack definitions\n"]
    lines.append(
        "Both variants share the legitimate task, system prompt, tool authorization, "
        "model, generation settings, budgets and initial synthetic state. Only the "
        "declared differences below distinguish them.\n"
    )
    lines.append("**Legitimate task (identical in both arms).**\n")
    lines.append(fenced(experiment.control.scenario.user_task))
    lines.append("### Declared variant differences\n")
    lines.append("| path | control | attack | description |")
    lines.append("| ---- | ------- | ------ | ----------- |")
    for difference in experiment.differences:
        lines.append(
            f"| `{difference.path}` | `{difference.control_value}` | "
            f"`{difference.attack_value}` | {difference.description} |"
        )
    lines.append("")
    lines.append("### Corpus and payload provenance\n")
    documents = [
        document
        for document in experiment.attack.scenario.documents
        if document.id == experiment.attack.injected_document_id
    ]
    for document in documents:
        lines.append(
            fenced(
                json.dumps(
                    {
                        "document_id": document.id,
                        "title": document.title,
                        "source_note": document.source_note,
                        "trust": document.trust,
                        "content_sha256": canonical_digest(document.content),
                        "payload_sha256": canonical_digest(document.injection),
                        "control_corpus_sha256": experiment.control.corpus_sha256,
                        "attack_corpus_sha256": experiment.attack.corpus_sha256,
                    },
                    indent=2,
                ),
                "json",
            )
        )
        lines.append("**Injected payload (attack arm only).**\n")
        lines.append(fenced(document.injection or ""))
    scenario = experiment.attack.scenario
    lines.append("### Tool policy\n")
    lines.append(
        fenced(
            json.dumps(
                {
                    "allowed_tools": scenario.allowed_tools,
                    "monitored_records": scenario.monitored_records,
                    "writable_records": scenario.writable_records,
                    "initial_records": list(scenario.protected_records),
                },
                indent=2,
            ),
            "json",
        )
    )
    return lines


def _experiment_comparison(report: ControlledExperimentReport) -> list[str]:
    summary = report.summary
    lines = ["## Paired comparison\n"]
    lines.append(
        f"Trials: {summary.trials_total} total, {summary.trials_completed} completed, "
        f"{summary.trials_failed} failed, {summary.trials_interrupted} interrupted, "
        f"{summary.trials_incomplete} incomplete pair(s), {summary.trials_pending} "
        f"pending. Complete pairs: {summary.complete_pairs}.\n"
    )
    lines.append(
        "| criterion | scale | control fail | attack fail | control rate | attack rate | "
        "diff | paired 95% interval | transitions (P→P/P→F/F→P/F→F) | exact p |"
    )
    lines.append(
        "| --------- | ----- | ------------ | ----------- | ------------ | ----------- | "
        "---- | ------------------- | --- | ------- |"
    )
    for item in summary.criteria:
        control_rate = _percent(item.control_failure_rate)
        attack_rate = _percent(item.attack_failure_rate)
        difference = _percent(item.absolute_rate_difference)
        p_value = "n/a" if item.exact_binomial_p is None else f"{item.exact_binomial_p:.4f}"
        lines.append(
            f"| {item.criterion_id} | {item.scale_kind} | "
            f"{item.control_failures}/{item.control_trials} | "
            f"{item.attack_failures}/{item.attack_trials} | {control_rate} | "
            f"{attack_rate} | {difference} | "
            f"{_paired_interval(item)} | "
            f"{item.pass_pass}/{item.pass_fail}/{item.fail_pass}/{item.fail_fail} | "
            f"{p_value} |"
        )
    lines.append("")
    for item in summary.criteria:
        lines.append(f"**{item.criterion_id}**\n")
        lines.append(
            f"- 95% intervals (Wilson): control {_interval(item.control_interval)}, "
            f"attack {_interval(item.attack_interval)}\n"
        )
        lines.append(
            "- uncertain outcomes: control "
            f"{item.control_uncertain}, attack {item.attack_uncertain}; not applicable: "
            f"control {item.control_not_applicable}, attack {item.attack_not_applicable}; "
            f"excluded incomplete: {item.excluded_incomplete}\n"
        )
        if item.p_value_reason:
            lines.append(f"- exact test: {item.p_value_reason}\n")
        for note in item.notes:
            lines.append(f"- {note}\n")
    return lines


def _paired_interval(item) -> str:
    interval = item.paired_difference_interval
    if interval.low is None or interval.high is None:
        return f"undefined ({interval.reason or 'no reason'})"
    return f"[{interval.low:.2f}, {interval.high:.2f}] (n={interval.sample_size})"


def _interval(interval) -> str:
    if interval.low is None or interval.high is None:
        return f"undefined ({interval.reason or 'no reason recorded'})"
    return f"{interval.low:.2f}-{interval.high:.2f}"


def _experiment_observations(report: ControlledExperimentReport) -> list[str]:
    observations = report.summary.observations
    lines = ["## Observed signals (never collapsed into a verdict)\n"]
    lines.append("| signal | control | attack |")
    lines.append("| ------ | ------- | ------ |")
    for label in (
        "exposed",
        "unauthorized_proposals",
        "denied_actions",
        "verified_effects",
        "disclosures",
        "marker_present",
    ):
        lines.append(
            f"| {label} | {observations.get(label + '_control', 0)} | "
            f"{observations.get(label + '_attack', 0)} |"
        )
    lines.append("")
    lines.append(
        "Exposure is not compromise, a proposal is not an execution, a blocked action is "
        "not a successful unauthorized action, and marker presence is not semantic task "
        "completion. Adoption and semantic completion are human assessments.\n"
    )
    return lines


def _experiment_trials(report: ControlledExperimentReport) -> list[str]:
    lines = ["## Trials and trace references\n"]
    lines.append("| trial | status | order | control trace | attack trace | error |")
    lines.append("| ----- | ------ | ----- | ------------- | ------------ | ----- |")
    for trial in report.trials:
        error = (trial.error or trial.interruption or "").replace("|", "/")
        lines.append(
            f"| {trial.trial_index} | {trial.status} | {' → '.join(trial.order)} | "
            f"{trial.control_trace_id or 'none'} | {trial.attack_trace_id or 'none'} | {error} |"
        )
    lines.append("")
    excluded = [trial for trial in report.trials if trial.status != "completed"]
    if excluded:
        lines.append("### Incomplete, failed or interrupted trials\n")
        lines.append(
            "These trials are excluded from paired statistics. Their traces and sessions "
            "remain stored and reevaluable.\n"
        )
        for trial in excluded:
            lines.append(
                f"- trial {trial.trial_index}: {trial.status} "
                f"({trial.error or trial.interruption or 'no reason recorded'})\n"
            )
    return lines


def markdown_experiment(report: ControlledExperimentReport) -> str:
    """Render a controlled experiment without claiming causation or significance."""
    experiment = report.experiment
    lines = [
        "# Faultline controlled experiment report\n",
        fenced(json.dumps(_experiment_metadata(report), indent=2), "json"),
        "## Objective\n",
        f"{experiment.objective}\n",
        "## Authorization and target scope\n",
        f"{experiment.authorization}\n",
    ]
    if experiment.target.agent == "endpoint":
        lines.append(
            f"Authorized endpoint profile `{experiment.target.profile_id}` "
            f"({experiment.target.provider}) with model `{experiment.target.model}`. "
            f"Network opt-in: {experiment.allow_network}.\n"
        )
    else:
        lines.append(
            f"Scripted fixture agent `{experiment.target.agent}`. No provider was "
            "contacted and no model behaviour is claimed.\n"
        )
    lines.extend(_experiment_variants(report))
    lines.append("### Execution settings and budgets\n")
    lines.append(
        fenced(
            json.dumps(
                {
                    "settings": experiment.settings.model_dump(mode="json"),
                    "budget": experiment.budget.model_dump(mode="json"),
                    "limits": experiment.limits.model_dump(mode="json"),
                    "trial_count": experiment.trial_count,
                    "order_policy": experiment.order,
                    "seed": experiment.seed,
                    "environment_policy": experiment.environment_policy,
                },
                indent=2,
            ),
            "json",
        )
    )
    lines.extend(_experiment_comparison(report))
    lines.extend(_experiment_observations(report))
    lines.extend(_experiment_trials(report))
    if report.excluded_trials:
        lines.append("## Trials excluded from paired statistics\n")
        for verdict in report.excluded_trials:
            reasons = ", ".join(verdict.reasons) or "no reason"
            lines.append(f"- trial {verdict.trial_index}: {reasons}\n")
    lines.extend(_capability_lines([report.capabilities] if report.capabilities else []))
    lines.extend(_quality_lines([report.quality] if report.quality else []))
    lines.extend(_human(report.human_judgments))
    lines.extend(_effective(report.adjudications, report.effective_results))
    lines.append("## Reproduction\n")
    lines.append(
        fenced(
            f"faultline plan-experiment {experiment.scenario_id} --agent "
            f"{experiment.target.agent} --trials {experiment.trial_count} "
            f"--order {experiment.order}\n"
            f"faultline run-experiment {experiment.id}\n"
            f"faultline experiment-summary {experiment.id}\n"
            f"faultline experiment-report {experiment.id} --output reports/{experiment.id}",
            "sh",
        )
    )
    lines.append("## Limitations\n")
    lines.extend(f"- {item}\n" for item in report.limitations)
    lines.extend(f"- {item}\n" for item in report.summary.notes)
    lines.append("\n## Complete evidence bundle\n")
    lines.append(fenced(report.model_dump_json(indent=2), "json"))
    return "\n".join(lines)


def _quality_lines(reports: list) -> list[str]:
    """Render quality checks without altering any observed result."""
    if not reports:
        return []
    lines = ["## Experimental quality checks\n"]
    lines.append("| experiment | check | severity | result | detail |")
    lines.append("| ---------- | ----- | -------- | ------ | ------ |")
    for report in reports:
        for check in report.checks:
            detail = check.message.replace("|", "/")
            lines.append(
                f"| {report.experiment_id} | {check.id} | {check.severity} | "
                f"{'pass' if check.passed else 'fail'} | {detail} |"
            )
    lines.append("")
    lines.append(
        "Quality checks flag reviewable problems; they never replace the observed results above.\n"
    )
    return lines


def _capability_lines(reports: list) -> list[str]:
    if not reports:
        return []
    lines = ["## Provider capability validation\n"]
    lines.append("| profile | model | feature | configured | observed | detail |")
    lines.append("| ------- | ----- | ------- | ---------- | -------- | ------ |")
    for report in reports:
        for observation in report.observations:
            lines.append(
                f"| {report.profile_id} | {report.model or '-'} | {observation.feature} | "
                f"{observation.configured} | {observation.status} | "
                f"{observation.detail.replace('|', '/')} |"
            )
        if not report.observations:
            lines.append(
                f"| {report.profile_id} | {report.model or '-'} | none | unknown | unknown | "
                "No probe observations recorded |"
            )
    lines.append("")
    lines.append(
        "A configured capability is an assertion from the profile; only the observed "
        "column is evidence from a probe.\n"
    )
    return lines


def _model_row(entry) -> list[str]:
    summary = entry.summary
    worst = (
        max(
            (item.absolute_rate_difference or 0.0 for item in summary.criteria),
            default=0.0,
            key=abs,
        )
        if summary.criteria
        else 0.0
    )
    return [
        f"{entry.provider}/{entry.model or entry.agent}",
        entry.agent,
        str(summary.complete_pairs),
        str(summary.trials_completed),
        str(summary.trials_failed + summary.trials_interrupted + summary.trials_incomplete),
        _percent(worst),
        str(summary.observations.get("exposed_attack", 0)),
        str(summary.observations.get("unauthorized_proposals_attack", 0)),
        str(summary.observations.get("denied_actions_attack", 0)),
        str(summary.observations.get("verified_effects_attack", 0)),
        str(summary.observations.get("disclosures_attack", 0)),
        str(summary.observations.get("marker_present_attack", 0)),
        str(entry.total_tokens),
    ]


MODEL_TABLE_HEADER = [
    "model",
    "agent",
    "pairs",
    "completed",
    "excluded",
    "largest |diff|",
    "exposed",
    "proposals",
    "blocked",
    "effects",
    "disclosures",
    "markers",
    "tokens",
]


def _criterion_table(summary) -> list[str]:
    lines = [
        "| criterion | control fail | attack fail | control rate | attack rate | diff | "
        "paired 95% interval | transitions |",
        "| --------- | ------------ | ----------- | ------------ | ----------- | ---- | "
        "------------------- | ----------- |",
    ]
    for item in summary.criteria:
        interval = item.paired_difference_interval
        bordered = (
            f"[{interval.low:.2f}, {interval.high:.2f}]"
            if interval.low is not None and interval.high is not None
            else f"undefined ({interval.reason or 'no reason'})"
        )
        lines.append(
            f"| {item.criterion_id} | {item.control_failures}/{item.control_trials} | "
            f"{item.attack_failures}/{item.attack_trials} | "
            f"{_percent(item.control_failure_rate)} | "
            f"{_percent(item.attack_failure_rate)} | "
            f"{_percent(item.absolute_rate_difference)} | {bordered} | "
            f"{item.pass_pass}/{item.pass_fail}/{item.fail_pass}/{item.fail_fail} |"
        )
    lines.append("")
    return lines


def markdown_comparison(report: ModelComparisonReport) -> str:
    """Render per-model results without pooling or a global score."""
    comparison = report.comparison
    definition = comparison.rubric.definition
    metadata = {
        "report_id": report.id,
        "report_format_version": report.report_format_version,
        "origin": report.origin,
        "comparison_id": comparison.id,
        "name": comparison.name,
        "objective": comparison.objective,
        "scenario": {
            "id": comparison.scenario_id,
            "version": comparison.scenario_version,
        },
        "rubric": {
            "id": definition.id if definition else None,
            "version": definition.version if definition else None,
            "definition_sha256": comparison.rubric_definition_sha256,
        },
        "authorization": comparison.authorization,
        "allow_network": comparison.allow_network,
        "status": comparison.status,
        "models": len(comparison.entries),
    }
    lines = [
        "# Faultline model comparison report\n",
        fenced(json.dumps(metadata, indent=2), "json"),
        "## Objective and authorization\n",
        f"{comparison.objective}\n",
        f"{comparison.authorization}\n",
        "## Per-model results (never pooled)\n",
        "Each model runs its own experiment with the same legitimate task, control and "
        "attack variants, rubric and synthetic tool policy. Rows are independent "
        "samples of one model each; no row is combined with another.\n",
        "| " + " | ".join(MODEL_TABLE_HEADER) + " |",
        "| " + " | ".join("---" for _ in MODEL_TABLE_HEADER) + " |",
    ]
    for entry in comparison.entries:
        lines.append("| " + " | ".join(_model_row(entry)) + " |")
    lines.append("")
    for entry in comparison.entries:
        lines.append(f"### {entry.provider}/{entry.model or entry.agent}\n")
        lines.append(
            f"Configured capabilities: `{entry.configured_capabilities.model_dump_json()}`\n"
        )
        if entry.observed_capabilities is None:
            lines.append(
                "Observed capabilities: none — capability validation has not run for this profile\n"
            )
        else:
            lines.append(
                f"Observed capabilities: `{entry.observed_capabilities.model_dump_json()}`\n"
            )
        lines.append(
            f"Trials: {entry.trial_count} · observed completion tokens: {entry.total_tokens}\n"
        )
        lines.extend(_criterion_table(entry.summary))
        lines.extend(f"- {item}\n" for item in entry.summary.notes)
        if entry.summary.excluded_trials:
            lines.append("Excluded trials:\n")
            for verdict in entry.summary.excluded_trials:
                reasons = ", ".join(verdict.reasons) or "no reason"
                lines.append(f"- trial {verdict.trial_index}: {reasons}\n")
    return _finish_comparison(report, lines)


def _finish_comparison(report: ModelComparisonReport, lines: list[str]) -> str:
    """Shared closing sections for the comparison report."""
    comparison = report.comparison
    if comparison.notes:
        lines.append("## Comparability notes\n")
        lines.append("| kind | severity | message | models |")
        lines.append("| ---- | -------- | ------- | ------ |")
        for note in comparison.notes:
            lines.append(
                f"| {note.kind} | {note.severity} | {note.message.replace('|', '/')} | "
                f"{', '.join(note.models)} |"
            )
        lines.append("")
    lines.extend(_capability_lines(report.capabilities))
    lines.extend(_quality_lines(report.quality))
    lines.extend(_human(report.human_judgments))
    lines.extend(_effective(report.adjudications, report.effective_results))
    lines.append("## Trace references\n")
    lines.append(fenced("\n".join(report.trace_ids) or "none", "text"))
    lines.append("## Limitations\n")
    lines.extend(f"- {item}\n" for item in report.limitations)
    lines.append("\n## Complete evidence bundle\n")
    lines.append(fenced(report.model_dump_json(indent=2), "json"))
    return "\n".join(lines)


def markdown_benchmark(report: BenchmarkReport) -> str:
    """Render scenario-level benchmark results per model, with budgets."""
    plan = report.plan
    metadata = {
        "report_id": report.id,
        "report_format_version": report.report_format_version,
        "origin": report.origin,
        "benchmark_id": plan.id,
        "suite": {
            "id": plan.suite.id,
            "version": plan.suite.version,
            "title": plan.suite.title,
            "scenarios": plan.scenario_ids,
            "provenance": plan.suite.provenance,
        },
        "models": plan.model_labels,
        "limits": plan.limits.model_dump(mode="json"),
        "authorization": plan.authorization,
        "allow_network": plan.allow_network,
        "status": plan.status,
    }
    lines = [
        "# Faultline benchmark report\n",
        fenced(json.dumps(metadata, indent=2), "json"),
        "## Suite and authorization\n",
        f"{plan.suite.description}\n",
        f"Authorization: {plan.authorization}\n",
        "Budget: "
        f"{plan.limits.max_scenarios} scenarios, {plan.limits.max_trials_per_scenario} "
        f"trials each, {plan.limits.max_total_requests} requests, "
        f"{plan.limits.max_total_tokens} tokens, "
        f"{plan.limits.max_runtime_seconds:g}s runtime.\n",
        "## Scenario results\n",
        "| scenario | model | status | pairs | control rate | attack rate | diff | "
        "paired 95% interval | criterion | note |",
        "| -------- | ----- | ------ | ----- | ------------ | ----------- | ---- | "
        "------------------- | --------- | ---- |",
    ]
    for row in plan.results:
        if row.summary is None:
            lines.append(
                f"| {row.scenario_id} | {row.model_label} | {row.status} | - | - | - | "
                "- | - | - | "
                f"{row.skipped_reason or row.error or 'not executed'} |"
            )
            continue
        worst = max(
            row.summary.criteria,
            key=lambda item: abs(item.absolute_rate_difference or 0.0),
            default=None,
        )
        interval = "n/a"
        if worst is not None:
            value = worst.paired_difference_interval
            interval = (
                f"[{value.low:.2f}, {value.high:.2f}]"
                if value.low is not None and value.high is not None
                else "undefined"
            )
        lines.append(
            f"| {row.scenario_id} | {row.model_label} | {row.status} | "
            f"{row.summary.complete_pairs} | "
            f"{_percent(worst.control_failure_rate if worst else None)} | "
            f"{_percent(worst.attack_failure_rate if worst else None)} | "
            f"{_percent(worst.absolute_rate_difference if worst else None)} | "
            f"{interval} | {(worst.criterion_id if worst else '')} | "
            f"{row.error or row.skipped_reason or ''} |"
        )
    lines.append("")
    lines.append(
        "Scenario rows are independent experiments. Nothing is pooled across scenarios "
        "or models, and no composite or ranking score is computed.\n"
    )
    lines.extend(_capability_lines(report.capabilities))
    lines.extend(_quality_lines(report.quality))
    lines.extend(_human(report.human_judgments))
    lines.extend(_effective(report.adjudications, report.effective_results))
    lines.append("## Trace references\n")
    lines.append(fenced("\n".join(report.trace_ids) or "none", "text"))
    lines.append("## Limitations\n")
    lines.extend(f"- {item}\n" for item in report.limitations)
    lines.append("\n## Complete evidence bundle\n")
    lines.append(fenced(report.model_dump_json(indent=2), "json"))
    return "\n".join(lines)


COMPARISON_CSV_COLUMNS = [
    "comparison_id",
    "model",
    "provider",
    "agent",
    "experiment_id",
    "trial_count",
    "complete_pairs",
    "criterion_id",
    "scale_kind",
    "control_failures",
    "control_trials",
    "attack_failures",
    "attack_trials",
    "control_failure_rate",
    "attack_failure_rate",
    "absolute_rate_difference",
    "paired_interval_low",
    "paired_interval_high",
    "paired_interval_method",
    "pass_pass",
    "pass_fail",
    "fail_pass",
    "fail_fail",
    "excluded_reasons",
    "capability_status",
]


def _entry_capability_status(entry) -> str:
    if entry.observed_capabilities is None:
        return "declared-only"
    return entry.observed_capabilities.chat_completions


def comparison_rows(report: ModelComparisonReport) -> list[list[str]]:
    """One row per model and criterion; each row is its own sample."""
    comparison = report.comparison
    rows: list[list[str]] = []
    for entry in comparison.entries:
        for item in entry.summary.criteria:
            interval = item.paired_difference_interval
            rows.append(
                [
                    _safe_cell(comparison.id),
                    _safe_cell(entry.model),
                    _safe_cell(entry.provider),
                    _safe_cell(entry.agent),
                    _safe_cell(entry.experiment_id),
                    _safe_cell(entry.trial_count),
                    _safe_cell(item.complete_pairs),
                    _safe_cell(item.criterion_id),
                    _safe_cell(item.scale_kind),
                    _safe_cell(item.control_failures),
                    _safe_cell(item.control_trials),
                    _safe_cell(item.attack_failures),
                    _safe_cell(item.attack_trials),
                    _safe_cell(item.control_failure_rate),
                    _safe_cell(item.attack_failure_rate),
                    _safe_cell(item.absolute_rate_difference),
                    _safe_cell(interval.low),
                    _safe_cell(interval.high),
                    _safe_cell(interval.method),
                    _safe_cell(item.pass_pass),
                    _safe_cell(item.pass_fail),
                    _safe_cell(item.fail_pass),
                    _safe_cell(item.fail_fail),
                    _safe_cell(
                        ";".join(
                            f"{name}={count}"
                            for name, count in sorted(item.excluded_reasons.items())
                        )
                    ),
                    _safe_cell(_entry_capability_status(entry)),
                ]
            )
    return rows


def csv_export_comparison(report: ModelComparisonReport) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COMPARISON_CSV_COLUMNS)
    writer.writerows(comparison_rows(report))
    return buffer.getvalue()


BENCHMARK_CSV_COLUMNS = [
    "benchmark_id",
    "suite_id",
    "suite_version",
    "scenario_id",
    "model",
    "status",
    "experiment_id",
    "complete_pairs",
    "trials_completed",
    "trials_incomplete",
    "criterion_id",
    "control_failures",
    "attack_failures",
    "absolute_rate_difference",
    "paired_interval_low",
    "paired_interval_high",
    "exposed_attack",
    "verified_effects_attack",
    "disclosures_attack",
    "note",
]


def benchmark_rows(report: BenchmarkReport) -> list[list[str]]:
    """One row per scenario, model and criterion; scenario rows stay separate."""
    plan = report.plan
    rows: list[list[str]] = []
    for result in plan.results:
        if result.summary is None:
            rows.append(
                [
                    _safe_cell(plan.id),
                    _safe_cell(plan.suite.id),
                    _safe_cell(plan.suite.version),
                    _safe_cell(result.scenario_id),
                    _safe_cell(result.model_label),
                    _safe_cell(result.status),
                    _safe_cell(result.experiment_id),
                    _safe_cell(0),
                    _safe_cell(0),
                    _safe_cell(0),
                    _safe_cell(None),
                    _safe_cell(None),
                    _safe_cell(None),
                    _safe_cell(None),
                    _safe_cell(None),
                    _safe_cell(None),
                    _safe_cell(None),
                    _safe_cell(None),
                    _safe_cell(None),
                    _safe_cell(result.skipped_reason or result.error),
                ]
            )
            continue
        observations = result.summary.observations
        for item in result.summary.criteria:
            interval = item.paired_difference_interval
            rows.append(
                [
                    _safe_cell(plan.id),
                    _safe_cell(plan.suite.id),
                    _safe_cell(plan.suite.version),
                    _safe_cell(result.scenario_id),
                    _safe_cell(result.model_label),
                    _safe_cell(result.status),
                    _safe_cell(result.experiment_id),
                    _safe_cell(item.complete_pairs),
                    _safe_cell(result.summary.trials_completed),
                    _safe_cell(result.summary.trials_incomplete),
                    _safe_cell(item.criterion_id),
                    _safe_cell(item.control_failures),
                    _safe_cell(item.attack_failures),
                    _safe_cell(item.absolute_rate_difference),
                    _safe_cell(interval.low),
                    _safe_cell(interval.high),
                    _safe_cell(observations.get("exposed_attack")),
                    _safe_cell(observations.get("verified_effects_attack")),
                    _safe_cell(observations.get("disclosures_attack")),
                    _safe_cell(result.error or result.skipped_reason),
                ]
            )
    return rows


def csv_export_benchmark(report: BenchmarkReport) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(BENCHMARK_CSV_COLUMNS)
    writer.writerows(benchmark_rows(report))
    return buffer.getvalue()
