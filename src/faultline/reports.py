"""Portable, versioned report exports; never publish or fetch remote content."""

import json
import re
from pathlib import Path

from faultline.domain import Report
from faultline.techniques import technique_hash


def fenced(content: str, language: str = "text") -> str:
    longest = max((len(m.group()) for m in re.finditer(r"`+", content)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{content}\n{fence}\n"


def markdown(report: Report) -> str:
    e = report.experiment
    lines = [
        "# Faultline evaluation report\n",
        fenced(
            json.dumps(
                {
                    "report_id": report.id,
                    "experiment_id": e.id,
                    "name": e.name,
                    "status": e.status,
                    "generated_at": report.generated_at.isoformat(),
                    "requested_model": e.target.requested_model,
                    "provider": e.endpoint.provider,
                    "technique": f"{e.technique.id}@{e.technique.version}",
                    "technique_sha256": technique_hash(e.technique),
                    "rubric_source_sha256": e.rubric.source.sha256,
                },
                indent=2,
            ),
            "json",
        ),
        "## Observations\n",
    ]
    if not report.findings:
        lines.append("No failed automated checks recorded. Inspect coverage and run status.\n")
    for finding in report.findings:
        lines.append(
            fenced(
                f"[{finding.classification}] {finding.title}\n{finding.claim}\n"
                f"Run: {finding.run_id}\nEvaluation: {finding.evaluation_id}\n"
                f"Evidence: {', '.join(finding.evidence_ids)}"
            )
        )
    for run, score in zip(report.runs, report.automated_scores, strict=True):
        lines.append(f"## {run.case.kind.title()} response\n")
        lines.append(
            fenced(
                f"Run: {run.id}\nStatus: {run.status}\n"
                f"Weighted compliance: {score.weighted_compliance}\nCoverage: {score.coverage:.1%}"
            )
        )
        if run.response:
            lines.append(fenced(run.response.text))
        if run.error:
            lines.append(fenced(run.error))
        for value in run.evaluations:
            lines.append(
                fenced(
                    f"{value.criterion_id}: {value.outcome} (score={value.score}, {value.basis})\n"
                    f"{value.rationale}\nEvidence: {', '.join(value.evidence_ids)}"
                )
            )
    lines.append("## Human judgment\n")
    lines.append(
        "Original automated scores and findings remain unchanged. Overrides follow in order.\n"
    )
    for override in report.human_overrides:
        lines.append(fenced(override.model_dump_json(indent=2), "json"))
    lines.append("## Limits of interpretation\n")
    lines.extend(f"- {limit}\n" for limit in report.limitations)
    lines.append("\n## Complete reproducibility and evidence bundle\n")
    lines.append(
        "Contains full rendered requests, raw decoded responses, source documents, "
        "rubric definitions, identities, timestamps, settings and evidence hashes.\n"
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
    for path, content in [
        (json_path, report.model_dump_json(indent=2)),
        (md_path, markdown(report)),
    ]:
        # Exclusive creation prevents accidental evidence replacement and symlink following.
        with path.open("x", encoding="utf-8") as stream:
            path.chmod(0o600)
            stream.write(content + "\n")
    return json_path, md_path
