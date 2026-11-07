"""Audit an exported report against its own evidence. No provider contact, no network.

Every check is derived from the document itself: denominators, transition totals,
interval bounds, trace references, simulation labelling, credential patterns and the
companion CSV. Findings never modify the export and never invent a stronger claim
than the evidence supports.
"""

import csv
import io
import json
import re
from pathlib import Path

from faultline.domain import ReportIssue, ReportValidation, canonical_digest

ACCEPTED_FORMATS = {"2.0.0", "2.1.0", "2.2.0", "2.3.0"}
ORIGINS = {
    "experiment",
    "dataset_import",
    "agentic",
    "controlled_experiment",
    "model_comparison",
    "benchmark",
}
SIMULATION_WORDS = ("synthetic", "simulated", "scripted", "no external system")
SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"[Bb]earer\s+[A-Za-z0-9._-]{12,}"),
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*[A-Za-z0-9._-]{8,}"),
)
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _issue(severity: str, code: str, message: str, location: str = "") -> ReportIssue:
    return ReportIssue(severity=severity, code=code, message=message, location=location)


def _origin(document: dict) -> str:
    origin = document.get("origin")
    if isinstance(origin, str) and origin in ORIGINS:
        return origin
    if "experiment" in document and "summary" in document and "trials" in document:
        return "controlled_experiment"
    if "comparison" in document:
        return "model_comparison"
    if "plan" in document:
        return "benchmark"
    if "trace" in document and "result" in document:
        return "agentic"
    if "batch" in document:
        return "dataset_import"
    if "experiment" in document and "runs" in document:
        return "experiment"
    return "unknown"


def _criteria(document: dict, origin: str) -> list[dict]:
    """Collect every criterion-comparison block wherever the origin keeps it."""
    blocks: list[dict] = []
    if origin == "controlled_experiment":
        blocks.extend(document.get("summary", {}).get("criteria", [])) or None
    elif origin == "model_comparison":
        for entry in document.get("comparison", {}).get("entries", []):
            blocks.extend(entry.get("summary", {}).get("criteria", []))
    elif origin == "benchmark":
        for row in document.get("plan", {}).get("results", []):
            summary = row.get("summary") or {}
            blocks.extend(summary.get("criteria", []))
    return blocks


def _check_digest(document: dict, issues: list[ReportIssue]) -> None:
    digest = document.get("export_digest")
    if not isinstance(digest, dict) or not digest.get("sha256"):
        issues.append(_issue("blocking", "digest-missing", "The export carries no export digest"))
        return
    payload = {key: value for key, value in document.items() if key != "export_digest"}
    expected = canonical_digest(payload)
    if digest["sha256"] != expected:
        issues.append(
            _issue(
                "blocking",
                "digest-mismatch",
                "The recorded export digest does not describe this document",
                "export_digest",
            )
        )


def _check_criterion(block: dict, issues: list[ReportIssue], index: int) -> None:
    location = f"criteria[{index}]:{block.get('criterion_id', 'unknown')}"
    pairs = block.get("complete_pairs", 0)
    control_trials = block.get("control_trials", 0)
    attack_trials = block.get("attack_trials", 0)
    if pairs > min(control_trials, attack_trials):
        issues.append(
            _issue(
                "blocking",
                "denominator-inconsistent",
                f"complete_pairs {pairs} exceeds the scored arm counts "
                f"({control_trials}/{attack_trials})",
                location,
            )
        )
    transitions = (
        block.get("pass_pass", 0)
        + block.get("pass_fail", 0)
        + block.get("fail_pass", 0)
        + block.get("fail_fail", 0)
    )
    if transitions != pairs:
        issues.append(
            _issue(
                "blocking",
                "transition-total-mismatch",
                f"Transition counts total {transitions} but complete_pairs is {pairs}",
                location,
            )
        )
    # Scored, uncertain and not-applicable counts partition the observed variants,
    # so each part is bounded by the arm's total observation count.
    control_total = (
        control_trials + block.get("control_uncertain", 0) + block.get("control_not_applicable", 0)
    )
    attack_total = (
        attack_trials + block.get("attack_uncertain", 0) + block.get("attack_not_applicable", 0)
    )
    for name, limit in (
        ("control_failures", control_trials),
        ("attack_failures", attack_trials),
        ("control_uncertain", control_total),
        ("attack_uncertain", attack_total),
        ("control_not_applicable", control_total),
        ("attack_not_applicable", attack_total),
    ):
        value = block.get(name, 0)
        if value > limit:
            issues.append(
                _issue(
                    "blocking",
                    "count-exceeds-denominator",
                    f"{name} ({value}) exceeds its denominator ({limit})",
                    location,
                )
            )
    for name in ("control_failure_rate", "attack_failure_rate"):
        value = block.get(name)
        if value is not None and not 0.0 <= value <= 1.0:
            issues.append(
                _issue(
                    "blocking",
                    "rate-out-of-range",
                    f"{name} is outside [0, 1]",
                    location,
                )
            )
    difference = block.get("absolute_rate_difference")
    if difference is not None and not -1.0 <= difference <= 1.0:
        issues.append(
            _issue(
                "blocking",
                "difference-out-of-range",
                "The paired difference is outside [-1, 1]",
                location,
            )
        )
    interval = block.get("paired_difference_interval") or {}
    low, high = interval.get("low"), interval.get("high")
    if interval.get("method") not in {None, "none"}:
        if low is None or high is None:
            issues.append(
                _issue(
                    "blocking",
                    "interval-incomplete",
                    "A defined interval lacks a bound",
                    location,
                )
            )
        else:
            estimate = interval.get("estimate")
            if estimate is not None and not low <= estimate <= high:
                issues.append(
                    _issue(
                        "blocking",
                        "interval-excludes-estimate",
                        "The interval does not contain its own estimate",
                        location,
                    )
                )
            if not -1.0 <= low <= high <= 1.0:
                issues.append(
                    _issue(
                        "blocking",
                        "interval-out-of-range",
                        "Interval bounds fall outside [-1, 1]",
                        location,
                    )
                )
            if interval.get("sample_size") is not None and interval["sample_size"] != pairs:
                issues.append(
                    _issue(
                        "warning",
                        "interval-sample-size-mismatch",
                        "The interval sample size differs from complete_pairs",
                        location,
                    )
                )
    if interval.get("coverage") == "conditional-exact" and interval.get("method") == (
        "newcombe-mover-95"
    ):
        issues.append(
            _issue(
                "blocking",
                "coverage-mislabel",
                "A score-based interval is labelled as conditional coverage",
                location,
            )
        )


def _check_simulation(document: dict, origin: str, issues: list[ReportIssue]) -> None:
    limitations = " ".join(str(item) for item in document.get("limitations", [])).lower()
    synthetic_origins = {
        "agentic",
        "controlled_experiment",
        "model_comparison",
        "benchmark",
    }
    if origin in synthetic_origins and not any(word in limitations for word in SIMULATION_WORDS):
        issues.append(
            _issue(
                "blocking",
                "simulation-labelling-missing",
                "A synthetic report must state that its execution is simulated",
                "limitations",
            )
        )
    if origin == "controlled_experiment":
        target = document.get("experiment", {}).get("target", {})
        if target.get("agent") == "endpoint" and not document.get("experiment", {}).get(
            "allow_network"
        ):
            issues.append(
                _issue(
                    "blocking",
                    "network-claim-without-opt-in",
                    "An endpoint experiment is reported without a network opt-in",
                    "experiment.target",
                )
            )


def _check_traces(document: dict, origin: str, issues: list[ReportIssue]) -> None:
    if origin not in {"controlled_experiment", "model_comparison", "benchmark"}:
        return
    known = set(document.get("trace_ids", []))
    if not known:
        issues.append(
            _issue("blocking", "trace-references-missing", "No trace reference is retained")
        )
    trials = document.get("trials", [])
    for trial in trials:
        for role in ("control", "attack"):
            observation = trial.get(role)
            if observation is None:
                continue
            trace_id = observation.get("trace_id")
            if not trace_id:
                issues.append(
                    _issue(
                        "blocking",
                        "observation-without-trace",
                        f"Trial {trial.get('trial_index')} {role} observation has no trace",
                    )
                )
            elif trace_id not in known:
                issues.append(
                    _issue(
                        "blocking",
                        "trace-not-listed",
                        f"Trial {trial.get('trial_index')} references an unlisted trace",
                        trace_id,
                    )
                )
            executed = observation.get("executed_tools", [])
            changes = observation.get("state_changes", [])
            if changes and not executed:
                issues.append(
                    _issue(
                        "blocking",
                        "effect-without-execution",
                        "A verified state change is claimed without an executed tool",
                        str(trace_id),
                    )
                )
    if document.get("evaluation_sessions") is not None:
        for session in document.get("evaluation_sessions", []):
            if not session.get("evidence"):
                issues.append(
                    _issue(
                        "blocking",
                        "session-without-evidence",
                        "An evaluation session retains no evidence artifact",
                        str(session.get("id")),
                    )
                )


def _check_review_records(document: dict, issues: list[ReportIssue]) -> None:
    sessions = {item.get("id") for item in document.get("evaluation_sessions", [])}
    seen: set[str] = set()
    for judgment in document.get("human_judgments", []):
        identifier = judgment.get("id")
        if identifier in seen:
            issues.append(
                _issue(
                    "blocking",
                    "duplicate-judgment",
                    "A judgment identifier appears twice",
                    str(identifier),
                )
            )
        seen.add(identifier)
        if sessions and judgment.get("session_id") not in sessions:
            issues.append(
                _issue(
                    "blocking",
                    "judgment-orphan",
                    "A judgment references a session that is not in the report",
                    str(judgment.get("session_id")),
                )
            )
    for adjudication in document.get("adjudications", []):
        if sessions and adjudication.get("session_id") not in sessions:
            issues.append(
                _issue(
                    "blocking",
                    "adjudication-orphan",
                    "An adjudication references a session that is not in the report",
                    str(adjudication.get("session_id")),
                )
            )
    if document.get("human_judgments") and not document.get("effective_results"):
        issues.append(
            _issue(
                "warning",
                "judgments-without-effective-result",
                "Judgments are present but no effective result was derived",
            )
        )


def _check_secrets(payload: str, issues: list[ReportIssue]) -> None:
    for pattern in SECRET_PATTERNS:
        if pattern.search(payload):
            issues.append(
                _issue(
                    "blocking",
                    "credential-pattern",
                    "The export contains a string shaped like a credential; the value is "
                    "not reproduced here",
                )
            )


def _check_csv(path: Path, issues: list[ReportIssue]) -> None:
    companion = path.with_suffix(".csv")
    if not companion.exists():
        return
    text = companion.read_text(encoding="utf-8", errors="replace")
    reader = csv.reader(io.StringIO(text))
    header = next(reader, [])
    for row_index, row in enumerate(reader, start=2):
        for column, cell in enumerate(row):
            if cell.startswith(FORMULA_PREFIXES):
                field = header[column] if column < len(header) else str(column)
                issues.append(
                    _issue(
                        "blocking",
                        "csv-formula-injection",
                        f"CSV cell in row {row_index} column '{field}' starts with a formula "
                        "character and is not neutralised",
                        companion.name,
                    )
                )


def validate_export(path: Path) -> ReportValidation:
    """Audit one exported JSON report (and its CSV companion when present)."""
    path = Path(path)
    issues: list[ReportIssue] = []
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return ReportValidation(
            path=str(path),
            issues=[
                _issue("blocking", "unreadable", f"The export could not be read: {exc.strerror}")
            ],
            checks_run=1,
        )
    try:
        document = json.loads(raw)
    except ValueError:
        return ReportValidation(
            path=str(path),
            issues=[_issue("blocking", "not-json", "The export is not valid JSON")],
            checks_run=1,
        )
    if not isinstance(document, dict):
        return ReportValidation(
            path=str(path),
            issues=[_issue("blocking", "not-an-object", "The export is not a JSON object")],
            checks_run=1,
        )
    checks = 0
    origin = _origin(document)
    checks += 1
    if origin == "unknown":
        issues.append(
            _issue(
                "blocking",
                "origin-unknown",
                "The document does not identify a supported report origin",
            )
        )
    version = document.get("report_format_version")
    checks += 1
    if version is not None and version not in ACCEPTED_FORMATS:
        issues.append(
            _issue(
                "blocking",
                "format-version-unsupported",
                f"Report format {version} is not accepted by this build",
                "report_format_version",
            )
        )
    _check_digest(document, issues)
    checks += 1
    for index, block in enumerate(_criteria(document, origin)):
        _check_criterion(block, issues, index)
        checks += 1
    _check_simulation(document, origin, issues)
    _check_traces(document, origin, issues)
    _check_review_records(document, issues)
    checks += 3
    _check_secrets(raw, issues)
    checks += 1
    _check_csv(path, issues)
    checks += 1
    if origin == "controlled_experiment":
        trial_count = document.get("experiment", {}).get("trial_count")
        trials = document.get("trials", [])
        if trial_count is not None and trials and len(trials) != trial_count:
            issues.append(
                _issue(
                    "warning",
                    "trial-count-mismatch",
                    f"The plan declares {trial_count} trial(s) but the report lists {len(trials)}",
                    "trials",
                )
            )
        checks += 1
    return ReportValidation(
        path=str(path),
        origin=origin,
        report_id=document.get("id"),
        report_format_version=version,
        issues=issues,
        checks_run=checks,
    )
