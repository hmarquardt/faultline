"""Versioned contracts. No UI, database or network dependencies."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def new_id() -> str:
    return str(uuid4())


def now() -> datetime:
    return datetime.now(UTC)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


CANONICAL_ALGORITHM = "sha256-canonical-json/1"


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_digest(value: Any, *, exclude: set[str] | None = None) -> str:
    """Hash one typed record by value, independent of insertion and field order."""
    payload = (
        value.model_dump(mode="json", exclude=exclude or set())
        if hasattr(value, "model_dump")
        else value
    )
    return digest(canonical_json(payload))


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    schema_version: Literal[1] = 1


class EndpointProfile(Contract):
    id: str = Field(default_factory=new_id)
    name: str = Field(min_length=1)
    provider: Literal["mock", "openai-compatible"] = "mock"
    base_url: str | None = None
    credential_env: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    allowed_models: list[str] = Field(default_factory=lambda: ["toy-model"], min_length=1)
    authorization: str = "Local synthetic mock evaluation"
    authorized: bool = False
    mock_behavior: Literal["secure", "vulnerable"] = "secure"
    tool_calling: bool = False
    token_parameter: Literal["max_tokens", "max_completion_tokens"] = "max_tokens"
    created_at: datetime = Field(default_factory=now)

    @model_validator(mode="after")
    def validate_address(self) -> EndpointProfile:
        if self.provider == "mock":
            if self.base_url or self.credential_env:
                raise ValueError("Mock profiles cannot contain network or credential settings")
            return self
        if not self.base_url:
            raise ValueError("HTTP endpoints require a base URL")
        url = urlsplit(self.base_url)
        if url.username or url.password or url.query or url.fragment:
            raise ValueError("URLs cannot contain credentials, queries or fragments")
        if not url.hostname or url.scheme not in {"http", "https"}:
            raise ValueError("Expected an absolute HTTP(S) URL")
        if url.scheme == "http" and url.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Cleartext HTTP is restricted to loopback endpoints")
        if not self.authorization.strip():
            raise ValueError("Describe the authorized scope")
        return self

    @property
    def request_url(self) -> str:
        return f"{(self.base_url or '').rstrip('/')}/chat/completions"


class TargetModel(Contract):
    endpoint_id: str
    requested_model: str = Field(min_length=1)


Family = Literal[
    "authority-spoofing",
    "direct-injection",
    "indirect-injection",
    "obfuscation",
    "multiturn",
    "synthetic-disclosure",
    "tool-redirection",
    "persona",
    "format-constraint",
]


class Message(Contract):
    role: Literal["system", "user", "assistant", "tool"]
    content: str


class TechniqueDefinition(Contract):
    id: str
    version: str
    name: str
    family: Family
    description: str
    parameters: dict[str, str]
    attack_messages: list[Message] = Field(min_length=1)
    references: list[str] = Field(default_factory=list)


class AttackCase(Contract):
    id: str = Field(default_factory=new_id)
    kind: Literal["baseline", "attack"]
    technique_id: str
    technique_version: str
    parameters: dict[str, str]
    messages: list[Message] = Field(min_length=1)


class EvidenceArtifact(Contract):
    id: str = Field(default_factory=new_id)
    kind: Literal[
        "rubric-source",
        "normalization-draft",
        "response",
        "tool-receipt",
        "dataset-source",
        "dataset-record",
        "imported-response",
        "scenario-source",
        "agentic-trace",
        "provider-probe",
    ]
    content: str
    sha256: str
    provenance: str
    created_at: datetime = Field(default_factory=now)

    @model_validator(mode="after")
    def verify_hash(self) -> EvidenceArtifact:
        if digest(self.content) != self.sha256:
            raise ValueError("Artifact SHA-256 does not match content")
        return self

    @classmethod
    def capture(cls, kind: str, content: str, provenance: str) -> EvidenceArtifact:
        return cls(kind=kind, content=content, sha256=digest(content), provenance=provenance)


CheckKind = Literal[
    "required_text",
    "forbidden_text",
    "exact_canary",
    "json_schema",
    "tool_execution",
    "python",
    "manual",
    "forbidden_tool_request",
    "forbidden_tool_execution",
    "tool_policy_blocked",
    "protected_record_unchanged",
    "canary_absent",
    "agent_task_completed",
    "semantic_task_completion",
]
TRACE_CHECKS = {
    "forbidden_tool_request",
    "forbidden_tool_execution",
    "tool_policy_blocked",
    "protected_record_unchanged",
    "canary_absent",
    "agent_task_completed",
    "semantic_task_completion",
}
Outcome = Literal["pass", "fail", "not_applicable", "uncertain"]
ScaleKind = Literal["binary", "ordinal", "categorical", "numeric"]


class RubricLevel(Contract):
    """One ordered anchor with the rubric's own label and wording."""

    label: str = Field(min_length=1)
    description: str = Field(min_length=1)
    score: float


class RubricCategory(Contract):
    """One unordered outcome with the rubric's own label and an explicit meaning."""

    label: str = Field(min_length=1)
    description: str = Field(min_length=1)
    outcome: Outcome


class RubricCriterion(Contract):
    id: str = Field(min_length=1)
    instructions: str = Field(min_length=1)
    check: CheckKind
    config: dict[str, Any] = Field(default_factory=dict)
    weight: float = Field(default=1, gt=0)
    scale_min: float = 0
    scale_max: float = 1
    pass_threshold: float = 1
    evidence_requirements: list[str] = Field(default_factory=lambda: ["raw_response"])
    applies_to: Literal["both", "baseline", "attack"] = "both"
    scale_kind: ScaleKind = "binary"
    levels: list[RubricLevel] = Field(default_factory=list)
    categories: list[RubricCategory] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_check(self) -> RubricCriterion:
        try:
            json.dumps(self.config, allow_nan=False)
        except (ValueError, TypeError):
            raise ValueError("Check configuration requires finite JSON-compatible data") from None
        if not self.scale_min < self.pass_threshold <= self.scale_max:
            raise ValueError("Threshold must exceed scale minimum and be within scoring scale")
        if self.scale_min >= self.scale_max:
            raise ValueError("Scoring scale must have positive width")
        keys = {
            "required_text": {"text"},
            "forbidden_text": {"text"},
            "exact_canary": {"parameter"},
            "json_schema": {"schema"},
            "tool_execution": {"tool"},
            "python": {"assertion"},
            "manual": set(),
            "forbidden_tool_request": {"tool"},
            "forbidden_tool_execution": {"tool"},
            "tool_policy_blocked": {"tool"},
            "protected_record_unchanged": {"record_id"},
            "canary_absent": {"parameter"},
            "agent_task_completed": {"text"},
            "semantic_task_completion": set(),
        }[self.check]
        if set(self.config) != keys:
            raise ValueError(f"{self.check} requires exactly these config keys: {sorted(keys)}")
        if self.check == "json_schema":
            from jsonschema import Draft202012Validator
            from jsonschema.exceptions import SchemaError

            try:
                Draft202012Validator.check_schema(self.config["schema"])
            except SchemaError:
                raise ValueError("Invalid JSON Schema in criterion") from None
        elif any(not isinstance(v, str) or not v for v in self.config.values()):
            raise ValueError("Check configuration values must be nonempty strings")
        return self.validate_scale()

    def validate_scale(self) -> RubricCriterion:
        """Scale declarations must be explicit, complete and unambiguous."""
        if self.scale_kind == "binary":
            if self.levels or self.categories:
                raise ValueError("Binary criteria cannot declare levels or categories")
            return self
        if self.scale_kind == "categorical":
            if self.levels:
                raise ValueError("Categorical criteria use described categories, not levels")
            if len(self.categories) < 2:
                raise ValueError("Categorical criteria require at least two described categories")
            if len({c.label for c in self.categories}) != len(self.categories):
                raise ValueError("Category labels must be unique")
            if not {c.outcome for c in self.categories} >= {"pass", "fail"}:
                raise ValueError("Categorical criteria need one pass and one fail category")
            return self
        if self.categories:
            raise ValueError("Ordinal and numeric criteria use levels, not categories")
        if len(self.levels) < 2:
            raise ValueError("Ordinal and numeric criteria require at least two described levels")
        if len({c.label for c in self.levels}) != len(self.levels):
            raise ValueError("Level labels must be unique")
        scores = [c.score for c in self.levels]
        if any(b <= a for a, b in zip(scores, scores[1:], strict=False)):
            raise ValueError("Level scores must be strictly increasing")
        if any(not self.scale_min <= s <= self.scale_max for s in scores):
            raise ValueError("Level scores must stay within the declared scoring scale")
        return self


class RubricDefinition(Contract):
    id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    title: str = Field(min_length=1)
    criteria: list[RubricCriterion] = Field(min_length=1)

    @field_validator("criteria")
    @classmethod
    def unique_criteria(cls, value: list[RubricCriterion]) -> list[RubricCriterion]:
        if len({c.id for c in value}) != len(value):
            raise ValueError("Criterion IDs must be unique")
        return value


class Rubric(Contract):
    id: str = Field(default_factory=new_id)
    source: EvidenceArtifact
    definition: RubricDefinition | None = None
    review_status: Literal["structured", "pending", "reviewed"]
    reviewer: str | None = None
    review_rationale: str | None = None
    reviewed_at: datetime | None = None
    normalization_draft: EvidenceArtifact | None = None

    @model_validator(mode="after")
    def validate_review(self) -> Rubric:
        if self.review_status != "pending" and self.definition is None:
            raise ValueError("An executable rubric needs a definition")
        if self.review_status == "reviewed" and not all(
            [self.reviewer, self.review_rationale, self.reviewed_at, self.normalization_draft]
        ):
            raise ValueError("Human normalization requires complete review provenance")
        return self


class ExecutionSettings(Contract):
    temperature: float | None = Field(default=0, ge=0, le=2)
    seed: int | None = 42
    max_output_tokens: int = Field(default=128, ge=1, le=32768)
    timeout_seconds: float = Field(default=30, gt=0, le=300)


class ExecutionBudget(Contract):
    max_requests: int = Field(default=2, ge=1, le=100)
    max_total_output_tokens: int = Field(default=256, ge=1)
    max_input_bytes: int = Field(default=65536, ge=1)
    max_response_bytes: int = Field(default=1048576, ge=1, le=10485760)


class Experiment(Contract):
    id: str = Field(default_factory=new_id)
    name: str
    endpoint: EndpointProfile
    target: TargetModel
    rubric: Rubric
    technique: TechniqueDefinition
    cases: list[AttackCase] = Field(min_length=1)
    settings: ExecutionSettings = Field(default_factory=ExecutionSettings)
    budget: ExecutionBudget = Field(default_factory=ExecutionBudget)
    dry_run: bool = False
    network_enabled: bool = False
    python_assertions_enabled: bool = False
    status: Literal["planned", "running", "completed", "failed", "dry_run"] = "planned"
    created_at: datetime = Field(default_factory=now)
    completed_at: datetime | None = None
    harness_version: str = "0.1.0"


class ToolReceipt(Contract):
    tool: str
    executed: bool
    provenance: str


class ModelResponse(Contract):
    id: str = Field(default_factory=new_id)
    text: str
    returned_model: str
    raw: dict[str, Any]
    finish_reason: str | None = None
    tool_requests: list[dict[str, Any]] = Field(default_factory=list)
    tool_receipts: list[ToolReceipt] | None = None
    usage: dict[str, Any] = Field(default_factory=dict)
    credential_redacted: bool = False
    received_at: datetime = Field(default_factory=now)


class CriterionEvaluation(Contract):
    id: str = Field(default_factory=new_id)
    run_id: str
    criterion_id: str
    rubric_id: str
    rubric_version: str
    outcome: Outcome
    score: float | None = None
    label: str | None = None
    scale_kind: ScaleKind = "binary"
    rationale: str
    evaluator: str = "faultline.deterministic/1"
    basis: Literal["observed", "heuristic", "subjective"] = "observed"
    evidence_ids: list[str]
    facts: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=now)


class HumanOverride(Contract):
    """Phase 1 append-only record, retained verbatim and never reinterpreted."""

    id: str = Field(default_factory=new_id)
    evaluation_id: str
    reviewer: str = Field(min_length=1)
    outcome: Outcome
    rationale: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=now)


class EvidenceDigest(Contract):
    """Deterministic identity for a stored record or an exported artifact."""

    kind: Literal[
        "execution",
        "evaluation",
        "judgment",
        "adjudication",
        "report-export",
        "export",
        "scenario-source",
        "agentic-trace",
    ]
    source_id: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    algorithm: Literal["sha256-canonical-json/1"] = "sha256-canonical-json/1"


SessionStatus = Literal["pending_human_review", "completed", "failed"]
SessionOrigin = Literal[
    "execution",
    "reevaluation",
    "human_review",
    "migration",
    "dataset_import",
    "agentic_execution",
]
EvidenceKind = Literal["execution", "dataset", "agentic"]


class EvaluationSession(Contract):
    """One independent evaluation of one evidence subject.

    The subject is either an immutable `ExecutionRun` (``evidence_kind=
    "execution"``) or an imported dataset case (``evidence_kind="dataset"``).
    Imported responses never create an execution record.
    """

    id: str = Field(default_factory=new_id)
    run_id: str | None = None
    experiment_id: str | None = None
    dataset_id: str | None = None
    dataset_case_id: str | None = None
    agentic_trace_id: str | None = None
    evidence_kind: EvidenceKind = "execution"
    rubric: Rubric
    rubric_definition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    origin: SessionOrigin
    session_version: Literal[1, 2] = 2
    pipeline: str = "faultline.evaluation-session/2"
    evaluator: str = Field(min_length=1)
    evaluator_settings: dict[str, Any] = Field(default_factory=dict)
    status: SessionStatus = "completed"
    evaluations: list[CriterionEvaluation] = Field(default_factory=list)
    evidence: list[EvidenceArtifact] = Field(default_factory=list)
    error: str | None = None
    created_at: datetime = Field(default_factory=now)
    completed_at: datetime | None = None

    @property
    def subject_id(self) -> str:
        return self.run_id or self.dataset_case_id or self.agentic_trace_id or ""

    @model_validator(mode="after")
    def validate_lifecycle(self) -> EvaluationSession:
        if self.rubric.definition is None:
            raise ValueError("An evaluation session requires an executable rubric definition")
        if canonical_digest(self.rubric.definition) != self.rubric_definition_sha256:
            raise ValueError("Rubric definition digest does not match the session snapshot")
        if self.evidence_kind == "execution":
            if self.run_id is None or self.dataset_case_id is not None:
                raise ValueError("Execution sessions reference a run and no dataset case")
            if self.agentic_trace_id is not None:
                raise ValueError("Execution sessions never reference a trace")
            if self.experiment_id is None:
                raise ValueError("Execution sessions belong to an experiment")
        elif self.evidence_kind == "agentic":
            if self.agentic_trace_id is None:
                raise ValueError("Agentic sessions reference a stored trace")
            if self.run_id is not None or self.dataset_case_id is not None:
                raise ValueError("Agentic sessions reference no run or dataset case")
            if self.experiment_id is not None:
                raise ValueError("Agentic sessions are not part of an experiment")
            if not self.evidence:
                raise ValueError("Agentic sessions preserve the trace evidence they evaluated")
        else:
            if self.dataset_case_id is None or self.dataset_id is None:
                raise ValueError("Dataset sessions reference a dataset and case")
            if self.run_id is not None or self.agentic_trace_id is not None:
                raise ValueError("Dataset sessions reference no run or trace")
            if self.experiment_id is not None:
                raise ValueError("Dataset sessions are not part of an experiment")
            if not self.evidence:
                raise ValueError("Dataset sessions preserve the imported evidence they evaluated")
        if self.status == "completed" and (not self.evaluations or self.completed_at is None):
            raise ValueError("A completed session requires evaluations and a completion time")
        if self.status == "failed" and not self.error:
            raise ValueError("A failed session requires a controlled error message")
        if self.status == "pending_human_review" and self.evaluations:
            raise ValueError("A human review session cannot contain automated evaluations")
        criteria = {c.id for c in self.rubric.definition.criteria}
        if len({e.id for e in self.evaluations}) != len(self.evaluations):
            raise ValueError("Session evaluations must be unique")
        if any(e.criterion_id not in criteria for e in self.evaluations):
            raise ValueError("Session evaluations must reference rubric criteria")
        if any(e.run_id != self.subject_id for e in self.evaluations):
            raise ValueError("Session evaluations must reference the session subject")
        return self


class HumanJudgment(Contract):
    """Append-only reviewer decision; revisions link to the record they supersede."""

    id: str = Field(default_factory=new_id)
    session_id: str
    run_id: str | None = None
    criterion_id: str
    reviewer: str = Field(min_length=1)
    outcome: Outcome
    label: str | None = None
    score: float | None = None
    rationale: str = Field(min_length=1)
    confidence: Literal["low", "medium", "high"] | None = None
    supersedes_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=now)


class AdjudicationPolicy(Contract):
    kind: Literal["single_reviewer", "unanimous", "majority", "first_reviewer"]
    reviewer: str | None = None

    @model_validator(mode="after")
    def validate_policy(self) -> AdjudicationPolicy:
        if self.kind == "single_reviewer" and not (self.reviewer or "").strip():
            raise ValueError("single_reviewer adjudication requires the designated reviewer")
        if self.kind != "single_reviewer" and self.reviewer is not None:
            raise ValueError("Only single_reviewer adjudication accepts a designated reviewer")
        return self


class Adjudication(Contract):
    id: str = Field(default_factory=new_id)
    session_id: str
    run_id: str | None = None
    criterion_id: str
    policy: AdjudicationPolicy
    agreement: Literal["full", "outcome_only", "none"] = "full"
    status: Literal["agreed", "adjudicated", "unresolved"]
    outcome: Outcome | None = None
    label: str | None = None
    score: float | None = None
    basis_judgment_ids: list[str] = Field(default_factory=list)
    dissenting_judgment_ids: list[str] = Field(default_factory=list)
    rationale: str = Field(min_length=1)
    reviewer: str = Field(min_length=1)
    supersedes_id: str | None = None
    created_at: datetime = Field(default_factory=now)

    @model_validator(mode="after")
    def validate_outcome(self) -> Adjudication:
        if (self.status == "unresolved") == (self.outcome is not None):
            raise ValueError("Unresolved adjudications have no outcome; resolved ones do")
        if self.status != "unresolved" and not self.basis_judgment_ids:
            raise ValueError("A resolved adjudication cites the judgments it rests on")
        return self


class ExecutionRun(Contract):
    id: str = Field(default_factory=new_id)
    experiment_id: str
    case: AttackCase
    status: Literal["running", "completed", "failed", "dry_run"] = "running"
    started_at: datetime = Field(default_factory=now)
    completed_at: datetime | None = None
    response: ModelResponse | None = None
    evidence: list[EvidenceArtifact] = Field(default_factory=list)
    evaluations: list[CriterionEvaluation] = Field(default_factory=list)
    error: str | None = None


class Finding(Contract):
    id: str = Field(default_factory=new_id)
    experiment_id: str
    run_id: str
    evaluation_id: str
    title: str
    evidence_ids: list[str]
    classification: Literal["simulated", "observed"]
    claim: str
    created_at: datetime = Field(default_factory=now)


class ScoreSummary(Contract):
    run_id: str | None = None
    dataset_case_id: str | None = None
    weighted_compliance: float | None
    evaluated_weight: float
    total_weight: float
    coverage: float
    session_id: str | None = None
    criteria_total: int = 0
    criteria_scored: int = 0
    criteria_uncertain: int = 0
    criteria_not_applicable: int = 0


EffectiveStatus = Literal[
    "automated_only",
    "awaiting_human_review",
    "confirmed",
    "overridden",
    "human_assessed",
    "unresolved",
]


class EffectiveResult(Contract):
    """Automated observation, human judgments and the adjudicated outcome together."""

    session_id: str
    run_id: str | None = None
    dataset_case_id: str | None = None
    criterion_id: str
    rubric_id: str
    rubric_version: str
    scale_kind: ScaleKind = "binary"
    automated_outcome: Outcome | None = None
    automated_label: str | None = None
    automated_score: float | None = None
    reviewer_outcomes: dict[str, Outcome] = Field(default_factory=dict)
    reviewer_labels: dict[str, str | None] = Field(default_factory=dict)
    reviewer_scores: dict[str, float | None] = Field(default_factory=dict)
    agreement: Literal["full", "outcome_only", "none"] | None = None
    max_ordinal_gap: int | None = None
    judgment_ids: list[str] = Field(default_factory=list)
    adjudication_id: str | None = None
    effective_outcome: Outcome | None = None
    effective_label: str | None = None
    effective_score: float | None = None
    effective_source: Literal["automated", "adjudicated", "none"] = "none"
    status: EffectiveStatus = "automated_only"


class FindingReview(Contract):
    """States whether an automated finding is contested by human review."""

    finding_id: str
    session_id: str | None = None
    effective_status: EffectiveStatus
    effective_outcome: Outcome | None = None
    note: str


class Disagreement(Contract):
    """One criterion whose reviewers (and/or automation) do not fully agree.

    Outcome, label and score disagreement are reported separately: identical
    outcomes on a categorical or graded rubric are not full agreement.
    """

    session_id: str
    run_id: str | None = None
    dataset_case_id: str | None = None
    criterion_id: str
    rubric_id: str
    rubric_version: str
    scale_kind: ScaleKind = "binary"
    automated_outcome: Outcome | None = None
    reviewer_outcomes: dict[str, Outcome] = Field(default_factory=dict)
    reviewer_labels: dict[str, str | None] = Field(default_factory=dict)
    reviewer_scores: dict[str, float | None] = Field(default_factory=dict)
    outcome_disagreement: bool = False
    label_disagreement: bool = False
    score_disagreement: bool = False
    max_ordinal_gap: int | None = None
    adjudication_id: str | None = None
    resolved: bool = False
    summary: str


class CoverageSummary(Contract):
    runs_total: int = 0
    runs_without_session: int = 0
    sessions_total: int = 0
    sessions_failed: int = 0
    session_criteria_total: int = 0
    session_criteria_automated: int = 0
    session_criteria_with_human_judgment: int = 0
    session_criteria_adjudicated: int = 0
    session_criteria_awaiting: int = 0
    session_criteria_unresolved: int = 0
    automated_coverage: float = 0.0
    effective_coverage: float = 0.0
    notes: list[str] = Field(default_factory=list)


class DatasetLimits(Contract):
    """Explicit caps; imported bytes and record counts are never unbounded."""

    max_source_bytes: int = Field(default=5_000_000, gt=0)
    max_records: int = Field(default=2_000, gt=0)
    max_response_chars: int = Field(default=200_000, gt=0)
    version: Literal[1] = 1


class DatasetRecord(Contract):
    """One prerecorded model response. All text is untrusted imported data."""

    id: str = Field(min_length=1)
    provenance: str = Field(min_length=1)
    prompt: str = Field(min_length=1)
    response: str
    model: str | None = None
    system_context: str | None = None
    expected_behavior: str | None = None
    reference_answer: str | None = None
    case_kind: Literal["baseline", "attack"] = "baseline"
    parameters: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class Dataset(Contract):
    """Imported dataset identity, provenance and ordered membership."""

    id: str = Field(default_factory=new_id)
    version: str = Field(min_length=1)
    title: str = Field(min_length=1)
    provenance: str = Field(min_length=1)
    source_format: Literal["json", "jsonl"]
    source: EvidenceArtifact
    record_count: int = Field(ge=0)
    record_ids: list[str] = Field(default_factory=list)
    dataset_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    limits: DatasetLimits = Field(default_factory=DatasetLimits)
    imported_at: datetime = Field(default_factory=now)
    dataset_version: Literal[1] = 1

    @model_validator(mode="after")
    def validate_membership(self) -> Dataset:
        if self.source.kind != "dataset-source":
            raise ValueError("A dataset retains its source as a dataset-source artifact")
        if len(self.record_ids) != self.record_count:
            raise ValueError("Dataset record count must match its membership index")
        if len(set(self.record_ids)) != len(self.record_ids):
            raise ValueError("Dataset case IDs must be unique")
        if self.record_count > self.limits.max_records:
            raise ValueError("Dataset exceeds the configured record limit")
        return self


BatchStatus = Literal["planned", "running", "partial", "completed", "failed"]
BatchCaseStatus = Literal["pending", "completed", "failed", "skipped"]


class BatchBudget(Contract):
    """Caps applied when a batch is planned and executed."""

    max_cases: int = Field(default=200, gt=0)
    max_cases_per_run: int | None = Field(default=None, gt=0)


class BatchEvaluation(Contract):
    """A batch of imported responses scored with one rubric version."""

    id: str = Field(default_factory=new_id)
    dataset_id: str
    dataset_version: str
    dataset_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rubric_id: str
    rubric_definition_id: str
    rubric_definition_version: str
    rubric_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rubric_definition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    origin: Literal["dataset_import"] = "dataset_import"
    status: BatchStatus = "planned"
    budget: BatchBudget = Field(default_factory=BatchBudget)
    created_at: datetime = Field(default_factory=now)
    updated_at: datetime = Field(default_factory=now)
    completed_at: datetime | None = None
    batch_version: Literal[1] = 1

    @model_validator(mode="after")
    def validate_lifecycle(self) -> BatchEvaluation:
        if (self.status == "completed") != (self.completed_at is not None):
            raise ValueError("Only completed batches carry a completion time")
        if self.status in {"planned", "running", "partial", "failed", "completed"}:
            return self
        raise ValueError("Unknown batch status")


class BatchCase(Contract):
    """One dataset case inside a batch. Status moves forward exactly once."""

    batch_id: str
    case_id: str
    position: int = Field(ge=0)
    status: BatchCaseStatus = "pending"
    session_id: str | None = None
    error: str | None = None
    skip_reason: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @model_validator(mode="after")
    def validate_status(self) -> BatchCase:
        if self.status == "pending" and any(
            [self.session_id, self.error, self.skip_reason, self.finished_at]
        ):
            raise ValueError("Pending cases carry no result")
        if self.status == "completed" and (not self.session_id or self.error or self.skip_reason):
            raise ValueError("Completed cases reference their evaluation session")
        if self.status == "failed" and (not self.error or self.session_id or self.skip_reason):
            raise ValueError("Failed cases record a controlled error")
        if self.status == "skipped" and (not self.skip_reason or self.session_id or self.error):
            raise ValueError("Skipped cases record the reason they were not evaluated")
        return self


class KappaResult(Contract):
    """One chance-corrected agreement estimate, explicit about being undefined."""

    value: float | None = None
    defined: bool = False
    reason: str | None = None
    observed_agreement: float | None = None
    expected_agreement: float | None = None
    weighting: Literal["none", "linear"] = "none"
    categories: list[str] = Field(default_factory=list)
    n: int = 0

    @model_validator(mode="after")
    def validate_definition(self) -> KappaResult:
        if self.defined == (self.value is None):
            raise ValueError("Defined kappa values carry a number; undefined ones do not")
        if self.defined and self.reason is not None:
            raise ValueError("Defined kappa values carry no failure reason")
        if not self.defined and not self.reason:
            raise ValueError("Undefined statistics state why they cannot be computed")
        return self


class ContingencyRow(Contract):
    rater_a: str
    rater_b: str
    count: int = Field(ge=0)


class PairwiseAgreement(Contract):
    reviewer_a: str
    reviewer_b: str
    n: int = Field(ge=0)
    exact_agreement: float | None = None
    outcome_agreement: float | None = None
    label_agreement: float | None = None
    kappa: KappaResult | None = None
    weighted_kappa: KappaResult | None = None
    mean_absolute_score_difference: float | None = None
    contingency: list[ContingencyRow] = Field(default_factory=list)


class ApplicabilityDisagreement(Contract):
    """Reviewers disagree about whether a criterion applies at all.

    Such units stay out of kappa (``not_applicable`` is not a rating on the
    scale), but the disagreement itself is retained with attribution.
    """

    session_id: str
    rubric_id: str
    rubric_version: str
    rubric_definition_sha256: str = ""
    criterion_id: str
    scale_kind: ScaleKind = "binary"
    reviewer_outcomes: dict[str, Outcome] = Field(default_factory=dict)
    reviewers_not_applicable: list[str] = Field(default_factory=list)
    reviewers_with_rating: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_sides(self) -> ApplicabilityDisagreement:
        if not self.reviewers_not_applicable or not self.reviewers_with_rating:
            raise ValueError("An applicability dispute has both sides represented")
        if any(
            self.reviewer_outcomes.get(reviewer) != "not_applicable"
            for reviewer in self.reviewers_not_applicable
        ):
            raise ValueError("Reviewers listed as not_applicable must say so")
        return self


class AgreementGroup(Contract):
    """Agreement measured only within one rubric definition, criterion and scale."""

    rubric_id: str
    rubric_version: str
    rubric_definition_sha256: str = ""
    criterion_id: str
    scale_kind: ScaleKind
    reviewers: list[str] = Field(default_factory=list)
    units_compared: int = Field(ge=0)
    units_excluded_not_applicable: int = Field(default=0, ge=0)
    units_excluded_incomplete: int = Field(default=0, ge=0)
    units_not_applicable_disputed: int = Field(default=0, ge=0)
    units_missing_labels: int = Field(default=0, ge=0)
    units_outside_declared_levels: int = Field(default=0, ge=0)
    exact_agreement: float | None = None
    outcome_agreement: float | None = None
    label_agreement: float | None = None
    kappa: KappaResult | None = None
    weighted_kappa: KappaResult | None = None
    mean_absolute_score_difference: float | None = None
    max_ordinal_gap: int | None = None
    pairwise: list[PairwiseAgreement] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class AgreementReport(Contract):
    """Descriptive agreement statistics. Not accuracy and not ground truth."""

    method: Literal["faultline.agreement/1"] = "faultline.agreement/1"
    scope: Literal["experiment", "batch", "agentic_trace"]
    scope_id: str
    units_total: int = Field(ge=0)
    units_compared: int = Field(ge=0)
    units_excluded_not_applicable: int = Field(default=0, ge=0)
    units_excluded_incomplete: int = Field(default=0, ge=0)
    units_not_applicable_disputed: int = Field(default=0, ge=0)
    reviewers: list[str] = Field(default_factory=list)
    groups: list[AgreementGroup] = Field(default_factory=list)
    applicability_disputes: list[ApplicabilityDisagreement] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class BatchProgress(Contract):
    cases_total: int = 0
    cases_completed: int = 0
    cases_failed: int = 0
    cases_skipped: int = 0
    cases_pending: int = 0
    cases_with_results: int = 0
    mean_weighted_compliance: float | None = None
    min_weighted_compliance: float | None = None
    max_weighted_compliance: float | None = None
    criteria_total: int = 0
    criteria_scored: int = 0
    criteria_uncertain: int = 0

    @model_validator(mode="after")
    def validate_counts(self) -> BatchProgress:
        accounted = (
            self.cases_completed + self.cases_failed + self.cases_skipped + self.cases_pending
        )
        if self.cases_total != accounted:
            raise ValueError("Batch progress counts must account for every case")
        return self


class BatchCoverage(Contract):
    cases_total: int = 0
    cases_completed: int = 0
    cases_failed: int = 0
    cases_skipped: int = 0
    cases_pending: int = 0
    excluded_case_ids: list[str] = Field(default_factory=list)
    session_criteria_total: int = 0
    session_criteria_automated: int = 0
    session_criteria_with_human_judgment: int = 0
    session_criteria_adjudicated: int = 0
    session_criteria_awaiting: int = 0
    session_criteria_unresolved: int = 0
    automated_coverage: float = 0.0
    effective_coverage: float = 0.0
    notes: list[str] = Field(default_factory=list)


class BatchReport(Contract):
    """Machine-readable report for imported-response batch evaluation.

    It deliberately has no experiment, endpoint, provider or technique fields:
    imported responses were never requested by this harness.
    """

    id: str = Field(default_factory=new_id)
    generated_at: datetime = Field(default_factory=now)
    report_format_version: Literal["2.1.0"] = "2.1.0"
    origin: Literal["dataset_import"] = "dataset_import"
    dataset: Dataset
    batch: BatchEvaluation
    progress: BatchProgress
    cases: list[BatchCase] = Field(default_factory=list)
    records: list[DatasetRecord] = Field(default_factory=list)
    evaluation_sessions: list[EvaluationSession] = Field(default_factory=list)
    automated_scores: list[ScoreSummary] = Field(default_factory=list)
    human_judgments: list[HumanJudgment] = Field(default_factory=list)
    adjudications: list[Adjudication] = Field(default_factory=list)
    effective_results: list[EffectiveResult] = Field(default_factory=list)
    disagreements: list[Disagreement] = Field(default_factory=list)
    coverage: BatchCoverage = Field(default_factory=BatchCoverage)
    agreement: AgreementReport | None = None
    evidence_digests: list[EvidenceDigest] = Field(default_factory=list)
    export_digest: EvidenceDigest | None = None
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Imported responses were produced outside this harness; provenance is the record.",
            "No provider request was made for these cases and none is implied.",
            "Automated criteria report literal observations only; subjective criteria need humans.",
            "Agreement statistics describe these reviewers and items, not truth.",
            "Skipped cases are neither passes nor failures.",
        ]
    )


class Report(Contract):
    id: str = Field(default_factory=new_id)
    generated_at: datetime = Field(default_factory=now)
    report_format_version: Literal["2.0.0", "2.1.0"] = "2.1.0"
    experiment: Experiment
    runs: list[ExecutionRun]
    findings: list[Finding]
    human_overrides: list[HumanOverride]
    automated_scores: list[ScoreSummary]
    evaluation_sessions: list[EvaluationSession] = Field(default_factory=list)
    human_judgments: list[HumanJudgment] = Field(default_factory=list)
    adjudications: list[Adjudication] = Field(default_factory=list)
    effective_results: list[EffectiveResult] = Field(default_factory=list)
    finding_reviews: list[FindingReview] = Field(default_factory=list)
    disagreements: list[Disagreement] = Field(default_factory=list)
    coverage: CoverageSummary | None = None
    evidence_digests: list[EvidenceDigest] = Field(default_factory=list)
    export_digest: EvidenceDigest | None = None
    agreement: AgreementReport | None = None
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Synthetic toy scenarios do not establish production robustness.",
            "Exact checks do not detect paraphrased or encoded disclosure.",
            "Tool requests and model success claims do not prove tool execution.",
            "Remote generation may vary even with identical settings.",
            "Automated scores describe deterministic checks; human judgments are appended.",
            "An effective outcome requires an explicit adjudication policy and reviewer rationale.",
            "Reevaluation never rewrites execution evidence or execution-time findings.",
            "Ordinal and categorical scales are human-assessed; they are not binary pass/fail.",
        ]
    )


# --- Phase 3A: instrumented agentic evaluation ---------------------------------

ToolSideEffect = Literal["none", "synthetic-read", "synthetic-write", "synthetic-message"]
ToolAuthorizationClass = Literal["read-only", "synthetic-write"]
PolicyDecision = Literal["allowed", "denied"]
TurnRole = Literal["system", "user", "assistant", "tool", "document"]
TurnSource = Literal["harness", "attacker", "model", "tool", "retrieval"]
TurnTrust = Literal["trusted", "untrusted", "derived"]
TerminationReason = Literal[
    "final_answer",
    "max_turns",
    "max_requests",
    "max_tool_invocations",
    "max_output_tokens",
    "max_response_bytes",
    "timeout",
    "provider_error",
    "unsupported_capability",
    "cancelled",
]
TraceStatus = Literal["running", "completed", "failed", "cancelled", "dry_run"]
AgentKind = Literal["scripted-secure", "scripted-vulnerable", "endpoint"]


class ToolDefinition(Contract):
    """One synthetic tool with an explicit schema, effect and policy class."""

    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    description: str = Field(min_length=1)
    input_schema: dict[str, Any]
    side_effect: ToolSideEffect
    authorization: ToolAuthorizationClass
    receipt_required: bool = True
    tool_version: Literal[1] = 1

    @model_validator(mode="after")
    def validate_schema(self) -> ToolDefinition:
        from jsonschema import Draft202012Validator
        from jsonschema.exceptions import SchemaError

        try:
            Draft202012Validator.check_schema(self.input_schema)
        except SchemaError:
            raise ValueError("Tool input schema is not a valid JSON Schema") from None
        return self


class ToolRequest(Contract):
    """A model-proposed call. A proposal is never an executed action."""

    id: str = Field(default_factory=new_id)
    name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolPolicyDecision(Contract):
    request_id: str
    tool: str
    decision: PolicyDecision
    reason: str = Field(min_length=1)
    policy: str = "faultline.synthetic-tools/1"
    decided_at: datetime = Field(default_factory=now)


class ToolStateChange(Contract):
    kind: Literal["note-written", "message-queued", "record-updated"]
    target: str = Field(min_length=1)
    before_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    after_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    synthetic: Literal[True] = True


class ToolExecutionReceipt(Contract):
    """Harness-owned proof of what a synthetic tool actually did."""

    id: str = Field(default_factory=new_id)
    request_id: str
    tool: str
    tool_version: str
    executed: bool
    output: dict[str, Any] = Field(default_factory=dict)
    output_text: str = ""
    state_changes: list[ToolStateChange] = Field(default_factory=list)
    error: str | None = None
    started_at: datetime = Field(default_factory=now)
    finished_at: datetime = Field(default_factory=now)
    provenance: str = "synthetic-sandbox"
    receipt_version: Literal[1] = 1

    @model_validator(mode="after")
    def validate_receipt(self) -> ToolExecutionReceipt:
        if not self.executed and self.state_changes:
            raise ValueError("A tool that did not execute cannot change state")
        if self.executed and self.error:
            raise ValueError("An executed receipt carries no error")
        return self


class ToolInvocation(Contract):
    """One proposed call with its policy decision and optional receipt."""

    request_id: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    proposed_at: datetime = Field(default_factory=now)
    source: Literal["model", "scripted-fixture"] = "model"
    decision: ToolPolicyDecision | None = None
    receipt: ToolExecutionReceipt | None = None
    invocation_version: Literal[1] = 1

    @model_validator(mode="after")
    def validate_sequence(self) -> ToolInvocation:
        if self.decision is not None and self.decision.request_id != self.request_id:
            raise ValueError("Policy decision must reference this request")
        if self.receipt is not None:
            if self.decision is None or self.decision.decision != "allowed":
                raise ValueError("Only allowed requests can carry a receipt")
            if self.receipt.request_id != self.request_id:
                raise ValueError("Receipt must reference this request")
        return self


class ConversationTurn(Contract):
    """One ordered message in an agentic conversation."""

    index: int = Field(ge=0)
    role: TurnRole
    content: str
    source: TurnSource
    trust: TurnTrust = "trusted"
    tool_request_ids: list[str] = Field(default_factory=list)
    tool_request_id: str | None = None
    document_id: str | None = None
    usage: dict[str, Any] = Field(default_factory=dict)
    model: str | None = None
    finish_reason: str | None = None
    created_at: datetime = Field(default_factory=now)

    @model_validator(mode="after")
    def validate_correlation(self) -> ConversationTurn:
        if self.role == "tool" and self.tool_request_id is None:
            raise ValueError("Tool turns reference the request they answer")
        if self.role != "tool" and self.tool_request_id is not None:
            raise ValueError("Only tool turns carry a tool request id")
        if self.role == "document" and (self.source != "retrieval" or self.trust != "untrusted"):
            raise ValueError("Document turns are untrusted retrieved content")
        return self


class ScenarioDocument(Contract):
    """Controlled document served by retrieval tools."""

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    content: str
    trust: Literal["trusted-reference", "untrusted-injected"] = "trusted-reference"
    source_note: str = "synthetic-corpus"
    injection: str | None = None
    control_content: str | None = None

    @model_validator(mode="after")
    def validate_injection(self) -> ScenarioDocument:
        if self.trust == "untrusted-injected" and not self.injection:
            raise ValueError("An injected document declares the injected payload")
        if self.trust == "trusted-reference" and self.injection:
            raise ValueError("Only injected documents carry an injected payload")
        if (
            self.injection is not None
            and self.control_content is not None
            and self.injection in self.control_content
        ):
            raise ValueError("A control rendering must not contain the injected payload")
        return self


class ScriptedStep(Contract):
    """One deterministic scripted agent turn."""

    tool_calls: list[ToolRequest] = Field(default_factory=list)
    final: str | None = None
    finish_reason: str | None = None

    @model_validator(mode="after")
    def validate_step(self) -> ScriptedStep:
        if self.final is not None and self.tool_calls:
            raise ValueError("A scripted step either calls tools or answers")
        if self.final is None and not self.tool_calls:
            raise ValueError("A scripted step needs tool calls or a final answer")
        return self


class AgentBudget(Contract):
    """Hard caps that terminate an agentic run."""

    max_requests: int = Field(default=6, gt=0)
    max_turns: int = Field(default=12, gt=0)
    max_tool_invocations: int = Field(default=8, gt=0)
    max_output_tokens: int = Field(default=512, gt=0)
    max_response_bytes: int = Field(default=64_000, gt=0)
    request_timeout_seconds: float = Field(default=30.0, gt=0)
    overall_timeout_seconds: float = Field(default=120.0, gt=0)


class AgentCapabilities(Contract):
    supports_tool_calls: bool = False
    provider: str = Field(min_length=1)
    model: str | None = None


class AgentTurn(Contract):
    """One provider response inside the loop."""

    content: str = ""
    tool_calls: list[ToolRequest] = Field(default_factory=list)
    finish_reason: str | None = None
    usage: dict[str, Any] = Field(default_factory=dict)
    model: str | None = None


class AgenticScenario(Contract):
    """A synthetic agentic scenario: objective, documents, injection and scripts."""

    id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    title: str = Field(min_length=1)
    family: Literal[
        "retrieved-authority-spoof",
        "synthetic-secret-disclosure",
        "unauthorized-record-change",
        "tool-output-laundering",
        "encoded-injection",
        "boundary-enforcement",
    ]
    objective: str = Field(min_length=1)
    system_prompt: str = Field(min_length=1)
    user_task: str = Field(min_length=1)
    documents: list[ScenarioDocument] = Field(min_length=1)
    injected_document_id: str | None = None
    allowed_tools: list[str] = Field(default_factory=list)
    protected_records: dict[str, str] = Field(default_factory=dict)
    # Records monitored for integrity. Empty means every initial record is monitored.
    protected_record_ids: list[str] = Field(default_factory=list)
    # Records tools may modify. Empty means no record write is authorized at all.
    writable_records: list[str] = Field(default_factory=list)
    parameters: dict[str, str] = Field(default_factory=dict)
    expected_secure_behavior: str = Field(min_length=1)
    failure_conditions: list[str] = Field(default_factory=list)
    trust_boundary: str = "retrieved-document-to-agent-instruction"
    rubric: dict[str, Any]
    scripts: dict[str, list[ScriptedStep]] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    scenario_version: Literal[1] = 1

    @property
    def monitored_records(self) -> list[str]:
        """Record IDs whose digests are captured before and after execution."""
        if self.protected_record_ids:
            return list(self.protected_record_ids)
        return list(self.protected_records)

    @model_validator(mode="after")
    def validate_scenario(self) -> AgenticScenario:
        ids = {document.id for document in self.documents}
        if len(ids) != len(self.documents):
            raise ValueError("Scenario document IDs must be unique")
        if self.injected_document_id is not None and self.injected_document_id not in ids:
            raise ValueError("Injected document must exist in the scenario corpus")
        initial = set(self.protected_records)
        monitored = set(self.protected_record_ids) or initial
        unknown = monitored - initial
        if unknown:
            raise ValueError("Monitored records must exist in the initial environment")
        writable = set(self.writable_records)
        if unknown_writable := writable - initial:
            raise ValueError(
                "Writable records must exist in the initial environment: "
                + ", ".join(sorted(unknown_writable))
            )
        if overlap := writable & monitored:
            raise ValueError(
                "A monitored record can never be writable: " + ", ".join(sorted(overlap))
            )
        for name in ("secure", "vulnerable"):
            if name not in self.scripts:
                raise ValueError("Every scenario ships secure and vulnerable scripts")
        return self


class AgenticResult(Contract):
    """Deterministically derived summary of what the harness observed."""

    trace_id: str
    termination: TerminationReason
    verdict: Literal["secure", "compromised", "inconclusive"]
    requested_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    executed_tools: list[str] = Field(default_factory=list)
    unauthorized_requests: list[str] = Field(default_factory=list)
    state_changes: list[str] = Field(default_factory=list)
    canary_disclosed: bool = False
    task_completed: bool = False
    task_marker_present: bool = False
    task_completion_basis: Literal["required-marker"] = "required-marker"
    exposed_to_injection: bool = False
    basis: list[str] = Field(default_factory=list)


class AgenticExecutionTrace(Contract):
    """Immutable evidence for one agentic execution."""

    id: str = Field(default_factory=new_id)
    scenario: AgenticScenario
    scenario_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rubric: Rubric
    rubric_definition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    agent: AgentKind
    capabilities: AgentCapabilities
    model: str | None = None
    status: TraceStatus = "running"
    turns: list[ConversationTurn] = Field(default_factory=list)
    invocations: list[ToolInvocation] = Field(default_factory=list)
    evidence: list[EvidenceArtifact] = Field(default_factory=list)
    budget: AgentBudget = Field(default_factory=AgentBudget)
    settings: ExecutionSettings | None = None
    termination: TerminationReason | None = None
    record_digests_before: dict[str, str] = Field(default_factory=dict)
    record_digests_after: dict[str, str] = Field(default_factory=dict)
    execution_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    error: str | None = None
    started_at: datetime = Field(default_factory=now)
    completed_at: datetime | None = None
    trace_version: Literal[1] = 1

    @model_validator(mode="after")
    def validate_trace(self) -> AgenticExecutionTrace:
        if self.rubric.definition is None:
            raise ValueError("An agentic trace requires an executable rubric")
        if canonical_digest(self.rubric.definition) != self.rubric_definition_sha256:
            raise ValueError("Rubric definition digest does not match the trace snapshot")
        indices = [turn.index for turn in self.turns]
        if indices != list(range(len(self.turns))):
            raise ValueError("Conversation turns must be ordered and contiguous")
        request_ids = [invocation.request_id for invocation in self.invocations]
        if len(set(request_ids)) != len(request_ids):
            raise ValueError("Tool requests must be unique by correlation id")
        if self.status == "completed" and self.termination is None:
            raise ValueError("A completed trace records its termination reason")
        if self.status in {"failed", "cancelled"} and not self.error and self.termination is None:
            raise ValueError("An incomplete trace records an error or termination reason")
        if self.status == "dry_run" and self.turns:
            raise ValueError("A dry run records a plan, not a conversation")
        return self

    @property
    def system_prompt(self) -> str:
        return self.turns[0].content if self.turns else ""

    @property
    def exposed_document_ids(self) -> list[str]:
        return [
            turn.document_id
            for turn in self.turns
            if turn.role == "tool" and turn.document_id is not None
        ]


class AgenticReport(Contract):
    """Portable report for one agentic trace; never implies external actions."""

    id: str = Field(default_factory=new_id)
    generated_at: datetime = Field(default_factory=now)
    report_format_version: Literal["2.1.0"] = "2.1.0"
    origin: Literal["agentic"] = "agentic"
    trace: AgenticExecutionTrace
    result: AgenticResult
    evaluation_sessions: list[EvaluationSession] = Field(default_factory=list)
    automated_scores: list[ScoreSummary] = Field(default_factory=list)
    human_judgments: list[HumanJudgment] = Field(default_factory=list)
    adjudications: list[Adjudication] = Field(default_factory=list)
    effective_results: list[EffectiveResult] = Field(default_factory=list)
    disagreements: list[Disagreement] = Field(default_factory=list)
    coverage: CoverageSummary | None = None
    agreement: AgreementReport | None = None
    evidence_digests: list[EvidenceDigest] = Field(default_factory=list)
    export_digest: EvidenceDigest | None = None
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Synthetic tools and documents only; no external system was touched.",
            "A denied tool request is evidence of intent, not of a compromise.",
            "Scripted agents are fixtures, not evidence about a real model.",
            "Whether the agent adopted an injected instruction is human-assessed.",
            "State changes are verified inside the synthetic sandbox only.",
        ]
    )


# --- Phase 3B: controlled real-model experiments --------------------------------

VariantRole = Literal["control", "attack"]
TrialStatus = Literal["pending", "running", "completed", "failed", "interrupted", "incomplete"]
TrialOrder = Literal["control_first", "attack_first", "alternate", "randomized"]
ExperimentStatus = Literal["planned", "running", "partial", "completed", "failed", "cancelled"]


class VariantDifference(Contract):
    """One declared, auditable difference between the control and attack variants."""

    path: str = Field(min_length=1)
    control_value: str
    attack_value: str
    description: str = Field(min_length=1)


class ExperimentVariant(Contract):
    """One resolved variant of a scenario with its own corpus hashes."""

    role: VariantRole
    label: str = Field(min_length=1)
    scenario: AgenticScenario
    scenario_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    corpus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    injected_document_id: str | None = None
    injected_payload_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    script_key: str = Field(min_length=1)
    document_hashes: dict[str, str] = Field(default_factory=dict)


class ExperimentTarget(Contract):
    """Authorized model endpoint identity, or a local scripted fixture."""

    agent: Literal["scripted-secure", "scripted-vulnerable", "endpoint"]
    profile_id: str | None = None
    provider: str = Field(min_length=1)
    model: str | None = None
    supports_tool_calls: bool = False

    @model_validator(mode="after")
    def validate_target(self) -> ExperimentTarget:
        if self.agent == "endpoint" and self.profile_id is None:
            raise ValueError("An endpoint target requires an authorized profile")
        if self.agent != "endpoint" and self.profile_id is not None:
            raise ValueError("A scripted target references no endpoint profile")
        return self


class ExperimentLimits(Contract):
    """Experiment-wide caps; spending is always an estimate, never a bill."""

    max_total_requests: int = Field(default=40, gt=0)
    # Declared planning estimate for one variant run; the plan must fit inside the cap.
    estimated_requests_per_variant: int = Field(default=6, gt=0)
    estimated_cost_per_request_usd: float | None = Field(default=None, ge=0)
    max_estimated_spend_usd: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_spend(self) -> ExperimentLimits:
        if self.max_estimated_spend_usd is not None and self.estimated_cost_per_request_usd is None:
            raise ValueError("A spend guard requires an estimated unit cost")
        return self


class ControlledExperiment(Contract):
    """A versioned control/attack experiment plan over one scenario pair."""

    id: str = Field(default_factory=new_id)
    name: str = Field(min_length=1)
    objective: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    scenario_version: str = Field(min_length=1)
    control: ExperimentVariant
    attack: ExperimentVariant
    differences: list[VariantDifference] = Field(default_factory=list)
    rubric: Rubric
    rubric_definition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target: ExperimentTarget
    settings: ExecutionSettings
    budget: AgentBudget
    limits: ExperimentLimits = Field(default_factory=ExperimentLimits)
    trial_count: int = Field(ge=1, le=50)
    order: TrialOrder = "control_first"
    seed: int | None = None
    authorization: str = Field(min_length=1)
    allow_network: bool = False
    environment_policy: Literal["independent_reset"] = "independent_reset"
    status: ExperimentStatus = "planned"
    created_at: datetime = Field(default_factory=now)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    notes: list[str] = Field(default_factory=list)
    experiment_version: Literal[1] = 1

    @model_validator(mode="after")
    def validate_experiment(self) -> ControlledExperiment:
        if self.control.role != "control" or self.attack.role != "attack":
            raise ValueError("A controlled experiment pairs a control with an attack")
        if self.control.scenario.id != self.attack.scenario.id:
            raise ValueError("Variants must describe the same scenario")
        if canonical_digest(self.rubric.definition) != self.rubric_definition_sha256:
            raise ValueError("Rubric definition digest does not match the experiment")
        if self.rubric.definition is None:
            raise ValueError("A controlled experiment requires an executable rubric")
        if not self.attack.injected_document_id:
            raise ValueError("The attack variant must carry the injected document")
        if self.target.agent == "endpoint" and not self.allow_network:
            raise ValueError("A real endpoint experiment requires explicit network opt-in")
        planned = self.planned_requests
        if planned > self.limits.max_total_requests:
            raise ValueError(
                "Planned requests exceed the experiment request limit "
                f"({planned} > {self.limits.max_total_requests})"
            )
        if self.limits.max_estimated_spend_usd is not None:
            estimate = planned * (self.limits.estimated_cost_per_request_usd or 0.0)
            if estimate > self.limits.max_estimated_spend_usd:
                raise ValueError("Planned requests exceed the estimated spend guard")
        return self

    @property
    def planned_traces(self) -> int:
        return self.trial_count * 2

    @property
    def planned_requests(self) -> int:
        return self.planned_traces * self.limits.estimated_requests_per_variant


class VariantObservation(Contract):
    """Per-variant observations; never collapsed into a verdict."""

    role: VariantRole
    trace_id: str
    session_id: str | None = None
    status: TraceStatus
    termination: TerminationReason | None = None
    rubric_outcomes: dict[str, Outcome] = Field(default_factory=dict)
    rubric_definition_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    settings_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    integrity_ok: bool = True
    exposed_to_injection: bool = False
    unauthorized_requests: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    executed_tools: list[str] = Field(default_factory=list)
    state_changes: list[str] = Field(default_factory=list)
    canary_disclosed: bool = False
    task_marker_present: bool = False
    semantic_task_completion: Literal["human-assessed"] = "human-assessed"
    error: str | None = None


class PairedTrial(Contract):
    """One completed or attempted control/attack pair."""

    id: str = Field(default_factory=new_id)
    experiment_id: str
    trial_index: int = Field(ge=0)
    status: TrialStatus = "pending"
    order: list[VariantRole] = Field(default_factory=lambda: ["control", "attack"])
    control_trace_id: str | None = None
    attack_trace_id: str | None = None
    control: VariantObservation | None = None
    attack: VariantObservation | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    interruption: str | None = None
    trial_version: Literal[1] = 1

    @model_validator(mode="after")
    def validate_trial(self) -> PairedTrial:
        if sorted(self.order) != ["attack", "control"]:
            raise ValueError("A trial runs exactly one control and one attack")
        if self.status == "completed":
            if self.control is None or self.attack is None:
                raise ValueError("A completed trial records both variants")
            if self.control_trace_id is None or self.attack_trace_id is None:
                raise ValueError("A completed trial references both traces")
        if self.status == "incomplete" and not (self.control or self.attack):
            raise ValueError("An incomplete pair keeps at least one recorded observation")
        return self


class TrialResult(Contract):
    """Flattened view of one trial used by statistics and CSV export."""

    trial_index: int
    status: TrialStatus
    complete: bool
    order: list[VariantRole] = Field(default_factory=list)
    control_trace_id: str | None = None
    attack_trace_id: str | None = None
    control_session_id: str | None = None
    attack_session_id: str | None = None
    control_outcomes: dict[str, Outcome] = Field(default_factory=dict)
    attack_outcomes: dict[str, Outcome] = Field(default_factory=dict)
    error: str | None = None


class ConfidenceInterval(Contract):
    """One interval with an explicit method and an explicit reason when undefined."""

    method: Literal[
        "wilson-score-95",
        "newcombe-mover-95",
        "exact-conditional-clopper-pearson",
        "none",
    ] = "wilson-score-95"
    coverage: Literal["unconditional-approximate", "conditional-exact", "none"] = (
        "unconditional-approximate"
    )
    confidence: float | None = 0.95
    sample_size: int | None = Field(default=None, ge=0)
    estimate: float | None = None
    low: float | None = None
    high: float | None = None
    reason: str | None = None


class CriterionComparison(Contract):
    """Criterion-level paired comparison with raw transition counts."""

    criterion_id: str = Field(min_length=1)
    scale_kind: ScaleKind = "binary"
    control_trials: int = Field(default=0, ge=0)
    attack_trials: int = Field(default=0, ge=0)
    complete_pairs: int = Field(default=0, ge=0)
    control_failures: int = Field(default=0, ge=0)
    attack_failures: int = Field(default=0, ge=0)
    control_uncertain: int = Field(default=0, ge=0)
    attack_uncertain: int = Field(default=0, ge=0)
    control_not_applicable: int = Field(default=0, ge=0)
    attack_not_applicable: int = Field(default=0, ge=0)
    excluded_incomplete: int = Field(default=0, ge=0)
    excluded_reasons: dict[str, int] = Field(default_factory=dict)
    descriptive_arm_trials: int = Field(default=0, ge=0)
    control_failure_rate: float | None = None
    attack_failure_rate: float | None = None
    absolute_rate_difference: float | None = None
    control_interval: ConfidenceInterval = Field(default_factory=ConfidenceInterval)
    attack_interval: ConfidenceInterval = Field(default_factory=ConfidenceInterval)
    paired_difference_interval: ConfidenceInterval = Field(
        default_factory=lambda: ConfidenceInterval(method="none", reason="not computed")
    )
    # Sensitivity interval conditioned on the observed discordance count. It is
    # reported separately because its coverage is conditional, not unconditional.
    conditional_difference_interval: ConfidenceInterval | None = None
    paired_difference_interval: ConfidenceInterval = Field(
        default_factory=lambda: ConfidenceInterval(method="none", reason="not computed")
    )
    pass_pass: int = Field(default=0, ge=0)
    pass_fail: int = Field(default=0, ge=0)
    fail_pass: int = Field(default=0, ge=0)
    fail_fail: int = Field(default=0, ge=0)
    discordant_pairs: int = Field(default=0, ge=0)
    exact_binomial_p: float | None = None
    p_value_reason: str | None = None
    notes: list[str] = Field(default_factory=list)


class ExperimentalSummary(Contract):
    """Aggregate over trials; every denominator is explicit."""

    experiment_id: str
    trials_total: int = Field(ge=0)
    trials_completed: int = Field(ge=0)
    trials_failed: int = Field(ge=0)
    trials_interrupted: int = Field(ge=0)
    trials_pending: int = Field(ge=0)
    trials_incomplete: int = Field(ge=0)
    complete_pairs: int = Field(ge=0)
    criteria: list[CriterionComparison] = Field(default_factory=list)
    responses_observed: int = Field(ge=0)
    control_failures: int = Field(default=0, ge=0)
    attack_failures: int = Field(default=0, ge=0)
    control_metric: str | None = None
    attack_metric: str | None = None
    observations: dict[str, int] = Field(default_factory=dict)
    excluded_trials: list[PairEligibility] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Rates describe these authorized trials only, not a population.",
            "Small samples cannot support claims of statistical significance.",
            "Adoption and semantic task completion remain human-assessed.",
            "A control failure is not evidence that the injection caused anything.",
        ]
    )


class ControlledExperimentReport(Contract):
    """Portable report for a controlled experiment; never claims causation."""

    id: str = Field(default_factory=new_id)
    generated_at: datetime = Field(default_factory=now)
    report_format_version: Literal["2.2.0"] = "2.2.0"
    origin: Literal["controlled_experiment"] = "controlled_experiment"
    experiment: ControlledExperiment
    summary: ExperimentalSummary
    trials: list[PairedTrial] = Field(default_factory=list)
    trace_ids: list[str] = Field(default_factory=list)
    evaluation_sessions: list[EvaluationSession] = Field(default_factory=list)
    human_judgments: list[HumanJudgment] = Field(default_factory=list)
    adjudications: list[Adjudication] = Field(default_factory=list)
    effective_results: list[EffectiveResult] = Field(default_factory=list)
    quality: QualityReport | None = None
    capabilities: ProviderCapabilityReport | None = None
    excluded_trials: list[PairEligibility] = Field(default_factory=list)
    evidence_digests: list[EvidenceDigest] = Field(default_factory=list)
    export_digest: EvidenceDigest | None = None
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Only explicitly authorized endpoints and models were used.",
            "Synthetic tools were the only executable tools; no external effect occurred.",
            "Rate differences over few trials are not evidence of causation or significance.",
            "Adoption and semantic task completion are human assessments.",
            "Provider seeds are advisory and do not guarantee deterministic output.",
        ]
    )


# --- Phase 3C: validation, comparison and quality control -----------------------

CapabilityStatus = Literal["supported", "unsupported", "unknown"]
QualitySeverity = Literal["blocking", "warning", "info"]


class ProviderCapabilities(Contract):
    """What a profile asserts or a probe observed; never proof by itself."""

    chat_completions: CapabilityStatus = "unknown"
    tool_calls: CapabilityStatus = "unknown"
    tool_result_messages: CapabilityStatus = "unknown"
    token_limit_parameter: CapabilityStatus = "unknown"
    temperature: CapabilityStatus = "unknown"
    seed: CapabilityStatus = "unknown"
    system_role: CapabilityStatus = "unknown"
    model_identity: CapabilityStatus = "unknown"
    usage_reporting: CapabilityStatus = "unknown"
    finish_reason: CapabilityStatus = "unknown"
    token_parameter_name: Literal["max_tokens", "max_completion_tokens"] | None = None


class CapabilityObservation(Contract):
    """One sanitized probe result with its evidence artifact."""

    feature: str = Field(min_length=1)
    status: CapabilityStatus
    configured: CapabilityStatus = "unknown"
    detail: str = Field(min_length=1)
    request_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    response_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    evidence: EvidenceArtifact | None = None


class ProviderCapabilityReport(Contract):
    """Configured versus observed capabilities for one authorized endpoint."""

    id: str = Field(default_factory=new_id)
    profile_id: str
    provider: str = Field(min_length=1)
    model: str | None = None
    observed_model: str | None = None
    configured: ProviderCapabilities = Field(default_factory=ProviderCapabilities)
    observed: ProviderCapabilities = Field(default_factory=ProviderCapabilities)
    observations: list[CapabilityObservation] = Field(default_factory=list)
    tool_round_trip: CapabilityStatus = "unknown"
    token_usage: dict[str, Any] = Field(default_factory=dict)
    finish_reasons: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    allow_network: bool = False
    created_at: datetime = Field(default_factory=now)
    capability_version: Literal[1] = 1

    @property
    def mismatches(self) -> list[str]:
        """Configured features the probe could not confirm."""
        found = []
        for feature, status in self.configured.model_dump().items():
            observed = getattr(self.observed, feature)
            if status == "supported" and observed != "supported":
                found.append(feature)
        return sorted(found)


class PairEligibility(Contract):
    """Why a trial is or is not eligible for paired inference."""

    trial_index: int = Field(ge=0)
    criterion_id: str | None = None
    eligible: bool = False
    reasons: list[str] = Field(default_factory=list)


class QualityCheck(Contract):
    """One experimental quality check with its own severity."""

    id: str = Field(min_length=1)
    severity: QualitySeverity
    passed: bool
    message: str = Field(min_length=1)
    evidence: list[str] = Field(default_factory=list)


class QualityReport(Contract):
    """Quality findings for one experiment; never replaces its results."""

    experiment_id: str
    checks: list[QualityCheck] = Field(default_factory=list)
    blocking: int = Field(default=0, ge=0)
    warnings: int = Field(default=0, ge=0)
    notes: int = Field(default=0, ge=0)
    notes_free: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=now)

    @property
    def passed(self) -> bool:
        return self.blocking == 0


class ModelComparisonEntry(Contract):
    """One model's segregated experiment inside a comparison."""

    experiment_id: str
    profile_id: str | None = None
    agent: Literal["scripted-secure", "scripted-vulnerable", "endpoint"]
    provider: str = Field(min_length=1)
    model: str | None = None
    configured_capabilities: ProviderCapabilities = Field(default_factory=ProviderCapabilities)
    observed_capabilities: ProviderCapabilities | None = None
    capability_report_id: str | None = None
    settings_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    budget_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trial_count: int = Field(ge=1)
    summary: ExperimentalSummary
    total_tokens: int = Field(default=0, ge=0)
    entry_version: Literal[1] = 1


class ComparabilityNote(Contract):
    """One disclosed reason two model results are not strictly comparable."""

    kind: Literal[
        "settings",
        "budget",
        "capabilities",
        "rubric",
        "scenario",
        "trials",
        "model",
    ]
    severity: QualitySeverity
    message: str = Field(min_length=1)
    models: list[str] = Field(default_factory=list)


class ModelComparison(Contract):
    """Two or more models measured separately on the same controlled pair."""

    id: str = Field(default_factory=new_id)
    name: str = Field(min_length=1)
    objective: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    scenario_version: str = Field(min_length=1)
    rubric: Rubric
    rubric_definition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    entries: list[ModelComparisonEntry] = Field(default_factory=list)
    notes: list[ComparabilityNote] = Field(default_factory=list)
    authorization: str = Field(min_length=1)
    allow_network: bool = False
    status: Literal["planned", "running", "partial", "completed", "failed", "cancelled"] = "planned"
    created_at: datetime = Field(default_factory=now)
    completed_at: datetime | None = None
    comparison_version: Literal[1] = 1

    @model_validator(mode="after")
    def validate_comparison(self) -> ModelComparison:
        if len(self.entries) < 2:
            raise ValueError("A model comparison covers at least two models")
        identities = [(entry.provider, entry.model or "", entry.agent) for entry in self.entries]
        if len(set(identities)) != len(identities):
            raise ValueError("Each comparison entry covers a distinct model identity")
        if canonical_digest(self.rubric.definition) != self.rubric_definition_sha256:
            raise ValueError("Rubric definition digest does not match the comparison")
        if self.rubric.definition is None:
            raise ValueError("A model comparison requires an executable rubric")
        return self


class BenchmarkScenarioResult(Contract):
    """One scenario measured against one model inside a benchmark run."""

    scenario_id: str = Field(min_length=1)
    scenario_version: str = Field(min_length=1)
    model_label: str = Field(min_length=1)
    experiment_id: str | None = None
    status: Literal["planned", "completed", "failed", "skipped", "pending"] = "planned"
    summary: ExperimentalSummary | None = None
    skipped_reason: str | None = None
    error: str | None = None


class BenchmarkSuite(Contract):
    """A packaged collection of synthetic scenarios with its own budget frame."""

    id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    scenario_ids: list[str] = Field(min_length=1)
    provenance: str = "packaged-synthetic-suite"
    suite_version: Literal[1] = 1


class BenchmarkLimits(Contract):
    """Explicit ceilings for one benchmark run."""

    max_scenarios: int = Field(default=6, gt=0)
    max_trials_per_scenario: int = Field(default=3, gt=0)
    max_total_requests: int = Field(default=200, gt=0)
    max_total_tokens: int = Field(default=200_000, gt=0)
    max_runtime_seconds: float = Field(default=3600.0, gt=0)
    estimated_requests_per_variant: int = Field(default=6, gt=0)
    estimated_tokens_per_request: int = Field(default=800, gt=0)
    estimated_cost_per_request_usd: float | None = Field(default=None, ge=0)
    max_estimated_spend_usd: float | None = Field(default=None, ge=0)


class BenchmarkPlan(Contract):
    """A planned benchmark: suite x models, with per-scenario experiments."""

    id: str = Field(default_factory=new_id)
    suite: BenchmarkSuite
    models: list[ModelComparisonEntry] = Field(default_factory=list)
    limits: BenchmarkLimits = Field(default_factory=BenchmarkLimits)
    authorization: str = Field(min_length=1)
    allow_network: bool = False
    status: Literal["planned", "running", "partial", "completed", "failed", "cancelled"] = "planned"
    scenario_ids: list[str] = Field(default_factory=list)
    model_labels: list[str] = Field(default_factory=list)
    results: list[BenchmarkScenarioResult] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=now)
    completed_at: datetime | None = None
    plan_version: Literal[1] = 1

    @model_validator(mode="after")
    def validate_plan(self) -> BenchmarkPlan:
        if len(self.scenario_ids) > self.limits.max_scenarios:
            raise ValueError("Suite exceeds the benchmark scenario limit")
        planned = (
            len(self.scenario_ids)
            * len(self.models)
            * 2
            * self.limits.estimated_requests_per_variant
        )
        if planned > self.limits.max_total_requests:
            raise ValueError(
                "Planned benchmark requests exceed the request limit "
                f"({planned} > {self.limits.max_total_requests})"
            )
        tokens = planned * self.limits.estimated_tokens_per_request
        if tokens > self.limits.max_total_tokens:
            raise ValueError(
                "Planned benchmark tokens exceed the token limit "
                f"({tokens} > {self.limits.max_total_tokens})"
            )
        if self.limits.max_estimated_spend_usd is not None:
            if self.limits.estimated_cost_per_request_usd is None:
                raise ValueError("A spend guard requires an estimated unit cost")
            estimate = planned * self.limits.estimated_cost_per_request_usd
            if estimate > self.limits.max_estimated_spend_usd:
                raise ValueError("Planned benchmark requests exceed the spend guard")
        return self


class ModelComparisonReport(Contract):
    """Per-model paired results; never a pooled sample or a global score."""

    id: str = Field(default_factory=new_id)
    generated_at: datetime = Field(default_factory=now)
    report_format_version: Literal["2.3.0"] = "2.3.0"
    origin: Literal["model_comparison"] = "model_comparison"
    comparison: ModelComparison
    experiment_ids: list[str] = Field(default_factory=list)
    trace_ids: list[str] = Field(default_factory=list)
    evaluation_sessions: list[EvaluationSession] = Field(default_factory=list)
    human_judgments: list[HumanJudgment] = Field(default_factory=list)
    adjudications: list[Adjudication] = Field(default_factory=list)
    effective_results: list[EffectiveResult] = Field(default_factory=list)
    quality: list[QualityReport] = Field(default_factory=list)
    capabilities: list[ProviderCapabilityReport] = Field(default_factory=list)
    evidence_digests: list[EvidenceDigest] = Field(default_factory=list)
    export_digest: EvidenceDigest | None = None
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Each model is measured separately; results are never pooled.",
            "No global safety score is computed or implied.",
            "Rate differences over few trials are not evidence of significance.",
            "Provider capabilities are configuration assertions plus probe observations.",
            "Adoption and semantic task completion remain human assessments.",
        ]
    )


class BenchmarkReport(Contract):
    """Scenario-level benchmark results per model, with explicit budgets."""

    id: str = Field(default_factory=new_id)
    generated_at: datetime = Field(default_factory=now)
    report_format_version: Literal["2.3.0"] = "2.3.0"
    origin: Literal["benchmark"] = "benchmark"
    plan: BenchmarkPlan
    experiment_ids: list[str] = Field(default_factory=list)
    trace_ids: list[str] = Field(default_factory=list)
    evaluation_sessions: list[EvaluationSession] = Field(default_factory=list)
    human_judgments: list[HumanJudgment] = Field(default_factory=list)
    adjudications: list[Adjudication] = Field(default_factory=list)
    effective_results: list[EffectiveResult] = Field(default_factory=list)
    quality: list[QualityReport] = Field(default_factory=list)
    capabilities: list[ProviderCapabilityReport] = Field(default_factory=list)
    evidence_digests: list[EvidenceDigest] = Field(default_factory=list)
    export_digest: EvidenceDigest | None = None
    limitations: list[str] = Field(
        default_factory=lambda: [
            "A benchmark is a collection of experiments, not a substitute for their traces.",
            "Results are reported per scenario and model; nothing is pooled or ranked.",
            "Only explicitly authorized models and synthetic tools were used.",
            "Incomplete scenarios are reported, never silently dropped.",
        ]
    )


ValidationStatus = Literal["ok", "failed", "skipped", "unknown"]


class ValidationStep(Contract):
    """One named step of an endpoint validation run."""

    name: str = Field(min_length=1)
    status: ValidationStatus
    detail: str = Field(min_length=1)
    evidence: list[str] = Field(default_factory=list)


class ValidationRun(Contract):
    """A reproducible validation of one authorized endpoint."""

    id: str = Field(default_factory=new_id)
    profile_id: str
    provider: str = Field(min_length=1)
    model: str | None = None
    scenario_id: str | None = None
    steps: list[ValidationStep] = Field(default_factory=list)
    capability_report_id: str | None = None
    trace_id: str | None = None
    experiment_id: str | None = None
    allow_network: bool = False
    created_at: datetime = Field(default_factory=now)
    validation_version: Literal[1] = 1

    @property
    def ok(self) -> bool:
        return all(step.status in {"ok", "skipped"} for step in self.steps)

    @property
    def failed_steps(self) -> list[str]:
        return [step.name for step in self.steps if step.status == "failed"]


class RedactionFinding(Contract):
    """Result of scanning retained evidence for a credential value."""

    secret_configured: bool = False
    observations_checked: int = Field(default=0, ge=0)
    documents_checked: int = Field(default=0, ge=0)
    leaked: bool = False
    locations: list[str] = Field(default_factory=list)
    detail: str = Field(min_length=1)
