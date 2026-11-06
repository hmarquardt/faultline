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
]
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

    kind: Literal["execution", "evaluation", "judgment", "adjudication", "report-export"]
    source_id: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    algorithm: Literal["sha256-canonical-json/1"] = "sha256-canonical-json/1"


SessionStatus = Literal["pending_human_review", "completed", "failed"]
SessionOrigin = Literal["execution", "reevaluation", "human_review", "migration", "dataset_import"]
EvidenceKind = Literal["execution", "dataset"]


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
        return self.run_id or self.dataset_case_id or ""

    @model_validator(mode="after")
    def validate_lifecycle(self) -> EvaluationSession:
        if self.rubric.definition is None:
            raise ValueError("An evaluation session requires an executable rubric definition")
        if canonical_digest(self.rubric.definition) != self.rubric_definition_sha256:
            raise ValueError("Rubric definition digest does not match the session snapshot")
        if self.evidence_kind == "execution":
            if self.run_id is None or self.dataset_case_id is not None:
                raise ValueError("Execution sessions reference a run and no dataset case")
            if self.experiment_id is None:
                raise ValueError("Execution sessions belong to an experiment")
        else:
            if self.dataset_case_id is None or self.dataset_id is None:
                raise ValueError("Dataset sessions reference a dataset and case")
            if self.run_id is not None:
                raise ValueError("Dataset sessions never reference a run")
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


class AgreementGroup(Contract):
    """Agreement measured only within one rubric version, criterion and scale."""

    rubric_id: str
    rubric_version: str
    criterion_id: str
    scale_kind: ScaleKind
    reviewers: list[str] = Field(default_factory=list)
    units_compared: int = Field(ge=0)
    units_excluded_not_applicable: int = Field(default=0, ge=0)
    units_excluded_incomplete: int = Field(default=0, ge=0)
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
    scope: Literal["experiment", "batch"]
    scope_id: str
    units_total: int = Field(ge=0)
    units_compared: int = Field(ge=0)
    units_excluded_not_applicable: int = Field(default=0, ge=0)
    units_excluded_incomplete: int = Field(default=0, ge=0)
    reviewers: list[str] = Field(default_factory=list)
    groups: list[AgreementGroup] = Field(default_factory=list)
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
