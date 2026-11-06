"""Deterministic record identity. Pure functions: no storage, clock or network.

Two identities are kept apart on purpose:

* ``EvidenceArtifact.sha256`` hashes the retained source bytes (Phase 1).
* Canonical digests hash a typed record by value, so the same evidence has the
  same identity regardless of JSON key order or file layout.
"""

from faultline.domain import (
    Adjudication,
    EvaluationSession,
    EvidenceDigest,
    ExecutionRun,
    HumanJudgment,
    ModelResponse,
    canonical_digest,
    digest,
)


def execution_digest(run: ExecutionRun) -> str:
    """Identity of everything the target produced for one case, plus its evidence."""
    return canonical_digest(run)


def session_digest(session: EvaluationSession) -> str:
    return canonical_digest(session)


def judgment_digest(judgment: HumanJudgment) -> str:
    return canonical_digest(judgment)


def adjudication_digest(adjudication: Adjudication) -> str:
    return canonical_digest(adjudication)


def execution_evidence(run: ExecutionRun) -> EvidenceDigest:
    return EvidenceDigest(kind="execution", source_id=run.id, sha256=execution_digest(run))


def session_evidence(session: EvaluationSession) -> EvidenceDigest:
    return EvidenceDigest(kind="evaluation", source_id=session.id, sha256=session_digest(session))


def judgment_evidence(judgment: HumanJudgment) -> EvidenceDigest:
    return EvidenceDigest(kind="judgment", source_id=judgment.id, sha256=judgment_digest(judgment))


def adjudication_evidence(adjudication: Adjudication) -> EvidenceDigest:
    return EvidenceDigest(
        kind="adjudication",
        source_id=adjudication.id,
        sha256=adjudication_digest(adjudication),
    )


def response_artifact_matches(run: ExecutionRun) -> bool:
    """The stored response must still be the response captured as evidence."""
    if run.response is None:
        return False
    return any(
        a.kind == "response" and ModelResponse.model_validate_json(a.content) == run.response
        for a in run.evidence
    )


def verify_execution(run: ExecutionRun) -> list[str]:
    """Integrity problems with one stored run; empty means self-consistent."""
    problems = [
        f"Artifact {artifact.id} hash does not match its content"
        for artifact in run.evidence
        if digest(artifact.content) != artifact.sha256
    ]
    if run.response is not None and not response_artifact_matches(run):
        problems.append("Stored response does not match its preserved evidence artifact")
    return problems


def trace_digest(trace) -> str:
    """Canonical identity of a stored agentic trace, excluding its own digest."""
    return canonical_digest(trace, exclude={"execution_sha256"})


def verify_trace(trace) -> bool:
    """True when the stored execution digest still describes the trace."""
    return trace_digest(trace) == trace.execution_sha256
