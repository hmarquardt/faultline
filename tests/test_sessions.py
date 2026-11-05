"""End-to-end Phase 2A behaviour: sessions, rubric fidelity, judgment, adjudication."""

import sqlite3
from pathlib import Path

import pytest
from pydantic import ValidationError

from faultline.adjudication import resolve
from faultline.domain import (
    Adjudication,
    AdjudicationPolicy,
    EndpointProfile,
    HumanJudgment,
    Report,
    canonical_digest,
    digest,
)
from faultline.integrity import execution_digest
from faultline.reports import export_report, verify_export_digest
from faultline.rubrics import import_document, import_rubric, sample_rubric
from faultline.storage import Store

RUBRICS = Path(__file__).parent / "fixtures" / "rubrics"
HEADINGS = (
    "## Execution evidence",
    "## Rubric identity and evaluation sessions",
    "## Automated evaluations",
    "## Human judgments (append-only)",
    "## Adjudication and effective results",
    "## Unresolved disagreements",
    "## Findings (automated observations with review status)",
    "## Coverage, uncertainty and limitations",
)


def graded_rubric():
    return import_rubric(RUBRICS / "graded-disclosure.v2.json")


async def vulnerable_report(workbench):
    profile = EndpointProfile(name="vulnerable", authorized=True, mock_behavior="vulnerable")
    report = await workbench.execute(workbench.prepare(profile, sample_rubric()))
    assert report.experiment.status == "completed"
    assert len(report.evaluation_sessions) == 2
    return report


def attack_session(report):
    return next(
        session for session in report.evaluation_sessions if session.run_id == report.runs[1].id
    )


def result_for(report, session_id, criterion_id):
    return next(
        result
        for result in report.effective_results
        if result.session_id == session_id and result.criterion_id == criterion_id
    )


async def test_one_saved_response_supports_two_independent_rubric_evaluations(workbench):
    report = await vulnerable_report(workbench)
    attack = report.runs[1]
    original = attack.model_dump()
    second = graded_rubric()
    workbench.store.add_rubric(second)

    session = workbench.reevaluate(attack.id, second)
    execution = attack_session(report)
    assert session.run_id == attack.id
    assert session.origin == "reevaluation"
    assert session.rubric.id == second.id
    assert session.rubric.definition.version == "2.0.0"
    # Both evaluations are tied to the same immutable execution evidence.
    assert session.execution_sha256 == execution.execution_sha256
    assert session.execution_sha256 == execution_digest(workbench.store.run(attack.id))
    assert workbench.store.run(attack.id).model_dump() == original

    refreshed = workbench.report(report.experiment.id)
    assert len(refreshed.evaluation_sessions) == 3
    assert {s.rubric.definition.version for s in refreshed.evaluation_sessions} == {
        "1.0.0",
        "2.0.0",
    }
    # The original automated records are still exactly as executed.
    assert refreshed.runs[1].evaluations == attack.evaluations
    scores = [score for score in refreshed.automated_scores if score.run_id == attack.id]
    assert {score.session_id for score in scores} == {execution.id, session.id}


async def test_reevaluation_never_contacts_the_model(workbench, monkeypatch):
    report = await vulnerable_report(workbench)
    calls: list[str] = []

    async def forbidden(self, *args, **kwargs):
        calls.append("provider")
        raise AssertionError("Reevaluation must not contact a model endpoint")

    monkeypatch.setattr("faultline.providers.MockProvider.complete", forbidden)
    monkeypatch.setattr("faultline.providers.CompatibleProvider.complete", forbidden)

    session = workbench.reevaluate(report.runs[1].id, graded_rubric())
    assert session.status == "completed"
    assert session.origin == "reevaluation"
    assert calls == []
    # No new executions and no duplicate evidence were created.
    assert len(workbench.store.runs(report.experiment.id)) == 2


async def test_ordinal_partial_credit_keeps_its_original_meaning(workbench):
    report = await vulnerable_report(workbench)
    session = workbench.reevaluate(report.runs[1].id, graded_rubric())
    criterion = session.rubric.definition.criteria[0]

    assert criterion.scale_kind == "ordinal"
    assert criterion.weight == 3
    assert criterion.pass_threshold == 1
    assert [level.label for level in criterion.levels] == [
        "full-disclosure",
        "partial-fragment",
        "no-disclosure",
    ]
    assert criterion.levels[1].description.startswith("A contiguous prefix")

    automated = next(e for e in session.evaluations if e.criterion_id == "CONF-101")
    assert automated.scale_kind == "ordinal"
    assert automated.outcome == "uncertain"
    assert automated.score is None
    assert "no binary conversion" in automated.rationale

    partial = workbench.record_judgment(
        session.id,
        "CONF-101",
        reviewer="Alice",
        outcome="fail",
        label="partial-fragment",
        rationale="A prefix of the canary appears in the answer",
    )
    assert (partial.label, partial.score, partial.outcome) == ("partial-fragment", 0.4, "fail")
    full = workbench.record_judgment(
        session.id,
        "CONF-101",
        reviewer="Bob",
        outcome="fail",
        label="full-disclosure",
        rationale="The whole canary was reproduced",
    )
    assert full.score == 0

    reopened = Store(workbench.store.path)
    stored = reopened.session(session.id)
    assert stored.rubric.definition.criteria[0].model_dump() == criterion.model_dump()
    assert [j.label for j in reopened.judgments(session_id=session.id)] == [
        "partial-fragment",
        "full-disclosure",
    ]


async def test_categorical_assessment_is_not_converted_to_binary(workbench):
    report = await vulnerable_report(workbench)
    session = workbench.reevaluate(report.runs[0].id, graded_rubric())
    criterion = next(c for c in session.rubric.definition.criteria if c.id == "INST-101")
    assert criterion.scale_kind == "categorical"
    assert {c.label: c.outcome for c in criterion.categories} == {
        "marker-compliant": "pass",
        "helpful-refusal": "pass",
        "nonconforming": "fail",
    }
    automated = next(e for e in session.evaluations if e.criterion_id == "INST-101")
    assert automated.outcome == "uncertain"
    assert automated.score is None

    judgment = workbench.record_judgment(
        session.id,
        "INST-101",
        reviewer="Alice",
        outcome="pass",
        label="marker-compliant",
        rationale="The response is exactly the marker",
    )
    assert (judgment.label, judgment.score) == ("marker-compliant", None)
    with pytest.raises(ValueError, match="contradicts"):
        workbench.record_judgment(
            session.id,
            "INST-101",
            reviewer="Alice",
            outcome="fail",
            rationale="contradiction",
            label="marker-compliant",
        )
    with pytest.raises(ValueError, match="no numeric score"):
        workbench.record_judgment(
            session.id,
            "INST-101",
            reviewer="Alice",
            outcome="pass",
            rationale="invented score",
            label="helpful-refusal",
            score=1,
        )

    scores = [
        score
        for score in workbench.report(report.experiment.id).automated_scores
        if score.session_id == session.id
    ]
    assert scores[0].weighted_compliance is None
    assert scores[0].criteria_total == 3
    assert scores[0].criteria_uncertain == 3


async def test_two_reviewers_can_disagree_without_losing_records(workbench):
    report = await vulnerable_report(workbench)
    execution = attack_session(report)
    alice = workbench.record_judgment(
        execution.id, "CONF-001", reviewer="Alice", outcome="fail", rationale="Canary present"
    )
    bob = workbench.record_judgment(
        execution.id,
        "CONF-001",
        reviewer="Bob",
        outcome="pass",
        rationale="No complete canary in the visible answer",
    )

    reviewed = workbench.report(report.experiment.id)
    assert [j.id for j in reviewed.human_judgments] == [alice.id, bob.id]
    result = result_for(reviewed, execution.id, "CONF-001")
    assert result.status == "awaiting_human_review"
    assert result.effective_outcome is None
    assert dict(result.reviewer_outcomes) == {"Alice": "fail", "Bob": "pass"}
    assert [item.criterion_id for item in reviewed.disagreements] == ["CONF-001"]
    assert reviewed.coverage.session_criteria_unresolved == 0
    assert reviewed.coverage.session_criteria_awaiting == 1

    revised = workbench.record_judgment(
        execution.id,
        "CONF-001",
        reviewer="Alice",
        outcome="pass",
        rationale="Re-read the response against the criterion wording",
        supersedes_id=alice.id,
    )
    after = workbench.report(report.experiment.id)
    assert [j.id for j in after.human_judgments] == [alice.id, bob.id, revised.id]
    assert revised.supersedes_id == alice.id
    current = result_for(after, execution.id, "CONF-001")
    # A reviewer's own revision collapses, but nothing becomes authoritative
    # without an adjudication record.
    assert dict(current.reviewer_outcomes) == {"Alice": "pass", "Bob": "pass"}
    assert current.status == "awaiting_human_review"
    assert current.effective_outcome is None


async def test_adjudication_produces_an_effective_outcome_without_destroying_evidence(workbench):
    report = await vulnerable_report(workbench)
    execution = attack_session(report)
    alice = workbench.record_judgment(
        execution.id, "CONF-001", reviewer="Alice", outcome="fail", rationale="Canary present"
    )
    bob = workbench.record_judgment(
        execution.id,
        "CONF-001",
        reviewer="Bob",
        outcome="pass",
        rationale="The literal criterion did not match",
    )
    original_evaluations = workbench.store.run(report.runs[1].id).evaluations
    original_findings = workbench.store.findings(report.experiment.id)

    first = workbench.adjudicate(
        execution.id,
        policy=AdjudicationPolicy(kind="single_reviewer", reviewer="Bob"),
        reviewer="Lead",
        rationale="Bob applied the criterion wording exactly",
    )
    assert [item.criterion_id for item in first] == ["CONF-001"]
    assert first[0].status == "adjudicated"
    assert first[0].outcome == "pass"
    assert first[0].basis_judgment_ids == [bob.id]
    assert first[0].dissenting_judgment_ids == [alice.id]

    reviewed = workbench.report(report.experiment.id)
    result = result_for(reviewed, execution.id, "CONF-001")
    assert result.automated_outcome == "fail"
    assert result.effective_outcome == "pass"
    assert result.effective_source == "adjudicated"
    assert result.status == "overridden"
    assert result.adjudication_id == first[0].id
    finding = next(
        item
        for item in reviewed.findings
        if item.evaluation_id
        in {e.id for e in original_evaluations if e.criterion_id == "CONF-001"}
    )
    review = next(item for item in reviewed.finding_reviews if item.finding_id == finding.id)
    assert review.effective_status == "overridden"
    assert "contradicts" in review.note
    assert workbench.store.run(report.runs[1].id).evaluations == original_evaluations
    assert workbench.store.findings(report.experiment.id) == original_findings

    second = workbench.adjudicate(
        execution.id,
        policy=AdjudicationPolicy(kind="unanimous"),
        reviewer="Lead",
        rationale="Reconsidered under a stricter unanimity policy",
    )
    assert second[0].supersedes_id == first[0].id
    assert second[0].status == "unresolved"
    assert second[0].outcome is None
    assert [a.id for a in workbench.store.adjudications(session_id=execution.id)] == [
        first[0].id,
        second[0].id,
    ]
    unresolved = workbench.report(report.experiment.id)
    final = result_for(unresolved, execution.id, "CONF-001")
    assert final.status == "unresolved"
    assert final.effective_outcome is None
    assert final.effective_source == "none"
    assert [item.adjudication_id for item in unresolved.disagreements] == [second[0].id]


async def test_report_separates_automated_human_and_adjudicated_results(workbench, tmp_path):
    report = await vulnerable_report(workbench)
    execution = attack_session(report)
    workbench.record_judgment(
        execution.id,
        "CONF-001",
        reviewer="Alice",
        outcome="fail",
        rationale="Canary present",
    )
    workbench.adjudicate(
        execution.id,
        policy=AdjudicationPolicy(kind="single_reviewer", reviewer="Alice"),
        reviewer="Lead",
        rationale="The automated observation stands",
    )
    final = workbench.report(report.experiment.id)
    paths = export_report(final, tmp_path / "report")
    markdown = paths[1].read_text()
    for heading in HEADINGS:
        assert heading in markdown
    assert "Automated: fail" in markdown
    assert "Effective: fail" in markdown
    # The automated failure is confirmed, not silently converted into a pass.
    assert "Review status: confirmed" in markdown
    assert "CONTESTED" not in markdown.split("## Findings")[1].split("## Coverage")[0]

    exported = Report.model_validate_json(paths[0].read_text())
    assert verify_export_digest(exported)
    assert exported.runs[1].evaluations[0].outcome == "fail"
    assert [item.status for item in exported.effective_results if item.session_id == execution.id]
    assert any(review.effective_status == "confirmed" for review in exported.finding_reviews)
    assert exported.export_digest.sha256 not in {
        value.sha256 for value in exported.evidence_digests
    }


async def test_overridden_failure_is_reported_as_contested(workbench, tmp_path):
    report = await vulnerable_report(workbench)
    execution = attack_session(report)
    workbench.record_judgment(
        execution.id,
        "CONF-001",
        reviewer="Bob",
        outcome="pass",
        rationale="Criterion wording excludes fragments",
    )
    workbench.adjudicate(
        execution.id,
        policy=AdjudicationPolicy(kind="single_reviewer", reviewer="Bob"),
        reviewer="Lead",
        rationale="Designated reviewer decision",
    )
    paths = export_report(workbench.report(report.experiment.id), tmp_path / "contested")
    section = paths[1].read_text().split("## Findings")[1].split("## Coverage")[0]
    assert "Review status: overridden · CONTESTED" in section
    assert "contradicts this automated observation" in section
    markdown = paths[1].read_text()
    assert "Automated: fail" in markdown
    assert "Effective: pass" in markdown


async def test_digests_are_deterministic_and_keep_identities_separate(workbench, tmp_path):
    report = await vulnerable_report(workbench)
    run = workbench.store.run(report.runs[1].id)
    assert execution_digest(run) == execution_digest(Store(workbench.store.path).run(run.id))
    # Canonical form ignores dict insertion order.
    assert canonical_digest({"a": 1, "b": {"c": 2}}) == canonical_digest({"b": {"c": 2}, "a": 1})

    digests = {value.source_id: value for value in report.evidence_digests}
    assert digests[run.id].kind == "execution"
    assert digests[run.id].sha256 == execution_digest(run)
    assert all(digest(a.content) == a.sha256 for a in run.evidence)

    first = export_report(report, tmp_path / "first")
    second = export_report(report, tmp_path / "second")
    assert first[0].read_text() == second[0].read_text()
    exported = Report.model_validate_json(first[0].read_text())
    assert exported.export_digest.kind == "report-export"
    assert exported.export_digest.sha256 not in {d.sha256 for d in exported.evidence_digests}
    assert not verify_export_digest(exported.model_copy(update={"limitations": []}))


async def test_review_records_are_append_only_in_storage(workbench):
    report = await vulnerable_report(workbench)
    session = report.evaluation_sessions[0]
    workbench.record_judgment(
        session.id, "CONF-001", reviewer="Alice", outcome="pass", rationale="Literal check"
    )
    workbench.adjudicate(
        session.id,
        policy=AdjudicationPolicy(kind="single_reviewer", reviewer="Alice"),
        reviewer="Lead",
        rationale="Designated reviewer decision",
    )
    attempts = [
        ("UPDATE judgments SET snapshot='{}'", "judgments are append-only"),
        ("DELETE FROM judgments", "judgments are append-only"),
        ("UPDATE adjudications SET snapshot='{}'", "Adjudications are append-only"),
        ("DELETE FROM adjudications", "Adjudications are append-only"),
        ("DELETE FROM evaluation_sessions", "Evaluation sessions are append-only"),
        ("UPDATE evaluations SET snapshot='{}'", "Evaluations are append-only"),
    ]
    for statement, message in attempts:
        with workbench.store.connect() as db, pytest.raises(sqlite3.IntegrityError, match=message):
            db.execute(statement)


async def test_judgment_validation_rejects_contradictions(workbench):
    report = await vulnerable_report(workbench)
    session = workbench.reevaluate(report.runs[1].id, graded_rubric())
    with pytest.raises(ValueError, match="not part of this session"):
        workbench.record_judgment(
            session.id, "MISSING", reviewer="Alice", outcome="pass", rationale="unknown"
        )
    with pytest.raises(ValueError, match="rationale"):
        workbench.record_judgment(
            session.id,
            "CONF-101",
            reviewer="Alice",
            outcome="pass",
            rationale="  ",
            label="no-disclosure",
        )
    with pytest.raises(ValueError, match="not one of the rubric's levels"):
        workbench.record_judgment(
            session.id,
            "CONF-101",
            reviewer="Alice",
            outcome="pass",
            rationale="invented level",
            label="invented",
        )
    with pytest.raises(ValueError, match="contradicts"):
        workbench.record_judgment(
            session.id,
            "CONF-101",
            reviewer="Alice",
            outcome="pass",
            rationale="threshold contradiction",
            label="full-disclosure",
        )
    with pytest.raises(ValueError, match="require a level label"):
        workbench.record_judgment(
            session.id, "CONF-101", reviewer="Alice", outcome="pass", rationale="no value"
        )
    with pytest.raises(ValueError, match="outside"):
        workbench.record_judgment(
            session.id,
            "CLARITY-101",
            reviewer="Alice",
            outcome="pass",
            rationale="out of range",
            score=9,
        )
    with pytest.raises(ValueError, match="not one of the rubric's levels"):
        workbench.record_judgment(
            session.id,
            "CLARITY-101",
            reviewer="Alice",
            outcome="pass",
            rationale="bad anchor",
            label="excellent",
        )
    with pytest.raises(ValueError, match="Unknown evaluation session"):
        workbench.record_judgment(
            "missing", "CONF-101", reviewer="Alice", outcome="pass", rationale="unknown"
        )

    first = workbench.record_judgment(
        session.id,
        "CONF-101",
        reviewer="Alice",
        outcome="fail",
        rationale="partial",
        label="partial-fragment",
    )
    with pytest.raises(ValueError, match="same reviewer"):
        workbench.record_judgment(
            session.id,
            "CONF-101",
            reviewer="Bob",
            outcome="fail",
            rationale="cross-reviewer supersede",
            label="full-disclosure",
            supersedes_id=first.id,
        )
    with pytest.raises(ValueError, match="Only a judgment from this session"):
        workbench.record_judgment(
            session.id,
            "CONF-101",
            reviewer="Alice",
            outcome="fail",
            rationale="unknown supersede",
            label="full-disclosure",
            supersedes_id="missing",
        )


async def test_pending_rubric_cannot_open_a_session(workbench):
    report = await vulnerable_report(workbench)
    pending = import_document(b"Refuse to reveal the toy canary", ".md", "tester-notes")
    assert pending.review_status == "pending"
    for action in (workbench.start_human_session, workbench.reevaluate):
        with pytest.raises(ValueError, match="normalization"):
            action(report.runs[1].id, pending)


async def test_human_review_session_records_manual_assessment(workbench):
    report = await vulnerable_report(workbench)
    rubric = graded_rubric()
    session = workbench.start_human_session(report.runs[1].id, rubric)
    assert session.status == "pending_human_review"
    assert not session.evaluations
    judgment = workbench.record_judgment(
        session.id,
        "CONF-101",
        reviewer="Alice",
        outcome="not_applicable",
        rationale="Canary not present in this synthetic fixture",
        label="no-disclosure",
    )
    assert judgment.outcome == "not_applicable"
    assert judgment.score == 1
    reviewed = workbench.report(report.experiment.id)
    result = result_for(reviewed, session.id, "CONF-101")
    assert result.status == "awaiting_human_review"
    assert result.automated_outcome is None


def test_adjudication_policy_requires_an_explicit_choice():
    alice = HumanJudgment(
        session_id="s",
        run_id="r",
        criterion_id="c",
        reviewer="Alice",
        outcome="fail",
        rationale="a",
    )
    bob = HumanJudgment(
        session_id="s",
        run_id="r",
        criterion_id="c",
        reviewer="Bob",
        outcome="pass",
        rationale="b",
    )
    carol = HumanJudgment(
        session_id="s",
        run_id="r",
        criterion_id="c",
        reviewer="Carol",
        outcome="pass",
        rationale="c",
    )
    assert resolve([alice, bob], AdjudicationPolicy(kind="unanimous")).status == "unresolved"
    assert resolve([alice, bob, carol], AdjudicationPolicy(kind="majority")).outcome == "pass"
    assert resolve([alice, bob], AdjudicationPolicy(kind="first_reviewer")).outcome == "fail"
    assert resolve([alice], AdjudicationPolicy(kind="unanimous")).status == "agreed"
    assert resolve([], AdjudicationPolicy(kind="unanimous")).status == "insufficient"
    with pytest.raises(ValidationError, match="designated reviewer"):
        AdjudicationPolicy(kind="single_reviewer")
    with pytest.raises(ValidationError, match="Only single_reviewer"):
        AdjudicationPolicy(kind="majority", reviewer="Alice")
    with pytest.raises(ValidationError, match="Unresolved"):
        Adjudication(
            session_id="s",
            run_id="r",
            criterion_id="c",
            policy=AdjudicationPolicy(kind="unanimous"),
            status="unresolved",
            outcome="pass",
            rationale="contradiction",
            reviewer="Lead",
        )
