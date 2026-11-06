"""End-to-end review: disagreements survive persistence, adjudication and export."""

import json
from pathlib import Path

from faultline.conformance import load_pack
from faultline.domain import AdjudicationPolicy, BatchReport
from faultline.reports import export_report
from faultline.rubrics import import_document
from faultline.service import Workbench
from faultline.storage import Store

PACKS = Path(__file__).parent / "fixtures" / "conformance"


def dataset_from_pack(pack, tmp_path):
    path = tmp_path / f"{pack.id}.jsonl"
    lines = []
    for sample in pack.responses:
        record = {
            "id": sample.id,
            "provenance": f"conformance:{pack.id}",
            "prompt": sample.prompt,
            "response": sample.response,
            "case_kind": sample.case_kind,
            "parameters": sample.parameters,
        }
        if sample.system_context:
            record["system_context"] = sample.system_context
        if sample.reference_answer:
            record["reference_answer"] = sample.reference_answer
        lines.append(json.dumps(record))
    path.write_text("\n".join(lines))
    return path


def batch_for(workbench, pack_name, tmp_path):
    pack = load_pack(PACKS / f"{pack_name}.json")
    rubric = import_document(
        json.dumps(pack.rubric, ensure_ascii=False).encode(),
        ".json",
        f"conformance:{pack.id}",
    )
    workbench.store.add_rubric(rubric)
    dataset = workbench.import_dataset(dataset_from_pack(pack, tmp_path))
    batch = workbench.create_batch(dataset.id, rubric)
    workbench.execute_batch(batch.id)
    sessions = {
        session.dataset_case_id: session
        for session in workbench.store.sessions_for_dataset(dataset.id)
    }
    return pack, dataset, batch, sessions


def test_categorical_labels_differing_with_identical_outcome_are_a_disagreement(tmp_path):
    workbench = Workbench(Store(tmp_path / "db.sqlite3"))
    pack, dataset, batch, sessions = batch_for(workbench, "factual-accuracy", tmp_path)
    session = sessions["fa-partial"]
    alice = workbench.record_judgment(
        session.id,
        "FA-001",
        reviewer="Alice",
        outcome="fail",
        label="partly-supported",
        rationale="One claim is only partly supported",
    )
    bob = workbench.record_judgment(
        session.id,
        "FA-001",
        reviewer="Bob",
        outcome="fail",
        label="unsupported",
        rationale="A material claim is unsupported",
    )
    assert alice.label != bob.label

    report = workbench.batch_report(batch.id)
    result = next(
        item
        for item in report.effective_results
        if item.session_id == session.id and item.criterion_id == "FA-001"
    )
    assert result.automated_outcome == "uncertain"
    assert result.agreement == "outcome_only"
    assert result.status == "awaiting_human_review"
    assert result.effective_outcome is None
    assert result.reviewer_labels == {
        "Alice": "partly-supported",
        "Bob": "unsupported",
    }
    (disagreement,) = [
        item
        for item in report.disagreements
        if item.session_id == session.id and item.criterion_id == "FA-001"
    ]
    assert disagreement.label_disagreement
    assert not disagreement.outcome_disagreement
    assert "label" in disagreement.summary
    assert disagreement.reviewer_labels["Bob"] == "unsupported"

    # Persistence keeps both judgments and the disagreement detail.
    reopened = Workbench(Store(workbench.store.path))
    persisted = reopened.batch_report(batch.id)
    assert [j.id for j in persisted.human_judgments] == [alice.id, bob.id]
    (persisted_disagreement,) = [
        item
        for item in persisted.disagreements
        if item.session_id == session.id and item.criterion_id == "FA-001"
    ]
    assert persisted_disagreement.label_disagreement

    # Unanimity cannot resolve a label disagreement.
    unresolved = reopened.adjudicate(
        session.id,
        policy=AdjudicationPolicy(kind="unanimous"),
        reviewer="Lead",
        rationale="Unanimity required",
    )
    (unanimous,) = [item for item in unresolved if item.criterion_id == "FA-001"]
    assert unanimous.status == "unresolved"
    assert unanimous.agreement == "outcome_only"

    # A designated reviewer decision preserves that reviewer's exact label.
    decided = reopened.adjudicate(
        session.id,
        policy=AdjudicationPolicy(kind="single_reviewer", reviewer="Bob"),
        reviewer="Lead",
        rationale="Bob applied the stricter category",
    )
    (chosen,) = [item for item in decided if item.criterion_id == "FA-001"]
    assert chosen.status == "adjudicated"
    assert chosen.outcome == "fail"
    assert chosen.label == "unsupported"
    assert chosen.basis_judgment_ids == [bob.id]
    assert chosen.dissenting_judgment_ids == [alice.id]
    final = reopened.batch_report(batch.id)
    final_result = next(
        item
        for item in final.effective_results
        if item.session_id == session.id and item.criterion_id == "FA-001"
    )
    assert final_result.effective_label == "unsupported"
    assert final_result.status == "human_assessed"
    # Both original judgments still exist after adjudication.
    assert [j.id for j in final.human_judgments] == [alice.id, bob.id]


def test_ordinal_scores_stay_distinguishable_through_export(tmp_path):
    workbench = Workbench(Store(tmp_path / "db.sqlite3"))
    pack, dataset, batch, sessions = batch_for(workbench, "response-quality", tmp_path)
    session = sessions["rq-full"]
    workbench.record_judgment(
        session.id,
        "RQ-001",
        reviewer="Alice",
        outcome="pass",
        label="excellent",
        rationale="Complete answer",
    )
    workbench.record_judgment(
        session.id,
        "RQ-001",
        reviewer="Bob",
        outcome="pass",
        label="solid",
        rationale="One small omission",
    )
    report = workbench.batch_report(batch.id)
    result = next(
        item
        for item in report.effective_results
        if item.session_id == session.id and item.criterion_id == "RQ-001"
    )
    assert result.reviewer_scores == {"Alice": 1.0, "Bob": 0.8}
    assert result.agreement == "outcome_only"
    assert result.max_ordinal_gap == 1
    (disagreement,) = [
        item
        for item in report.disagreements
        if item.session_id == session.id and item.criterion_id == "RQ-001"
    ]
    assert disagreement.score_disagreement
    assert disagreement.max_ordinal_gap == 1

    paths = export_report(report, tmp_path / "ordinal")
    exported = BatchReport.model_validate_json(paths[0].read_text())
    exported_result = next(
        item
        for item in exported.effective_results
        if item.session_id == session.id and item.criterion_id == "RQ-001"
    )
    assert exported_result.reviewer_scores == {"Alice": 1.0, "Bob": 0.8}
    csv_text = paths[2].read_text()
    assert "Alice=excellent" in csv_text and "Bob=solid" in csv_text
    assert "Alice=1" in csv_text and "Bob=0.8" in csv_text

    # No effective number is invented while the disagreement is unresolved.
    assert exported_result.effective_score is None
    assert exported_result.effective_outcome is None
