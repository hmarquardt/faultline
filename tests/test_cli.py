import json
from pathlib import Path

import pytest

from faultline.cli import main
from faultline.domain import Report
from faultline.service import Workbench
from faultline.storage import Store


def invoke(monkeypatch, capsys, db, *arguments):
    monkeypatch.setattr("sys.argv", ["faultline", "--db", str(db), *map(str, arguments)])
    main()
    return capsys.readouterr().out


def test_cli_demo_history_export_override_and_schema(tmp_path, monkeypatch, capsys):
    db = tmp_path / "cli.sqlite3"
    prefix = tmp_path / "vulnerable"
    output = invoke(monkeypatch, capsys, db, "demo", "--behavior", "vulnerable", "--output", prefix)
    report = Report.model_validate_json(prefix.with_suffix(".json").read_text())
    assert "2 findings" in output
    history = invoke(monkeypatch, capsys, db, "history")
    assert report.experiment.id in history
    assert report.experiment.endpoint.id in invoke(monkeypatch, capsys, db, "profiles")
    invoke(
        monkeypatch,
        capsys,
        db,
        "override",
        report.runs[1].evaluations[0].id,
        "--outcome",
        "uncertain",
        "--reviewer",
        "Human",
        "--rationale",
        "Review pending",
    )
    invoke(
        monkeypatch, capsys, db, "export", report.experiment.id, "--output", tmp_path / "reviewed"
    )
    reviewed = Report.model_validate_json((tmp_path / "reviewed.json").read_text())
    assert reviewed.human_overrides[0].reviewer == "Human"
    assert reviewed.runs == report.runs
    invoke(monkeypatch, capsys, db, "schemas", tmp_path / "schemas")
    assert (
        json.loads((tmp_path / "schemas" / "EndpointProfile.json").read_text())["title"]
        == "EndpointProfile"
    )


def test_cli_profile_rubric_import_review_dry_run_and_connection_test(
    tmp_path, monkeypatch, capsys
):
    db = tmp_path / "cli.sqlite3"
    profile_id = invoke(monkeypatch, capsys, db, "add-profile", "Tester", "--authorize").strip()
    source = tmp_path / "notes.md"
    source.write_text("Do not reveal the toy canary. Human normalization required.")
    output = invoke(monkeypatch, capsys, db, "import-rubric", source)
    rubric_id = output.split("\t")[0]
    assert "pending" in output
    invoke(
        monkeypatch,
        capsys,
        db,
        "review-rubric",
        rubric_id,
        "src/faultline/data/canary-rubric.v1.json",
        "--reviewer",
        "Alice",
        "--rationale",
        "Confirmed exact literal interpretation",
    )
    reviewed = next(r for r in Store(db).rubrics() if r.review_status == "reviewed")
    output = invoke(
        monkeypatch, capsys, db, "run", profile_id, "--rubric", reviewed.id, "--dry-run"
    )
    assert "dry_run" in output
    output = invoke(monkeypatch, capsys, db, "test-endpoint", profile_id)
    report = Workbench(Store(db)).report(output.split("\t")[0])
    assert len(report.runs) == 1
    assert report.runs[0].case.kind == "baseline"


def test_cli_policy_error_is_actionable(tmp_path, monkeypatch, capsys):
    db = tmp_path / "cli.sqlite3"
    profile_id = invoke(monkeypatch, capsys, db, "add-profile", "Unapproved").strip()
    with pytest.raises(SystemExit) as exc:
        invoke(monkeypatch, capsys, db, "run", profile_id)
    assert exc.value.code == 2
    assert "authorized scope" in capsys.readouterr().err


def test_cli_reevaluate_review_adjudicate_and_migrate(tmp_path, monkeypatch, capsys):
    db = tmp_path / "cli.sqlite3"
    prefix = tmp_path / "demo"
    invoke(monkeypatch, capsys, db, "demo", "--behavior", "vulnerable", "--output", prefix)
    report = Report.model_validate_json(prefix.with_suffix(".json").read_text())
    attack_run = report.runs[1].id

    source = Path(__file__).parent / "fixtures" / "rubrics" / "graded-disclosure.v2.json"
    graded_id = invoke(monkeypatch, capsys, db, "import-rubric", source).split("\t")[0]
    output = invoke(monkeypatch, capsys, db, "reevaluate", attack_run, "--rubric", graded_id)
    session_id, version, execution_sha = output.strip().split("\t")
    assert version == "2.0.0"
    assert len(execution_sha) == 64

    listing = invoke(monkeypatch, capsys, db, "sessions", "--run", attack_run)
    assert len(listing.strip().splitlines()) == 2
    assert "reevaluation" in listing

    judgment_id = invoke(
        monkeypatch,
        capsys,
        db,
        "judge",
        session_id,
        "CONF-101",
        "--outcome",
        "fail",
        "--label",
        "partial-fragment",
        "--reviewer",
        "Alice",
        "--rationale",
        "A prefix of the canary appears",
        "--confidence",
        "medium",
    ).strip()
    assert judgment_id
    output = invoke(
        monkeypatch,
        capsys,
        db,
        "adjudicate",
        session_id,
        "--policy",
        "single_reviewer",
        "--designated-reviewer",
        "Alice",
        "--reviewer",
        "Lead",
        "--rationale",
        "Designated reviewer decision",
    )
    assert "CONF-101" in output and output.split("\t")[2] in {"agreed", "adjudicated"}

    disputes = invoke(monkeypatch, capsys, db, "disagreements", report.experiment.id)
    assert disputes.strip() == ""
    invoke(monkeypatch, capsys, db, "export", report.experiment.id, "--output", tmp_path / "final")
    reviewed = Report.model_validate_json((tmp_path / "final.json").read_text())
    assert reviewed.human_judgments[0].reviewer == "Alice"
    assert any(
        item.status in {"confirmed", "overridden", "human_assessed"}
        for item in reviewed.effective_results
    )
    assert invoke(monkeypatch, capsys, db, "migrate").strip() == "schema_version\t3"


def test_cli_dataset_batch_agreement_and_conformance(tmp_path, monkeypatch, capsys):
    db = tmp_path / "cli.sqlite3"
    dataset_line = invoke(
        monkeypatch,
        capsys,
        db,
        "import-dataset",
        Path(__file__).parent / "fixtures" / "datasets" / "reviewed-batch.jsonl",
        "--title",
        "CLI batch",
    )
    dataset_id, count, version, digest = dataset_line.strip().split("\t")
    assert (count, version) == ("5", "1.0.0")
    assert len(digest) == 64
    assert dataset_id in invoke(monkeypatch, capsys, db, "datasets")
    records = invoke(monkeypatch, capsys, db, "dataset-records", dataset_id, "--limit", "2")
    assert len(records.strip().splitlines()) == 2

    rubric_id = invoke(
        monkeypatch, capsys, db, "import-rubric", "src/faultline/data/canary-rubric.v1.json"
    ).split("\t")[0]
    batch_line = invoke(
        monkeypatch, capsys, db, "create-batch", dataset_id, "--rubric", rubric_id, "--per-run", "2"
    )
    batch_id, status, planned = batch_line.strip().split("\t")
    assert (status, planned) == ("planned", "5")

    # --per-run 2 caps each pass, so resuming is explicit progress.
    first = invoke(monkeypatch, capsys, db, "run-batch", batch_id)
    assert "partial" in first and "pending=3" in first
    second = invoke(monkeypatch, capsys, db, "run-batch", batch_id)
    assert "partial" in second and "pending=1" in second
    resumed = invoke(monkeypatch, capsys, db, "run-batch", batch_id)
    assert "completed" in resumed and "pending=0" in resumed
    status_output = invoke(monkeypatch, capsys, db, "batch-status", batch_id)
    assert "completed\t4" in status_output and "skipped\t1" in status_output

    session_id = Workbench(Store(db)).store.sessions_for_dataset(dataset_id)[0].id
    invoke(
        monkeypatch,
        capsys,
        db,
        "judge",
        session_id,
        "CONF-001",
        "--outcome",
        "pass",
        "--reviewer",
        "Alice",
        "--rationale",
        "Literal check only",
    )
    agreement = invoke(monkeypatch, capsys, db, "agreement", "--batch", batch_id)
    payload = json.loads(agreement)
    assert payload["scope"] == "batch"
    assert payload["reviewers"] == ["Alice"]
    assert any(group["units_excluded_incomplete"] >= 1 for group in payload["groups"])

    invoke(
        monkeypatch,
        capsys,
        db,
        "batch-report",
        batch_id,
        "--output",
        tmp_path / "batch",
    )
    for suffix in (".json", ".md", ".csv"):
        assert (tmp_path / f"batch{suffix}").exists()
    exported = json.loads((tmp_path / "batch.json").read_text())
    assert exported["origin"] == "dataset_import"
    assert exported["dataset"]["id"] == dataset_id
    assert "experiment" not in exported

    conformance = invoke(
        monkeypatch,
        capsys,
        db,
        "rubric-conformance",
        "--pack",
        Path(__file__).parent / "fixtures" / "conformance" / "instruction-adherence.json",
    )
    assert "0 error(s)" in conformance
    assert '"code": "subjective-criterion"' in conformance
