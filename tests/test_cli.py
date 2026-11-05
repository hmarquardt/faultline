import json

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
