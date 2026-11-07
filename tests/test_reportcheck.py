"""Report validation: an export may not claim more than its evidence supports."""

import asyncio
import json
from pathlib import Path

from faultline.reportcheck import validate_export
from faultline.reports import export_report


def export_controlled(workbench, tmp_path):
    experiment = workbench.plan_experiment("retrieved-authority-spoof", trial_count=1)
    asyncio.run(workbench.execute_experiment(experiment.id))
    prefix = tmp_path / "experiment"
    export_report(workbench.experiment_report(experiment.id), prefix)
    return prefix.with_suffix(".json")


def rewrite(path: Path, mutate) -> Path:
    payload = json.loads(path.read_text())
    mutate(payload)
    path.write_text(json.dumps(payload, indent=2))
    return path


def codes(finding):
    return {issue.code for issue in finding.issues}


def test_valid_controlled_export_passes(workbench, tmp_path):
    path = export_controlled(workbench, tmp_path)
    finding = validate_export(path)
    assert finding.origin == "controlled_experiment"
    assert finding.report_format_version == "2.2.0"
    assert finding.errors == []
    assert finding.checks_run >= 6
    assert finding.report_id


def test_valid_agentic_and_comparison_exports_pass(workbench, tmp_path):
    trace = asyncio.run(workbench.run_scenario("tool-output-laundering"))
    agentic = tmp_path / "agentic"
    export_report(workbench.agentic_report(trace.id), agentic)
    assert validate_export(agentic.with_suffix(".json")).errors == []

    comparison = workbench.plan_model_comparison(
        "retrieved-authority-spoof",
        [{"agent": "scripted-vulnerable"}, {"agent": "scripted-secure"}],
        trials=1,
    )
    asyncio.run(workbench.execute_model_comparison(comparison.id))
    multi = tmp_path / "comparison"
    export_report(workbench.comparison_report(comparison.id), multi)
    finding = validate_export(multi.with_suffix(".json"))
    assert finding.origin == "model_comparison"
    assert finding.errors == []


def test_benign_export_passes(workbench, tmp_path):
    from faultline.rubrics import sample_rubric

    rubric = sample_rubric()
    workbench.store.add_rubric(rubric)
    dataset = workbench.import_dataset(Path("tests/fixtures/datasets/reviewed-batch.json"))
    batch = workbench.create_batch(dataset.id, rubric)
    workbench.execute_batch(batch.id)
    prefix = tmp_path / "batch"
    export_report(workbench.batch_report(batch.id), prefix)
    finding = validate_export(prefix.with_suffix(".json"))
    assert finding.origin == "dataset_import"
    assert finding.errors == []


def test_tampered_digest_is_detected(workbench, tmp_path):
    path = export_controlled(workbench, tmp_path)
    rewrite(path, lambda payload: payload["summary"]["criteria"][0].update({"pass_pass": 9}))
    finding = validate_export(path)
    assert "digest-mismatch" in codes(finding)
    assert finding.ok is False


def test_inflated_denominator_is_detected(workbench, tmp_path):
    path = export_controlled(workbench, tmp_path)

    def mutate(payload):
        criterion = payload["summary"]["criteria"][0]
        criterion["complete_pairs"] = 5
        criterion["control_trials"] = 1
        criterion["attack_trials"] = 1
        payload.pop("export_digest")

    rewrite(path, mutate)
    finding = validate_export(path)
    assert "denominator-inconsistent" in codes(finding)
    assert any(issue.severity == "blocking" for issue in finding.issues)


def test_transition_total_mismatch_is_detected(workbench, tmp_path):
    path = export_controlled(workbench, tmp_path)

    def mutate(payload):
        payload["summary"]["criteria"][0]["pass_fail"] = 7
        payload.pop("export_digest")

    rewrite(path, mutate)
    assert "transition-total-mismatch" in codes(validate_export(path))


def test_interval_outside_its_estimate_is_detected(workbench, tmp_path):
    path = export_controlled(workbench, tmp_path)

    def mutate(payload):
        interval = payload["summary"]["criteria"][0]["paired_difference_interval"]
        interval["low"] = 0.9
        interval["high"] = 1.0
        interval["estimate"] = -0.5
        payload.pop("export_digest")

    rewrite(path, mutate)
    assert "interval-excludes-estimate" in codes(validate_export(path))


def test_effect_without_execution_is_detected(workbench, tmp_path):
    path = export_controlled(workbench, tmp_path)

    def mutate(payload):
        for trial in payload["trials"]:
            attack = trial.get("attack")
            if attack:
                attack["state_changes"] = ["note-written:forged"]
                attack["executed_tools"] = []
                break
        payload.pop("export_digest")

    rewrite(path, mutate)
    assert "effect-without-execution" in codes(validate_export(path))


def test_missing_trace_reference_is_detected(workbench, tmp_path):
    path = export_controlled(workbench, tmp_path)

    def mutate(payload):
        payload["trace_ids"] = payload["trace_ids"][:1]
        payload.pop("export_digest")

    rewrite(path, mutate)
    assert "trace-not-listed" in codes(validate_export(path))


def test_simulation_labelling_is_required(workbench, tmp_path):
    path = export_controlled(workbench, tmp_path)

    def mutate(payload):
        payload["limitations"] = ["Results are reported for this experiment only."]
        payload.pop("export_digest")

    rewrite(path, mutate)
    assert "simulation-labelling-missing" in codes(validate_export(path))


def test_network_claim_without_opt_in_is_detected(workbench, tmp_path):
    path = export_controlled(workbench, tmp_path)

    def mutate(payload):
        payload["experiment"]["target"]["agent"] = "endpoint"
        payload["experiment"]["allow_network"] = False
        payload.pop("export_digest")

    rewrite(path, mutate)
    assert "network-claim-without-opt-in" in codes(validate_export(path))


def test_credential_shaped_string_is_detected_without_echo(workbench, tmp_path):
    path = export_controlled(workbench, tmp_path)
    planted = "sk-live-should-never-appear"

    def mutate(payload):
        payload["experiment"]["notes"] = [planted]
        payload.pop("export_digest")

    rewrite(path, mutate)
    finding = validate_export(path)
    assert "credential-pattern" in codes(finding)
    assert planted not in finding.model_dump_json()


def test_csv_formula_injection_is_detected(workbench, tmp_path):
    path = export_controlled(workbench, tmp_path)
    csv_path = path.with_suffix(".csv")
    rows = csv_path.read_text().splitlines()
    rows[1] = "=cmd|' /C calc'!A0," + rows[1]
    csv_path.write_text("\n".join(rows) + "\n")
    assert "csv-formula-injection" in codes(validate_export(path))


def test_neutralised_csv_is_accepted(workbench, tmp_path):
    path = export_controlled(workbench, tmp_path)
    csv_path = path.with_suffix(".csv")
    rows = csv_path.read_text().splitlines()
    rows[1] = "'" + rows[1]
    csv_path.write_text("\n".join(rows) + "\n")
    assert "csv-formula-injection" not in codes(validate_export(path))


def test_unreadable_and_invalid_documents_are_reported(tmp_path):
    missing = validate_export(tmp_path / "absent.json")
    assert missing.errors and missing.errors[0].code == "unreadable"
    broken = tmp_path / "broken.json"
    broken.write_text("not json")
    assert validate_export(broken).errors[0].code == "not-json"
    array = tmp_path / "array.json"
    array.write_text("[1, 2, 3]")
    assert validate_export(array).errors[0].code == "not-an-object"


def test_unknown_origin_and_format_are_rejected(tmp_path):
    document = tmp_path / "unknown.json"
    document.write_text(json.dumps({"report_format_version": "9.9.9"}))
    finding = validate_export(document)
    assert {"origin-unknown", "format-version-unsupported"} <= codes(finding)
