"""Local performance baseline: measured, reproducible, never asserted arbitrarily.

These tests build realistic local workloads, print the measurements so a run is
reproducible, and enforce only very generous ceilings so a regression of an order of
magnitude fails loudly while ordinary machine variance does not.
"""

import json
import time
from pathlib import Path

import pytest

from faultline.service import Workbench
from faultline.storage import Store


def dataset(path: Path, records: int) -> Path:
    lines = []
    for index in range(records):
        lines.append(
            json.dumps(
                {
                    "id": f"case-{index:04d}",
                    "prompt": f"Summarise synthetic notice {index}",
                    "response": (
                        f"Notice {index}: reference REF-{index}. The canary value is "
                        "FAULTLINE_SYNTHETIC_CANARY_7Q2."
                        if index % 5 == 0
                        else f"Notice {index}: reference REF-{index}."
                    ),
                    "provenance": "perf-fixture",
                }
            )
        )
    path.write_text("\n".join(lines) + "\n")
    return path


def measure(label: str, action):
    started = time.perf_counter()
    value = action()
    elapsed = time.perf_counter() - started
    print(f"PERF {label}\t{elapsed:.3f}s")
    return value, elapsed


@pytest.fixture
def bench(tmp_path):
    return Workbench(Store(tmp_path / "perf.sqlite3"))


def test_dataset_import_and_batch_evaluation_scale(bench, tmp_path):
    from faultline.rubrics import sample_rubric

    rubric = sample_rubric()
    bench.store.add_rubric(rubric)
    source = dataset(tmp_path / "records.jsonl", 300)
    dataset_value, import_seconds = measure("import-300", lambda: bench.import_dataset(source))
    assert dataset_value.record_count == 300
    batch = bench.create_batch(dataset_value.id, rubric)
    _, evaluate_seconds = measure("evaluate-300", lambda: bench.execute_batch(batch.id))
    report, report_seconds = measure("report-300", lambda: bench.batch_report(batch.id))
    # The default batch budget caps cases; assert the reported totals instead.
    assert report.progress.cases_total >= 200
    assert report.progress.cases_completed == report.progress.cases_total
    # Generous ceilings: an order-of-magnitude regression fails, normal variance does not.
    assert import_seconds < 10.0
    assert evaluate_seconds < 60.0
    assert report_seconds < 15.0
    print(
        f"PERF throughput\t{300 / max(evaluate_seconds, 1e-9):.1f} cases/s"
        f"\tdb={Path(bench.store.path).stat().st_size / 1024:.0f} KiB"
    )


def test_repeated_sessions_and_reviewers_scale(bench):
    from faultline.domain import AdjudicationPolicy

    experiment = bench.plan_experiment("retrieved-authority-spoof", trial_count=3)

    def run_experiment():
        import asyncio

        return asyncio.run(bench.execute_experiment(experiment.id))

    _, run_seconds = measure("controlled-3-trials", run_experiment)
    summary, summary_seconds = measure(
        "summary-3-trials", lambda: bench.experiment_summary(experiment.id)
    )
    report, report_seconds = measure(
        "experiment-report", lambda: bench.experiment_report(experiment.id)
    )
    assert summary.complete_pairs == 3
    assert report.trials
    trials = bench.store.trials(experiment.id)
    session = bench.store.sessions_for_traces(
        [trial.attack_trace_id for trial in trials if trial.attack_trace_id]
    )[0]
    criteria = session.rubric.definition.criteria
    for reviewer in ("Alice", "Bob", "Cleo"):
        for criterion in criteria:
            bench.record_judgment(
                session.id,
                criterion.id,
                reviewer=reviewer,
                outcome="pass",
                rationale="perf fixture",
            )
    agreement, agreement_seconds = measure(
        "agreement-3-reviewers", lambda: bench.agreement(trace_id=session.agentic_trace_id)
    )
    assert agreement.reviewers == ["Alice", "Bob", "Cleo"]
    bench.adjudicate(
        session.id,
        policy=AdjudicationPolicy(kind="unanimous"),
        reviewer="Alice",
        rationale="perf fixture",
    )
    assert run_seconds < 30.0
    assert summary_seconds < 10.0
    assert report_seconds < 15.0
    assert agreement_seconds < 10.0


def test_reopening_a_database_is_fast_and_intact(bench, tmp_path):
    bench.plan_experiment("retrieved-authority-spoof", trial_count=1)
    experiment = bench.store.controlled_experiments()[0]
    import asyncio

    asyncio.run(bench.execute_experiment(experiment.id))
    store = Store(bench.store.path)
    _, reopen_seconds = measure("reopen", lambda: store.controlled_experiments())
    assert reopen_seconds < 5.0
    assert store.schema_version == 6
