from pathlib import Path

from textual.widgets import DataTable, Input, Select, Static, TabbedContent, TextArea

from faultline.rubrics import import_rubric, sample_rubric
from faultline.tui import FaultlineApp


async def test_tui_run_compare_evidence_export_and_history(workbench, tmp_path):
    app = FaultlineApp(workbench)
    async with app.run_test(size=(130, 55)) as pilot:
        # Selection is a real saved profile; execution uses the same core as CLI.
        vulnerable = next(p for p in workbench.store.profiles() if p.mock_behavior == "vulnerable")
        app.query_one("#profile", Select).value = vulnerable.id
        app.query_one("#export-path", Input).value = str(tmp_path / "reports")
        await pilot.press("ctrl+r")
        await app.workers.wait_for_complete()
        await pilot.pause()
        report = app.current_report
        assert report is not None
        assert app.query_one("#baseline", TextArea).text == "SAFE"
        assert app.query_one("#attack", TextArea).text == "FAULTLINE_SYNTHETIC_CANARY_7D4C"
        assert app.query_one("#results", DataTable).row_count == 4
        app.query_one("#results", DataTable).focus()
        await pilot.press("down")
        await pilot.pause()
        assert "evidence_ids" in app.query_one("#evidence", TextArea).text
        await pilot.press("ctrl+e")
        assert (tmp_path / "reports" / f"{report.experiment.id}.json").exists()
        # Load through the actual history row event.
        app.query_one(TabbedContent).active = "history"
        await pilot.pause()
        app.query_one("#history-table", DataTable).focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert app.query_one(TabbedContent).active == "workbench"
        assert app.current_report.experiment.id == report.experiment.id


async def test_tui_create_profile_import_and_dry_run(workbench, tmp_path):
    app = FaultlineApp(workbench)
    async with app.run_test(size=(120, 50)) as pilot:
        app.query_one("#profile-name", Input).value = "Tester-created mock"
        await pilot.click("#create-profile")
        await pilot.pause()
        profile = workbench.store.profile(str(app.query_one("#profile", Select).value))
        assert profile.name == "Tester-created mock"
        assert profile.authorized
        source = tmp_path / "rubric.json"
        source.write_text(workbench.store.rubrics()[0].source.content)
        app.query_one("#rubric-path", Input).value = str(source)
        await pilot.click("#import-rubric")
        await pilot.pause()
        assert len(workbench.store.rubrics()) == 2
        # The reviewer workbench offers the freshly imported rubric too.
        imported = workbench.store.rubrics()[-1]
        review = app.query_one("#review-rubric", Select)
        review.value = imported.id
        await pilot.pause()
        assert review.value == imported.id
        await pilot.press("ctrl+d")
        await app.workers.wait_for_complete()
        assert app.current_report.experiment.status == "dry_run"
        assert app.query_one("#history-table", DataTable).row_count == 1


async def test_tui_reviewer_workbench_records_review_and_adjudication(workbench):
    # Seed the packaged rubric first so it stays the default selection.
    workbench.store.add_rubric(sample_rubric())
    graded = import_rubric(
        Path(__file__).parent / "fixtures" / "rubrics" / "graded-disclosure.v2.json"
    )
    workbench.store.add_rubric(graded)
    app = FaultlineApp(workbench)
    async with app.run_test(size=(150, 60)) as pilot:
        vulnerable = next(p for p in workbench.store.profiles() if p.mock_behavior == "vulnerable")
        app.query_one("#profile", Select).value = vulnerable.id
        await pilot.press("ctrl+r")
        await app.workers.wait_for_complete()
        await pilot.pause()
        report = app.current_report
        assert report is not None
        attack = report.runs[1]

        app.query_one(TabbedContent).active = "review"
        await pilot.pause()
        app.query_one("#review-run", Select).value = attack.id
        await pilot.pause()
        execution_session = next(
            session for session in report.evaluation_sessions if session.run_id == attack.id
        )
        assert app.query_one("#review-session", Select).value == execution_session.id
        criteria = app.query_one("#review-criteria", DataTable)
        assert criteria.row_count == 2
        # The workbench shows the complete original criterion wording and evidence.
        assert app.review_criterion_id == "CONF-001"
        assert "exact synthetic canary" in str(app.query_one("#review-wording", Static).content)
        assert "Response (attack)" in app.query_one("#review-evidence", TextArea).text

        # Reevaluate the saved response with the graded rubric without a new request.
        app.query_one("#review-rubric", Select).value = graded.id
        await pilot.pause()
        await pilot.click("#review-reevaluate")
        await pilot.pause()
        sessions = workbench.store.sessions(run_id=attack.id)
        assert [session.origin for session in sessions] == ["execution", "reevaluation"]
        assert app.review_session_id == sessions[1].id
        assert "0 criterion awaiting adjudication" in str(
            app.query_one("#review-disagreements", Static).content
        )
        assert "2.0.0" in str(app.query_one("#review-summary", Static).content)

        # Move to the ordinal criterion and record an append-only judgment.
        app.query_one("#review-criteria", DataTable).move_cursor(row=0)
        await pilot.pause()
        app.query_one("#review-reviewer", Input).value = "TUI reviewer"
        app.query_one("#review-outcome", Select).value = "fail"
        app.query_one("#review-label", Input).value = "partial-fragment"
        app.query_one("#review-rationale", TextArea).text = "A contiguous fragment appears"
        await pilot.press("ctrl+j")
        await pilot.pause()
        judgments = workbench.store.judgments(session_id=sessions[1].id)
        assert [(j.reviewer, j.label, j.score) for j in judgments] == [
            ("TUI reviewer", "partial-fragment", 0.4)
        ]
        assert "0 unresolved disagreement(s)" in str(
            app.query_one("#review-disagreements", Static).content
        )
        assert "1 criterion awaiting adjudication" in str(
            app.query_one("#review-disagreements", Static).content
        )
        # No effective outcome appears from a lone judgment.
        pending = next(
            result
            for result in app.current_report.effective_results
            if result.session_id == sessions[1].id and result.criterion_id == "CONF-101"
        )
        assert pending.status == "awaiting_human_review"
        assert pending.effective_outcome is None

        # Revising the same reviewer's judgment appends a linked record.
        first = judgments[0]
        app.query_one("#review-label", Input).value = "full-disclosure"
        app.query_one("#review-supersedes", Input).value = first.id
        app.query_one("#review-rationale", TextArea).text = "The whole canary was reproduced"
        await pilot.press("ctrl+j")
        await pilot.pause()
        revised = workbench.store.judgments(session_id=sessions[1].id)
        assert [j.id for j in revised[:1]] == [first.id]
        assert [(j.label, j.supersedes_id) for j in revised] == [
            ("partial-fragment", None),
            ("full-disclosure", first.id),
        ]
        assert first.id in str(app.query_one("#review-judgments", Static).content)

        # Adjudicate explicitly; the effective result then appears in the table.
        app.query_one("#review-policy", Select).value = "single_reviewer"
        app.query_one("#review-designated", Input).value = "TUI reviewer"
        app.query_one("#review-adjudication", Input).value = "Designated reviewer decision"
        await pilot.press("ctrl+a")
        await pilot.pause()
        adjudications = workbench.store.adjudications(session_id=sessions[1].id)
        assert [(a.criterion_id, a.status) for a in adjudications] == [("CONF-101", "agreed")]
        effective = next(
            result
            for result in app.current_report.effective_results
            if result.session_id == sessions[1].id and result.criterion_id == "CONF-101"
        )
        assert (effective.status, effective.effective_outcome) == ("human_assessed", "fail")
        assert "Adjudicated" in str(app.query_one("#review-status", Static).content)
