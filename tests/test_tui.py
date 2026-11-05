from textual.widgets import DataTable, Input, Select, TabbedContent, TextArea

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
        await pilot.press("ctrl+d")
        await app.workers.wait_for_complete()
        assert app.current_report.experiment.status == "dry_run"
        assert app.query_one("#history-table", DataTable).row_count == 1
