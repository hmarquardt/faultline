"""Keyboard-first Textual client. Business rules stay in Workbench."""

from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from faultline.bootstrap import seed_defaults
from faultline.domain import EndpointProfile, Report
from faultline.reports import export_report
from faultline.rubrics import import_rubric
from faultline.service import Workbench
from faultline.techniques import techniques


class FaultlineApp(App):
    TITLE = "Faultline · authorized evaluation workbench"
    CSS = """
    Screen { min-width: 60; }
    TabPane { padding: 1; }
    Select, Input { margin-bottom: 1; }
    .row { height: auto; }
    .row > * { margin-right: 1; }
    .row > Input, .row > Select { width: 1fr; min-width: 8; }
    Button { margin-bottom: 1; }
    #status { height: auto; min-height: 2; padding: 1; background: $boost; }
    #inspection { height: auto; margin-bottom: 1; }
    .response { width: 1fr; height: 12; }
    #results { height: 12; }
    #history-table { height: 1fr; }
    """
    BINDINGS = [
        ("ctrl+r", "run_experiment", "Run"),
        ("ctrl+d", "dry_run", "Dry run"),
        ("ctrl+e", "export", "Export"),
        ("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self, workbench: Workbench) -> None:
        super().__init__()
        self.workbench = workbench
        seed_defaults(workbench.store)
        self.current_report: Report | None = None
        self.busy = False

    def compose(self) -> ComposeResult:
        profiles = self.workbench.store.profiles()
        rubrics = self.workbench.store.rubrics()
        yield Header()
        with TabbedContent():
            with TabPane("Workbench", id="workbench"), VerticalScroll():
                yield Label("Endpoint profile (network remains disabled until explicitly allowed)")
                yield Select(
                    [(Text(p.name), p.id) for p in profiles],
                    value=profiles[0].id,
                    allow_blank=False,
                    id="profile",
                )
                with Horizontal(classes="row"):
                    yield Input(placeholder="New mock profile name", id="profile-name")
                    yield Select(
                        [("Secure mock", "secure"), ("Vulnerable mock", "vulnerable")],
                        value="secure",
                        allow_blank=False,
                        id="behavior",
                    )
                    yield Button("Create mock", id="create-profile")
                yield Label("Rubric")
                yield Select(
                    self.rubric_options(), value=rubrics[0].id, allow_blank=False, id="rubric"
                )
                with Horizontal(classes="row"):
                    yield Input(
                        placeholder="Local JSON/YAML/Markdown/text rubric path",
                        id="rubric-path",
                    )
                    yield Button("Import rubric", id="import-rubric")
                yield Label("Technique")
                yield Select(
                    [(t.name, t.id) for t in techniques().values()],
                    value="authority-spoof",
                    allow_blank=False,
                    id="technique",
                )
                yield Static("", id="inspection", markup=False)
                yield Input(value="FAULTLINE_SYNTHETIC_CANARY_7D4C", id="canary")
                yield Checkbox(
                    "Allow requests to the selected authorized network endpoint", id="network"
                )
                with Horizontal(classes="row"):
                    yield Button("Run baseline + attack", id="run", variant="primary")
                    yield Button("Dry run", id="dry-run")
                    yield Button("Test endpoint", id="test-endpoint")
                yield Static(
                    "Ready. Default mocks are entirely offline.", id="status", markup=False
                )
                yield Label("Baseline (left) / attack (right) · exact response text")
                with Horizontal(classes="row"):
                    yield TextArea(read_only=True, id="baseline", classes="response")
                    yield TextArea(read_only=True, id="attack", classes="response")
                yield DataTable(id="results", cursor_type="row")
                yield Label("Selected criterion evidence and scoring rationale")
                yield TextArea(read_only=True, id="evidence")
                with Horizontal(classes="row"):
                    yield Input(value="reports", placeholder="Export directory", id="export-path")
                    yield Button("Export JSON + Markdown", id="export")
            with TabPane("History", id="history"):
                yield Label("Enter a row to load its saved responses and evidence")
                yield DataTable(id="history-table", cursor_type="row")
                yield Button("Refresh history", id="refresh-history")
        yield Footer()

    def rubric_options(self) -> list[tuple[Text, str]]:
        return [
            (
                Text(
                    f"{r.definition.title if r.definition else 'Needs normalization'} "
                    f"[{r.review_status}]"
                ),
                r.id,
            )
            for r in self.workbench.store.rubrics()
        ]

    def on_mount(self) -> None:
        self.query_one("#results", DataTable).add_columns(
            "Case", "Criterion", "Outcome", "Score", "Rationale"
        )
        self.query_one("#history-table", DataTable).add_columns(
            "ID", "Status", "Experiment", "Created UTC"
        )
        self.refresh_history()
        self.inspect_selection()

    def status(self, text: str) -> None:
        self.query_one("#status", Static).update(text)

    def inspect_selection(self) -> None:
        value = self.query_one("#technique", Select).value
        if value == Select.BLANK:
            return
        technique = techniques()[str(value)]
        profile_id = self.query_one("#profile", Select).value
        profile = self.workbench.store.profile(str(profile_id))
        self.query_one("#inspection", Static).update(
            f"{technique.id}@{technique.version} · {technique.family}\n{technique.description}\n"
            f"Target: {profile.allowed_models[0]} · {profile.base_url or 'offline mock'}\n"
            "Budget: 2 requests · 128 output tokens each · 256 total · 30s/request. "
            "Use the CLI for custom models, generation settings and budgets."
        )

    @on(Select.Changed, "#technique")
    @on(Select.Changed, "#profile")
    def selection_changed(self) -> None:
        self.inspect_selection()

    @on(Button.Pressed, "#create-profile")
    def create_profile(self) -> None:
        name = self.query_one("#profile-name", Input).value.strip()
        if not name:
            self.status("Enter a name for the new mock profile.")
            return
        profile = EndpointProfile(
            name=name, authorized=True, mock_behavior=str(self.query_one("#behavior", Select).value)
        )
        self.workbench.store.add_profile(profile)
        select = self.query_one("#profile", Select)
        select.set_options([(Text(p.name), p.id) for p in self.workbench.store.profiles()])
        select.value = profile.id
        self.status("Mock profile created and selected.")

    @on(Button.Pressed, "#import-rubric")
    def import_selected_rubric(self) -> None:
        try:
            rubric = import_rubric(Path(self.query_one("#rubric-path", Input).value).expanduser())
            self.workbench.store.add_rubric(rubric)
            select = self.query_one("#rubric", Select)
            select.set_options(self.rubric_options())
            select.value = rubric.id
            self.status(
                f"Imported: {rubric.review_status}. Use review-rubric in the CLI for normalization."
            )
        except Exception:
            self.status(
                "Rubric import failed. Check the path, UTF-8 encoding and structured schema."
            )

    @on(Button.Pressed, "#run")
    def run_pressed(self) -> None:
        self.action_run_experiment()

    @on(Button.Pressed, "#dry-run")
    def dry_pressed(self) -> None:
        self.action_dry_run()

    @on(Button.Pressed, "#test-endpoint")
    def test_pressed(self) -> None:
        self.execute_selected(connection_test=True)

    def action_run_experiment(self) -> None:
        self.execute_selected()

    def action_dry_run(self) -> None:
        self.execute_selected(dry_run=True)

    @work(group="execution")
    async def execute_selected(self, dry_run: bool = False, connection_test: bool = False) -> None:
        if self.busy:
            return
        self.busy = True
        for selector in ("#run", "#dry-run", "#test-endpoint"):
            self.query_one(selector, Button).disabled = True
        try:
            profile = self.workbench.store.profile(str(self.query_one("#profile", Select).value))
            rubric = self.workbench.store.rubric(str(self.query_one("#rubric", Select).value))
            experiment = self.workbench.prepare(
                profile,
                rubric,
                str(self.query_one("#technique", Select).value),
                parameters={"canary": self.query_one("#canary", Input).value},
                dry_run=dry_run,
                allow_network=self.query_one("#network", Checkbox).value,
                connection_test=connection_test,
            )
            self.status("Executing bounded experiment…" if not dry_run else "Saving dry-run plan…")
            report = await self.workbench.execute(experiment)
            self.show_report(report)
            self.refresh_history()
        except Exception:
            self.status(
                "Cannot execute. Check authorization, network opt-in, synthetic canary, "
                "credentials and rubric review state. History preserves partial attempts."
            )
        finally:
            self.busy = False
            for selector in ("#run", "#dry-run", "#test-endpoint"):
                self.query_one(selector, Button).disabled = False

    def show_report(self, report: Report) -> None:
        self.current_report = report
        self.query_one("#baseline", TextArea).load_text("")
        self.query_one("#attack", TextArea).load_text("")
        self.query_one("#evidence", TextArea).load_text("")
        table = self.query_one("#results", DataTable)
        table.clear()
        for run in report.runs:
            self.query_one(f"#{run.case.kind}", TextArea).load_text(
                run.response.text if run.response else run.error or run.status
            )
            for value in run.evaluations:
                table.add_row(
                    run.case.kind,
                    Text(value.criterion_id),
                    value.outcome,
                    str(value.score),
                    Text(value.rationale),
                    key=value.id,
                )
        self.status(
            f"{report.experiment.status} · {report.experiment.id} · "
            f"{len(report.findings)} findings · "
            f"{'SIMULATED' if report.experiment.endpoint.provider == 'mock' else 'REAL ENDPOINT'}"
        )

    @on(DataTable.RowHighlighted, "#results")
    def inspect_evidence(self, event: DataTable.RowHighlighted) -> None:
        if not self.current_report:
            return
        for run in self.current_report.runs:
            for value in run.evaluations:
                if value.id == event.row_key.value:
                    artifacts = [
                        a.model_dump_json(indent=2)
                        for a in run.evidence
                        if a.id in value.evidence_ids
                    ]
                    self.query_one("#evidence", TextArea).load_text(
                        value.model_dump_json(indent=2) + "\n\n" + "\n".join(artifacts)
                    )

    @on(Button.Pressed, "#refresh-history")
    def refresh_history(self) -> None:
        table = self.query_one("#history-table", DataTable)
        table.clear()
        for experiment in self.workbench.store.history():
            table.add_row(
                experiment.id,
                experiment.status,
                Text(experiment.name),
                experiment.created_at.isoformat(),
                key=experiment.id,
            )

    @on(DataTable.RowSelected, "#history-table")
    def load_history(self, event: DataTable.RowSelected) -> None:
        # Remove focus from the old pane before switching: otherwise Textual's
        # descendant-focus watcher can reactivate History during table refresh.
        self.screen.set_focus(None)
        self.show_report(self.workbench.report(str(event.row_key.value)))
        self.query_one(TabbedContent).active = "workbench"
        self.call_after_refresh(self.query_one("#results", DataTable).focus)

    @on(Button.Pressed, "#export")
    def export_pressed(self) -> None:
        self.action_export()

    def action_export(self) -> None:
        if not self.current_report:
            self.status("Run an experiment or select a saved history row first.")
            return
        try:
            prefix = Path(self.query_one("#export-path", Input).value).expanduser()
            paths = export_report(self.current_report, prefix / self.current_report.experiment.id)
            self.status("Exported: " + " and ".join(str(p) for p in paths))
        except (ValueError, OSError):
            self.status("Export failed. Choose a writable directory without existing report files.")
