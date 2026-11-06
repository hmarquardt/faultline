"""Keyboard-first Textual client. Business rules stay in Workbench."""

from pathlib import Path

from pydantic import ValidationError
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
from faultline.domain import AdjudicationPolicy, AgentBudget, EndpointProfile, Report
from faultline.reports import export_report
from faultline.rubrics import import_rubric
from faultline.service import Workbench
from faultline.techniques import techniques


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


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
    #review-criteria { height: 10; }
    #review-wording { height: auto; min-height: 4; padding: 1; background: $boost; }
    #review-evidence { height: 8; }
    #review-rationale { height: 4; }
    #review-status { height: auto; min-height: 2; padding: 1; background: $boost; }
    #batch-summary, #batch-case-detail, #batch-status {
        height: auto;
        min-height: 2;
        padding: 1;
        background: $boost;
    }
    #batch-cases { height: 8; }
    #batch-rationale { height: 3; }
    #agentic-brief, #agentic-status { height: auto; min-height: 2; padding: 1; background: $boost; }
    #agentic-timeline { height: 10; }
    #agentic-turn-detail { height: auto; min-height: 3; padding: 1; background: $boost; }
    #agentic-criteria { height: 7; }
    #agentic-criterion-detail { height: auto; min-height: 3; padding: 1; background: $boost; }
    #agentic-rationale { height: 3; }
    """
    BINDINGS = [
        ("ctrl+r", "run_experiment", "Run"),
        ("ctrl+d", "dry_run", "Dry run"),
        ("ctrl+e", "export", "Export"),
        ("ctrl+j", "record_judgment", "Judge"),
        ("ctrl+a", "adjudicate", "Adjudicate"),
        ("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self, workbench: Workbench) -> None:
        super().__init__()
        self.workbench = workbench
        seed_defaults(workbench.store)
        self.current_report: Report | None = None
        self.review_session_id: str | None = None
        self.review_criterion_id: str | None = None
        self.current_batch_report = None
        self.batch_case_id: str | None = None
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
            with TabPane("Review", id="review"), VerticalScroll():
                yield Label("Saved execution (requires a completed baseline + attack run)")
                yield Select([], allow_blank=True, id="review-run", prompt="Choose a run")
                yield Select([], allow_blank=True, id="review-session", prompt="Choose a session")
                yield Label("Rubric for a new evaluation session")
                yield Select(self.rubric_options(), allow_blank=True, id="review-rubric")
                with Horizontal(classes="row"):
                    yield Button("Reevaluate offline", id="review-reevaluate")
                    yield Button("Start human session", id="review-start")
                yield Label("Criteria · automated, human and effective outcomes")
                yield Static("", id="review-summary", markup=False)
                yield DataTable(id="review-criteria", cursor_type="row")
                yield Static("", id="review-disagreements", markup=False)
                yield Label("Complete original criterion wording and scale")
                yield Static("", id="review-wording", markup=False)
                yield Label("Response evidence for the selected criterion")
                yield TextArea(read_only=True, id="review-evidence")
                yield Label("Human judgment (append-only; prior records are never replaced)")
                with Horizontal(classes="row"):
                    yield Input(placeholder="Reviewer name", id="review-reviewer")
                    yield Select(
                        [
                            ("Pass", "pass"),
                            ("Fail", "fail"),
                            ("Uncertain", "uncertain"),
                            ("Not applicable", "not_applicable"),
                        ],
                        value="pass",
                        allow_blank=False,
                        id="review-outcome",
                    )
                with Horizontal(classes="row"):
                    yield Input(placeholder="Level or category label (if any)", id="review-label")
                    yield Input(placeholder="Numeric score (ordered scales)", id="review-score")
                    yield Input(placeholder="Supersede your judgment ID", id="review-supersedes")
                yield TextArea(id="review-rationale")
                yield Button("Record judgment (Ctrl+J)", id="record-judgment")
                yield Static("", id="review-judgments", markup=False)
                yield Label("Adjudication (an explicit policy is required for an effective result)")
                with Horizontal(classes="row"):
                    yield Select(
                        [
                            ("Unanimous reviewers", "unanimous"),
                            ("Majority", "majority"),
                            ("Designated reviewer", "single_reviewer"),
                            ("First reviewer", "first_reviewer"),
                        ],
                        value="unanimous",
                        allow_blank=False,
                        id="review-policy",
                    )
                    yield Input(placeholder="Designated reviewer", id="review-designated")
                    yield Input(placeholder="Adjudication rationale", id="review-adjudication")
                yield Button("Adjudicate (Ctrl+A)", id="adjudicate")
                yield Static("No review session selected.", id="review-status", markup=False)
            with TabPane("Batch", id="batch"), VerticalScroll():
                yield Label("Dataset of prerecorded responses (nothing is dispatched)")
                with Horizontal(classes="row"):
                    yield Input(placeholder="Dataset .json/.jsonl path", id="dataset-path")
                    yield Button("Import dataset", id="import-dataset")
                yield Select([], allow_blank=True, id="batch-dataset", prompt="Choose a dataset")
                yield Label("Rubric for the batch")
                yield Select(self.rubric_options(), allow_blank=True, id="batch-rubric")
                with Horizontal(classes="row"):
                    yield Input(placeholder="Max cases", id="batch-max-cases")
                    yield Button("Create batch", id="create-batch")
                yield Select([], allow_blank=True, id="batch-select", prompt="Choose a batch")
                with Horizontal(classes="row"):
                    yield Input(placeholder="Cases per run", id="batch-limit")
                    yield Button("Run / resume", id="run-batch")
                    yield Input(value="reports", placeholder="Export directory", id="batch-export")
                    yield Button("Export report", id="export-batch")
                yield Static("No batch selected.", id="batch-summary", markup=False)
                yield DataTable(id="batch-cases", cursor_type="row")
                yield Static("", id="batch-case-detail", markup=False)
                yield Label("Criterion for review")
                yield Select([], allow_blank=True, id="batch-criterion")
                with Horizontal(classes="row"):
                    yield Input(placeholder="Reviewer name", id="batch-reviewer")
                    yield Select(
                        [
                            ("Pass", "pass"),
                            ("Fail", "fail"),
                            ("Uncertain", "uncertain"),
                            ("Not applicable", "not_applicable"),
                        ],
                        value="pass",
                        allow_blank=False,
                        id="batch-outcome",
                    )
                    yield Input(placeholder="Level or category label", id="batch-label")
                    yield Input(placeholder="Numeric score", id="batch-score")
                yield TextArea(id="batch-rationale")
                yield Button("Record judgment (Ctrl+J)", id="batch-record-judgment")
                with Horizontal(classes="row"):
                    yield Select(
                        [
                            ("Unanimous reviewers", "unanimous"),
                            ("Majority", "majority"),
                            ("Designated reviewer", "single_reviewer"),
                            ("First reviewer", "first_reviewer"),
                        ],
                        value="unanimous",
                        allow_blank=False,
                        id="batch-policy",
                    )
                    yield Input(placeholder="Designated reviewer", id="batch-designated")
                    yield Input(placeholder="Adjudication rationale", id="batch-adjudication")
                yield Button("Adjudicate (Ctrl+A)", id="batch-adjudicate")
                yield Static(
                    "Import a dataset, then plan and run a batch.",
                    id="batch-status",
                    markup=False,
                )
            with TabPane("Agentic", id="agentic"), VerticalScroll():
                yield Label("Synthetic agentic scenario (all tools run in a sandbox)")
                yield Select(
                    [(Text(s.title), s.id) for s in self.workbench.scenarios().values()],
                    allow_blank=False,
                    id="agentic-scenario",
                )
                with Horizontal(classes="row"):
                    yield Select(
                        [
                            ("Scripted secure", "scripted-secure"),
                            ("Scripted vulnerable", "scripted-vulnerable"),
                        ],
                        value="scripted-secure",
                        allow_blank=False,
                        id="agentic-agent",
                    )
                    yield Input(placeholder="Max requests", id="agentic-requests")
                    yield Input(placeholder="Max turns", id="agentic-turns-budget")
                    yield Input(placeholder="Max tool calls", id="agentic-tool-budget")
                with Horizontal(classes="row"):
                    yield Button("Dry run", id="agentic-dry")
                    yield Button("Run scenario", id="agentic-run")
                    yield Input(
                        value="reports", placeholder="Export directory", id="agentic-export-dir"
                    )
                    yield Button("Export report", id="agentic-export")
                yield Static(
                    "Select a scenario to inspect its objective.",
                    id="agentic-status",
                    markup=False,
                )
                yield Static("", id="agentic-brief", markup=False)
                yield DataTable(id="agentic-timeline", cursor_type="row")
                yield Static("", id="agentic-turn-detail", markup=False)
                yield DataTable(id="agentic-criteria", cursor_type="row")
                yield Static("", id="agentic-criterion-detail", markup=False)
                with Horizontal(classes="row"):
                    yield Input(placeholder="Reviewer name", id="agentic-reviewer")
                    yield Select(
                        [
                            ("Pass", "pass"),
                            ("Fail", "fail"),
                            ("Uncertain", "uncertain"),
                            ("Not applicable", "not_applicable"),
                        ],
                        value="pass",
                        allow_blank=False,
                        id="agentic-outcome",
                    )
                    yield Input(placeholder="Label", id="agentic-label")
                    yield Input(placeholder="Score", id="agentic-score")
                yield TextArea(id="agentic-rationale")
                yield Button("Record judgment (Ctrl+J)", id="agentic-judge")
                with Horizontal(classes="row"):
                    yield Select(
                        [
                            ("Unanimous reviewers", "unanimous"),
                            ("Majority", "majority"),
                            ("Designated reviewer", "single_reviewer"),
                        ],
                        value="unanimous",
                        allow_blank=False,
                        id="agentic-policy",
                    )
                    yield Input(placeholder="Designated reviewer", id="agentic-designated")
                    yield Input(placeholder="Adjudication rationale", id="agentic-adjudication")
                yield Button("Adjudicate (Ctrl+A)", id="agentic-adjudicate")
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
        self.query_one("#review-criteria", DataTable).add_columns(
            "Criterion", "Automated", "Human", "Effective", "Status"
        )
        self.query_one("#history-table", DataTable).add_columns(
            "ID", "Status", "Experiment", "Created UTC"
        )
        self.query_one("#batch-cases", DataTable).add_columns(
            "Case", "Status", "Automated", "Effective"
        )
        self.refresh_history()
        self.inspect_selection()
        self.refresh_review()
        rubric_select = self.query_one("#batch-rubric", Select)
        options = self.rubric_options()
        if options and rubric_select.value is Select.BLANK:
            rubric_select.value = options[0][1]
        self.refresh_batches()

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
            options = self.rubric_options()
            select = self.query_one("#rubric", Select)
            select.set_options(options)
            select.value = rubric.id
            # Keep the reviewer workbench able to pick the newly imported rubric.
            review = self.query_one("#review-rubric", Select)
            previous = review.value
            review.set_options(options)
            if previous is not Select.BLANK:
                review.value = previous
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
        self.refresh_review()

    # --- Reviewer workbench --------------------------------------------------

    def review_status(self, text: str) -> None:
        self.query_one("#review-status", Static).update(text)

    def refresh_review(self, session_id: str | None = None) -> None:
        report = self.current_report
        runs = [run for run in (report.runs if report else []) if run.status == "completed"]
        select = self.query_one("#review-run", Select)
        previous = select.value
        select.set_options([(Text(f"{run.case.kind} · {run.id}"), run.id) for run in runs])
        known = {run.id for run in runs}
        if previous in known:
            select.value = previous
        else:
            select.value = runs[0].id if runs else Select.BLANK
        self.review_session_id = session_id
        self.review_criterion_id = None
        self.refresh_sessions()

    def refresh_sessions(self) -> None:
        report = self.current_report
        run_id = self.query_one("#review-run", Select).value
        sessions = [
            session
            for session in (report.evaluation_sessions if report else [])
            if session.run_id == run_id
        ]
        select = self.query_one("#review-session", Select)
        select.set_options(
            [
                (
                    Text(
                        f"{session.origin} · {session.rubric.definition.version}"
                        if session.rubric.definition
                        else session.origin
                    )
                    + Text(f" · {session.id}"),
                    session.id,
                )
                for session in sessions
            ]
        )
        known = {session.id for session in sessions}
        chosen = (
            self.review_session_id
            if self.review_session_id in known
            else (sessions[0].id if sessions else None)
        )
        select.value = chosen if chosen else Select.BLANK
        self.select_session(chosen)

    def select_session(self, session_id: str | None) -> None:
        self.review_session_id = session_id
        self.review_criterion_id = None
        table = self.query_one("#review-criteria", DataTable)
        table.clear()
        indicator = self.query_one("#review-disagreements", Static)
        summary = self.query_one("#review-summary", Static)
        judgments_panel = self.query_one("#review-judgments", Static)
        if not session_id or self.current_report is None:
            self.query_one("#review-wording", Static).update("")
            self.query_one("#review-evidence", TextArea).load_text("")
            indicator.update("No review session selected.")
            summary.update("")
            judgments_panel.update("")
            self.review_status("No review session selected.")
            return
        results = [
            result
            for result in self.current_report.effective_results
            if result.session_id == session_id
        ]
        for result in results:
            humans = ", ".join(
                f"{reviewer}={outcome}" for reviewer, outcome in result.reviewer_outcomes.items()
            )
            table.add_row(
                Text(result.criterion_id),
                result.automated_outcome or "none",
                humans or "none",
                result.effective_outcome or "none",
                result.status,
                key=result.criterion_id,
            )
        if results:
            table.move_cursor(row=0)
            self.show_criterion(results[0].criterion_id)
        unresolved = [
            item for item in self.current_report.disagreements if item.session_id == session_id
        ]
        awaiting = [result for result in results if result.status == "awaiting_human_review"]
        indicator.update(
            f"{len(unresolved)} unresolved disagreement(s) · "
            f"{len(awaiting)} criterion awaiting adjudication"
        )
        session = next(
            (item for item in self.current_report.evaluation_sessions if item.id == session_id),
            None,
        )
        if session is not None and session.rubric.definition is not None:
            definition = session.rubric.definition
            summary.update(
                f"Session {session.id} · {session.origin} · {session.status} · "
                f"rubric {definition.id}@{definition.version} · "
                f"evaluator {session.evaluator} · execution {session.execution_sha256[:12]}"
            )
        else:
            summary.update(f"Session {session_id}")

    def show_criterion(self, criterion_id: str) -> None:
        report = self.current_report
        if report is None or not self.review_session_id:
            return
        session = next(
            (item for item in report.evaluation_sessions if item.id == self.review_session_id),
            None,
        )
        if session is None or session.rubric.definition is None:
            return
        criterion = next(
            (c for c in session.rubric.definition.criteria if c.id == criterion_id), None
        )
        if criterion is None:
            return
        self.review_criterion_id = criterion_id
        lines = [
            f"{criterion.id} · scale={criterion.scale_kind} · weight={criterion.weight} "
            f"· threshold={criterion.pass_threshold} "
            f"· range {criterion.scale_min}–{criterion.scale_max}",
            criterion.instructions,
        ]
        for level in criterion.levels:
            lines.append(f"  level {level.label} = {level.score}: {level.description}")
        for category in criterion.categories:
            lines.append(
                f"  category {category.label} → {category.outcome}: {category.description}"
            )
        lines.append(f"  automated check: {criterion.check}")
        lines.append(f"  evidence required: {', '.join(criterion.evidence_requirements)}")
        self.query_one("#review-wording", Static).update("\n".join(lines))
        run = next((item for item in report.runs if item.id == session.run_id), None)
        evidence: list[str] = []
        if run is not None:
            text = run.response.text if run.response else run.error or run.status
            evidence.append(f"Response ({run.case.kind}):\n{text}")
            for artifact in run.evidence:
                evidence.append(
                    f"Artifact {artifact.id} ({artifact.kind}) source sha256={artifact.sha256}"
                )
        self.query_one("#review-evidence", TextArea).load_text("\n".join(evidence))
        existing = [
            judgment
            for judgment in report.human_judgments
            if judgment.session_id == session.id and judgment.criterion_id == criterion_id
        ]
        judgments_panel = self.query_one("#review-judgments", Static)
        if not existing:
            judgments_panel.update("No human judgment recorded for this criterion.")
        else:
            rows = ["Existing judgments (append-only):"]
            for judgment in existing:
                detail = f"  {judgment.id} · {judgment.reviewer} · {judgment.outcome}"
                if judgment.label:
                    detail += f" · {judgment.label}"
                if judgment.score is not None:
                    detail += f" · score {judgment.score}"
                if judgment.supersedes_id:
                    detail += f" · supersedes {judgment.supersedes_id}"
                rows.append(detail)
            judgments_panel.update("\n".join(rows))

    @on(Select.Changed, "#review-run")
    def review_run_changed(self) -> None:
        self.refresh_sessions()

    @on(Select.Changed, "#review-session")
    def review_session_changed(self) -> None:
        value = self.query_one("#review-session", Select).value
        self.select_session(None if value is Select.BLANK else str(value))

    @on(DataTable.RowHighlighted, "#review-criteria")
    def review_criterion_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key.value:
            self.show_criterion(str(event.row_key.value))

    @on(Button.Pressed, "#review-reevaluate")
    def reevaluate_pressed(self) -> None:
        self.action_reevaluate()

    @on(Button.Pressed, "#review-start")
    def start_review_pressed(self) -> None:
        self.action_start_review()

    @on(Button.Pressed, "#record-judgment")
    def judgment_pressed(self) -> None:
        self.action_record_judgment()

    @on(Button.Pressed, "#adjudicate")
    def adjudicate_pressed(self) -> None:
        self.action_adjudicate()

    def reload_review(self, session_id: str, message: str) -> None:
        report = self.current_report
        if report is None:
            return
        self.current_report = self.workbench.report(report.experiment.id)
        self.refresh_review(session_id)
        self.call_after_refresh(self.review_status, message)

    def action_reevaluate(self) -> None:
        report = self.current_report
        run_id = self.query_one("#review-run", Select).value
        rubric_id = self.query_one("#review-rubric", Select).value
        if report is None or run_id is Select.BLANK or rubric_id is Select.BLANK:
            self.review_status("Select a saved run and a rubric before reevaluating.")
            return
        try:
            session = self.workbench.reevaluate(
                str(run_id), self.workbench.store.rubric(str(rubric_id))
            )
        except (ValueError, ValidationError):
            self.review_status(
                "Reevaluation failed. Check the rubric review state and stored evidence."
            )
            return
        version = session.rubric.definition.version if session.rubric.definition else "?"
        self.reload_review(session.id, f"Reevaluated offline with rubric {version}.")

    def action_start_review(self) -> None:
        report = self.current_report
        run_id = self.query_one("#review-run", Select).value
        rubric_id = self.query_one("#review-rubric", Select).value
        if report is None or run_id is Select.BLANK or rubric_id is Select.BLANK:
            self.review_status("Select a saved run and a rubric before starting review.")
            return
        try:
            session = self.workbench.start_human_session(
                str(run_id), self.workbench.store.rubric(str(rubric_id))
            )
        except (ValueError, ValidationError):
            self.review_status("Cannot open a review session for this run and rubric.")
            return
        self.reload_review(session.id, f"Human review session {session.id} opened.")

    @staticmethod
    def _entered_score(text: str) -> float | None:
        text = text.strip()
        if not text:
            return None
        try:
            return float(text)
        except ValueError:
            raise ValueError("Numeric score must be a number") from None

    def action_record_judgment(self) -> None:
        active = self.query_one(TabbedContent).active
        if active == "batch":
            self.action_record_batch_judgment()
            return
        if active == "agentic":
            self.action_record_agentic_judgment()
            return
        if not self.review_session_id or not self.review_criterion_id:
            self.review_status("Select a session and criterion before recording a judgment.")
            return
        outcome = self.query_one("#review-outcome", Select).value
        try:
            judgment = self.workbench.record_judgment(
                self.review_session_id,
                self.review_criterion_id,
                reviewer=self.query_one("#review-reviewer", Input).value.strip(),
                outcome=str(outcome),
                rationale=self.query_one("#review-rationale", TextArea).text,
                label=self.query_one("#review-label", Input).value.strip() or None,
                score=self._entered_score(self.query_one("#review-score", Input).value),
                supersedes_id=(self.query_one("#review-supersedes", Input).value.strip() or None),
            )
        except ValueError as exc:
            self.review_status(f"Judgment rejected: {exc}")
            return
        self.query_one("#review-supersedes", Input).value = ""
        self.reload_review(self.review_session_id, f"Judgment appended: {judgment.id}")

    def action_adjudicate(self) -> None:
        active = self.query_one(TabbedContent).active
        if active == "batch":
            self.action_adjudicate_batch()
            return
        if active == "agentic":
            self.action_adjudicate_agentic()
            return
        if not self.review_session_id:
            self.review_status("Select a review session before adjudicating.")
            return
        designated = self.query_one("#review-designated", Input).value.strip() or None
        try:
            policy = AdjudicationPolicy(
                kind=str(self.query_one("#review-policy", Select).value), reviewer=designated
            )
            recorded = self.workbench.adjudicate(
                self.review_session_id,
                policy=policy,
                reviewer=self.query_one("#review-reviewer", Input).value.strip(),
                rationale=self.query_one("#review-adjudication", Input).value,
            )
        except (ValueError, ValidationError) as exc:
            self.review_status(f"Adjudication rejected: {exc}")
            return
        statuses = ", ".join(f"{item.criterion_id}={item.status}" for item in recorded)
        self.reload_review(
            self.review_session_id, f"Adjudicated {len(recorded)} criterion(s): {statuses}"
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

    # --- Batch review --------------------------------------------------------

    def refresh_batches(self) -> None:
        datasets = self.workbench.store.datasets()
        dataset_select = self.query_one("#batch-dataset", Select)
        previous_dataset = dataset_select.value
        dataset_select.set_options(
            [
                (Text(f"{item.title} · v{item.version} · {item.record_count} cases"), item.id)
                for item in datasets
            ]
        )
        known_datasets = {item.id for item in datasets}
        dataset_select.value = (
            previous_dataset
            if previous_dataset in known_datasets
            else (datasets[0].id if datasets else Select.BLANK)
        )
        batches = self.workbench.store.batches()
        batch_select = self.query_one("#batch-select", Select)
        previous_batch = batch_select.value
        batch_select.set_options(
            [
                (Text(f"{item.status} · {item.id[:8]} · v{item.dataset_version}"), item.id)
                for item in batches
            ]
        )
        known_batches = {item.id for item in batches}
        batch_select.value = (
            previous_batch
            if previous_batch in known_batches
            else (batches[0].id if batches else Select.BLANK)
        )
        self.load_batch()

    def load_batch(self) -> None:
        value = self.query_one("#batch-select", Select).value
        table = self.query_one("#batch-cases", DataTable)
        table.clear()
        if value is Select.BLANK:
            self.current_batch_report = None
            self.query_one("#batch-summary", Static).update("No batch selected.")
            self.query_one("#batch-case-detail", Static).update("")
            self.query_one("#batch-criterion", Select).set_options([])
            return
        report = self.workbench.batch_report(str(value))
        self.current_batch_report = report
        progress = report.progress
        kappas = []
        for group in report.agreement.groups if report.agreement else []:
            if group.kappa is None:
                kappas.append(f"{group.criterion_id}=n/a")
            elif group.kappa.defined:
                kappas.append(f"{group.criterion_id}={group.kappa.value:.3f}")
            else:
                kappas.append(f"{group.criterion_id}=undefined")
        self.query_one("#batch-summary", Static).update(
            f"{report.dataset.title} · v{report.dataset.version} · "
            f"cases {progress.cases_completed}/{progress.cases_total} "
            f"({progress.cases_failed} failed, {progress.cases_skipped} skipped, "
            f"{progress.cases_pending} pending)\n"
            f"mean weighted compliance {_fmt(progress.mean_weighted_compliance)} · "
            f"kappa {', '.join(kappas) or 'not available'} · "
            f"disagreements {len(report.disagreements)}"
        )
        for case in report.cases:
            session = next(
                (
                    item
                    for item in report.evaluation_sessions
                    if item.dataset_case_id == case.case_id
                ),
                None,
            )
            automated = "none"
            effective = "none"
            if session is not None:
                automated = ", ".join(
                    f"{value.criterion_id}={value.outcome}" for value in session.evaluations
                )
                effective = ", ".join(
                    f"{result.criterion_id}={result.effective_outcome or result.status}"
                    for result in report.effective_results
                    if result.session_id == session.id
                )
            table.add_row(
                Text(case.case_id),
                case.status,
                automated,
                effective,
                key=case.case_id,
            )
        if report.cases:
            table.move_cursor(row=0)
            self.select_batch_case(report.cases[0].case_id)

    def select_batch_case(self, case_id: str | None) -> None:
        report = self.current_batch_report
        self.batch_case_id = case_id
        criterion_select = self.query_one("#batch-criterion", Select)
        if report is None or case_id is None:
            criterion_select.set_options([])
            return
        record = next((item for item in report.records if item.id == case_id), None)
        session = next(
            (item for item in report.evaluation_sessions if item.dataset_case_id == case_id),
            None,
        )
        details = [f"Case {case_id}"]
        if record is not None:
            details.extend(
                [
                    f"Provenance: {record.provenance}",
                    f"Model: {record.model or 'not recorded'}",
                    f"Prompt: {record.prompt}",
                    f"Response: {record.response or '(empty)'}",
                ]
            )
        if session is not None:
            details.append(f"Session: {session.id} · {session.evidence_kind}")
            definition = session.rubric.definition
            criteria = definition.criteria if definition else []
            criterion_select.set_options(
                [(Text(f"{item.id} · {item.scale_kind}"), item.id) for item in criteria]
            )
            criterion_select.value = criteria[0].id if criteria else Select.BLANK
        else:
            criterion_select.set_options([])
            details.append("No evaluation session yet; run or resume the batch.")
        self.query_one("#batch-case-detail", Static).update("\n".join(details))

    def batch_status(self, text: str) -> None:
        self.query_one("#batch-status", Static).update(text)

    def batch_session(self):  # noqa: ANN201 - small internal lookup
        report = self.current_batch_report
        if report is None or self.batch_case_id is None:
            return None
        return next(
            (
                item
                for item in report.evaluation_sessions
                if item.dataset_case_id == self.batch_case_id
            ),
            None,
        )

    @on(Button.Pressed, "#import-dataset")
    def import_dataset_pressed(self) -> None:
        self.action_import_dataset()

    @on(Button.Pressed, "#create-batch")
    def create_batch_pressed(self) -> None:
        self.action_create_batch()

    @on(Button.Pressed, "#run-batch")
    def run_batch_pressed(self) -> None:
        self.action_run_batch()

    @on(Button.Pressed, "#export-batch")
    def export_batch_pressed(self) -> None:
        self.action_export_batch()

    @on(Button.Pressed, "#batch-record-judgment")
    def batch_judgment_pressed(self) -> None:
        self.action_record_batch_judgment()

    @on(Button.Pressed, "#batch-adjudicate")
    def batch_adjudicate_pressed(self) -> None:
        self.action_adjudicate_batch()

    @on(Select.Changed, "#batch-select")
    def batch_changed(self) -> None:
        self.load_batch()

    @on(DataTable.RowHighlighted, "#batch-cases")
    def batch_case_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key.value:
            self.select_batch_case(str(event.row_key.value))

    def action_import_dataset(self) -> None:
        text = self.query_one("#dataset-path", Input).value.strip()
        if not text:
            self.batch_status("Enter a dataset path first.")
            return
        try:
            dataset = self.workbench.import_dataset(Path(text).expanduser())
        except (ValueError, OSError) as exc:
            self.batch_status(f"Dataset import failed: {exc}")
            return
        self.refresh_batches()
        after = self.query_one("#batch-dataset", Select)
        known = {item.id for item in self.workbench.store.datasets()}
        if dataset.id in known:
            after.value = dataset.id
        self.batch_status(
            f"Imported {dataset.record_count} case(s) from {dataset.source_format} "
            f"as dataset {dataset.id[:8]}."
        )

    def action_create_batch(self) -> None:
        dataset_id = self.query_one("#batch-dataset", Select).value
        rubric_id = self.query_one("#batch-rubric", Select).value
        if dataset_id is Select.BLANK or rubric_id is Select.BLANK:
            self.batch_status("Choose a dataset and a rubric first.")
            return
        raw_cases = self.query_one("#batch-max-cases", Input).value.strip()
        try:
            max_cases = int(raw_cases) if raw_cases else None
        except ValueError:
            self.batch_status("Max cases must be a whole number.")
            return
        try:
            batch = self.workbench.create_batch(
                str(dataset_id),
                self.workbench.store.rubric(str(rubric_id)),
                max_cases=max_cases,
            )
        except (ValueError, OSError) as exc:
            self.batch_status(f"Batch planning failed: {exc}")
            return
        self.refresh_batches()
        self.query_one("#batch-select", Select).value = batch.id
        self.batch_status(f"Planned {batch.budget.max_cases} case(s) in batch {batch.id[:8]}.")

    def action_run_batch(self) -> None:
        batch_id = self.query_one("#batch-select", Select).value
        if batch_id is Select.BLANK:
            self.batch_status("Choose a batch first.")
            return
        raw_limit = self.query_one("#batch-limit", Input).value.strip()
        try:
            limit = int(raw_limit) if raw_limit else None
        except ValueError:
            self.batch_status("Cases per run must be a whole number.")
            return
        try:
            batch = self.workbench.execute_batch(str(batch_id), limit=limit)
        except (ValueError, OSError) as exc:
            self.batch_status(f"Batch execution failed: {exc}")
            return
        counts = self.workbench.store.batch_case_counts(batch.id)
        self.load_batch()
        self.batch_status(
            f"Batch {batch.status}: {counts.get('completed', 0)} completed, "
            f"{counts.get('failed', 0)} failed, {counts.get('skipped', 0)} skipped, "
            f"{counts.get('pending', 0)} pending."
        )

    def action_record_batch_judgment(self) -> None:
        session = self.batch_session()
        criterion_id = self.query_one("#batch-criterion", Select).value
        if session is None:
            self.batch_status("Select an evaluated case first.")
            return
        if criterion_id is Select.BLANK:
            self.batch_status("Select a criterion first.")
            return
        try:
            judgment = self.workbench.record_judgment(
                session.id,
                str(criterion_id),
                reviewer=self.query_one("#batch-reviewer", Input).value.strip(),
                outcome=str(self.query_one("#batch-outcome", Select).value),
                rationale=self.query_one("#batch-rationale", TextArea).text,
                label=self.query_one("#batch-label", Input).value.strip() or None,
                score=self._entered_score(self.query_one("#batch-score", Input).value),
            )
        except ValueError as exc:
            self.batch_status(f"Judgment rejected: {exc}")
            return
        self.reload_batch(f"Judgment appended: {judgment.id}")

    def action_adjudicate_batch(self) -> None:
        session = self.batch_session()
        if session is None:
            self.batch_status("Select an evaluated case first.")
            return
        designated = self.query_one("#batch-designated", Input).value.strip() or None
        try:
            policy = AdjudicationPolicy(
                kind=str(self.query_one("#batch-policy", Select).value),
                reviewer=designated,
            )
            recorded = self.workbench.adjudicate(
                session.id,
                policy=policy,
                reviewer=self.query_one("#batch-reviewer", Input).value.strip(),
                rationale=self.query_one("#batch-adjudication", Input).value,
            )
        except (ValueError, ValidationError) as exc:
            self.batch_status(f"Adjudication rejected: {exc}")
            return
        self.reload_batch(f"Adjudicated {len(recorded)} criterion(s).")

    def action_export_batch(self) -> None:
        batch_id = self.query_one("#batch-select", Select).value
        if batch_id is Select.BLANK:
            self.batch_status("Choose a batch first.")
            return
        try:
            prefix = Path(self.query_one("#batch-export", Input).value).expanduser() / str(batch_id)
            paths = export_report(self.workbench.batch_report(str(batch_id)), prefix)
            self.batch_status("Exported: " + ", ".join(path.name for path in paths))
        except (ValueError, OSError):
            self.batch_status("Export failed. Choose a writable directory without report files.")

    def reload_batch(self, message: str) -> None:
        case_id = self.batch_case_id
        self.load_batch()
        if case_id is not None:
            self.select_batch_case(case_id)
        self.batch_status(message)

    # --- Agentic lab ---------------------------------------------------------

    def agentic_status(self, text: str) -> None:
        self.query_one("#agentic-status", Static).update(text)

    def agentic_trace(self):  # noqa: ANN201 - small internal lookup
        trace_id = getattr(self, "agentic_trace_id", None)
        return self.workbench.trace(trace_id) if trace_id else None

    def agentic_session(self):  # noqa: ANN201 - small internal lookup
        trace_id = getattr(self, "agentic_trace_id", None)
        if not trace_id:
            return None
        sessions = self.workbench.trace_sessions(trace_id)
        return sessions[-1] if sessions else None

    def describe_scenario(self) -> None:
        scenario_id = self.query_one("#agentic-scenario", Select).value
        if scenario_id is Select.BLANK:
            return
        scenario = self.workbench.scenario(str(scenario_id))
        injected = [
            document
            for document in scenario.documents
            if document.id == scenario.injected_document_id
        ]
        lines = [
            f"Objective: {scenario.objective}",
            f"Attack surface: {scenario.trust_boundary} · tools: "
            f"{', '.join(scenario.allowed_tools)}",
            f"Expected secure behaviour: {scenario.expected_secure_behavior}",
        ]
        for document in injected:
            lines.append(f"Injected {document.id} ({document.source_note}): {document.injection}")
        self.query_one("#agentic-brief", Static).update("\n".join(lines))

    def budget_input(self, selector: str) -> int | None:
        raw = self.query_one(selector, Input).value.strip()
        return int(raw) if raw else None

    def action_run_agentic(self, dry_run: bool = False) -> None:
        self.run_agentic_worker(dry_run)

    @work(group="agentic", exclusive=True)
    async def run_agentic_worker(self, dry_run: bool = False) -> None:
        scenario_id = self.query_one("#agentic-scenario", Select).value
        if scenario_id is Select.BLANK:
            self.agentic_status("Choose a scenario first.")
            return
        agent = str(self.query_one("#agentic-agent", Select).value)
        values = {
            "max_requests": self.budget_input("#agentic-requests"),
            "max_turns": self.budget_input("#agentic-turns-budget"),
            "max_tool_invocations": self.budget_input("#agentic-tool-budget"),
        }
        try:
            budget = AgentBudget(
                **{key: value for key, value in values.items() if value is not None}
            )
            trace = await self.workbench.run_scenario(
                str(scenario_id), agent=agent, budget=budget, dry_run=dry_run
            )
        except (ValueError, OSError) as exc:
            self.agentic_status(f"Scenario run failed: {exc}")
            return
        self.agentic_trace_id = trace.id
        self.load_agentic(
            f"{'Dry run' if dry_run else 'Trace'} {trace.id}: {trace.status} ({trace.termination})"
        )

    def load_agentic(self, message: str) -> None:
        trace = self.agentic_trace()
        if trace is None:
            self.agentic_status("No agentic trace selected.")
            return
        result = self.workbench.agentic_result(trace)
        self.agentic_status(
            f"{message}\nObserved verdict: {result.verdict} · requested "
            f"{', '.join(result.requested_tools) or 'none'} · denied "
            f"{', '.join(result.denied_tools) or 'none'} · executed "
            f"{', '.join(result.executed_tools) or 'none'} · state changes "
            f"{', '.join(result.state_changes) or 'none'}"
        )
        table = self.query_one("#agentic-timeline", DataTable)
        table.clear(columns=True)
        table.add_columns("#", "role", "source", "trust", "content")
        for turn in trace.turns:
            table.add_row(
                str(turn.index),
                turn.role,
                turn.source,
                turn.trust,
                turn.content.replace("\n", " ")[:90],
                key=turn.index,
            )
        self.refresh_agentic_criteria()

    def refresh_agentic_criteria(self) -> None:
        table = self.query_one("#agentic-criteria", DataTable)
        table.clear(columns=True)
        table.add_columns("criterion", "scale", "outcome", "score")
        session = self.agentic_session()
        if session is None:
            self.query_one("#agentic-criterion-detail", Static).update(
                "No evaluation session exists for this trace."
            )
            return
        for value in session.evaluations:
            table.add_row(
                value.criterion_id,
                value.scale_kind,
                value.outcome,
                "" if value.score is None else f"{value.score:g}",
                key=value.criterion_id,
            )

    @on(DataTable.RowHighlighted, "#agentic-timeline")
    def agentic_turn_highlighted(self, event: DataTable.RowHighlighted) -> None:
        trace = self.agentic_trace()
        if trace is None or event.row_key.value is None:
            return
        turn = trace.turns[int(event.row_key.value)]
        detail = [
            f"turn {turn.index} · {turn.role} · source={turn.source} · trust={turn.trust}",
            f"content: {turn.content[:400]}",
        ]
        for invocation in trace.invocations:
            if invocation.request_id in turn.tool_request_ids or (
                turn.tool_request_id == invocation.request_id
            ):
                decision = invocation.decision
                detail.append(
                    f"tool {invocation.tool} → "
                    f"{decision.decision if decision else 'unrecorded'} "
                    f"({decision.reason if decision else ''})"
                )
                if invocation.receipt is not None:
                    detail.append(
                        "receipt executed="
                        f"{invocation.receipt.executed} state_changes="
                        f"{len(invocation.receipt.state_changes)}"
                    )
        self.query_one("#agentic-turn-detail", Static).update("\n".join(detail))

    @on(DataTable.RowHighlighted, "#agentic-criteria")
    def agentic_criterion_highlighted(self, event: DataTable.RowHighlighted) -> None:
        session = self.agentic_session()
        if session is None or event.row_key.value is None:
            return
        criterion_id = str(event.row_key.value)
        value = next((v for v in session.evaluations if v.criterion_id == criterion_id), None)
        if value is None:
            return
        self.agentic_criterion_id = criterion_id
        definition = session.rubric.definition
        criterion = (
            next((c for c in definition.criteria if c.id == criterion_id), None)
            if definition
            else None
        )
        self.query_one("#agentic-criterion-detail", Static).update(
            "\n".join(
                [
                    f"{criterion_id} [{value.scale_kind}] → {value.outcome}",
                    f"wording: {criterion.instructions if criterion else 'unknown'}",
                    f"basis: {value.basis or 'human'} · {value.rationale or ''}",
                ]
            )
        )

    @on(Button.Pressed, "#agentic-run")
    def agentic_run_pressed(self) -> None:
        self.action_run_agentic()

    @on(Button.Pressed, "#agentic-dry")
    def agentic_dry_pressed(self) -> None:
        self.action_run_agentic(dry_run=True)

    @on(Button.Pressed, "#agentic-export")
    def agentic_export_pressed(self) -> None:
        self.action_export_agentic()

    @on(Button.Pressed, "#agentic-judge")
    def agentic_judge_pressed(self) -> None:
        self.action_record_agentic_judgment()

    @on(Button.Pressed, "#agentic-adjudicate")
    def agentic_adjudicate_pressed(self) -> None:
        self.action_adjudicate_agentic()

    @on(Select.Changed, "#agentic-scenario")
    def agentic_scenario_changed(self) -> None:
        self.describe_scenario()

    def action_export_agentic(self) -> None:
        trace_id = getattr(self, "agentic_trace_id", None)
        if not trace_id:
            self.agentic_status("Run a scenario before exporting a report.")
            return
        directory = self.query_one("#agentic-export-dir", Input).value.strip() or "reports"
        try:
            paths = export_report(
                self.workbench.agentic_report(trace_id),
                Path(directory) / f"agentic-{trace_id}",
            )
        except (ValueError, OSError) as exc:
            self.agentic_status(f"Export failed: {exc}")
            return
        self.agentic_status("Exported: " + ", ".join(str(path) for path in paths))

    def action_record_agentic_judgment(self) -> None:
        session = self.agentic_session()
        if session is None:
            self.agentic_status("Run a scenario and select a criterion first.")
            return
        criterion_id = getattr(self, "agentic_criterion_id", None)
        if not criterion_id:
            self.agentic_status("Select a criterion first.")
            return
        try:
            judgment = self.workbench.record_judgment(
                session.id,
                criterion_id,
                reviewer=self.query_one("#agentic-reviewer", Input).value.strip(),
                outcome=str(self.query_one("#agentic-outcome", Select).value),
                rationale=self.query_one("#agentic-rationale", TextArea).text,
                label=self.query_one("#agentic-label", Input).value.strip() or None,
                score=self._entered_score(self.query_one("#agentic-score", Input).value),
            )
        except ValueError as exc:
            self.agentic_status(f"Judgment rejected: {exc}")
            return
        self.load_agentic(f"Judgment appended: {judgment.id}")

    def action_adjudicate_agentic(self) -> None:
        session = self.agentic_session()
        if session is None:
            self.agentic_status("Run a scenario before adjudicating.")
            return
        designated = self.query_one("#agentic-designated", Input).value.strip() or None
        try:
            policy = AdjudicationPolicy(
                kind=str(self.query_one("#agentic-policy", Select).value),
                reviewer=designated,
            )
            recorded = self.workbench.adjudicate(
                session.id,
                policy=policy,
                reviewer=self.query_one("#agentic-reviewer", Input).value.strip(),
                rationale=self.query_one("#agentic-adjudication", Input).value,
            )
        except (ValueError, ValidationError) as exc:
            self.agentic_status(f"Adjudication rejected: {exc}")
            return
        statuses = ", ".join(f"{item.criterion_id}={item.status}" for item in recorded)
        self.load_agentic(f"Adjudicated {len(recorded)} criterion(s): {statuses}")
