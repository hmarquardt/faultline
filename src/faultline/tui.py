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
from faultline.domain import AdjudicationPolicy, EndpointProfile, Report
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
    #review-criteria { height: 10; }
    #review-wording { height: auto; min-height: 4; padding: 1; background: $boost; }
    #review-evidence { height: 8; }
    #review-rationale { height: 4; }
    #review-status { height: auto; min-height: 2; padding: 1; background: $boost; }
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
        self.refresh_history()
        self.inspect_selection()
        self.refresh_review()

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
