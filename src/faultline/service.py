"""UI-independent use cases: prepare, enforce policy, execute, preserve evidence."""

import asyncio
import os
from pathlib import Path

from faultline.adjudication import coverage, disagreements, effective_results, resolve
from faultline.agreement import AgreementUnit
from faultline.agreement import build_report as build_agreement_report
from faultline.batch import coverage as batch_coverage
from faultline.batch import progress as batch_progress
from faultline.datasets import (
    evaluation_case,
    evaluation_response,
    evidence_digest,
    import_dataset,
    record_evidence,
)
from faultline.domain import (
    Adjudication,
    AdjudicationPolicy,
    AgreementReport,
    BatchBudget,
    BatchCase,
    BatchEvaluation,
    BatchReport,
    Dataset,
    DatasetLimits,
    DatasetRecord,
    EffectiveResult,
    EndpointProfile,
    EvaluationSession,
    EvidenceArtifact,
    ExecutionBudget,
    ExecutionRun,
    ExecutionSettings,
    Experiment,
    Finding,
    FindingReview,
    HumanJudgment,
    Outcome,
    Report,
    Rubric,
    RubricCriterion,
    ScoreSummary,
    TargetModel,
    canonical_digest,
    now,
)
from faultline.evaluation import Evaluator, summarize
from faultline.integrity import (
    adjudication_evidence,
    execution_digest,
    execution_evidence,
    judgment_evidence,
    session_evidence,
    verify_execution,
)
from faultline.providers import (
    CompatibleProvider,
    MockProvider,
    Provider,
    ProviderError,
    contains_credential,
    protect_response,
)
from faultline.storage import Store
from faultline.techniques import render_cases, techniques


class Workbench:
    def __init__(self, store: Store, evaluator: Evaluator | None = None) -> None:
        self.store = store
        self.evaluator = evaluator or Evaluator()

    def prepare(
        self,
        profile: EndpointProfile,
        rubric: Rubric,
        technique_id: str = "authority-spoof",
        *,
        model: str | None = None,
        parameters: dict[str, str] | None = None,
        settings: ExecutionSettings | None = None,
        budget: ExecutionBudget | None = None,
        dry_run: bool = False,
        allow_network: bool = False,
        connection_test: bool = False,
    ) -> Experiment:
        if technique_id not in techniques():
            raise ValueError("Unknown technique")
        technique = techniques()[technique_id]
        cases = render_cases(technique, parameters)
        return Experiment(
            name="Connection test" if connection_test else f"{technique.name} / {profile.name}",
            endpoint=profile,
            target=TargetModel(
                endpoint_id=profile.id, requested_model=model or profile.allowed_models[0]
            ),
            rubric=rubric,
            technique=technique,
            cases=cases[:1] if connection_test else cases,
            settings=settings or ExecutionSettings(),
            budget=budget or ExecutionBudget(),
            dry_run=dry_run,
            network_enabled=allow_network,
            python_assertions_enabled=self.evaluator.allow_python,
        )

    def preflight(self, experiment: Experiment) -> None:
        e = experiment
        if e.rubric.definition is None or e.rubric.review_status == "pending":
            raise ValueError("Rubric needs explicit human normalization before running")
        if not e.endpoint.authorized or not e.endpoint.authorization.strip():
            raise ValueError("Endpoint profile requires an authorized scope")
        if e.target.endpoint_id != e.endpoint.id:
            raise ValueError("Target endpoint does not match the profile")
        if e.target.requested_model not in e.endpoint.allowed_models:
            raise ValueError("Model is outside the profile's allowed scope")
        if len(e.cases) > e.budget.max_requests:
            raise ValueError("Request budget is insufficient")
        if len(e.cases) * e.settings.max_output_tokens > e.budget.max_total_output_tokens:
            raise ValueError("Output-token allocation exceeds experiment budget")
        if sum(len(c.model_dump_json().encode()) for c in e.cases) > e.budget.max_input_bytes:
            raise ValueError("Rendered cases exceed input-byte budget")
        if e.endpoint.provider != "mock" and not e.dry_run and not e.network_enabled:
            raise ValueError("Real endpoint execution requires explicit allow_network")
        if e.python_assertions_enabled != self.evaluator.allow_python:
            raise ValueError("Assertion execution policy differs from experiment snapshot")
        if e.endpoint.provider != "mock" and e.endpoint.credential_env:
            secret = os.environ.get(e.endpoint.credential_env, "")
            if not secret and not e.dry_run:
                raise ValueError("Credential environment variable is unset or empty")
            # Reject credential material in source/parameters before persisting a snapshot.
            if contains_credential(e.model_dump(mode="json"), secret):
                raise ValueError(
                    "Credential value appears in experiment data; refusing persistence"
                )

    async def execute(self, experiment: Experiment, *, provider: Provider | None = None) -> Report:
        # Revalidate nested collections supplied through the library API.
        experiment = Experiment.model_validate(experiment.model_dump())
        self.preflight(experiment)
        if experiment.status != "planned":
            raise ValueError("Only a new planned experiment can execute")
        experiment = experiment.model_copy(update={"status": "running"})
        self.store.add_experiment(experiment)
        adapter = provider
        if adapter is None:
            adapter = (
                MockProvider(experiment.endpoint.mock_behavior)
                if experiment.endpoint.provider == "mock"
                else CompatibleProvider(experiment.endpoint)
            )
        failed = False
        secret = (
            os.environ.get(experiment.endpoint.credential_env, "")
            if experiment.endpoint.credential_env
            else ""
        )
        for case in experiment.cases:
            run = ExecutionRun(experiment_id=experiment.id, case=case)
            self.store.start_run(run)
            if experiment.dry_run:
                run = run.model_copy(update={"status": "dry_run", "completed_at": now()})
                self.store.finish_run(run, [])
                continue
            try:
                # Bounds trusted adapter implementations too; no automatic retries.
                async with asyncio.timeout(experiment.settings.timeout_seconds):
                    response = await adapter.complete(
                        case,
                        experiment.target,
                        experiment.settings,
                        experiment.budget.max_response_bytes,
                    )
            except ProviderError as exc:
                message = str(exc).replace(secret, "[CREDENTIAL REDACTED]") if secret else str(exc)
                run = run.model_copy(
                    update={
                        "status": "failed",
                        "completed_at": now(),
                        "error": message,
                    }
                )
                self.store.finish_run(run, [])
                failed = True
                break
            except Exception as exc:
                run = run.model_copy(
                    update={
                        "status": "failed",
                        "completed_at": now(),
                        "error": "Endpoint request timed out"
                        if isinstance(exc, TimeoutError)
                        else "Execution failed; details excluded to protect credentials",
                    }
                )
                self.store.finish_run(run, [])
                failed = True
                break
            response = protect_response(response, secret)
            artifact = EvidenceArtifact.capture("response", response.model_dump_json(), run.id)
            run = run.model_copy(update={"response": response, "evidence": [artifact]})
            self.store.record_response(run)
            try:
                values = self.evaluator.evaluate(
                    experiment.rubric, case, response, run.id, artifact
                )
            except Exception:
                run = run.model_copy(
                    update={
                        "status": "failed",
                        "completed_at": now(),
                        "error": "Evaluation failed; response evidence preserved for human review",
                    }
                )
                self.store.finish_run(run, [])
                failed = True
                break
            run = run.model_copy(
                update={
                    "status": "completed",
                    "completed_at": now(),
                    "response": response,
                    "evidence": [artifact],
                    "evaluations": values,
                }
            )
            session = self._execution_session(experiment, run)
            findings = [
                Finding(
                    experiment_id=experiment.id,
                    run_id=run.id,
                    evaluation_id=value.id,
                    title=f"{case.kind}: {value.criterion_id} failed",
                    evidence_ids=value.evidence_ids,
                    classification="simulated"
                    if experiment.endpoint.provider == "mock"
                    else "observed",
                    claim=value.rationale,
                )
                for value in values
                if value.outcome == "fail"
            ]
            self.store.finish_run(run, findings, [session])
        experiment = experiment.model_copy(
            update={
                "status": "failed" if failed else "dry_run" if experiment.dry_run else "completed",
                "completed_at": now(),
            }
        )
        self.store.update_experiment(experiment)
        return self.report(experiment.id)

    # --- Evaluation sessions -------------------------------------------------

    def evaluator_identity(self) -> tuple[str, dict]:
        """Record exactly which scorer and policy produced a session."""
        name = (
            "faultline.trusted-python/1"
            if self.evaluator.allow_python and self.evaluator.assertions
            else "faultline.deterministic/1"
        )
        settings = {
            "allow_python": self.evaluator.allow_python,
            "evaluator_class": type(self.evaluator).__name__,
            "assertion_sources": dict(sorted(self.evaluator.assertion_sources.items())),
        }
        return name, settings

    def _execution_session(self, experiment: Experiment, run: ExecutionRun) -> EvaluationSession:
        assert experiment.rubric.definition is not None
        evaluator, settings = self.evaluator_identity()
        completed = run.completed_at or now()
        return EvaluationSession(
            run_id=run.id,
            experiment_id=experiment.id,
            rubric=experiment.rubric,
            rubric_definition_sha256=canonical_digest(experiment.rubric.definition),
            execution_sha256=execution_digest(run),
            origin="execution",
            evaluator=evaluator,
            evaluator_settings=settings,
            status="completed",
            evaluations=run.evaluations,
            created_at=completed,
            completed_at=completed,
        )

    @staticmethod
    def _require_rubric(rubric: Rubric) -> None:
        if rubric.definition is None or rubric.review_status == "pending":
            raise ValueError("Rubric requires human normalization before evaluation")

    @staticmethod
    def _session_evidence_ids(session: EvaluationSession) -> list[str]:
        """Evidence ids a judgment cites: run evidence or dataset session evidence."""
        if session.run_id is not None:
            return [artifact.id for artifact in Workbench._run_evidence(session.run_id)]
        return [artifact.id for artifact in session.evidence]

    def _session_evidence_ids(self, session: EvaluationSession) -> list[str]:
        """Evidence a judgment cites: run artifacts, or the imported session artifacts."""
        if session.run_id is not None:
            return [artifact.id for artifact in self.store.run(session.run_id).evidence]
        return [artifact.id for artifact in session.evidence]

    def _stored_evidence(self, run_id: str) -> tuple[ExecutionRun, EvidenceArtifact]:
        run = self.store.run(run_id)
        if run.response is None:
            raise ValueError("Run has no stored response to evaluate")
        if verify_execution(run):
            raise ValueError("Stored execution evidence failed its integrity check")
        artifact = next((a for a in run.evidence if a.kind == "response"), None)
        if artifact is None:
            raise ValueError("Run has no preserved response evidence")
        return run, artifact

    def reevaluate(self, run_id: str, rubric: Rubric) -> EvaluationSession:
        """Score a stored response again. No provider is constructed or contacted."""
        self._require_rubric(rubric)
        run, artifact = self._stored_evidence(run_id)
        assert run.response is not None and rubric.definition is not None
        evaluations = self.evaluator.evaluate(rubric, run.case, run.response, run.id, artifact)
        evaluator, settings = self.evaluator_identity()
        session = EvaluationSession(
            run_id=run.id,
            experiment_id=run.experiment_id,
            rubric=rubric,
            rubric_definition_sha256=canonical_digest(rubric.definition),
            execution_sha256=execution_digest(run),
            origin="reevaluation",
            evaluator=evaluator,
            evaluator_settings=settings,
            status="completed",
            evaluations=evaluations,
            completed_at=now(),
        )
        self.store.add_session(session)
        return session

    def start_human_session(self, run_id: str, rubric: Rubric) -> EvaluationSession:
        """Open a session that carries a rubric for manual assessment only."""
        self._require_rubric(rubric)
        run, _ = self._stored_evidence(run_id)
        assert rubric.definition is not None
        evaluator, settings = self.evaluator_identity()
        session = EvaluationSession(
            run_id=run.id,
            experiment_id=run.experiment_id,
            rubric=rubric,
            rubric_definition_sha256=canonical_digest(rubric.definition),
            execution_sha256=execution_digest(run),
            origin="human_review",
            evaluator=evaluator,
            evaluator_settings=settings,
            status="pending_human_review",
        )
        self.store.add_session(session)
        return session

    def sessions(self, experiment_id: str) -> list[EvaluationSession]:
        return self.store.sessions(experiment_id=experiment_id)

    # --- Human judgment ------------------------------------------------------

    @staticmethod
    def _criterion(session: EvaluationSession, criterion_id: str) -> RubricCriterion:
        definition = session.rubric.definition
        assert definition is not None
        criterion = next((c for c in definition.criteria if c.id == criterion_id), None)
        if criterion is None:
            raise ValueError("Criterion is not part of this session's rubric")
        return criterion

    @staticmethod
    def _human_value(
        criterion: RubricCriterion,
        outcome: Outcome,
        label: str | None,
        score: float | None,
    ) -> tuple[str | None, float | None]:
        """Keep the rubric's own labels and refuse a silent binary conversion."""
        described = {category.label: category for category in criterion.categories}
        if criterion.scale_kind == "binary":
            if label is not None or score is not None:
                raise ValueError("Binary criteria record an outcome only")
            return None, None
        if criterion.scale_kind == "categorical":
            if label is None or label not in described:
                raise ValueError("Categorical judgment requires one of the rubric's labels")
            if score is not None:
                raise ValueError("Categorical criteria carry no numeric score")
            if outcome not in {described[label].outcome, "uncertain", "not_applicable"}:
                raise ValueError("Outcome contradicts the rubric's meaning for this category")
            return label, None
        ordered = {level.label: level for level in criterion.levels}
        if label is not None:
            if label not in ordered:
                raise ValueError("Label is not one of the rubric's levels")
            if score is not None and score != ordered[label].score:
                raise ValueError("Score contradicts the selected rubric level")
            score = ordered[label].score
        if score is None:
            raise ValueError("Ordered criteria require a level label or a numeric score")
        if not criterion.scale_min <= score <= criterion.scale_max:
            raise ValueError("Human score is outside the rubric's scoring scale")
        expected = "pass" if score >= criterion.pass_threshold else "fail"
        if outcome not in {expected, "uncertain", "not_applicable"}:
            raise ValueError("Outcome contradicts the rubric's threshold for this score")
        return label, score

    def record_judgment(
        self,
        session_id: str,
        criterion_id: str,
        *,
        reviewer: str,
        outcome: Outcome,
        rationale: str,
        label: str | None = None,
        score: float | None = None,
        confidence: str | None = None,
        supersedes_id: str | None = None,
    ) -> HumanJudgment:
        """Append one reviewer decision; earlier decisions are never rewritten."""
        if not reviewer.strip() or not rationale.strip():
            raise ValueError("Reviewer identity and rationale are required")
        session = self.store.session(session_id)
        criterion = self._criterion(session, criterion_id)
        label, score = self._human_value(criterion, outcome, label, score)
        if supersedes_id is not None:
            previous = {j.id: j for j in self.store.judgments(session_id=session_id)}.get(
                supersedes_id
            )
            if previous is None:
                raise ValueError("Only a judgment from this session can be superseded")
            if (previous.criterion_id, previous.reviewer) != (criterion_id, reviewer):
                raise ValueError("A judgment can only be superseded by the same reviewer")
        judgment = HumanJudgment(
            session_id=session.id,
            run_id=session.run_id,
            criterion_id=criterion_id,
            reviewer=reviewer,
            outcome=outcome,
            label=label,
            score=score,
            rationale=rationale,
            confidence=confidence,
            supersedes_id=supersedes_id,
            evidence_ids=self._session_evidence_ids(session),
        )
        self.store.add_judgment(judgment)
        return judgment

    # --- Adjudication --------------------------------------------------------

    def adjudicate(
        self,
        session_id: str,
        *,
        policy: AdjudicationPolicy,
        reviewer: str,
        rationale: str,
    ) -> list[Adjudication]:
        """Record an explicit adjudication for every judged criterion of a session."""
        if not reviewer.strip() or not rationale.strip():
            raise ValueError("Adjudicator identity and rationale are required")
        session = self.store.session(session_id)
        definition = session.rubric.definition
        assert definition is not None
        judgments = self.store.judgments(session_id=session_id)
        previous = {
            (a.session_id, a.criterion_id): a
            for a in self.store.adjudications(session_id=session_id)
        }
        recorded: list[Adjudication] = []
        for criterion in definition.criteria:
            relevant = [j for j in judgments if j.criterion_id == criterion.id]
            if not relevant:
                continue
            resolution = resolve(relevant, policy, criterion)
            if resolution.status == "insufficient":
                continue
            prior = previous.get((session.id, criterion.id))
            adjudication = Adjudication(
                session_id=session.id,
                run_id=session.run_id,
                criterion_id=criterion.id,
                policy=policy,
                agreement=resolution.agreement,
                status=resolution.status,
                outcome=resolution.outcome,
                label=resolution.label,
                score=resolution.score,
                basis_judgment_ids=list(resolution.basis_ids),
                dissenting_judgment_ids=list(resolution.dissenting_ids),
                rationale=rationale,
                reviewer=reviewer,
                supersedes_id=prior.id if prior else None,
            )
            self.store.add_adjudication(adjudication)
            recorded.append(adjudication)
        if not recorded:
            raise ValueError("No human judgment is available to adjudicate in this session")
        return recorded

    # --- Datasets and batch evaluation ---------------------------------------

    def import_dataset(
        self,
        path: Path,
        *,
        title: str | None = None,
        version: str | None = None,
        provenance: str | None = None,
        limits: DatasetLimits | None = None,
    ) -> Dataset:
        """Import prerecorded responses. Nothing is evaluated or dispatched."""
        imported = import_dataset(
            path, limits=limits, title=title, version=version, provenance=provenance
        )
        self.store.add_dataset(imported.dataset, imported.records)
        return imported.dataset

    def datasets(self) -> list[Dataset]:
        return self.store.datasets()

    def dataset(self, dataset_id: str) -> Dataset:
        return self.store.dataset(dataset_id)

    def create_batch(
        self,
        dataset_id: str,
        rubric: Rubric,
        *,
        max_cases: int | None = None,
        budget: BatchBudget | None = None,
    ) -> BatchEvaluation:
        """Plan a batch over dataset membership. No case is evaluated yet."""
        self._require_rubric(rubric)
        dataset = self.store.dataset(dataset_id)
        definition = rubric.definition
        assert definition is not None
        budget = budget or BatchBudget()
        cap = min(budget.max_cases, len(dataset.record_ids))
        if max_cases is not None:
            cap = min(cap, max_cases)
        if cap <= 0:
            raise ValueError("A batch requires at least one dataset case")
        batch = BatchEvaluation(
            dataset_id=dataset.id,
            dataset_version=dataset.version,
            dataset_sha256=dataset.dataset_sha256,
            rubric_id=rubric.id,
            rubric_definition_id=definition.id,
            rubric_definition_version=definition.version,
            rubric_source_sha256=rubric.source.sha256,
            rubric_definition_sha256=canonical_digest(definition),
            budget=budget.model_copy(update={"max_cases": cap}),
        )
        cases = [
            BatchCase(batch_id=batch.id, case_id=case_id, position=position)
            for position, case_id in enumerate(dataset.record_ids[:cap])
        ]
        self.store.add_batch(batch, cases)
        return batch

    def batch(self, batch_id: str) -> BatchEvaluation:
        return self.store.batch(batch_id)

    def batches(self) -> list[BatchEvaluation]:
        return self.store.batches()

    def batch_cases(self, batch_id: str) -> list[BatchCase]:
        return self.store.batch_cases(batch_id)

    def pending_batch_cases(self, batch_id: str, *, limit: int | None = None) -> list[BatchCase]:
        """Cases a run (or a dry run) would evaluate, without changing anything."""
        batch = self.store.batch(batch_id)
        per_run = (
            limit
            if limit is not None
            else (batch.budget.max_cases_per_run or batch.budget.max_cases)
        )
        if per_run <= 0:
            raise ValueError("A batch execution limit must be positive")
        return self.store.pending_batch_cases(batch_id, per_run)

    def execute_batch(
        self, batch_id: str, *, limit: int | None = None, dry_run: bool = False
    ) -> BatchEvaluation:
        """Evaluate pending imported cases. No provider is constructed or contacted."""
        batch = self.store.batch(batch_id)
        if batch.status == "completed":
            return batch
        rubric = self.store.rubric(batch.rubric_id)
        self._require_rubric(rubric)
        dataset = self.store.dataset(batch.dataset_id)
        per_run = (
            limit
            if limit is not None
            else (batch.budget.max_cases_per_run or batch.budget.max_cases)
        )
        if per_run <= 0:
            raise ValueError("A batch execution limit must be positive")
        if dry_run:
            # Validate the plan and stop: no session, no case transition, no IO.
            return batch
        batch = batch.model_copy(
            update={"status": "running", "updated_at": now(), "completed_at": None}
        )
        self.store.update_batch(batch)
        for case in self.store.pending_batch_cases(batch_id, per_run):
            record = self.store.dataset_record(dataset.id, case.case_id)
            self._evaluate_batch_case(dataset, rubric, case, record)
        pending = self.store.batch_case_counts(batch_id).get("pending", 0)
        batch = batch.model_copy(
            update={
                "status": "partial" if pending else "completed",
                "updated_at": now(),
                "completed_at": None if pending else now(),
            }
        )
        self.store.update_batch(batch)
        return batch

    def _evaluate_batch_case(
        self,
        dataset: Dataset,
        rubric: Rubric,
        case: BatchCase,
        record: DatasetRecord,
    ) -> None:
        finished = now()
        if not record.response.strip():
            self.store.finish_batch_case(
                case.model_copy(
                    update={
                        "status": "skipped",
                        "skip_reason": "Imported response is empty",
                        "finished_at": finished,
                    }
                )
            )
            return
        evidence = record_evidence(record, dataset)
        assert rubric.definition is not None
        try:
            evaluations = self.evaluator.evaluate(
                rubric,
                evaluation_case(record, dataset),
                evaluation_response(record),
                record.id,
                evidence[-1],
            )
        except Exception:
            self.store.finish_batch_case(
                case.model_copy(
                    update={
                        "status": "failed",
                        "error": "Evaluation failed; imported evidence preserved for review",
                        "finished_at": finished,
                    }
                )
            )
            return
        evaluator, settings = self.evaluator_identity()
        session = EvaluationSession(
            dataset_id=dataset.id,
            dataset_case_id=record.id,
            evidence_kind="dataset",
            rubric=rubric,
            rubric_definition_sha256=canonical_digest(rubric.definition),
            execution_sha256=evidence_digest(dataset.id, record),
            origin="dataset_import",
            evaluator=evaluator,
            evaluator_settings=settings,
            status="completed",
            evaluations=evaluations,
            evidence=evidence,
            created_at=finished,
            completed_at=finished,
        )
        self.store.complete_batch_case(
            case.model_copy(
                update={
                    "status": "completed",
                    "session_id": session.id,
                    "finished_at": finished,
                }
            ),
            session,
        )

    def agreement(
        self, *, experiment_id: str | None = None, batch_id: str | None = None
    ) -> AgreementReport:
        """Inter-rater statistics per rubric criterion; never mixes scales."""
        if (experiment_id is None) == (batch_id is None):
            raise ValueError("Choose exactly one experiment or batch")
        if experiment_id is not None:
            sessions = self.store.sessions(experiment_id=experiment_id)
            scope, scope_id = "experiment", experiment_id
        else:
            assert batch_id is not None
            cases = self.store.batch_cases(batch_id)
            sessions = [
                self.store.session(case.session_id) for case in cases if case.session_id is not None
            ]
            scope, scope_id = "batch", batch_id
        judgments = [
            judgment
            for session in sessions
            for judgment in self.store.judgments(session_id=session.id)
        ]
        by_key: dict[tuple[str, str], list[HumanJudgment]] = {}
        for judgment in judgments:
            by_key.setdefault((judgment.session_id, judgment.criterion_id), []).append(judgment)
        units: list[AgreementUnit] = []
        for session in sessions:
            definition = session.rubric.definition
            if definition is None:
                continue
            for criterion in definition.criteria:
                units.append(
                    AgreementUnit(
                        session_id=session.id,
                        rubric_id=definition.id,
                        rubric_version=definition.version,
                        criterion=criterion,
                        judgments=by_key.get((session.id, criterion.id), []),
                    )
                )
        return build_agreement_report(units, scope=scope, scope_id=scope_id)

    def batch_report(self, batch_id: str) -> BatchReport:
        """Assemble the imported-response report for one batch."""
        batch = self.store.batch(batch_id)
        dataset = self.store.dataset(batch.dataset_id)
        cases = self.store.batch_cases(batch_id)
        sessions = [
            self.store.session(case.session_id) for case in cases if case.session_id is not None
        ]
        records = [self.store.dataset_record(dataset.id, case.case_id) for case in cases]
        judgments = [
            judgment
            for session in sessions
            for judgment in self.store.judgments(session_id=session.id)
        ]
        adjudications = [
            value
            for session in sessions
            for value in self.store.adjudications(session_id=session.id)
        ]
        results = effective_results(sessions, judgments, adjudications)
        unresolved = disagreements(results, adjudications)
        scores = [
            summarize(
                None,
                session.rubric,
                session.evaluations,
                session.id,
                session.dataset_case_id,
            )
            for session in sessions
        ]
        return BatchReport(
            dataset=dataset,
            batch=batch,
            progress=batch_progress(cases, scores),
            cases=cases,
            records=records,
            evaluation_sessions=sessions,
            automated_scores=scores,
            human_judgments=judgments,
            adjudications=adjudications,
            effective_results=results,
            disagreements=unresolved,
            coverage=batch_coverage(cases, results, unresolved),
            agreement=self.agreement(batch_id=batch.id),
            evidence_digests=[
                *[session_evidence(session) for session in sessions],
                *[judgment_evidence(judgment) for judgment in judgments],
                *[adjudication_evidence(value) for value in adjudications],
            ],
        )

    def report(self, experiment_id: str) -> Report:
        """Assemble evidence, automated evaluations, human judgment and adjudication."""
        experiment = self.store.experiment(experiment_id)
        runs = self.store.runs(experiment_id)
        sessions = self.store.sessions(experiment_id=experiment_id)
        judgments = self.store.judgments(experiment_id=experiment_id)
        adjudications = self.store.adjudications(experiment_id=experiment_id)
        results = effective_results(sessions, judgments, adjudications)
        unresolved = disagreements(results, adjudications)
        scores: list[ScoreSummary] = []
        for run in runs:
            run_sessions = [s for s in sessions if s.run_id == run.id]
            if run_sessions:
                scores.extend(
                    summarize(run.id, s.rubric, s.evaluations, s.id) for s in run_sessions
                )
            else:
                scores.append(summarize(run.id, experiment.rubric, []))
        finding_reviews = self._finding_reviews(experiment_id, sessions, results)
        return Report(
            experiment=experiment,
            runs=runs,
            findings=self.store.findings(experiment_id),
            human_overrides=self.store.overrides(experiment_id),
            automated_scores=scores,
            evaluation_sessions=sessions,
            human_judgments=judgments,
            adjudications=adjudications,
            effective_results=results,
            finding_reviews=finding_reviews,
            disagreements=unresolved,
            coverage=coverage(runs, sessions, results, unresolved),
            agreement=self.agreement(experiment_id=experiment_id),
            evidence_digests=[
                *[execution_evidence(run) for run in runs],
                *[session_evidence(session) for session in sessions],
                *[judgment_evidence(judgment) for judgment in judgments],
                *[adjudication_evidence(value) for value in adjudications],
            ],
        )

    def _finding_reviews(
        self,
        experiment_id: str,
        sessions: list[EvaluationSession],
        results: list[EffectiveResult],
    ) -> list[FindingReview]:
        """Attach the effective status of the criterion behind each finding."""
        owners = {e.id: s.id for s in sessions for e in s.evaluations}
        criteria = {e.id: e.criterion_id for s in sessions for e in s.evaluations}
        by_key = {(r.session_id, r.criterion_id): r for r in results}
        reviews: list[FindingReview] = []
        for finding in self.store.findings(experiment_id):
            session_id = owners.get(finding.evaluation_id)
            result = by_key.get((session_id, criteria.get(finding.evaluation_id, "")))
            if result is None:
                reviews.append(
                    FindingReview(
                        finding_id=finding.id,
                        session_id=session_id,
                        effective_status="automated_only",
                        effective_outcome=None,
                        note="No session criterion matches this finding",
                    )
                )
                continue
            note = {
                "confirmed": "Adjudicated human judgment confirms the automated observation",
                "human_assessed": "Automated evaluation had no definite outcome; the "
                "adjudicated human assessment supplies one",
                "overridden": "Adjudicated human judgment contradicts this automated observation",
                "unresolved": "Human reviewers disagree and no adjudication resolved the criterion",
                "awaiting_human_review": "Human judgment recorded but not adjudicated",
                "automated_only": "Automated observation only; no human judgment recorded",
            }[result.status]
            reviews.append(
                FindingReview(
                    finding_id=finding.id,
                    session_id=session_id,
                    effective_status=result.status,
                    effective_outcome=result.effective_outcome,
                    note=note,
                )
            )
        return reviews
