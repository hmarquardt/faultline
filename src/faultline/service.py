"""UI-independent use cases: prepare, enforce policy, execute, preserve evidence."""

import asyncio
import os

from faultline.domain import (
    EndpointProfile,
    EvidenceArtifact,
    ExecutionBudget,
    ExecutionRun,
    ExecutionSettings,
    Experiment,
    Finding,
    Report,
    Rubric,
    TargetModel,
    now,
)
from faultline.evaluation import Evaluator, summarize
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
            self.store.finish_run(run, findings)
        experiment = experiment.model_copy(
            update={
                "status": "failed" if failed else "dry_run" if experiment.dry_run else "completed",
                "completed_at": now(),
            }
        )
        self.store.update_experiment(experiment)
        return self.report(experiment.id)

    def report(self, experiment_id: str) -> Report:
        experiment = self.store.experiment(experiment_id)
        runs = self.store.runs(experiment_id)
        return Report(
            experiment=experiment,
            runs=runs,
            findings=self.store.findings(experiment_id),
            human_overrides=self.store.overrides(experiment_id),
            automated_scores=[summarize(r.id, experiment.rubric, r.evaluations) for r in runs],
        )
