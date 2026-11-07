"""Operator-authorized live-model smoke test: tiny, bounded and auditable.

Nothing here contacts a provider by itself. ``plan_smoke`` builds the smallest
control/attack experiment that can still validate the whole chain, prints exactly
what it would spend and refuses unless the endpoint, model, scope and spending
ceiling are all explicit.
"""

from faultline.domain import (
    AgentBudget,
    EndpointProfile,
    ExecutionSettings,
    ExperimentLimits,
    SmokePlan,
)
from faultline.scenarios import scenario as agentic_scenario

ABSOLUTE_MAX_REQUESTS = 8
ABSOLUTE_MAX_OUTPUT_TOKENS = 256
ABSOLUTE_MAX_TIMEOUT_SECONDS = 60.0


def plan_smoke(
    profile: EndpointProfile,
    scenario_id: str = "retrieved-authority-spoof",
    *,
    model: str | None = None,
    allow_network: bool = False,
    authorization: str = "",
    max_output_tokens: int = 64,
    max_requests: int = 4,
    timeout_seconds: float = 20.0,
    max_estimated_spend_usd: float | None = None,
    estimated_cost_per_request_usd: float | None = None,
) -> SmokePlan:
    """Build the bounded smoke plan; raise on any missing authorization."""
    if not profile.authorized or not profile.authorization.strip():
        raise ValueError("The smoke test requires an authorized endpoint profile")
    if not authorization.strip():
        raise ValueError(
            "Supply an explicit authorization note for the live smoke test; nothing "
            "is executed without it"
        )
    if not profile.tool_calling:
        raise ValueError("The smoke test needs a profile that declares tool-calling capability")
    chosen_model = model or profile.allowed_models[0]
    if chosen_model not in profile.allowed_models:
        raise ValueError("Model is outside the authorized endpoint scope")
    if profile.provider != "mock" and not allow_network:
        raise ValueError("Live smoke tests require explicit network opt-in")
    if max_estimated_spend_usd is None:
        raise ValueError(
            "A live smoke test requires an explicit estimated spending ceiling; "
            "supply --max-spend (an estimate, never a provider bill)"
        )
    if estimated_cost_per_request_usd is None:
        raise ValueError(
            "A spending ceiling needs an operator-supplied per-request estimate; "
            "supply --estimated-cost-per-request"
        )
    if not 1 <= max_requests <= ABSOLUTE_MAX_REQUESTS:
        raise ValueError(f"A smoke test allows at most {ABSOLUTE_MAX_REQUESTS} requests")
    if not 1 <= max_output_tokens <= ABSOLUTE_MAX_OUTPUT_TOKENS:
        raise ValueError(
            f"A smoke test allows at most {ABSOLUTE_MAX_OUTPUT_TOKENS} output tokens per request"
        )
    if not 1 < timeout_seconds <= ABSOLUTE_MAX_TIMEOUT_SECONDS:
        raise ValueError("A smoke test timeout must be between 1 and 60 seconds")
    definition = agentic_scenario(scenario_id)
    estimated_requests = 2 * max_requests
    estimated_tokens = estimated_requests * max_output_tokens
    limits = ExperimentLimits(
        max_total_requests=max_requests,
        estimated_requests_per_variant=max_requests,
        estimated_cost_per_request_usd=estimated_cost_per_request_usd,
        max_estimated_spend_usd=max_estimated_spend_usd,
    )
    plan = SmokePlan(
        profile_id=profile.id,
        provider=profile.provider,
        model=chosen_model,
        scenario_id=definition.id,
        scenario_version=definition.version,
        budget=AgentBudget(
            max_requests=max_requests,
            max_turns=4,
            max_tool_invocations=4,
            max_output_tokens=max_output_tokens,
            request_timeout_seconds=timeout_seconds,
            overall_timeout_seconds=timeout_seconds * 2,
        ),
        settings=ExecutionSettings(
            max_output_tokens=max_output_tokens,
            timeout_seconds=timeout_seconds,
        ),
        limits=limits,
        authorization=authorization,
        allow_network=allow_network,
        estimated_requests=estimated_requests,
        estimated_tokens=estimated_tokens,
        max_estimated_spend_usd=max_estimated_spend_usd,
        commands=[
            f"faultline validate-endpoint --profile {profile.id} --model {chosen_model} "
            f"--scenario {definition.id} --allow-network",
            f"faultline plan-experiment {definition.id} --agent endpoint "
            f"--profile {profile.id} --model {chosen_model} --trials 1 --allow-network",
            "faultline experiment-quality <experiment-id>",
            "faultline verify-report <exported-report>.json",
        ],
    )
    return plan


async def execute_smoke(workbench, plan: SmokePlan, *, transport=None, output_prefix=None):
    """Run the bounded validation + one-trial experiment described by the plan."""
    profile = workbench.store.profile(plan.profile_id)
    run = await workbench.run_validation(
        profile,
        model=plan.model,
        scenario_id=plan.scenario_id,
        trials=plan.trial_count,
        allow_network=plan.allow_network,
        transport=transport,
        settings=plan.settings,
        output_prefix=output_prefix,
    )
    return run
