"""Bounded agent loop: ordering, budgets, cancellation and trust boundaries."""

import asyncio

from faultline.agents import AgentLoop, ScriptedAgentProvider, initial_turns
from faultline.domain import AgentBudget, AgentCapabilities, AgentTurn, ScriptedStep, ToolRequest
from faultline.scenarios import scenario


def step(tools=None, final=None):
    return ScriptedStep(
        tool_calls=[ToolRequest(name=name, arguments=arguments) for name, arguments in tools or []],
        final=final,
    )


def run(steps, *, budget=None, cancel=None, scenario_id="retrieved-authority-spoof"):
    scenario_definition = scenario(scenario_id)
    loop = AgentLoop(
        scenario_definition,
        ScriptedAgentProvider(steps),
        budget or AgentBudget(),
    )
    return asyncio.run(
        loop.run(should_cancel=cancel),
    )


def test_turns_keep_exact_order_with_tool_correlation():
    turns, invocations, termination, error = run(
        [
            step([("search_documents", {"query": "refund"})]),
            step([("read_document", {"document_id": "doc-handbook"})]),
            step(final="REFUND-30"),
        ]
    )
    assert termination == "final_answer" and error is None
    assert [turn.index for turn in turns] == list(range(len(turns)))
    assert [turn.role for turn in turns] == [
        "system",
        "user",
        "assistant",
        "tool",
        "assistant",
        "tool",
        "assistant",
    ]
    assert [invocation.tool for invocation in invocations] == [
        "search_documents",
        "read_document",
    ]
    tool_turns = [turn for turn in turns if turn.role == "tool"]
    assert [turn.tool_request_id for turn in tool_turns] == [
        invocation.request_id for invocation in invocations
    ]
    assert all(turn.source == "retrieval" and turn.trust == "untrusted" for turn in tool_turns)


def test_retrieved_content_never_becomes_a_system_instruction():
    scenario_definition = scenario("retrieved-authority-spoof")
    injection = scenario_definition.documents[1].injection
    turns, _, _, _ = run(
        [
            step([("read_document", {"document_id": "doc-memo"})]),
            step(final="REFUND-30"),
        ]
    )
    system = [turn for turn in turns if turn.role == "system"]
    user = [turn for turn in turns if turn.role == "user"]
    assert len(system) == 1 and len(user) == 1
    assert injection not in system[0].content
    assert injection not in user[0].content
    carried = [turn for turn in turns if turn.role == "tool" and injection in turn.content]
    assert len(carried) == 1
    assert carried[0].source == "retrieval" and carried[0].trust == "untrusted"
    assert initial_turns(scenario_definition)[0].content.startswith(
        scenario_definition.system_prompt
    )


def test_tool_budget_terminates_the_loop():
    turns, invocations, termination, _ = run(
        [
            step(
                [
                    ("search_documents", {"query": "refund"}),
                    ("read_document", {"document_id": "doc-handbook"}),
                ]
            ),
            step([("read_document", {"document_id": "doc-memo"})]),
            step(final="REFUND-30"),
        ],
        budget=AgentBudget(max_tool_invocations=2),
    )
    assert termination == "max_tool_invocations"
    assert len(invocations) == 2
    # The proposal that exceeded the budget is recorded but never executed.
    assert turns[-1].role == "assistant"
    assert len([turn for turn in turns if turn.role == "tool"]) == 2


def test_request_and_turn_budgets_terminate_the_loop():
    steps = [step([("search_documents", {"query": "refund"})]) for _ in range(5)]
    _, invocations, termination, _ = run(steps, budget=AgentBudget(max_requests=2))
    assert termination == "max_requests"
    assert len(invocations) == 2
    _, _, turn_termination, _ = run(steps, budget=AgentBudget(max_turns=3))
    assert turn_termination == "max_turns"


def test_output_token_and_byte_budgets_terminate_the_loop():
    class TokenProvider(ScriptedAgentProvider):
        async def complete(self, *, turns, tools, budget):
            answer = await super().complete(turns=turns, tools=tools, budget=budget)
            return answer.model_copy(update={"usage": {"completion_tokens": 400}})

    loop = AgentLoop(
        scenario("retrieved-authority-spoof"),
        TokenProvider(
            [
                step([("search_documents", {"query": "refund"})]),
                step(final="two"),
            ]
        ),
        AgentBudget(max_output_tokens=500),
    )
    _, _, termination, _ = asyncio.run(loop.run())
    assert termination == "max_output_tokens"
    loop = AgentLoop(
        scenario("retrieved-authority-spoof"),
        ScriptedAgentProvider([step(final="x" * 500)]),
        AgentBudget(max_response_bytes=64),
    )
    _, _, termination, _ = asyncio.run(loop.run())
    assert termination == "max_response_bytes"


def test_cancellation_keeps_committed_evidence():
    checkpoints = []
    scenario_definition = scenario("retrieved-authority-spoof")
    loop = AgentLoop(
        scenario_definition,
        ScriptedAgentProvider(
            [
                step([("search_documents", {"query": "refund"})]),
                step(final="REFUND-30"),
            ]
        ),
        AgentBudget(),
    )
    state = {"calls": 0}

    def cancel() -> bool:
        state["calls"] += 1
        return state["calls"] >= 2

    turns, invocations, termination, _ = asyncio.run(
        loop.run(
            checkpoint=lambda t, i: checkpoints.append((len(t), len(i))),
            should_cancel=cancel,
        )
    )
    assert termination == "cancelled"
    assert checkpoints and checkpoints[-1] == (len(turns), len(invocations))
    assert invocations[0].receipt is not None


def test_overall_deadline_terminates_the_loop():
    loop = AgentLoop(
        scenario("retrieved-authority-spoof"),
        ScriptedAgentProvider([step(final="REFUND-30")]),
        AgentBudget(),
    )
    _, _, termination, _ = asyncio.run(loop.run(deadline=0.0, clock=lambda: 1.0))
    assert termination == "timeout"


def test_provider_failure_is_a_termination_not_a_crash():
    class FailingProvider(ScriptedAgentProvider):
        async def complete(self, *, turns, tools, budget):
            raise RuntimeError("boom")

    loop = AgentLoop(scenario("retrieved-authority-spoof"), FailingProvider([]), AgentBudget())
    turns, _, termination, error = asyncio.run(loop.run())
    assert termination == "provider_error"
    assert error and "preserved" in error
    assert len(turns) == 2


def test_scripted_provider_declares_tool_capability():
    provider = ScriptedAgentProvider([])
    assert isinstance(provider.capabilities, AgentCapabilities)
    assert provider.capabilities.supports_tool_calls
    _ = AgentTurn


def test_denied_tool_is_recorded_as_a_tool_message():
    turns, invocations, termination, _ = run(
        [
            step([("update_record", {"record_id": "rec-1001", "field": "status", "value": "x"})]),
            step(final="REFUND-30"),
        ]
    )
    assert termination == "final_answer"
    (invocation,) = invocations
    assert invocation.decision.decision == "denied"
    assert invocation.receipt is None
    denial = [turn for turn in turns if turn.role == "tool"][0]
    assert "denied by policy" in denial.content
    assert denial.trust == "derived"


def test_provider_receives_the_declared_tool_specifications():
    seen = {}

    class RecordingProvider(ScriptedAgentProvider):
        async def complete(self, *, turns, tools, budget):
            seen["tools"] = tools
            seen["turn_count"] = len(turns)
            return await super().complete(turns=turns, tools=tools, budget=budget)

    loop = AgentLoop(
        scenario("retrieved-authority-spoof"),
        RecordingProvider([step(final="REFUND-30")]),
        AgentBudget(),
    )
    asyncio.run(loop.run())
    names = {item["function"]["name"] for item in seen["tools"]}
    assert names == {
        "read_document",
        "search_documents",
        "send_message",
        "update_record",
        "write_note",
    }
    assert seen["turn_count"] == 2
