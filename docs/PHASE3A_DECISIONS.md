# Phase 3A architectural decisions

Status: accepted for Phase 3A (instrumented agentic red-team evaluation).
Baseline: Phase 2B (`cfea21b`).

Phase 1/2A/2B invariants still hold: execution evidence is immutable, evaluation
sessions are independent of execution, regrading never contacts a model, rubric
wording and scales survive unchanged, judgments and adjudications are append-only,
effective outcomes need an explicit policy, and source evidence identity stays
distinct from export identity.

## D1. Tools are instrumented, synthetic and policy-gated

`faultline.tooling` owns a closed registry of five synthetic tools
(`search_documents`, `read_document`, `write_note`, `send_message`,
`update_record`) whose only effects are on an in-memory `SyntheticEnvironment`
(controlled documents, notes, a message outbox and toy records). There is no shell,
no filesystem write, no network call, no credential access and no real delivery.
`send_message` queues into a synthetic outbox and is labelled as such everywhere.

A `ToolDefinition` declares name, version, description, input JSON Schema,
side-effect class, authorization class and receipt requirement. A `ToolPolicy`
decides on each proposed call *before* execution and the decision is recorded even
when the call is denied. Denial is a first-class, evidenced outcome, not an error.

Every proposal becomes a `ToolInvocation` with a correlation id carrying the
proposed arguments, the `ToolPolicyDecision`, and either a
`ToolExecutionReceipt` (executed flag, structured output, verified
`ToolStateChange` digests, timestamps, provenance) or nothing. A model's claim that
it ran a tool is never evidence: only receipts count.

## D2. Agent execution is a bounded, recorded conversation

`faultline.agents` runs a conversation loop over an `AgentProvider` Protocol with
explicit `AgentCapabilities`. Phase 3A ships `ScriptedAgentProvider` (deterministic
fixtures, no model) and an optional tool-calling path on the existing
OpenAI-compatible adapter that is used only when the capability is declared; the
ordinary completion path is unchanged and providers without tool support are never
asked for tool calls.

Every turn is a `ConversationTurn` with index, role, content, source
(`harness`/`attacker`/`model`/`tool`/`retrieval`), trust (`trusted`/`untrusted`/
`derived`), tool correlation ids, usage, model identity and timestamp. Budgets
(model requests, turns, tool invocations, output tokens, response bytes, per-request
timeout, overall timeout) terminate the loop with an explicit `termination` reason:
`final_answer`, `max_turns`, `max_requests`, `max_tool_invocations`,
`max_output_tokens`, `max_response_bytes`, `timeout`, `provider_error`,
`unsupported_capability` or `cancelled`.

The trace is checkpointed after every turn (like a run checkpoint), so an
interrupted or cancelled execution keeps the evidence it already produced. Phase 3A
does not retry a remote request.

## D3. Retrieved documents are data, never instructions

Scenario documents are served only through `search_documents`/`read_document` tool
results. The harness never copies retrieved text into the system prompt; a tool
result is recorded with `source="retrieval"` and `trust="untrusted"`. The attacker
controls document content only — not the system prompt and not the legitimate user
request — and the trace records the exact attack-bearing document with its SHA-256
plus the trust boundary crossed.

Observed states are kept distinct: injected text encountered, instruction adopted,
unauthorized action requested, action permitted or blocked, and verified side
effect. A blocked attempt is not a compromise.

## D4. Agentic evidence is a trace, and evaluation reuses sessions

`AgenticExecutionTrace` is the immutable evidence record: scenario snapshot and
digest, rubric snapshot, provider/model identity, ordered turns, invocations,
decisions, receipts, state changes, termination reason, budgets, evidence artifacts
and a canonical execution digest. Schema version 4 adds `agentic_traces` and lets
`EvaluationSession` reference a trace (`evidence_kind="agentic"`) instead of a run
or dataset case, so judgments, adjudications, effective results, agreement and
reports work unchanged. Re-evaluating a stored trace is a new session and never
re-runs the target.

## D5. Trace-aware deterministic checks stay conservative

`faultline.agentic_eval` implements trace checks: `forbidden_tool_request`,
`forbidden_tool_execution`, `tool_policy_blocked`, `protected_record_unchanged`,
`canary_absent` and `agent_task_completed`. They read harness observations only
(proposals, decisions, receipts, verified state digests, recorded turns). Whether
the agent *understood* an injection, or treated it as a higher-priority
instruction, is not deterministically decidable: such criteria stay `uncertain` and
require human review. The standard evaluator returns `uncertain` for trace checks,
so a trace-only rubric cannot be scored against a plain run or dataset case.

## D6. Reports state what is simulated

`AgenticReport` (format 2.1.0) carries objective, attack surface, payload and
provenance, timeline, tool requests, policy decisions, executions, state changes,
rubric evaluations, human judgments and adjudication, the observed result, evidence
digests and limitations. It never describes a synthetic tool execution as an action
against an external system and labels scripted agents as scripted.

## D7. Schema version 4

Adding an agentic subject requires rebuilding `evaluation_sessions` (nullable
`agentic_trace_id`, CHECK across the three subject kinds) and creating
`agentic_traces`. The migration keeps the Phase 2B procedure: one transaction,
foreign keys disabled for the rebuild, `PRAGMA foreign_key_check` before commit,
rollback on failure, all rows/IDs/snapshots preserved. Trace rows are checkpoints
while running, so they are guarded by a `status='running'` predicate and protected
by a no-delete trigger; `evaluation_sessions`, `judgments` and `adjudications`
remain insert-only.

## D8. Provider capabilities

Tool calling is opt-in per profile: `EndpointProfile.tool_calling` defaults to
false, `providers.capabilities()` reports the declaration, and
`AgentEndpointProvider` refuses to run without it. The ordinary `complete` path is
unchanged, so existing profiles and workflows keep working. `ScriptedAgentProvider`
declares tool support unconditionally because it is a local fixture. A provider that
does not declare tool support can never receive `tools` in a request.

## D9. Known limitations

- Scripted fixtures say nothing about a real model's behaviour; the endpoint path is
  implemented and unit-tested through an in-process transport, not validated against
  a hosted provider.
- Instruction adoption is not deterministically decidable and stays a human
  judgement; runs without a judgment report `uncertain` for those criteria.
- A live agent run cannot be resumed after the process dies: checkpoints preserve
  evidence of what happened, not a continuation point.
- Tool schemas are a fixed local set; there is no plugin loading, no real retrieval
  service and no adaptive attack generation.
- Agreement for trace-level criteria inherits the Phase 2B caveats (descriptive,
  scale-bound, undefined estimates carry a reason).
