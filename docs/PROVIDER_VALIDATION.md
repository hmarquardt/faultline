# Provider validation

A profile's capability declaration is a configuration assertion. It is not proof
that the endpoint accepts the request shape, and Faultline never treats it as proof.
`faultline capabilities` measures what an authorized endpoint actually does; the
result is stored next to the declaration so a reviewer can see both.

## What is distinguished

| Feature | Configured when | Observed when |
| ------- | --------------- | ------------- |
| `chat_completions` | profile is authorized | a bounded completion returns HTTP 200 |
| `tool_calls` | `tool_calling=True` | the response contains a `tool_calls` entry in the declared schema |
| `tool_result_messages` | `tool_calling=True` | a follow-up `role="tool"` message is accepted |
| `token_limit_parameter` | always (`max_tokens` or `max_completion_tokens`) | the completion with that parameter is accepted |
| `temperature` | always | accepted **and** actually sent (not configured as `None`) |
| `seed` | always | accepted **and** actually sent |
| `system_role` | always | a `system` message is accepted |
| `model_identity` | never asserted | the response carries a `model` field |
| `usage_reporting` | never asserted | the response carries `usage` |
| `finish_reason` | never asserted | `choices[0].finish_reason` is present |

Each feature is `supported`, `unsupported` or `unknown`. `unknown` means the probe
did not exercise it — most importantly, an endpoint that accepts tool declarations
but returns no tool call leaves tool support **unknown**, because that observation
cannot distinguish "tools unsupported" from "model chose not to call one".

## Probe protocol

1. **Gates.** Authorized profile with a scope string, model inside `allowed_models`,
   `tool_calling` for the tool round trip, and `allow_network` unless an in-process
   transport was injected (an injected transport cannot open a socket).
2. **Credential.** A configured `credential_env` must resolve to a non-empty value;
   only presence is checked and only the variable name is recorded.
3. **Plain completion.** System + user message, `max_tokens`/`max_completion_tokens`
   = 16, `stream=false`, plus `temperature`/`seed` when configured.
4. **Tool round trip.** Declares the five synthetic tools, asks for
   `read_document`, then sends a `role="tool"` message whose content begins
   `[synthetic tool result]`. The tool is **never executed**: the content is
   fabricated by the probe, and the report says so.
5. **Evidence.** Every request/response pair is sanitized (credential replaced by
   `[CREDENTIAL REDACTED]`, strings truncated, list/dict sizes bounded), hashed, and
   captured as a `provider-probe` artifact. Token usage and finish reasons are
   copied from the first completion.
6. **Errors.** HTTP status codes are surfaced, transport failures raise
   `ProviderError` with an actionable message, and a rejected parameter is reported
   as `unsupported` for that feature rather than retried with different values.

## Validation workflow

```sh
uv run faultline validate-endpoint --profile <profile-id> \
  --scenario retrieved-authority-spoof --trials 1 \
  --allow-network --output reports/validation
```

Steps, each with `ok | failed | skipped | unknown` and a detail line:

1. `authorization` — authorized profile and scope statement.
2. `credential` — variable presence, never the value.
3. `capabilities` — the probe above; a failed chat completion ends the protocol.
4. `model_identity` — requested versus reported model.
5. `usage_and_finish_reason` — observed reporting.
6. `tool_round_trip` — synthetic round trip result.
7. `evidence_sanitization` — no credential text in the stored evidence.
8. `scenario_execution` — one real scenario run over the endpoint.
9. `retrieval_delivery` — how many retrieved tool results reached the model.
10. `multiturn_continuation` — assistant turns after tool results.
11. `tool_authorization` — every proposed call carries a policy decision.
12. `trace_evidence` — the stored trace digest matches its content.
13. `controlled_experiment` — a one-trial control/attack experiment.
14. `quality_checks` — blocking/warning/note counts.
15. `report_export` — JSON/Markdown/CSV written and digest verified, or `skipped`
    with a reason when no output prefix was supplied.

```sh
uv run faultline capabilities --profile <profile-id> --allow-network
uv run faultline capability-reports
uv run faultline validation-runs --profile <profile-id>
```

## Offline verification and what remains unverified

Because no hosted credential is available to automated tests, the protocol is
exercised through `httpx.MockTransport` with realistic compatible fixtures: a
supporting endpoint, an endpoint that rejects tool declarations, an endpoint that
accepts them but returns no tool call, an endpoint that rejects the token parameter,
a credential echo, and a transport failure. Those tests prove the workflow's
mechanics and its reports; they do **not** constitute live-model validation.

Still unverified without a real endpoint: real credential resolution against a
hosted service, real model identity strings, real rate limits and billing, vendor
specific tool-call schemas, and whether a hosted model actually chooses to call the
synthetic tools. Every report and validation run repeats the phrase "simulated" or
"synthetic" where that distinction matters.

## Recording

`ProviderCapabilityReport` is stored in `capability_reports` and linked from
comparison and benchmark reports. It keeps the configured snapshot, the observed
snapshot, every observation with its evidence hash, the observed model identity,
token usage, finish reasons and collected error messages. `mismatches` lists every
configured feature the probe could not confirm, which is exactly what a reviewer
needs before trusting an experiment.
