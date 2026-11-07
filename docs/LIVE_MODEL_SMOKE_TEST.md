# Live-model smoke test

A bounded, operator-authorized check that a real OpenAI-compatible endpoint behaves as
configured. It is **not** run automatically, by CI, or by any background process, and
Faultline never contacts a provider without an explicit endpoint profile, an explicit
authorization note, explicit network opt-in and an explicit spending ceiling.

## Before you start

1. Add the endpoint profile (credential value stays in the environment):

   ```sh
   export MY_LAB_KEY=...            # never committed, never exported
   uv run faultline add-profile --name "Lab endpoint" \
     --provider openai-compatible --base-url https://your-endpoint.invalid/v1 \
     --credential-env MY_LAB_KEY --model your-model \
     --scope "Authorized by <owner> on <date> for <purpose>" --authorize
   ```

   `tool_calling` must be enabled for the profile (the smoke test exercises a tool
   round trip). The profile records the environment variable *name* only.

2. Confirm the local installation:

   ```sh
   uv run faultline version
   uv run faultline doctor
   ```

## Plan first: nothing is sent

```sh
uv run faultline smoke-plan --profile <profile-id> \
  --scenario retrieved-authority-spoof \
  --authorization "Owner approved one smoke run on <date>" \
  --allow-network \
  --max-requests 4 --max-output-tokens 64 --timeout 20 \
  --estimated-cost-per-request 0.002 --max-spend 0.05
```

`smoke-plan` prints the `SmokePlan` JSON: the exact model, scenario version, one
control/attack pair, per-request budgets, the request/token estimate, the spending
ceiling and the follow-up commands. It refuses to plan if the profile is not
authorized, the model is outside scope, tool calling is not declared, network opt-in
is missing, a spending ceiling is absent (or has no per-request estimate), or the caps
exceed the smoke limits (8 requests, 256 output tokens, 60 s).

## Execute

```sh
uv run faultline run-smoke --profile <profile-id> \
  --authorization "Owner approved one smoke run on <date>" --allow-network \
  --max-requests 4 --max-output-tokens 64 --timeout 20 \
  --estimated-cost-per-request 0.002 --max-spend 0.05 \
  --output reports/smoke
uv run faultline verify-report reports/smoke.json
```

`run-smoke` walks the validation protocol (authorization, credential presence,
capabilities, model identity, usage/finish reasons, tool round trip, evidence
sanitization, one scenario execution, retrieval delivery, multiturn continuation, tool
authorization, trace integrity, a one-trial control/attack experiment, quality checks,
export and export redaction) and prints each step's status. A failed step stops the
run and nothing is retried automatically.

## What to inspect afterwards

```sh
uv run faultline traces                     # stored traces
uv run faultline trace-tools <trace-id>     # proposals, decisions, receipts
uv run faultline trace-turns <trace-id>     # full ordered conversation
uv run faultline experiments                # the one-trial pair
uv run faultline experiment-status <id>
uv run faultline experiment-quality <id>    # blocking findings must be zero
uv run faultline experiment-summary <id>    # paired rates and interval
uv run faultline capability-reports         # observed versus configured
uv run faultline validation-runs --profile <profile-id>
```

Anomalies to look for: `tool_calls unknown` (endpoint accepted tools but never called
one), `model_identity` different from the requested model, `finish_reason: length`,
missing usage, a policy denial the agent ignored, any `blocking` quality check, or a
step reported as `skipped` when you expected execution.

## What this proves, and what it does not

It proves that Faultline's request shape, authentication, tool round trip, trace
recording, policy enforcement, evaluation, statistics and report export work against
*that* endpoint on *that* day. It does not validate model safety in general, does not
transfer to other models or versions, and does not replace the offline suite. A single
pair is descriptive only.

## If authorization or credentials are unavailable

Do not run it. Complete the offline work instead: the same protocol is exercised in
`tests/test_smoke.py` and `tests/test_validation.py` through in-process transports, and
`docs/VERIFICATION.md` records exactly which live steps remain unverified. Never
substitute scripted results for real observations.
