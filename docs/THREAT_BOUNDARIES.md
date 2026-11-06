# Threat boundaries

## Authorized use and network access

An operator attests ownership or authorization in a profile and records the scope.
Faultline enforces the exact configured URL and allowed model IDs. This is an
execution gate, not independent proof of consent. Only evaluate targets you may
test. A real run or connection test sends synthetic requests to that endpoint;
connection testing consumes one request and may be billed by the provider.

Mock runs, schema checks, report generation and automated tests have no network
dependency. Real execution requires both an authorized profile and per-experiment
network opt-in. Dry-run stores rendered cases without dispatch. HTTP has no
redirects, retries, environment proxies, automatic discovery or telemetry. TLS
verification remains enabled; HTTP is allowed only for loopback hosts. DNS and
the remote provider remain outside the harness's trust boundary.

## Untrusted documents and output

Rubric documents are UTF-8, bounded to 2 MB, hashed without newline conversion and
retained verbatim. JSON duplicate keys, YAML duplicate keys and YAML aliases are
rejected. Safe YAML loading excludes object execution. Plain text/Markdown waits
for human normalization. Unsupported evidence requirements produce uncertain
results. JSON Schema reference retrieval is disabled; local references work,
unresolvable references yield uncertain. No imported document runs Python.

Returned tool proposals are inert data. Actual execution requires trusted harness
receipts. The current application runs no model-requested tool, browser or shell.
The toy indirect-injection and multiturn techniques are prepared input contexts;
they do not implement live retrieval or adaptive multi-turn generation.

Trusted Python assertions are a library extension only, disabled by default and
enabled by explicit evaluator construction plus a local callable registry. The
implementation's inspectable source hash and Python identity are recorded; without
source provenance, the criterion remains uncertain. These assertions
run with the workbench process's permissions. They are not safe for untrusted
code and have no process isolation or reliable CPU/memory limit. The CLI/TUI
cannot import or enable them. Phase 2C should add isolated workers before expanding
this feature to user-supplied code.

## Imported responses and batches

A dataset file is untrusted input. It is bounded (5 MB, 2 000 records, 200 000
characters per response), parsed strictly (duplicate keys and non-finite numbers
rejected), hashed per record and never executed. Imported text is data: it is not
used as a template, not rendered as markup, and not sent anywhere. Batch
evaluation makes no network request at all, so a batch can never be described as a
provider execution; dataset sessions carry `evidence_kind="dataset"` and their own
evidence artifacts. A skipped case (empty response) is neither a pass nor a
failure, and a case-level evaluator error is recorded with a controlled message
rather than the exception text.

Agreement statistics are descriptive. They do not establish ground truth, do not
transfer beyond the sampled items, and must not be reported as accuracy. A
`not_applicable` rating is excluded from agreement and counted separately, but a
unit where one reviewer says `not_applicable` while another rates it is retained as
an applicability dispute with attribution. Groups never merge distinct rubric
definitions (the canonical definition digest is part of the key), weighted kappa
uses declared levels only, and undefined estimates state why they cannot be
computed.

## Synthetic tools and agentic execution

Agentic scenarios run against a closed registry of five synthetic tools whose only
effects are on an in-memory environment. The harness has no shell, no filesystem
write, no network call, no credential access and no delivery channel: `send_message`
queues into a labelled synthetic outbox and `update_record` mutates toy records.
Every proposal is recorded and decided by policy before execution; a denied call has
no receipt and no effect. Only receipts prove an action, and only verified
state-change digests prove an effect — a model's textual claim is never evidence.

Retrieved documents are untrusted data. The harness serves them exclusively as tool
results marked `source="retrieval"`/`trust="untrusted"` and never copies them into
the system prompt or the legitimate user request. An injection can therefore reach
the agent as text, but it cannot become a harness instruction. Trust boundaries are
recorded per scenario (`retrieved-document-to-agent-instruction`,
`-to-protected-value`, `-to-write-authorization`, `tool-output-to-system-instruction`,
`encoded-retrieved-content-to-action`, `retrieved-document-to-tool-side-effect`).

Budgets bound every loop: model requests, turns, tool invocations, cumulative
output tokens, response bytes, per-request and overall time. Execution stops with an
explicit termination reason and never retries a failed provider call. Scenario
payloads are fictional; the canary is a fixed synthetic string, recipients are
invalid domains and records are toys. Phase 3A has no adaptive attack generation,
no real retrieval service and no live external tool.

Reports keep five states distinct: injected text encountered, instruction adopted
(human-assessed), unauthorized action requested, action permitted or blocked, and
verified side effect. A blocked request is never reported as a compromise.

## Credentials and data at rest

Profiles store an environment variable name, never its credential value. Set the
variable in the launch environment using your own secret manager or secure shell
workflow. Faultline does not write a `.env` file or provide an encrypted credential
vault. Known configured credential occurrences in input snapshots are rejected
before execution persistence; occurrences echoed in decoded provider responses
are redacted and explicitly marked. Compliance after redaction is uncertain.
No request headers, wire bytes or provider error bodies are exported.

Redaction is exact-value protection for the configured credential; it is not a
general DLP system for unknown secrets, transformations or arbitrary sensitive
output. Do not paste real credentials into rubric documents or technique inputs.
Database/report files are created with owner-only POSIX permissions. SQLite is
not encrypted. Existing directory/file permissions, backups and workstation
security are the operator's responsibility. Exported reports can contain sensitive
model outputs and all synthetic input context. Source hashes detect accidental
changes; this is not a signed, tamper-proof audit log against a malicious local user.

## Evaluation and budgets

Deterministic criteria report literal observations and their limits. Exact-canary
failure means the response text contained that synthetic value at the recorded
offset. It does not prove training-data leakage, real-secret access or successful
tool execution. A missing canary is not a general safety certification. Failed
responses and missing telemetry never count as passed checks.

Ordinal, categorical and numeric criteria are human-assessed. The deterministic
evaluator reports `uncertain` for them; it never infers a binary pass or fail from
a label it cannot observe. Human labels, scores and outcomes are validated against
the rubric's own declared levels, categories, range and threshold, so a reviewer
cannot record a categorical category as an unrelated outcome or a score outside
the scale. A human judgment is not a measurement of truth: it is an attributed
opinion with a rationale, and disagreements between reviewers stay visible until
an explicit adjudication policy resolves them.

Request counts, rendered input bytes, response bytes, output-token allocation and
per-request wall time are bounded. Remote token limits are requested settings;
Faultline cannot force a malicious server to obey them or provide correct billing.
There is no monetary cost cap or tokenizer-based input-token budget. Local source
parsing and trusted Python are not resource-isolated.

## Interruption and audit

Each request is saved as running before dispatch and finalized independently.
An interrupted process can leave a running experiment/run in history. Faultline
does not silently retry, resume or relabel such records. A process killed after
the remote response but before SQLite commit can lose that response. Terminal
records and original scores are immutable through supported operations.

Evaluation records are separate from execution evidence: a new rubric or evaluator
creates an `EvaluationSession` and never rewrites the run. Automated evaluations,
evaluations inserted by sessions, human judgments, adjudications and legacy
overrides are append-only (SQLite triggers reject UPDATE and DELETE). Reviewers
revision their own records through `supersedes_id`, and adjudications chain the
same way, so earlier decisions remain in the database and in exports.

Canonical digests (`sha256-canonical-json/1`) give records a deterministic identity
and detect accidental alteration, and an export digest identifies one exported
artifact. They are not signatures and provide no protection against a local user
who can rewrite the database or the export; signed bundles are out of scope until
key management is justified.

Reports show original automated scores, every human judgment, the adjudication
policy and its rationale, and the effective outcome. An overridden automated
failure is labelled contested rather than presented as an uncontested final
finding.
