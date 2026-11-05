# Research influences and evidence policy

Reviewed public repository descriptions, file organization and README content on
2026-11-05. These notes are design synthesis, not validation of upstream claims.
Faultline imports no payload corpus, extracted system prompts, source code or
dependencies from these projects. Its toy prompts and fixtures are original.

| Reference | Design idea considered | Faultline decision |
| --- | --- | --- |
| [L1B3RT4S](https://github.com/elder-plinius/L1B3RT4S) | Provider-organized adversarial prompts, role and authority framing | A few synthetic authority/persona scenarios with explicit version and source references; no universal-success claims |
| [CL4R1T4S](https://github.com/elder-plinius/CL4R1T4S) | Visibility into prompt scaffolds and tool instructions | Preserve tester-owned full context and use synthetic system canaries; do not assume collected prompts are authentic or import private prompts |
| [P4RS3LT0NGV3](https://github.com/elder-plinius/P4RS3LT0NGV3) | Text transformation and encoding as composable perturbations | Implement one deterministic base64 toy request; retain the rendered input and parameters |
| [G0DM0D3](https://github.com/elder-plinius/G0DM0D3) | Multiple endpoint configuration, local compatible servers and comparative response workflows | Keep providers independent and baseline/attack responses side by side; no hosted telemetry or automatic races |
| [T3MP3ST](https://github.com/elder-plinius/T3MP3ST) | Orchestration, claims verification and tool receipt boundaries | Record bounded request attempts and insist on execution receipts; no autonomous offensive tool runner |

The family mappings above are our interpretation of public design ideas. A
reference on a technique means conceptual influence, not a copied prompt or a
demonstrated bypass. Local fixtures establish only that Faultline detects the
exact synthetic behavior in those fixtures. Baseline failures are recorded as
baseline failures and must not be attributed to the attack.

The optional HTTP adapter follows the documented Chat Completions shape from
the [official API reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create).
It sends role/content messages and records returned identity, finish reason and
usage. The profile explicitly chooses the output-token parameter; seed and
temperature can be omitted for endpoints that do not support them. Compatibility
must be checked per configured endpoint; no proprietary SDK is required.
