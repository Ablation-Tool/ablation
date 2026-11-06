# Security Policy

## Reporting a Vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/Ablation-Tool/kevlar/security/advisories/new)
to report security issues in Kevlar itself — bypasses to the CDR engine, scoring evasion techniques,
proxy escapes, or any other finding that affects the security guarantees described in the README.

Do not open a public issue for security reports.

Private vulnerability reporting must be enabled in the repository settings
(**Security → Advisories → Enable private vulnerability reporting**) before
this link becomes active.

## Scope

- CDR bypass: a tool description containing a known-malicious payload that survives `cdr_tool()` undetected.
- Scoring evasion: an indicator pattern that should fire but doesn't due to a regex gap.
- Proxy escape: content that reaches the client stdout containing attacker-controlled text that was not re-serialized through the policy engine.
- Egress DLP bypass: a credential-bearing `tools/call` argument that passes `scan_tool_call_args()` undetected.

Out of scope: false positives in the indicator registry (open an issue), Python version compatibility, performance.

## Supported Versions

Only the latest commit on `main` is supported.
