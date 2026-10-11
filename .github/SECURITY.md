# Security Policy

## Scope

This policy covers vulnerabilities **in Ablation itself** -- bugs that could affect an analyst running the tool.

**In scope:**
- Code execution triggered by a crafted binary input (malicious ELF/PE/Mach-O causes RCE in the analyzer)
- Arbitrary file read or write via crafted binary inputs
- Dependency vulnerabilities that expand Ablation's attack surface

**Out of scope:**
- Findings in binaries being analyzed -- that is the tool's job
- Issues that require an attacker to already have local code execution on the analyst's machine
- Theoretical issues with no practical attack path

## Reporting

Do not open a public GitHub issue for security vulnerabilities.

**Preferred:** Use GitHub's private advisory flow -- click "Report a vulnerability" on the [Security tab](https://github.com/Ablation-Tool/ablation/security/advisories/new).

**Alternative:** Open a draft security advisory directly at the link above. Include:

- A description of the vulnerability and its impact
- Steps to reproduce or a minimal proof-of-concept binary
- The Ablation version (`pip show ablation | grep Version`)

## Response

Acknowledgment within 72 hours. Bugs are remediated as fast as possible. Coordinated disclosure: no public details until a fix is available and you have reviewed the patch.

## Security Practices

Ablation meets all mapped requirements from NIST SP 800-218 (SSDF), CISA Secure by Design, and DoD MIL-HDBK-115C. The full compliance matrix is in [`docs/ABLATION-STANDARDS.md`](docs/ABLATION-STANDARDS.md).

**Supply chain.** Dependencies are pinned with hashes in `requirements-hashed.txt`. `scripts/monitor-supply-chain.sh` runs pip-audit against all dependencies and writes a dated JSON report to `docs/supply-chain-reports/` so new CVEs surface before the next engagement. A software bill of materials is at `docs/sbom/ablation-sbom.json`.

**Taint engine.** The six labeled taint tracker modules require 85% statement coverage on every commit. The gate is enforced by `fail_under = 85` in `pyproject.toml` so a regression in taint logic fails the test suite. Known anomalies for each tracker are documented in `docs/known-anomalies/`.

**Code review.** Every module passes a 10-section FORGE audit before it can be committed. The audit catches correctness gaps, failure modes, and weak test assertions. Results are cached so the gate does not block re-runs on unchanged code.

**AI provenance.** AI-assisted code is logged in `docs/ai-provenance-log.md` per DoWI 8430.01 §3.6.c.
