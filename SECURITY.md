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

**Alternative:** Email [ablation@nuclide-research.com](mailto:ablation@nuclide-research.com) with `[SECURITY]` in the subject line, or message on Signal at [@deadbug.06](https://signal.me/#p/deadbug.06). Include:

- A description of the vulnerability and its impact
- Steps to reproduce or a minimal proof-of-concept binary
- The Ablation version (`pip show ablation | grep Version`)

## Response

Acknowledgment within 72 hours. Bugs are remediated as fast as possible. Coordinated disclosure: no public details until a fix is available and you have reviewed the patch.
