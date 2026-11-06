# CEROTTO Repository Standards

## Repository structure

Follow the Ablation-Tool repository standard: concise positioning, verified capability tables, compact sections, and collapsible reference material. Link capability claims to implementation and tests. Do not claim unimplemented features or unverified compliance. Do not add banners, branding images, or shields.

## Documentation

Apply the white-bronco writing rules to README files and other documentation:

- Lead with the purpose or finding. Use short, direct sentences and precise verbs.
- Use no em dashes. Prefer separate sentences or a colon when appropriate.
- Remove filler, stacked hedges, and vague claims. Avoid "very," "really," "actually," "just," and "simply."
- Keep terminology consistent. Define abbreviations before using them.
- State tested behavior, limitations, and remaining work separately. Do not present hypotheses as evidence.
- Keep command examples minimal and test them before publication.

## Code review and publication

Run FORGE before staging code changes:

- For Python modules, run `FORGE.audit_module()` and resolve every HIGH or CRITICAL finding.
- For C and other languages not fully covered by the source scanner, complete the SAFE CODE ten-section review inline and record the result with `FORGE.record_result()`.
- `FORGE.audit_source()` alone is not a complete C review. Check its reported file inventory before relying on it.
- Do not commit or push with unresolved HIGH or CRITICAL findings.

Run the normal and sanitizer suites on the deliverable:

```sh
make clean && make && make check
make sanitize
make check BUILD_DIR=build/sanitize
```

Do not publish credentials, generated evidence, case databases, reports, build output, or local tool packages. Preserve the user's README positioning and integrate remote changes without force-pushing.
