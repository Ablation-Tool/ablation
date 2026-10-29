# Capability Documentation Standard

A capability reference should help a reader understand a system, not merely locate a function name. It should let a new user learn the underlying idea, give an experienced analyst precise operating guidance, and make the limits of the evidence visible.

---

## The reading contract

Every capability linked from the README is reviewed against these questions. A document can use different headings and organization when it answers them clearly.

1. **Why does this exist?** Explain the practical problem, missing capability, or manual workflow that motivated it.
2. **What should the reader understand first?** Define important terms and separate the layers before presenting implementation details.
3. **How does it work?** Describe inputs, transformations, outputs, and relevant boundaries.
4. **Why can this approach work?** Explain the evidence or invariant behind the method. Do not confuse a heuristic with a proof.
5. **How is it used?** Give a concrete example with current APIs and a meaningful result.
6. **What does the user gain?** Explain what becomes easier or newly possible and where the capability fits in a reverse-engineering workflow.
7. **What is its architectural role?** Identify a small building block, standalone workflow, integration, or compatibility layer. Possible future extension or replacement may be discussed without presenting speculation as planned work.
8. **Where does it stop?** Document unsupported cases, false positives, resource limits, security boundaries, and conclusions that need additional evidence.
9. **What should the reader do next?** Link prerequisites, related capabilities, and the appropriate next stage.

A short utility needs the same conceptual honesty as a large analyzer. Its explanation can be shorter because its scope is narrower, not because its purpose is unimportant.

---

## Explain the system in layers

Prefer a progression from problem to mechanism to API:

```text
artifact or question
  -> validated input
  -> useful transformation or analysis
  -> interpretable result
  -> independent verification
```

Define acronyms when they first matter. Use a small example to show what a term means before presenting a large table of variants. Complex output should be connected back to the input and the question the user asked.

Do not remove precise technical detail to make a page approachable. Add the conceptual steps that make the detail understandable.

---

## Examples and evidence

Examples must use current APIs and field names. Check them against implementation and existing tests. Execute deterministic examples when practical and record the verification in the capability documentation audit.

Label target-specific, privileged, network, and illustrative examples accurately. An illustrative output block must not be presented as observed output. A source-checked live-network example is not an executed live test.

Distinguish these levels of evidence:

- **Structural:** the input parsed successfully or the expected instruction sequence exists.
- **Analytical:** a model reports a candidate, score, path, or classification.
- **Confirmed:** independent evidence supports the claimed behavior under stated conditions.
- **Runtime:** a live target exhibited the behavior during an actual test.

A checksum is not a signature. A taint path is not automatically an exploitable path. A configuration file is not proof of a deployed service. A valid example is not proof that every input is supported.

---

## Role, scope, and change

Explain whether the capability is a foundational component, a compatibility wrapper, a focused analyzer, or an end-to-end workflow. Small components matter when they provide a reliable boundary that other tools can reuse.

Future integration, wider format support, and replacement are design possibilities unless a committed implementation exists. Do not advertise them as current behavior. State when a component intentionally remains independent or has no unified interface.

A capability reference should describe the implementation in the current checkout. Preserve historical findings as historical evidence, not as descriptions of current behavior.

---

## Review and maintenance

When code behavior changes, update the affected purpose, mechanism, examples, output fields, limitations, and related workflow documents in the same change. A correct API table beside an obsolete conceptual explanation is still obsolete documentation.

Keep README capability rows alphabetical by display name within each table. Insert a new capability at its alphabetical position rather than appending by recency, and verify the ordering before committing.

Review local links, relative anchors, prose, and deterministic examples. Keep audit evidence in [Capability Documentation Audit](capability-audit/CAPABILITY_DOCUMENTATION.md). The three firmware parser references demonstrate the intended style:

- [CAEN ASCII-Hex Firmware Containers](reference-modules/caen-ascii-hex.md)
- [bFLT (Binary Flat Format)](reference-modules/bflt.md)
- [JFFS2 Filesystem Reader](reference-modules/jffs2.md)

For the shared parsing example, see [Firmware Parsing: From Artifacts to Analysis](reference-modules/firmware-parsing.md).
