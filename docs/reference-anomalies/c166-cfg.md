# Known Anomalies: C166 CFG and Direct Xrefs

## Coverage and reachability

- **False negative: unseeded entry points.** Interrupt vectors, callbacks reached only through computed tables, and code entered by another runtime are absent unless supplied as entries. Use IVT evidence, direct-call targets, and target-specific tables as additional seeds.
- **False positive: shared tails.** Compiler-shared epilogues can look like separate function entries. Ownership issues are preserved for review rather than automatically split into confident functions.
- **False positive: unknown linear code.** Two- or four-byte alignment can be correct while semantics are unknown. The issue is recorded and decoding continues without inventing control flow.

## Branch recovery

- **False negative: indirect calls and jumps.** `JMPI` and computed calls have no destination without a validated table model. Conditional fallthrough is retained; unconditional indirect control flow stops.
- **False positive: absolute branch in data.** Seeded code can contain an embedded value decoded as a branch only if the seed or preceding flow was wrong. Validate function provenance and call evidence.
- **Partial result: outside-image targets.** They are issues, not silently folded into a different mirror unless the decoder's explicit ROM model already resolves them.

## Data xrefs

- **False negative: indirect pointers.** `MOVB [R4], RL5` and based-index operations do not identify the pointed-to object. Use execution or a target memory model.
- **False negative: uncharacterized absolute opcodes.** The conservative direct-operation tables omit operations whose semantics have not been validated. They never treat every immediate word as a pointer.
- **False positive: immediate coincidence.** An address-shaped immediate is excluded unless the opcode proves an absolute memory access. Even then, the access is conditional on actual runtime reachability.
- **Address ambiguity: DPP values.** DPP index and page offset are reported separately. A physical address is computed only with caller-supplied page values; no default page is treated as target truth.

## Output and limits

- Function, instruction, issue, and seed limits fail with an exception instead of returning a truncated success. Increase limits only after checking why the input exceeded them.
- `code_ranges` and `unclassified_ranges` describe this recovery, not definitive code/data segmentation of the whole image.
- JSON is evidence for subsequent analysis, not a security verdict by itself.
