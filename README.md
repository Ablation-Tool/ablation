
---

## ⚡ Overview

**Ablation reverse engineers systems from the inside**  platform detection, binary analysis, process enumeration, network mapping, privilege escalation paths, and syscall tracing. 


<p align="center">
  <img src="assets/sauce.jpg" width="480" alt="It's in the sauce">
</p>

**`core/bv41_decoder.py` is the only publicly available offline decoder for Apple's framed LZ4 container format.** No other tool — standard LZ4 libraries, 7-Zip (including LZ4-enabled forks), Keka, or APFS forensic suites (BlackBag, Cellebrite) — implements this specific framing.

What makes it the only open implementation:

- **Full magic check.** Correctly identifies all three chunk types: `bv41` (LZ4-compressed), `bv4-` (passthrough), and `bv4$` (terminator). Generic LZ4 decoders open with a frame magic check (`0x184D2204`) and fail immediately.
- **Multi-chunk stream iteration.** Walks the complete chain of variable-length chunks until the `bv4$` terminator — stopping at the first block silently truncates output.
- **Passthrough handling.** The `bv4-` uncompressed case is decoded correctly without calling into lz4 at all. Most implementations that do partial bv41 support miss this branch.
- **Fully offline.** Requires only the open-source `lz4` block API — no Apple frameworks, no macOS runtime, no private APIs. Works cross-platform.



