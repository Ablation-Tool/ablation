# Ablation

**Autonomous Reverse Engineering Tool**

```
    ___    ____  __    ___  ______________  _   __
   /   |  / __ )/ /   /   |/_  __/  _/ __ \/ | / /
  / /| | / __  / /   / /| | / /  / // / / /  |/ / 
 / ___ |/ /_/ / /___/ ___ |/ / _/ // /_/ / /|  /  
/_/  |_/_____/_____/_/  |_/_/ /___/\____/_/ |_/   
                                                   
 Autonomous Reverse Engineering Tool v2.2.0
```
---

<div>
  <img src="https://img.shields.io/badge/Language-Python_3-961490?style=flat-square" alt="Language">
  <img src="https://img.shields.io/badge/Build-PyInstaller-961490?style=flat-square" alt="Build">
  <img src="https://img.shields.io/badge/License-Research_Only-961490?style=flat-square" alt="License">
</div>

---

## ⚡ Overview

**Ablation fingerprints unknown systems from the inside** — platform detection, binary analysis, process enumeration, network mapping, privilege escalation paths, and syscall tracing. All autonomous. Zero dependencies on target.

### macOS

macOS support is first-class. Ablation runs natively without modification or target environment setup — no third-party packages required, no Python environment setup on target.


### 🍏 The "Special Sauce"

**`core/bv41_decoder.py` is the only publicly available offline decoder for Apple's framed LZ4 container format.** No other tool — standard LZ4 libraries, 7-Zip (including LZ4-enabled forks), Keka, or APFS forensic suites (BlackBag, Cellebrite) — implements this specific framing.

What makes it the only open implementation:

- **Full magic check.** Correctly identifies all three chunk types: `bv41` (LZ4-compressed), `bv4-` (passthrough), and `bv4$` (terminator). Generic LZ4 decoders open with a frame magic check (`0x184D2204`) and fail immediately.
- **Multi-chunk stream iteration.** Walks the complete chain of variable-length chunks until the `bv4$` terminator — stopping at the first block silently truncates output.
- **Passthrough handling.** The `bv4-` uncompressed case is decoded correctly without calling into lz4 at all. Most implementations that do partial bv41 support miss this branch.
- **Fully offline.** Requires only the open-source `lz4` block API — no Apple frameworks, no macOS runtime, no private APIs. Works cross-platform.



