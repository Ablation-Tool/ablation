# BARE Adapter

**File:** `modules/bare_adapter.py`

## Why this exists

Converts Ablation vulnerability findings to `findings.json` and pipes them through the BARE binary to get ranked Metasploit module matches. BARE encodes 3,904 Metasploit modules at compile time. AI/ML-specific findings (HPKE, STRAP, RADIUS) typically trigger `no_high_confidence_match`; classic overflow/memcpy primitives surface usable MSF modules.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. No file reads beyond writing a temporary JSON file. All subprocess calls have timeout guards. No lief.parse(). No HTTP reads.
