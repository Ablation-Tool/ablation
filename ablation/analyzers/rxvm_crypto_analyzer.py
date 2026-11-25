"""
Custom-VM, WebCrypto & Quantized-Model Analyzer (RXVM Full Archetype).

Derived from the complete RXVM reverse-engineering corpus (`components/RXVM/`:
`rxvm_crypto_layer_analysis.pdf`, `payload_0_crypto_annotated.txt`,
`ANALYSIS.md` [resolved `rx.M` revision], `a10_model.py`, `a10_model_weights.json`,
`rxvm_disasm.py`, and `rxc_decrypt.py`).

Capabilities:
  1. Custom JS-bytecode VM & WebCrypto anti-pattern detection:
     - Hybrid xxHash32 PRIME32_1 (`0x9E3779B1`) per-byte FNV-like mix +
       Murmur3 `fmix32` avalanche (`0x85EBCA6B`, `0xC2B2AE35`) with `0xDEADBEEF`
       seed (used to derive 4-byte `fnpb` RC4 cookie keys from `UA+SID`)
     - Predictable/unsalted `SHA-256(sid)` / `SHA-256(rid)` AES-128-CBC derivation
     - Legacy RC4 KSA/PRGA stream-cipher fallback downgrades (`rx.ep4` / `fn@433`)
     - 4-byte little-endian Unix timestamp replay-prefix framing
     - `config.DEBUG`-gated global key/IV exports (`__erk`, `__eri`, `__er`)
     - Embedded-key `rxc=` cookie framing & IE11 `msCrypto` polyfills
     - `"RX"` (`0x52 0x58`) XOR-reseeded bytecode wire header (`(offset % 127) + 37`)
     - Global Slot Map (`G0..Gn`) & Closure Table (`fn@<addr>`) extraction
  2. Full `rxc=` forensic cookie decryptor (unpadded Base64, RC4, `uint32 LE`
     timestamp, 7 `KNOWN_RXC_METRICS` stream parser, and `rx.df16` float16 decoder)
  3. Quantized client-side neural network saturation auditor
     (`analyze_quantization_saturation`) detecting BatchNorm-beta dominance &
     8-bit minifloat weight-collapse saturation (matching the resolved A10
     `sigmoid(26.5 ± 0.04) ≈ 1.0` proof)
  4. Annotated Markdown report renderer ready for PKCS #7 signing via
     `pdf-signature-toolkit`
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re
import struct
from typing import Any, Dict, List, Optional, Tuple


# ── Constants & Signatures ────────────────────────────────────────────────────

HYBRID_HASH_CONSTANTS = {
    "SEED_DEADBEEF": ("0xDEADBEEF", "3735928559"),
    "XXH32_PRIME32_1": ("0x9E3779B1", "2654435761"),
    "MURMUR3_FMIX_C1": ("0x85EBCA6B", "2246822507"),
    "MURMUR3_FMIX_C2": ("0xC2B2AE35", "3266489909"),
}
MURMUR3_CONSTANTS = HYBRID_HASH_CONSTANTS  # backwards-compatible alias

RXVM_OPCODES = (
    "STORE_LOCAL",
    "STORE_GLOBAL",
    "RESTORE_ARGS",
    "MAKE_CLOSURE",
    "PROP_SET",
    "ITER_INIT",
    "ITER_NEXT",
    "JMP_FALSE",
    "RET_VAL",
)

KNOWN_RXC_METRICS: Dict[int, str] = {
    16: "bot fingerprint bitmask (payload [4])",
    31: "scroll position hash",
    32: "mouse click timing (count/mean/sum, payload [5])",
    33: "mouse movement + acceleration (6 stats, payload [6])",
    34: "scroll velocity (count/mean/sum, payload [7])",
    35: "paint / navigation timing (payload [8])",
    48: "neural network score (float16, payload [11])",
}

SEVERITY_WEIGHTS = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 0}


@dataclass(frozen=True)
class RxvmCryptoFinding:
    rule_id: str
    severity: str
    title: str
    evidence: str
    line: int = 0
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RxvmCryptoReport:
    source: str
    findings: List[RxvmCryptoFinding] = field(default_factory=list)
    global_slots: Dict[str, str] = field(default_factory=dict)
    closures: List[Dict[str, str]] = field(default_factory=list)
    primitives_detected: List[str] = field(default_factory=list)
    opcode_hits: int = 0
    risk_score: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "risk_score": self.risk_score,
            "opcode_hits": self.opcode_hits,
            "primitives_detected": list(self.primitives_detected),
            "global_slots": dict(self.global_slots),
            "closures": list(self.closures),
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


# ── Pure-Python Crypto, Hash, Float16 & Full rxc= Cookie Decoder ─────────────

def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """Standard RC4 KSA + PRGA stream cipher (matches RXVM fn@433 / rxc_decrypt.py)."""
    if not key:
        raise ValueError("RC4 key must be non-empty")
    sbox = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + sbox[i] + key[i % klen]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]
    out = bytearray(len(data))
    i = 0
    j = 0
    for idx, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + sbox[i]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]
        out[idx] = b ^ sbox[(sbox[i] + sbox[j]) & 0xFF]
    return bytes(out)


def b64_decode_unpadded(s: str) -> bytes:
    """Decode standard Base64 with optional missing '=' padding (Amazon rxc= format)."""
    s = s.strip()
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.b64decode(s)


def decode_rxvm_float16(lo: int, hi: int) -> float:
    """Decode IEEE-754 half-precision float matching RXVM's `rx.df16`."""
    v = ((hi & 0xFF) << 8) | (lo & 0xFF)
    sign = -1.0 if (v & 0x8000) else 1.0
    exp = (v >> 10) & 0x1F
    mant = v & 0x3FF
    if exp == 31:
        return float("nan")
    if exp == 0:
        return sign * (mant / 1024.0) * (2.0 ** -14)
    return sign * (1.0 + mant / 1024.0) * (2.0 ** (exp - 15))


def parse_rxc_metrics(data: bytes) -> List[Dict[str, Any]]:
    """Parse decrypted RXVM `rxc=` metric stream (`E(v)` serialization)."""
    metrics: List[Dict[str, Any]] = []
    i = 0
    n = len(data)
    while i < n:
        metric_id = data[i]
        i += 1
        label = KNOWN_RXC_METRICS.get(metric_id, f"unknown (0x{metric_id:02x})")
        val_bytes: List[int] = []
        while i < n:
            if data[i] in KNOWN_RXC_METRICS and len(val_bytes) >= 2:
                break
            val_bytes.append(data[i])
            i += 1
        entry: Dict[str, Any] = {
            "id": metric_id,
            "label": label,
            "hex": bytes(val_bytes).hex(),
            "length": len(val_bytes),
        }
        if len(val_bytes) == 2:
            entry["float16"] = decode_rxvm_float16(val_bytes[0], val_bytes[1])
        elif metric_id == 48 and len(val_bytes) >= 2:
            entry["float16"] = decode_rxvm_float16(val_bytes[0], val_bytes[1])
            if len(val_bytes) >= 3:
                entry["model_id"] = val_bytes[2]
        if len(val_bytes) >= 2 and len(val_bytes) % 2 == 0:
            entry["uint16_le"] = [
                val_bytes[j] | (val_bytes[j + 1] << 8)
                for j in range(0, len(val_bytes), 2)
            ]
        metrics.append(entry)
    return metrics


def decrypt_rxc_cookie(cookie_b64: str) -> Dict[str, Any]:
    """
    Decrypt an RXVM-style `rxc=` behavioral cookie whose 4-byte RC4 key (`fnpb`)
    is shipped in cleartext bytes [1:5] after the 1-byte version header (`fnpv`),
    followed by RC4-encrypted `[uint32 LE unix_timestamp | metric_stream]`.
    """
    cleaned = cookie_b64.strip()
    if cleaned.startswith("rxc="):
        cleaned = cleaned[4:]
    cleaned = cleaned.split(";")[0].strip()

    raw = b64_decode_unpadded(cleaned)
    if len(raw) < 6:
        raise ValueError(f"rxc payload too short ({len(raw)} bytes; expected >= 6)")
    version = raw[0]
    key = raw[1:5]
    ciphertext = raw[5:]
    plaintext = rc4_crypt(key, ciphertext)

    timestamp: Optional[int] = None
    timestamp_utc: Optional[str] = None
    metric_bytes = b""
    if len(plaintext) >= 4:
        timestamp = struct.unpack("<I", plaintext[:4])[0]
        if 946684800 <= timestamp <= 4102444800:  # 2000-01-01 .. 2100-01-01
            timestamp_utc = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        metric_bytes = plaintext[4:]

    return {
        "version": version,
        "embedded_rc4_key_hex": key.hex(),
        "ciphertext_len": len(ciphertext),
        "plaintext_len": len(plaintext),
        "plaintext_hex": plaintext.hex(),
        "plaintext_ascii": plaintext.decode("utf-8", errors="replace"),
        "timestamp_le32": timestamp,
        "timestamp_utc": timestamp_utc,
        "metrics": parse_rxc_metrics(metric_bytes),
    }


def hybrid_xxh1_fmix32_hash(text: str, seed: int = 0xDEADBEEF) -> int:
    """
    Exact 32-bit unsigned hybrid hash matching RXVM Payload 0 `fn@263` (`G8`):
      - Per-byte FNV-like XOR-then-multiply with xxHash32 `PRIME32_1` (`0x9E3779B1`)
      - Verbatim Murmur3 `fmix32` avalanche (`0x85EBCA6B`, `0xC2B2AE35`)
    Used by RXVM to hash `userAgent + sessionId` for `rxc=` cookie key derivation.
    """
    h = seed & 0xFFFFFFFF
    raw = text.encode("utf-8")
    for b in raw:
        h = ((h ^ b) * 0x9E3779B1) & 0xFFFFFFFF
    h ^= len(text) & 0xFFFFFFFF
    h ^= (h >> 16)
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= (h >> 16)
    return h & 0xFFFFFFFF


# Backwards-compatible alias
murmur3_rxvm = hybrid_xxh1_fmix32_hash


# ── Quantized Client-Side Neural Net Saturation Auditor (Resolved A10 Proof) ─

def analyze_quantization_saturation(model_or_path: Dict[str, Any] | str | Path) -> Dict[str, Any]:
    """
    Audit an extracted quantized client-side MLP (e.g., `a10_model_weights.json`)
    for BatchNorm-beta dominance & low-bit minifloat weight-collapse saturation.

    Reproduces the resolved RXVM A10 finding: when hidden 8-bit minifloat weights
    (~0.01-0.05) are overwhelmed by final BatchNorm betas (~3.0) × output Dense
    weights (~1.5), the pre-sigmoid baseline offset (~26.5) dwarfs activation
    modulation (~0.04, <0.2% signal-to-offset ratio), collapsing `sigmoid(z)` to
    a near-constant output across diverse input distributions.
    """
    if isinstance(model_or_path, (str, Path)):
        p = Path(model_or_path)
        model = json.loads(p.read_text(encoding="utf-8"))
        source = str(p)
    else:
        model = model_or_path
        source = "<in-memory>"

    layers = list(model.get("layers", []))
    # RXVM JSON stores layers output-to-input; reverse to input-to-output order
    ordered = list(reversed(layers))
    features = model.get("features", [])
    norms = model.get("featureNorms", [])
    n_features = len(features)

    # Weight quantization statistics across hidden Dense layers
    dense_layers = [ly for ly in ordered if ly.get("type") == "dense"]
    bn_layers = [ly for ly in ordered if ly.get("type") == "batchnorm"]

    hidden_unique_levels = []
    hidden_mean_abs = []
    for d in dense_layers[:-1]:
        ws = [float(v) for v in d.get("weights", [])]
        if ws:
            hidden_unique_levels.append(len({round(v, 8) for v in ws}))
            hidden_mean_abs.append(sum(abs(v) for v in ws) / len(ws))

    # Compute structural baseline pre-sigmoid offset from last BN beta -> output Dense
    baseline_offset = 0.0
    bn_mean_abs_beta = 0.0
    out_mean_abs_w = 0.0
    if bn_layers and dense_layers:
        last_bn = bn_layers[-1]
        out_dense = dense_layers[-1]
        out_w = [float(v) for v in out_dense.get("weights", [])]
        out_b = [float(v) for v in out_dense.get("bias", [0.0])]
        n_units = len(out_w)
        params = [float(v) for v in last_bn.get("weights", [])]
        if n_units > 0 and len(params) == 4 * n_units:
            betas = params[n_units : 2 * n_units]
            bn_mean_abs_beta = sum(abs(b) for b in betas) / n_units
            out_mean_abs_w = sum(abs(w) for w in out_w) / n_units
            baseline_offset = out_b[0] + sum(max(0.0, betas[i]) * out_w[i] for i in range(n_units))

    # Forward-pass probe across 5 standardized synthetic profiles (-3σ, -1σ, 0, +1σ, +3σ)
    def _forward_pre_sigmoid(vec: List[float]) -> float:
        x = list(vec)
        for ly in ordered:
            lt = ly.get("type")
            if lt == "dense":
                bias = [float(v) for v in ly["bias"]]
                w = [float(v) for v in ly["weights"]]
                out_dim = len(bias)
                in_dim = len(x)
                y = list(bias)
                for i in range(out_dim):
                    for j in range(in_dim):
                        y[i] += x[j] * w[j * out_dim + i]
                x = y
            elif lt == "batchnorm":
                n = len(x)
                params = [float(v) for v in ly["weights"]]
                eps = float(ly.get("epsilon", 1e-3))
                gamma = params[0:n]
                beta = params[n : 2 * n]
                mean = params[2 * n : 3 * n]
                var = params[3 * n : 4 * n]
                x = [gamma[i] * ((x[i] - mean[i]) / math.sqrt(var[i] + eps)) + beta[i] for i in range(n)]
            elif lt == "relu":
                x = [max(0.0, v) for v in x]
            elif lt == "sigmoid":
                # Stop right before sigmoid so we inspect raw logit saturation
                return x[0]
        return x[0] if x else 0.0

    logits: List[float] = []
    probs: List[float] = []
    if n_features > 0:
        probes = [
            [0.0] * n_features,
            [-1.0] * n_features,
            [1.0] * n_features,
            [-3.0] * n_features,
            [3.0] * n_features,
            [(-2.0 if i % 2 == 0 else 2.0) for i in range(n_features)],
        ]
        for vec in probes:
            z = _forward_pre_sigmoid(vec)
            logits.append(z)
            z_clamped = max(-500.0, min(500.0, z))
            probs.append(1.0 / (1.0 + math.exp(-z_clamped)))

    logit_spread = (max(logits) - min(logits)) if logits else 0.0
    prob_spread = (max(probs) - min(probs)) if probs else 0.0
    mean_logit = (sum(logits) / len(logits)) if logits else baseline_offset
    signal_to_offset = (logit_spread / abs(mean_logit)) if abs(mean_logit) > 1e-9 else 1.0
    saturated = bool(abs(mean_logit) >= 10.0 and prob_spread < 1e-3)

    findings: List[Dict[str, Any]] = []
    if saturated:
        findings.append(
            {
                "rule_id": "QUANTIZED_MODEL_SIGMOID_SATURATION",
                "severity": "HIGH",
                "title": "Extracted neural classifier saturates to a constant output across test distributions",
                "evidence": (
                    f"mean_pre_sigmoid={mean_logit:.3f}, logit_spread={logit_spread:.4f}, "
                    f"signal_to_offset={signal_to_offset:.5f}, prob_spread={prob_spread:.2e}"
                ),
            }
        )
    if hidden_unique_levels and min(hidden_unique_levels) <= 64:
        findings.append(
            {
                "rule_id": "COARSE_MINIFLOAT_QUANTIZATION",
                "severity": "INFO",
                "title": "Hidden Dense weights occupy coarse low-bit quantization levels",
                "evidence": f"unique_levels_per_hidden_dense={hidden_unique_levels}, mean_abs_weight={[round(x, 4) for x in hidden_mean_abs]}",
            }
        )

    return {
        "source": source,
        "feature_count": n_features,
        "feature_norm_count": len(norms),
        "layer_count": len(layers),
        "hidden_unique_weight_levels": hidden_unique_levels,
        "hidden_mean_abs_weight": [round(x, 5) for x in hidden_mean_abs],
        "final_bn_mean_abs_beta": round(bn_mean_abs_beta, 4),
        "output_dense_mean_abs_weight": round(out_mean_abs_w, 4),
        "structural_baseline_offset": round(baseline_offset, 4),
        "mean_pre_sigmoid_logit": round(mean_logit, 4),
        "logit_spread": round(logit_spread, 5),
        "signal_to_offset_ratio": round(signal_to_offset, 6),
        "output_prob_spread": prob_spread,
        "saturated_constant_output": saturated,
        "findings": findings,
    }


# ── Core Bytecode / JS Crypto-Layer Analyzer ──────────────────────────────────

def _first_match_line(text: str, pattern: re.Pattern[str]) -> Tuple[int, str]:
    for lineno, line in enumerate(text.splitlines(), start=1):
        m = pattern.search(line)
        if m:
            return lineno, line.strip()[:140]
    m = pattern.search(text)
    if m:
        return 1, m.group(0).replace("\n", " ")[:140]
    return 0, ""


def _extract_global_slots_and_closures(text: str) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
    slots: Dict[str, str] = {}
    closures: List[Dict[str, str]] = []
    seen_closures = set()

    slot_re = re.compile(r"STORE_GLOBAL\s+(G\d+)\s*=\s*([^\n/#]+)")
    for m in slot_re.finditer(text):
        slot = m.group(1).strip()
        val = m.group(2).strip()[:80]
        slots.setdefault(slot, val)

    closure_re = re.compile(r"\b(fn@\d+)\b(?:\s*(?:—|--|:|->)\s*([^\n]{3,80}))?")
    for m in closure_re.finditer(text):
        addr = m.group(1)
        if addr not in seen_closures:
            seen_closures.add(addr)
            closures.append({"address": addr, "note": (m.group(2) or "").strip()})
    return slots, closures


def analyze_rxvm_source(text: str, *, source_name: str = "<memory>") -> RxvmCryptoReport:
    """
    Analyze bytecode disassembly or JavaScript source for RXVM-class custom VM
    crypto layers and client-side WebCrypto weaknesses.
    """
    findings: List[RxvmCryptoFinding] = []
    primitives: List[str] = []

    # 1. RXVM bytecode opcode fingerprint
    opcode_hits = sum(1 for op in RXVM_OPCODES if re.search(rf"\b{op}\b", text))
    if opcode_hits >= 4:
        primitives.append("RXVM_CUSTOM_BYTECODE_VM")
        findings.append(
            RxvmCryptoFinding(
                rule_id="RXVM_BYTECODE_VM_DETECTED",
                severity="INFO",
                title="Custom stack/register bytecode VM disassembly detected",
                evidence=f"{opcode_hits}/{len(RXVM_OPCODES)} RXVM VM opcodes present",
                line=1,
                remediation="Inspect global slot promotion and per-closure XOR key reseeding before trusting obfuscated telemetry.",
            )
        )

    # 2. Hybrid xxHash32 PRIME32_1 + Murmur3 fmix32 (0xDEADBEEF seed)
    matched_hash = []
    for cname, variants in HYBRID_HASH_CONSTANTS.items():
        if any(re.search(re.escape(v), text, re.IGNORECASE) for v in variants):
            matched_hash.append(cname)
    if len(matched_hash) >= 2:
        primitives.append("HYBRID_XXH1_FMIX32_HASH")
        ln, ev = _first_match_line(
            text,
            re.compile(r"0xDEADBEEF|3735928559|0x9E3779B1|2654435761|0x85EBCA6B", re.IGNORECASE),
        )
        findings.append(
            RxvmCryptoFinding(
                rule_id="HYBRID_XXH1_FMIX32_HASH",
                severity="LOW",
                title="Hybrid xxHash32 PRIME32_1 + Murmur3 fmix32 non-cryptographic hash detected",
                evidence=f"Matched constants {matched_hash}: {ev}",
                line=ln,
                remediation="Non-cryptographic 32-bit hashes must never derive confidentiality keys (e.g., UA+SID cookie keys).",
            )
        )

    # 3. Predictable SHA-256(session_id / request_id) AES-CBC key & IV derivation
    has_sha256 = bool(re.search(r"SHA-256|sha256", text, re.IGNORECASE))
    has_aes_cbc = bool(re.search(r"AES-CBC|importKey\s*\(|subtle\.encrypt", text, re.IGNORECASE))
    has_id_kdf = bool(re.search(r"\b(sid|rid|session_id|request_id)\b", text, re.IGNORECASE))
    if has_sha256 and has_aes_cbc:
        primitives.append("WEBCRYPTO_AES_128_CBC")
        if has_id_kdf:
            ln, ev = _first_match_line(text, re.compile(r"SHA-256|importKey|AES-CBC", re.IGNORECASE))
            findings.append(
                RxvmCryptoFinding(
                    rule_id="PREDICTABLE_ID_KEY_DERIVATION",
                    severity="HIGH",
                    title="Unsalted SHA-256 key/IV derivation from observable session/request IDs",
                    evidence=ev,
                    line=ln,
                    remediation="Derive session keys via HKDF-SHA256 with high-entropy secret key material and use AEAD (AES-GCM or ChaCha20-Poly1305) with random nonces.",
                )
            )
        else:
            ln, ev = _first_match_line(text, re.compile(r"AES-CBC", re.IGNORECASE))
            findings.append(
                RxvmCryptoFinding(
                    rule_id="UNAUTHENTICATED_AES_CBC",
                    severity="MEDIUM",
                    title="Unauthenticated AES-CBC encryption detected without MAC/AEAD",
                    evidence=ev,
                    line=ln,
                    remediation="Prefer authenticated encryption (AES-GCM or ChaCha20-Poly1305) to prevent ciphertext malleability and padding oracles.",
                )
            )

    # 4. RC4 legacy stream-cipher fallback (rx.ep4 / fn@433)
    rc4_re = re.compile(r"\bRC4\b|\brx\.ep4\b|(\%\s*256.*swap|\b256\b.*S-box|fn@433)", re.IGNORECASE | re.DOTALL)
    if rc4_re.search(text):
        primitives.append("RC4_STREAM_CIPHER_FALLBACK")
        ln, ev = _first_match_line(text, re.compile(r"RC4|rx\.ep4|%\s*256|S-box|fn@433", re.IGNORECASE))
        findings.append(
            RxvmCryptoFinding(
                rule_id="RC4_FALLBACK_DOWNGRADE",
                severity="HIGH",
                title="Legacy RC4 stream-cipher fallback path present (rx.ep4 / fn@433)",
                evidence=ev,
                line=ln,
                remediation="Remove RC4 fallback paths (RFC 7465 prohibits RC4); fail closed when WebCrypto AEAD is unavailable.",
            )
        )

    # 5. DEBUG-gated global crypto key/IV leak (__erk, __eri, __er)
    debug_leak_re = re.compile(r"(__erk|__eri|__er\b|\.DEBUG\b.*(?:key|iv|__er))", re.IGNORECASE)
    if debug_leak_re.search(text):
        primitives.append("DEBUG_KEY_EXPORT")
        ln, ev = _first_match_line(text, debug_leak_re)
        findings.append(
            RxvmCryptoFinding(
                rule_id="DEBUG_GATED_KEY_EXPORT",
                severity="CRITICAL",
                title="DEBUG flag exports derived encryption key/IV to global object",
                evidence=ev,
                line=ln,
                remediation="Strip debug key-export hooks before production builds and mark WebCrypto keys non-extractable without global references.",
            )
        )

    # 6. 4-byte LE Unix timestamp replay prefix
    ts_re = re.compile(r"Uint32Array|Date\.now\(\)\s*/\s*1000|timestamp_le32|4\s*\+\s*\w+\.length", re.IGNORECASE)
    if ts_re.search(text):
        primitives.append("TIMESTAMP_LE32_PREFIX")
        ln, ev = _first_match_line(text, ts_re)
        findings.append(
            RxvmCryptoFinding(
                rule_id="TIMESTAMP_PREFIX_FRAMING",
                severity="INFO",
                title="4-byte little-endian Unix timestamp prepended to encrypted payload",
                evidence=ev,
                line=ln,
                remediation="Bind timestamps as AEAD associated data (AAD) so replay fields cannot be truncated or malleated.",
            )
        )

    # 7. IE11 msCrypto / Promise polyfill
    mscrypto_re = re.compile(r"\bmsCrypto\b|\boncomplete\b", re.IGNORECASE)
    if mscrypto_re.search(text):
        primitives.append("MSCRYPTO_EVENT_POLYFILL")
        ln, ev = _first_match_line(text, mscrypto_re)
        findings.append(
            RxvmCryptoFinding(
                rule_id="LEGACY_MSCRYPTO_POLYFILL",
                severity="LOW",
                title="Legacy IE11 msCrypto event-based crypto fallback detected",
                evidence=ev,
                line=ln,
                remediation="Retire IE11 msCrypto code paths to eliminate legacy cipher downgrades and shrink attack surface.",
            )
        )

    # 8. Embedded-key cookie framing (rxc= fnpv/fnpb)
    rxc_re = re.compile(r"\b(fnpv|fnpb|rxc=)\b", re.IGNORECASE)
    if rxc_re.search(text):
        primitives.append("EMBEDDED_KEY_COOKIE_RC4")
        ln, ev = _first_match_line(text, rxc_re)
        findings.append(
            RxvmCryptoFinding(
                rule_id="EMBEDDED_KEY_COOKIE_FRAME",
                severity="HIGH",
                title="Plaintext RC4 key (`fnpb`) embedded directly inside serialized `rxc=` cookie",
                evidence=ev,
                line=ln,
                remediation="Treat self-keyed client cookies as obfuscation only, never confidentiality or integrity protection.",
            )
        )

    # 9. RXVM wire header / XOR reseeding signature
    xor_re = re.compile(r"0x52\s+0x58|%\s*127\s*\)\s*\+\s*37|rx\.ex64", re.IGNORECASE)
    if xor_re.search(text):
        primitives.append("RXVM_XOR_RESEED_WIRE_HEADER")
        ln, ev = _first_match_line(text, xor_re)
        findings.append(
            RxvmCryptoFinding(
                rule_id="RXVM_XOR_RESEED_STREAM",
                severity="INFO",
                title="RXVM 'RX' wire header or `(offset % 127) + 37` XOR key-reseeding stream detected",
                evidence=ev,
                line=ln,
                remediation="Decode per-closure XOR stream before static crypto-constant scanning.",
            )
        )

    slots, closures = _extract_global_slots_and_closures(text)
    score = min(100, sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings))
    return RxvmCryptoReport(
        source=source_name,
        findings=findings,
        global_slots=slots,
        closures=closures,
        primitives_detected=primitives,
        opcode_hits=opcode_hits,
        risk_score=score,
    )


def analyze_rxvm_file(path: str | Path) -> RxvmCryptoReport:
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    return analyze_rxvm_source(text, source_name=str(p))


def render_annotated_markdown(report: RxvmCryptoReport, *, title: str = "VM Crypto-Layer Analysis Report") -> str:
    """
    Render a structured Markdown report mirroring the RXVM Payload 0 Crypto-Layer
    document layout (Overview -> Global Slot Map -> Closure Summary -> Findings).
    """
    lines = [
        f"# {title}",
        "",
        f"**Source:** `{report.source}`  ",
        f"**Risk Score:** `{report.risk_score}/100` | **RXVM Opcode Hits:** `{report.opcode_hits}`  ",
        f"**Primitives Detected:** {', '.join(f'`{p}`' for p in report.primitives_detected) or '_none_'}",
        "",
        "## Global Slot Map",
        "",
    ]
    if report.global_slots:
        lines += ["| Slot | Assigned Value |", "|---|---|"]
        for slot, val in sorted(report.global_slots.items()):
            lines.append(f"| `{slot}` | `{val}` |")
    else:
        lines.append("_No explicit `STORE_GLOBAL` slot promotions extracted._")

    lines += ["", "## Closure Summary", ""]
    if report.closures:
        lines += ["| Address | Notes |", "|---|---|"]
        for c in report.closures:
            lines.append(f"| `{c['address']}` | {c['note'] or '—'} |")
    else:
        lines.append("_No `fn@<addr>` closures extracted._")

    lines += ["", "## Security Findings", ""]
    if report.findings:
        lines += ["| Severity | Rule ID | Line | Title | Remediation |", "|---|---|---:|---|---|"]
        for f in report.findings:
            lines.append(f"| **{f.severity}** | `{f.rule_id}` | {f.line} | {f.title} | {f.remediation} |")
    else:
        lines.append("_No client-side crypto anti-patterns detected._")
    lines.append("")
    return "\n".join(lines)


class RxvmCryptoAnalyzer:
    """Ablation analyzer facade for custom-VM, WebCrypto, and quantized-model pipelines."""

    name = "rxvm_crypto_analyzer"

    def analyze_text(self, text: str, source_name: str = "<memory>") -> RxvmCryptoReport:
        return analyze_rxvm_source(text, source_name=source_name)

    def analyze_file(self, path: str | Path) -> RxvmCryptoReport:
        return analyze_rxvm_file(path)

    def decrypt_rxc(self, cookie_b64: str) -> Dict[str, Any]:
        return decrypt_rxc_cookie(cookie_b64)

    def audit_quantization_saturation(self, model_or_path: Dict[str, Any] | str | Path) -> Dict[str, Any]:
        return analyze_quantization_saturation(model_or_path)

    def render_markdown(self, report: RxvmCryptoReport, title: str = "VM Crypto-Layer Analysis Report") -> str:
        return render_annotated_markdown(report, title=title)
