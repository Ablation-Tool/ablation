"""
BEAM IFF Container & Atom-Table Obfuscation Analyzer.

Implements strict EA IFF 85 container parsing and anti-decompiler obfuscation
heuristics for Erlang/Elixir `.beam` modules (complementing `beam_context.py`):
  1. Container header vs. physical size mismatch (trailing/hidden data past EOF)
  2. Chunk boundary violations & truncation
  3. Rogue / unregistered chunk IDs outside the OTP allowlist
  4. Atom-table Shannon entropy spikes (hashed/randomized identifiers)
  5. Illegal/non-printable/zero-width characters in atom names
  6. Atom starvation (large `Code` chunk with artificially minimal atom table)
  7. Deliberate `Line` chunk stripping (and missing `Dbgi`/`Abst`)
  8. Poisoned zlib payloads inside `Dbgi`, `Abst`, or `LitT` chunks
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
import math
from pathlib import Path
import struct
from typing import Any, Dict, List, Optional, Tuple
import zlib


BEAM_MAGIC = b"FOR1"
BEAM_FORM = b"BEAM"

STANDARD_BEAM_CHUNKS = frozenset(
    {
        "Atom",
        "AtU8",
        "Code",
        "StrT",
        "ImpT",
        "ExpT",
        "FunT",
        "LitT",
        "LocT",
        "Attr",
        "CInf",
        "Dbgi",
        "Abst",
        "Line",
        "Type",
        "Meta",
        "Docs",
    }
)

_ZERO_WIDTH_CHARS = frozenset({"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"})
_SEVERITY_WEIGHTS = {"CRITICAL": 35, "HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 0}


@dataclass(frozen=True)
class BeamObfuscationFinding:
    rule_id: str
    severity: str
    title: str
    evidence: str
    chunk_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BeamObfuscationReport:
    source: str
    valid_beam_header: bool
    physical_size: int
    declared_container_size: int
    chunk_ids: List[str] = field(default_factory=list)
    atom_count: int = 0
    atom_shannon_entropy: float = 0.0
    code_size: int = 0
    obfuscation_score: int = 0
    obfuscated: bool = False
    findings: List[BeamObfuscationFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "valid_beam_header": self.valid_beam_header,
            "physical_size": self.physical_size,
            "declared_container_size": self.declared_container_size,
            "chunk_ids": list(self.chunk_ids),
            "atom_count": self.atom_count,
            "atom_shannon_entropy": round(self.atom_shannon_entropy, 4),
            "code_size": self.code_size,
            "obfuscation_score": self.obfuscation_score,
            "obfuscated": self.obfuscated,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _parse_atoms(payload: bytes, *, utf8: bool = True) -> List[str]:
    if len(payload) < 4:
        return []
    raw_count = struct.unpack(">i", payload[:4])[0]
    count = abs(raw_count)
    pos = 4
    atoms: List[str] = []
    encoding = "utf-8" if utf8 else "latin-1"

    # OTP 28+ uses negative count for compact variable-length atom lengths;
    # standard format uses 1-byte unsigned length prefix per atom.
    if raw_count >= 0:
        for _ in range(count):
            if pos >= len(payload):
                break
            alen = payload[pos]
            pos += 1
            if pos + alen > len(payload):
                break
            atoms.append(payload[pos : pos + alen].decode(encoding, errors="replace"))
            pos += alen
    else:
        for _ in range(count):
            if pos >= len(payload):
                break
            b0 = payload[pos]
            pos += 1
            if (b0 & 0x08) == 0:
                alen = b0 >> 4
            else:
                if pos >= len(payload):
                    break
                b1 = payload[pos]
                pos += 1
                alen = ((b0 & 0xE0) << 3) | b1
            if pos + alen > len(payload):
                break
            atoms.append(payload[pos : pos + alen].decode(encoding, errors="replace"))
            pos += alen
    return atoms


def _looks_zlib_header(data: bytes) -> bool:
    if len(data) < 2:
        return False
    cmf, flg = data[0], data[1]
    return (cmf & 0x0F) == 8 and ((cmf * 256 + flg) % 31) == 0


def analyze_beam_bytes(raw: bytes, *, source_name: str = "<memory>") -> BeamObfuscationReport:
    """Strictly parse a `.beam` IFF container and run anti-decompiler obfuscation checks."""
    phys_size = len(raw)
    findings: List[BeamObfuscationFinding] = []

    if phys_size < 12 or raw[:4] != BEAM_MAGIC or raw[8:12] != BEAM_FORM:
        findings.append(
            BeamObfuscationFinding(
                rule_id="INVALID_BEAM_HEADER",
                severity="HIGH",
                title="Invalid EA IFF 85 FOR1/BEAM header",
                evidence=f"size={phys_size} header={raw[:12]!r}",
            )
        )
        return BeamObfuscationReport(
            source=source_name,
            valid_beam_header=False,
            physical_size=phys_size,
            declared_container_size=0,
            obfuscation_score=25,
            obfuscated=True,
            findings=findings,
        )

    declared_body = struct.unpack(">I", raw[4:8])[0]
    declared_total = declared_body + 8

    # 1. Header vs. Physical Size check
    if declared_total != phys_size:
        delta = phys_size - declared_total
        findings.append(
            BeamObfuscationFinding(
                rule_id="CONTAINER_SIZE_MISMATCH",
                severity="HIGH",
                title="FOR1 declared size does not match physical file size",
                evidence=f"declared_total={declared_total} physical_size={phys_size} delta={delta:+d} bytes",
            )
        )

    # Walk IFF chunks strictly
    pos = 12
    limit = min(phys_size, max(declared_total, 12))
    chunks: List[Tuple[str, bytes, int, int]] = []
    chunk_ids: List[str] = []

    while pos < phys_size:
        if pos >= declared_total:
            # Trailing garbage past declared EOF already flagged by CONTAINER_SIZE_MISMATCH
            break
        if pos + 8 > phys_size:
            findings.append(
                BeamObfuscationFinding(
                    rule_id="CHUNK_BOUNDARY_VIOLATION",
                    severity="HIGH",
                    title="Truncated chunk header at container boundary",
                    evidence=f"offset={pos} remaining={phys_size - pos}",
                )
            )
            break
        cid = raw[pos : pos + 4].decode("latin-1", errors="replace")
        csize = struct.unpack(">I", raw[pos + 4 : pos + 8])[0]
        data_start = pos + 8
        data_end = data_start + csize
        if data_end > phys_size or data_end > declared_total:
            findings.append(
                BeamObfuscationFinding(
                    rule_id="CHUNK_BOUNDARY_VIOLATION",
                    severity="CRITICAL",
                    title="Chunk size extends past EOF or declared FOR1 container boundary",
                    evidence=f"chunk={cid!r} offset={pos} size={csize} data_end={data_end} phys={phys_size} declared={declared_total}",
                    chunk_id=cid,
                )
            )
            break
        payload = raw[data_start:data_end]
        chunks.append((cid, payload, pos, csize))
        chunk_ids.append(cid)

        # 3. Rogue chunk check
        if cid not in STANDARD_BEAM_CHUNKS:
            findings.append(
                BeamObfuscationFinding(
                    rule_id="ROGUE_CHUNK_ID",
                    severity="MEDIUM",
                    title="Unregistered non-standard BEAM IFF chunk ID",
                    evidence=f"chunk={cid!r} size={csize} at offset={pos}",
                    chunk_id=cid,
                )
            )

        # IFF 4-byte alignment padding
        padded = (csize + 3) & ~3
        pos = data_start + padded

    chunk_map = {cid: payload for cid, payload, _, _ in chunks}
    code_size = len(chunk_map.get("Code", b""))

    # 4 & 5. Atom table entropy & character bounds
    atoms: List[str] = []
    if "AtU8" in chunk_map:
        atoms = _parse_atoms(chunk_map["AtU8"], utf8=True)
    elif "Atom" in chunk_map:
        atoms = _parse_atoms(chunk_map["Atom"], utf8=False)

    joined_atoms = "".join(atoms)
    atom_entropy = shannon_entropy(joined_atoms)
    if len(joined_atoms) >= 64 and atom_entropy >= 4.55:
        findings.append(
            BeamObfuscationFinding(
                rule_id="ATOM_ENTROPY_SPIKE",
                severity="HIGH",
                title="High Shannon entropy in BEAM atom pool (hashed/randomized names)",
                evidence=f"entropy={atom_entropy:.3f} bits/char across {len(atoms)} atoms ({len(joined_atoms)} chars)",
                chunk_id="AtU8" if "AtU8" in chunk_map else "Atom",
            )
        )

    bad_atoms = []
    for a in atoms:
        if any((ord(ch) < 32 or ord(ch) == 127 or ch in _ZERO_WIDTH_CHARS) for ch in a):
            bad_atoms.append(repr(a)[:40])
            if len(bad_atoms) >= 5:
                break
    if bad_atoms:
        findings.append(
            BeamObfuscationFinding(
                rule_id="ATOM_ILLEGAL_CHARS",
                severity="HIGH",
                title="Non-printable, control, or zero-width characters in BEAM atom table",
                evidence=f"samples={bad_atoms}",
                chunk_id="AtU8" if "AtU8" in chunk_map else "Atom",
            )
        )

    # 6. Atom starvation
    if code_size >= 4096 and (len(atoms) == 0 or (code_size / max(len(atoms), 1)) > 512.0):
        findings.append(
            BeamObfuscationFinding(
                rule_id="ATOM_STARVATION",
                severity="MEDIUM",
                title="Large Code chunk paired with abnormally sparse atom table",
                evidence=f"code_size={code_size} bytes, atom_count={len(atoms)}",
                chunk_id="Code",
            )
        )

    # 7. Missing Line chunk (and debug chunks)
    if "Code" in chunk_map and "Line" not in chunk_map:
        findings.append(
            BeamObfuscationFinding(
                rule_id="LINE_CHUNK_STRIPPED",
                severity="MEDIUM",
                title="BEAM Line chunk stripped (anti-analysis / stack-trace suppression)",
                evidence=f"present_chunks={chunk_ids}",
                chunk_id="Line",
            )
        )

    # 8. Poisoned zlib payloads in LitT / Dbgi / Abst
    if "LitT" in chunk_map:
        litt = chunk_map["LitT"]
        if len(litt) >= 6:
            uncomp_sz = struct.unpack(">I", litt[:4])[0]
            if uncomp_sz > 0:
                try:
                    zlib.decompress(litt[4:])
                except zlib.error as err:
                    findings.append(
                        BeamObfuscationFinding(
                            rule_id="POISONED_ZLIB_PAYLOAD",
                            severity="CRITICAL",
                            title="Corrupted/poisoned zlib stream inside LitT chunk",
                            evidence=f"declared_uncompressed={uncomp_sz} error={err}",
                            chunk_id="LitT",
                        )
                    )

    for dbg_id in ("Dbgi", "Abst"):
        if dbg_id in chunk_map:
            payload = chunk_map[dbg_id]
            # ETF compressed term starts with 0x83 0x50 <4B size> <zlib...>
            if len(payload) >= 8 and payload[0] == 0x83 and payload[1] == 0x50:
                try:
                    zlib.decompress(payload[6:])
                except zlib.error as err:
                    findings.append(
                        BeamObfuscationFinding(
                            rule_id="POISONED_ZLIB_PAYLOAD",
                            severity="CRITICAL",
                            title=f"Corrupted/poisoned zlib ETF payload inside {dbg_id} chunk",
                            evidence=f"error={err}",
                            chunk_id=dbg_id,
                        )
                    )
            elif _looks_zlib_header(payload):
                try:
                    zlib.decompress(payload)
                except zlib.error as err:
                    findings.append(
                        BeamObfuscationFinding(
                            rule_id="POISONED_ZLIB_PAYLOAD",
                            severity="CRITICAL",
                            title=f"Corrupted/poisoned raw zlib payload inside {dbg_id} chunk",
                            evidence=f"error={err}",
                            chunk_id=dbg_id,
                        )
                    )

    score = min(100, sum(_SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings))
    return BeamObfuscationReport(
        source=source_name,
        valid_beam_header=True,
        physical_size=phys_size,
        declared_container_size=declared_total,
        chunk_ids=chunk_ids,
        atom_count=len(atoms),
        atom_shannon_entropy=atom_entropy,
        code_size=code_size,
        obfuscation_score=score,
        obfuscated=score >= 15,
        findings=findings,
    )


def analyze_beam_file(path: str | Path) -> BeamObfuscationReport:
    p = Path(path)
    return analyze_beam_bytes(p.read_bytes(), source_name=str(p))


class BeamObfuscationAnalyzer:
    """Ablation analyzer facade for `.beam` IFF container & atom-table obfuscation."""

    name = "beam_obfuscation_analyzer"

    def analyze_bytes(self, raw: bytes, source_name: str = "<memory>") -> BeamObfuscationReport:
        return analyze_beam_bytes(raw, source_name=source_name)

    def analyze_file(self, path: str | Path) -> BeamObfuscationReport:
        return analyze_beam_file(path)
