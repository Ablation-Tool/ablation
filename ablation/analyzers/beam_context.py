"""
BeamContext -- Erlang BEAM bytecode analyzer.

Extracts the searchable attack surface from a .beam file:
  - Module name and exported functions (ExpT chunk)
  - Imported external calls (ImpT chunk)  -- equivalent to PLT in ELF
  - All atoms (AtU8/Atom chunk)           -- equivalent to string table
  - Literals (LitT chunk, ETF-decoded)    -- embedded constants
  - String table (StrT chunk)             -- raw string segments
  - Debug info (Dbgi chunk)               -- source file, AST-level function
                                             definitions with line numbers,
                                             record names, included headers
  - Obfuscation indicators                -- missing/stripped chunks

Usage:
    from ablation.analyzers.beam_context import BeamContext

    ctx = BeamContext.from_path('/path/to/module.beam')
    print(ctx.summary())

    # Atom / string search
    for atom in ctx.atoms:
        if 'password' in atom or 'secret' in atom:
            print(atom)

    # Dangerous import check
    for imp in ctx.imports:
        if imp.function in ('os_cmd', 'open_port', 'apply'):
            print(f'[!] {imp}')

    # Source-level function list (from Dbgi AST, when available)
    for fn in ctx.ast_functions:
        print(fn)   # "name/arity  line N"

    # Obfuscation check
    if ctx.obfuscated:
        print(f'Obfuscation indicators: {ctx.obfuscation_indicators}')
"""

from __future__ import annotations

import re
import struct
import zlib
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Matches /erlang/lib/<app>-<version>/ebin/ in a BEAM file path.
_OTP_APP_RE = re.compile(r'[/\\]erlang[/\\]lib[/\\]([^/\\]+?)-[\d.]+[/\\]ebin[/\\]')

# ---------------------------------------------------------------------------
# BEAM magic
# ---------------------------------------------------------------------------

BEAM_MAGIC = b'FOR1'
BEAM_TAG = b'BEAM'

# ---------------------------------------------------------------------------
# Dangerous Erlang import signatures worth flagging
# ---------------------------------------------------------------------------

# (module, function) pairs that represent high-risk sinks in Erlang
# Severity tiers for dangerous imports (ascending severity):
#   DISPATCH   -- dynamic dispatch; extremely common in OTP; low signal alone
#   NETWORK    -- outbound network connections / UDP sockets
#   INFO       -- local system enumeration (network interfaces, etc.)
#   CODE_EVAL  -- runtime code loading / evaluation (ETF AST execution)
#   CODE_EXEC  -- OS-level process execution / port driver spawn
#
# Used by BeamImport.severity and BeamContext.dangerous_imports(min_severity=...).
SEVERITY_DISPATCH  = "DISPATCH"
SEVERITY_NETWORK   = "NETWORK"
SEVERITY_INFO      = "INFO"
SEVERITY_CODE_EVAL = "CODE_EVAL"
SEVERITY_CODE_EXEC = "CODE_EXEC"

_SEVERITY_ORDER = {
    SEVERITY_DISPATCH:  0,
    SEVERITY_NETWORK:   1,
    SEVERITY_INFO:      2,
    SEVERITY_CODE_EVAL: 3,
    SEVERITY_CODE_EXEC: 4,
}

# Maps (module, function) -> severity tier.
# Any entry here is "dangerous"; severity distinguishes signal strength.
DANGEROUS_IMPORTS: dict = {
    # OS-level execution
    ('os',      'cmd'):          SEVERITY_CODE_EXEC,
    ('erlang',  'open_port'):    SEVERITY_CODE_EXEC,
    # Dynamic code evaluation / hot-loading
    ('erl_eval', 'exprs'):       SEVERITY_CODE_EVAL,
    ('file',    'eval'):         SEVERITY_CODE_EVAL,
    ('code',    'load_binary'):  SEVERITY_CODE_EVAL,
    ('code',    'load_abs'):     SEVERITY_CODE_EVAL,
    ('code',    'load_file'):    SEVERITY_CODE_EVAL,
    # Network egress
    ('ssl',     'connect'):      SEVERITY_NETWORK,
    ('httpc',   'request'):      SEVERITY_NETWORK,
    ('gen_tcp', 'connect'):      SEVERITY_NETWORK,
    ('gen_udp', 'open'):         SEVERITY_NETWORK,
    # Local system info
    ('inet',    'getifaddrs'):   SEVERITY_INFO,
    # Dynamic dispatch (high volume, low signal alone)
    ('erlang',  'apply'):        SEVERITY_DISPATCH,
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BeamExport:
    function: str
    arity: int

    def __str__(self) -> str:
        return f"{self.function}/{self.arity}"


@dataclass
class BeamImport:
    module: str
    function: str
    arity: int
    dangerous: bool = False
    severity: str = ""   # one of SEVERITY_* constants; empty string when not dangerous

    def __str__(self) -> str:
        if self.dangerous:
            flag = f" [{self.severity}]" if self.severity else " [DANGEROUS]"
        else:
            flag = ""
        return f"{self.module}:{self.function}/{self.arity}{flag}"


@dataclass
class BeamAstFunction:
    name: str
    arity: int
    line: int

    def __str__(self) -> str:
        return f"{self.name}/{self.arity}  line {self.line}"


@dataclass
class BeamContext:
    path: str
    module_name: str = ""
    atoms: List[str] = field(default_factory=list)
    exports: List[BeamExport] = field(default_factory=list)
    imports: List[BeamImport] = field(default_factory=list)
    literals: List[str] = field(default_factory=list)   # ETF-decoded repr strings
    strings: List[str] = field(default_factory=list)    # StrT raw segments
    chunks: List[str] = field(default_factory=list)     # chunk IDs present
    # Dbgi-derived (AST level, when debug info is present)
    source_file: str = ""                               # original .erl filename
    ast_functions: List[BeamAstFunction] = field(default_factory=list)
    ast_records: List[str] = field(default_factory=list)   # record names
    ast_includes: List[str] = field(default_factory=list)  # included .hrl files
    has_debug_info: bool = False
    # Obfuscation
    obfuscated: bool = False
    obfuscation_indicators: List[str] = field(default_factory=list)
    # OTP stdlib origin: non-empty when path matches .../erlang/lib/<app>-<vsn>/ebin/
    otp_app: str = ""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def is_otp(self) -> bool:
        """True when this module originates from an OTP stdlib application."""
        return bool(self.otp_app)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_path(cls, path: str) -> "BeamContext":
        data = Path(path).read_bytes()
        if data[:4] != BEAM_MAGIC or data[8:12] != BEAM_TAG:
            raise ValueError(
                f"{Path(path).name!r} is not a valid BEAM file "
                f"(magic={data[:4]!r}, tag={data[8:12]!r})"
            )
        return cls._parse(data, path)

    @classmethod
    def from_bytes(cls, data: bytes, path: str = "<bytes>") -> "BeamContext":
        return cls._parse(data, path)

    # ------------------------------------------------------------------
    # Parser
    # ------------------------------------------------------------------

    @classmethod
    def _parse(cls, data: bytes, path: str) -> "BeamContext":
        ctx = cls(path=path)
        m = _OTP_APP_RE.search(path)
        if m:
            ctx.otp_app = m.group(1)
        raw_chunks = _split_chunks(data)
        ctx.chunks = list(raw_chunks.keys())

        # 1. Atom table (AtU8 preferred; fall back to Atom for latin-1)
        atoms = _parse_atoms(raw_chunks)
        ctx.atoms = atoms
        ctx.module_name = atoms[0] if atoms else ""

        # 2. Exports
        ctx.exports = _parse_exports(raw_chunks.get('ExpT', b''), atoms)

        # 3. Imports
        ctx.imports = _parse_imports(raw_chunks.get('ImpT', b''), atoms)

        # 4. Literals (LitT, zlib-compressed ETF)
        ctx.literals = _parse_literals(raw_chunks.get('LitT', b''))

        # 5. String table (StrT, raw bytes)
        strt = raw_chunks.get('StrT', b'')
        if strt:
            ctx.strings = [seg for seg in strt.split(b'\x00') if seg]
            ctx.strings = [s.decode('utf-8', errors='replace') for s in ctx.strings]

        # 6. Debug info (Dbgi chunk: ETF COMPRESSED_EXT wrapping AST)
        if 'Dbgi' in raw_chunks:
            _parse_dbgi(raw_chunks['Dbgi'], ctx)

        # 7. Obfuscation indicators (needs raw data for structural checks)
        _detect_obfuscation(ctx, raw_chunks, data)

        return ctx

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def dangerous_imports(self, min_severity: str = SEVERITY_DISPATCH) -> List[BeamImport]:
        """Return imports flagged as dangerous at or above min_severity.

        min_severity examples (ascending):
            SEVERITY_DISPATCH  -- all dangerous (default)
            SEVERITY_NETWORK   -- network + code-eval + code-exec
            SEVERITY_CODE_EVAL -- code-eval + code-exec
            SEVERITY_CODE_EXEC -- OS execution only
        """
        min_ord = _SEVERITY_ORDER.get(min_severity, 0)
        return [
            i for i in self.imports
            if i.dangerous and _SEVERITY_ORDER.get(i.severity, 0) >= min_ord
        ]

    def search_atoms(self, keyword: str, case_sensitive: bool = False) -> List[str]:
        """Return atoms containing keyword."""
        if not case_sensitive:
            keyword = keyword.lower()
            return [a for a in self.atoms if keyword in a.lower()]
        return [a for a in self.atoms if keyword in a]

    def search_literals(self, keyword: str) -> List[str]:
        """Return literal reprs containing keyword."""
        return [l for l in self.literals if keyword in l]

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def summary(self) -> str:
        dangerous = self.dangerous_imports()
        dbgi_line = (
            f"yes  ({len(self.ast_functions)} funcs, src={self.source_file})"
            if self.has_debug_info else "no (stripped)"
        )
        obf_line = (
            f"YES -- {', '.join(self.obfuscation_indicators)}"
            if self.obfuscated else "no"
        )
        otp_line = self.otp_app if self.otp_app else "no"
        lines = [
            f"BeamContext: {Path(self.path).name}",
            f"  module     : {self.module_name}",
            f"  otp_app    : {otp_line}",
            f"  atoms      : {len(self.atoms)}",
            f"  exports    : {len(self.exports)}",
            f"  imports    : {len(self.imports)}  ({len(dangerous)} dangerous)",
            f"  literals   : {len(self.literals)}",
            f"  debug info : {dbgi_line}",
            f"  obfuscated : {obf_line}",
            f"  chunks     : {' '.join(self.chunks)}",
        ]
        if self.exports:
            lines.append("\n  exports:")
            for e in self.exports:
                lines.append(f"    {e}")
        if self.ast_functions:
            lines.append("\n  functions (from AST):")
            for f in self.ast_functions[:15]:
                lines.append(f"    {f}")
            if len(self.ast_functions) > 15:
                lines.append(f"    ... ({len(self.ast_functions) - 15} more)")
        if dangerous:
            lines.append("\n  dangerous imports:")
            for i in dangerous:
                lines.append(f"    [!] {i}")
        elif self.imports:
            lines.append("\n  imports (first 10):")
            for i in self.imports[:10]:
                lines.append(f"    {i}")
        return "\n".join(lines)

    def fmt_atoms(self) -> str:
        return "\n".join(self.atoms)


# ---------------------------------------------------------------------------
# Directory / plugin sweep
# ---------------------------------------------------------------------------

def sweep_beam_dir(directory: str, dangerous_only: bool = False, exclude_otp: bool = False) -> List[BeamContext]:
    """
    Parse all .beam files under directory and return BeamContext list.

    dangerous_only: only return modules with at least one dangerous import.
    exclude_otp:    skip modules whose path matches an OTP stdlib install tree
                    (/erlang/lib/<app>-<version>/ebin/). Use when scanning
                    application code to suppress expected OTP infrastructure noise.
    """
    results = []
    for beam_path in Path(directory).rglob("*.beam"):
        try:
            ctx = BeamContext.from_path(str(beam_path))
        except Exception:
            continue
        if exclude_otp and ctx.is_otp:
            continue
        if dangerous_only and not ctx.dangerous_imports():
            continue
        results.append(ctx)
    return results


def fmt_sweep(results: List[BeamContext], min_severity: str = SEVERITY_DISPATCH) -> str:
    lines = [f"sweep: {len(results)} module(s)"]
    for ctx in results:
        d = ctx.dangerous_imports(min_severity=min_severity)
        tag = f"  [{len(d)} DANGEROUS]" if d else ""
        lines.append(f"  {ctx.module_name}{tag}")
        for i in d:
            lines.append(f"      {i.module}:{i.function}/{i.arity} [{i.severity}]")
    return "\n".join(lines)


@dataclass
class BeamDiffEntry:
    """One module's dangerous-import delta between two BEAM versions."""
    module: str
    gained: List[tuple]   # (module, function, severity) tuples added in v2
    lost: List[tuple]     # (module, function, severity) tuples removed vs v1
    new_module: bool = False      # module not present in v1
    dropped_module: bool = False  # module not present in v2


def sweep_beam_diff(
    dir_v1: str,
    dir_v2: str,
    min_severity: str = SEVERITY_DISPATCH,
    exclude_otp: bool = False,
) -> List[BeamDiffEntry]:
    """Compare dangerous imports across two directories of BEAM files.

    Returns only modules where the dangerous-import set changed.
    Use min_severity to filter low-signal tiers (e.g., SEVERITY_NETWORK to
    exclude DISPATCH noise from erlang:apply).
    Set exclude_otp=True to skip OTP stdlib modules (useful when diffing
    OTP versions and only interested in application-code changes).

    Example:
        diff = sweep_beam_diff('/tmp/rmq311', '/tmp/rmq312',
                               min_severity=SEVERITY_NETWORK)
        print(fmt_sweep_diff(diff))
    """
    def index(directory: str) -> dict:
        out = {}
        for ctx in sweep_beam_dir(directory, exclude_otp=exclude_otp):
            key = ctx.module_name
            out[key] = {
                (i.module, i.function, i.severity)
                for i in ctx.dangerous_imports(min_severity=min_severity)
            }
        return out

    idx1, idx2 = index(dir_v1), index(dir_v2)
    names1, names2 = set(idx1), set(idx2)
    entries = []

    # Changed modules
    for mod in sorted(names1 & names2):
        gained = sorted(idx2[mod] - idx1[mod])
        lost   = sorted(idx1[mod] - idx2[mod])
        if gained or lost:
            entries.append(BeamDiffEntry(module=mod, gained=gained, lost=lost))

    # New modules in v2 with dangerous imports
    for mod in sorted(names2 - names1):
        if idx2[mod]:
            entries.append(BeamDiffEntry(
                module=mod, gained=sorted(idx2[mod]), lost=[], new_module=True
            ))

    # Dropped modules (in v1, not v2) with dangerous imports
    for mod in sorted(names1 - names2):
        if idx1[mod]:
            entries.append(BeamDiffEntry(
                module=mod, gained=[], lost=sorted(idx1[mod]), dropped_module=True
            ))

    return entries


def fmt_sweep_diff(entries: List[BeamDiffEntry]) -> str:
    if not entries:
        return "sweep_diff: no dangerous-import changes between versions"
    lines = [f"sweep_diff: {len(entries)} module(s) changed"]
    for e in entries:
        if e.new_module:
            label = "  [NEW]"
        elif e.dropped_module:
            label = "  [DROPPED]"
        else:
            label = "  [CHANGED]"
        lines.append(f"\n{e.module}{label}")
        for mod, fn, sev in e.gained:
            lines.append(f"    + {mod}:{fn} [{sev}]")
        for mod, fn, sev in e.lost:
            lines.append(f"    - {mod}:{fn} [{sev}]")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal parsers
# ---------------------------------------------------------------------------

def _parse_dbgi(dbgi_bytes: bytes, ctx: BeamContext) -> None:
    """
    Parse Dbgi chunk: ETF COMPRESSED_EXT wrapping {debug_info_v1, erl_abstract_code, {Forms, Opts}}.
    Extracts source file, AST-level function definitions, record names, included headers.
    """
    if len(dbgi_bytes) < 7:
        return
    if dbgi_bytes[0] != 0x83 or dbgi_bytes[1] != 0x50:
        return  # not the expected COMPRESSED_EXT format
    try:
        raw = zlib.decompress(dbgi_bytes[6:])
    except Exception:
        return

    # raw is ETF without the 0x83 version prefix; add it back for _etf_to_python
    full = b'\x83' + raw
    try:
        term = _etf_to_python(full, 1)[0]
    except Exception:
        return

    # Expected: ('debug_info_v1', 'erl_abstract_code', ({'Forms'}, opts))
    if not (isinstance(term, tuple) and len(term) == 3
            and term[0] == 'debug_info_v1' and term[1] == 'erl_abstract_code'):
        return

    inner = term[2]
    if not (isinstance(inner, tuple) and len(inner) == 2):
        return

    forms = inner[0]
    if not isinstance(forms, list):
        return

    ctx.has_debug_info = True

    for form in forms:
        if not isinstance(form, tuple) or len(form) < 3:
            continue
        tag = form[0]

        if tag == 'attribute':
            if len(form) < 4:
                continue
            attr_name = form[2]
            attr_val = form[3]
            if attr_name == 'file' and isinstance(attr_val, tuple) and len(attr_val) == 2:
                fname = attr_val[0]
                if isinstance(fname, str) and fname.endswith('.erl') and not ctx.source_file:
                    ctx.source_file = fname
            elif attr_name == 'file' and isinstance(attr_val, str) and attr_val.endswith('.erl'):
                if not ctx.source_file:
                    ctx.source_file = attr_val

        elif tag == 'function' and len(form) >= 4:
            fn_name = form[2]
            arity = form[3]
            line_info = form[1]
            line = line_info[0] if isinstance(line_info, tuple) else line_info
            if isinstance(fn_name, str) and isinstance(arity, int) and isinstance(line, int):
                ctx.ast_functions.append(BeamAstFunction(name=fn_name, arity=arity, line=line))

    # Detect included .hrl files from file attributes (multiple occurrences = includes)
    seen_files: list = []
    for form in forms:
        if (isinstance(form, tuple) and len(form) >= 4
                and form[0] == 'attribute' and form[2] == 'file'):
            val = form[3]
            fname = val[0] if isinstance(val, tuple) and len(val) == 2 else val
            if isinstance(fname, str) and fname not in seen_files:
                seen_files.append(fname)
    # First is the module's own source; rest are includes
    if len(seen_files) > 1:
        ctx.ast_includes = seen_files[1:]

    # Record names from record attributes
    for form in forms:
        if (isinstance(form, tuple) and len(form) >= 4
                and form[0] == 'attribute' and form[2] == 'record'):
            rec = form[3]
            rname = rec[0] if isinstance(rec, tuple) and len(rec) >= 1 else rec
            if isinstance(rname, str):
                ctx.ast_records.append(rname)


# Chunk IDs that beam_load.c knows about (EA IFF 85 standard BEAM chunks).
# Any ID outside this set is a rogue chunk.
_KNOWN_CHUNK_IDS: frozenset = frozenset({
    'Atom', 'AtU8', 'Code', 'StrT', 'ImpT', 'ExpT', 'FunT', 'LitT',
    'LocT', 'Attr', 'CInf', 'Dbgi', 'Line', 'Type', 'Meta',
    # Less common but legitimate
    'ExDc', 'ExDp', 'Abst', 'Docs',
})


def _detect_obfuscation(ctx: BeamContext, raw_chunks: dict, data: bytes) -> None:
    """
    Flag obfuscation indicators using three categories:

    1. Structural (EA IFF 85 container):
       - Container anomaly: declared size != physical file size
       - Boundary violation: chunk extends past EOF or overlaps another chunk
       - Rogue chunk: chunk ID not in _KNOWN_CHUNK_IDS

    2. Missing required chunks:
       - Atom table absent
       - Debug info / line info / local function table stripped

    3. Content anomalies:
       - Atom table suspiciously small relative to import count
    """
    indicators = []

    # ------------------------------------------------------------------
    # 1a. Container size check (FOR1 declared size vs physical file size)
    #     FOR1 layout: b'FOR1' <uint32 container_size> b'BEAM' <chunks...>
    #     container_size covers everything after the first 8 bytes.
    # ------------------------------------------------------------------
    if len(data) >= 8:
        declared = struct.unpack('>I', data[4:8])[0]
        physical = len(data) - 8
        if declared != physical:
            delta = physical - declared
            indicators.append(
                f"container anomaly: declared={declared} physical={physical} "
                f"({'appended data' if delta > 0 else 'truncated'} {abs(delta)} bytes)"
            )

    # ------------------------------------------------------------------
    # 1b. Boundary violations and rogue chunk IDs
    #     Walk the chunk sequence ourselves (not using raw_chunks dict
    #     which was built by the permissive _split_chunks).
    # ------------------------------------------------------------------
    file_size = len(data)
    pos = 12  # skip FOR1 <size> BEAM
    seen_ranges: list = []
    rogue: list = []
    boundary_violations: list = []

    while pos + 8 <= file_size:
        cid_bytes = data[pos:pos+4]
        try:
            cid = cid_bytes.decode('ascii')
        except Exception:
            cid = cid_bytes.decode('latin1', errors='replace')

        chunk_size = struct.unpack('>I', data[pos+4:pos+8])[0]
        chunk_start = pos + 8
        chunk_end = chunk_start + chunk_size
        padded_end = chunk_start + chunk_size + (4 - chunk_size % 4) % 4

        # Boundary: does this chunk extend past EOF?
        if chunk_end > file_size:
            boundary_violations.append(
                f"chunk {cid!r} at {pos:#x}: end {chunk_end:#x} > file {file_size:#x}"
            )
            break  # can't safely advance

        # Overlap: does this chunk overlap any previously seen chunk?
        for (prev_start, prev_end, prev_id) in seen_ranges:
            if chunk_start < prev_end and chunk_end > prev_start:
                boundary_violations.append(
                    f"chunk {cid!r} at {pos:#x} overlaps {prev_id!r}"
                )

        seen_ranges.append((chunk_start, chunk_end, cid))

        # Rogue chunk ID?
        if cid.strip() not in _KNOWN_CHUNK_IDS:
            rogue.append(f"{cid!r} at {pos:#x} (size={chunk_size})")

        pad = (4 - chunk_size % 4) % 4
        pos = chunk_start + chunk_size + pad

    if boundary_violations:
        for v in boundary_violations:
            indicators.append(f"boundary violation: {v}")
    if rogue:
        for r in rogue:
            indicators.append(f"rogue chunk: {r}")

    # ------------------------------------------------------------------
    # 2. Missing chunks
    # ------------------------------------------------------------------
    if 'AtU8' not in raw_chunks and 'Atom' not in raw_chunks:
        indicators.append("atom table missing")
    if 'Dbgi' not in raw_chunks:
        indicators.append("debug info stripped")
    if 'Line' not in raw_chunks:
        indicators.append("line info stripped")
    if 'LocT' not in raw_chunks:
        indicators.append("local function table missing")

    # ------------------------------------------------------------------
    # 3. Content anomaly
    # ------------------------------------------------------------------
    if ctx.atoms and len(ctx.atoms) < max(len(ctx.imports), len(ctx.exports)):
        indicators.append(
            f"atom table suspiciously small ({len(ctx.atoms)} atoms, "
            f"{len(ctx.imports)} imports)"
        )

    # Obfuscated if: structural anomaly present, atom table missing, or 2+ indicators
    structural = any(
        i.startswith(('container anomaly', 'boundary violation', 'rogue chunk'))
        for i in indicators
    )
    if structural or 'atom table missing' in indicators or len(indicators) >= 2:
        ctx.obfuscated = True

    ctx.obfuscation_indicators = indicators


def _split_chunks(data: bytes) -> dict:
    chunks = {}
    pos = 12  # skip FOR1 <size> BEAM
    while pos + 8 <= len(data):
        cid = data[pos:pos+4].decode('latin1', errors='replace')
        size = struct.unpack('>I', data[pos+4:pos+8])[0]
        chunks[cid] = data[pos+8:pos+8+size]
        pos += 8 + size + (4 - size % 4) % 4
    return chunks


def _parse_atoms(chunks: dict) -> List[str]:
    raw = chunks.get('AtU8') or chunks.get('Atom', b'')
    if len(raw) < 4:
        return []
    count = struct.unpack('>I', raw[:4])[0]
    p, atoms = 4, []
    encoding = 'utf-8' if 'AtU8' in chunks else 'latin-1'
    for _ in range(count):
        if p >= len(raw):
            break
        length = raw[p]
        atoms.append(raw[p+1:p+1+length].decode(encoding, errors='replace'))
        p += 1 + length
    return atoms


def _parse_exports(data: bytes, atoms: List[str]) -> List[BeamExport]:
    if len(data) < 4:
        return []
    count = struct.unpack('>I', data[:4])[0]
    exports = []
    for i in range(count):
        o = 4 + i * 12
        if o + 12 > len(data):
            break
        fi, ai, _ = struct.unpack('>III', data[o:o+12])
        fname = atoms[fi - 1] if 0 < fi <= len(atoms) else f"?{fi}"
        exports.append(BeamExport(function=fname, arity=ai))
    return exports


def _parse_imports(data: bytes, atoms: List[str]) -> List[BeamImport]:
    if len(data) < 4:
        return []
    count = struct.unpack('>I', data[:4])[0]
    imports = []
    for i in range(count):
        o = 4 + i * 12
        if o + 12 > len(data):
            break
        mi, fi, ai = struct.unpack('>III', data[o:o+12])
        mod = atoms[mi - 1] if 0 < mi <= len(atoms) else f"?{mi}"
        fn = atoms[fi - 1] if 0 < fi <= len(atoms) else f"?{fi}"
        severity = DANGEROUS_IMPORTS.get((mod, fn), "")
        dangerous = bool(severity)
        imports.append(BeamImport(module=mod, function=fn, arity=ai,
                                  dangerous=dangerous, severity=severity))
    return imports


def _parse_literals(data: bytes) -> List[str]:
    """Decode LitT chunk. Returns human-readable repr of each ETF literal."""
    if len(data) < 4:
        return []
    try:
        raw = zlib.decompress(data[4:])
    except Exception:
        return []
    if len(raw) < 4:
        return []
    count = struct.unpack('>I', raw[:4])[0]
    p, lits = 4, []
    for _ in range(count):
        if p + 4 > len(raw):
            break
        size = struct.unpack('>I', raw[p:p+4])[0]
        term_bytes = raw[p+4:p+4+size]
        lits.append(_etf_repr(term_bytes))
        p += 4 + size
    return lits


def _etf_to_python(data: bytes, pos: int):
    """
    Structured ETF decoder -- returns actual Python objects (str, int, list, tuple, bytes).
    Used for Dbgi AST parsing where we need to navigate the term tree.
    """
    tag = data[pos]; pos += 1

    if tag == 106:   # NIL
        return [], pos
    if tag == 97:    # SMALL_INTEGER_EXT
        return data[pos], pos + 1
    if tag == 98:    # INTEGER_EXT
        return struct.unpack('>i', data[pos:pos+4])[0], pos + 4
    if tag == 100:   # ATOM_EXT (latin-1)
        length = struct.unpack('>H', data[pos:pos+2])[0]
        return data[pos+2:pos+2+length].decode('latin-1', errors='replace'), pos + 2 + length
    if tag == 115:   # SMALL_ATOM_EXT (latin-1)
        length = data[pos]
        return data[pos+1:pos+1+length].decode('latin-1', errors='replace'), pos + 1 + length
    if tag == 118:   # ATOM_UTF8_EXT
        length = struct.unpack('>H', data[pos:pos+2])[0]
        return data[pos+2:pos+2+length].decode('utf-8', errors='replace'), pos + 2 + length
    if tag == 119:   # SMALL_ATOM_UTF8_EXT
        length = data[pos]
        return data[pos+1:pos+1+length].decode('utf-8', errors='replace'), pos + 1 + length
    if tag == 107:   # STRING_EXT
        length = struct.unpack('>H', data[pos:pos+2])[0]
        return data[pos+2:pos+2+length].decode('latin-1', errors='replace'), pos + 2 + length
    if tag == 109:   # BINARY_EXT
        length = struct.unpack('>I', data[pos:pos+4])[0]
        return data[pos+4:pos+4+length], pos + 4 + length
    if tag == 104:   # SMALL_TUPLE_EXT
        arity = data[pos]; pos += 1
        elements, pos = _etf_to_python_seq(data, pos, arity)
        return tuple(elements), pos
    if tag == 105:   # LARGE_TUPLE_EXT
        arity = struct.unpack('>I', data[pos:pos+4])[0]; pos += 4
        elements, pos = _etf_to_python_seq(data, pos, arity)
        return tuple(elements), pos
    if tag == 108:   # LIST_EXT
        length = struct.unpack('>I', data[pos:pos+4])[0]; pos += 4
        elements, pos = _etf_to_python_seq(data, pos, length)
        _tail, pos = _etf_to_python(data, pos)  # tail (usually [])
        return elements, pos
    if tag == 110:   # SMALL_BIG_EXT
        n = data[pos]; sign = data[pos+1]; pos += 2
        val = int.from_bytes(data[pos:pos+n], 'little')
        return (-val if sign else val), pos + n
    if tag == 111:   # LARGE_BIG_EXT
        n = struct.unpack('>I', data[pos:pos+4])[0]; sign = data[pos+4]; pos += 5
        val = int.from_bytes(data[pos:pos+n], 'little')
        return (-val if sign else val), pos + n
    if tag == 70:    # NEW_FLOAT_EXT
        val = struct.unpack('>d', data[pos:pos+8])[0]
        return val, pos + 8
    if tag == 116:   # MAP_EXT
        arity = struct.unpack('>I', data[pos:pos+4])[0]; pos += 4
        result = {}
        for _ in range(arity):
            k, pos = _etf_to_python(data, pos)
            v, pos = _etf_to_python(data, pos)
            result[k] = v
        return result, pos
    # Unknown tag -- return raw bytes marker
    return f"<etf:{tag:#x}>", pos


def _etf_to_python_seq(data: bytes, pos: int, count: int):
    elements = []
    for _ in range(count):
        elem, pos = _etf_to_python(data, pos)
        elements.append(elem)
    return elements, pos


def _etf_repr(data: bytes) -> str:
    """Best-effort human-readable repr of an Erlang External Term Format blob."""
    if not data or data[0] != 0x83:
        return repr(data)
    try:
        return _decode_etf(data, 1)[0]
    except Exception:
        return repr(data)


def _decode_etf(data: bytes, pos: int):
    tag = data[pos]
    pos += 1

    if tag == 106:  # NIL []
        return "[]", pos
    if tag == 97:   # SMALL_INTEGER_EXT
        return str(data[pos]), pos + 1
    if tag == 98:   # INTEGER_EXT
        val = struct.unpack('>i', data[pos:pos+4])[0]
        return str(val), pos + 4
    if tag == 100:  # ATOM_EXT (latin-1)
        length = struct.unpack('>H', data[pos:pos+2])[0]
        atom = data[pos+2:pos+2+length].decode('latin-1', errors='replace')
        return atom, pos + 2 + length
    if tag == 119:  # SMALL_ATOM_UTF8_EXT
        length = data[pos]
        atom = data[pos+1:pos+1+length].decode('utf-8', errors='replace')
        return atom, pos + 1 + length
    if tag == 118:  # ATOM_UTF8_EXT
        length = struct.unpack('>H', data[pos:pos+2])[0]
        atom = data[pos+2:pos+2+length].decode('utf-8', errors='replace')
        return atom, pos + 2 + length
    if tag == 107:  # STRING_EXT
        length = struct.unpack('>H', data[pos:pos+2])[0]
        s = data[pos+2:pos+2+length].decode('latin-1', errors='replace')
        return repr(s), pos + 2 + length
    if tag == 109:  # BINARY_EXT
        length = struct.unpack('>I', data[pos:pos+4])[0]
        b = data[pos+4:pos+4+length]
        return repr(b), pos + 4 + length
    if tag == 104:  # SMALL_TUPLE_EXT
        arity = data[pos]; pos += 1
        elements, pos = _decode_etf_seq(data, pos, arity)
        return '{' + ', '.join(elements) + '}', pos
    if tag == 108:  # LIST_EXT
        length = struct.unpack('>I', data[pos:pos+4])[0]; pos += 4
        elements, pos = _decode_etf_seq(data, pos, length)
        _tail, pos = _decode_etf(data, pos)  # tail (usually [])
        return '[' + ', '.join(elements) + ']', pos
    if tag == 110:  # SMALL_BIG_EXT
        n = data[pos]; sign = data[pos+1]; pos += 2
        val = int.from_bytes(data[pos:pos+n], 'little')
        return str(-val if sign else val), pos + n
    # Fallback
    return f"<etf:{tag:#x}>", pos


def _decode_etf_seq(data: bytes, pos: int, count: int):
    elements = []
    for _ in range(count):
        elem, pos = _decode_etf(data, pos)
        elements.append(elem)
    return elements, pos


# ---------------------------------------------------------------------------
# BEAM function-level lifter
# ---------------------------------------------------------------------------

# Compact-term tag constants (low 3 bits of each operand byte)
_CT_U, _CT_I, _CT_A, _CT_X, _CT_Y, _CT_F, _CT_H, _CT_Z = range(8)

# Z-extended subtypes (value encoded alongside the Z tag)
_CZ_FLOAT, _CZ_LIST, _CZ_FR, _CZ_ALLOC, _CZ_LITERAL, _CZ_TYPED = range(6)

# Opcode table: number -> (name, n_operands).
# Opcodes 1-78 are stable across OTP 18-26. Higher numbers were added
# incrementally and may shift in older OTP versions; entries above 78 use
# the OTP 18/19 numbering which is stable through OTP 26.
_BEAM_OPS: Dict[int, Tuple[str, int]] = {
    1:   ('label',               1),   2:   ('func_info',           3),
    3:   ('int_code_end',        0),   4:   ('call',                2),
    5:   ('call_last',           3),   6:   ('call_only',           2),
    7:   ('call_ext',            2),   8:   ('call_ext_last',       3),
    9:   ('bif0',                2),   10:  ('bif1',                4),
    11:  ('bif2',                5),   12:  ('allocate',            2),
    13:  ('allocate_heap',       3),   14:  ('allocate_zero',       2),
    15:  ('allocate_heap_zero',  3),   16:  ('test_heap',           2),
    17:  ('init',                1),   18:  ('deallocate',          1),
    19:  ('return',              0),   20:  ('send',                0),
    21:  ('remove_message',      0),   22:  ('timeout',             0),
    23:  ('loop_rec',            2),   24:  ('loop_rec_end',        1),
    25:  ('wait',                1),   26:  ('wait_timeout',        2),
    27:  ('m_plus',              4),   28:  ('m_minus',             4),
    29:  ('m_times',             4),   30:  ('m_div',               4),
    31:  ('int_div',             4),   32:  ('int_rem',             4),
    33:  ('int_band',            4),   34:  ('int_bor',             4),
    35:  ('int_bxor',            4),   36:  ('int_bsl',             4),
    37:  ('int_bsr',             4),   38:  ('int_bnot',            3),
    39:  ('is_lt',               3),   40:  ('is_ge',               3),
    41:  ('is_eq',               3),   42:  ('is_ne',               3),
    43:  ('is_eq_exact',         3),   44:  ('is_ne_exact',         3),
    45:  ('is_integer',          2),   46:  ('is_float',            2),
    47:  ('is_number',           2),   48:  ('is_atom',             2),
    49:  ('is_pid',              2),   50:  ('is_reference',        2),
    51:  ('is_port',             2),   52:  ('is_nil',              2),
    53:  ('is_binary',           2),   54:  ('is_constant',         2),
    55:  ('is_list',             2),   56:  ('is_nonempty_list',    2),
    57:  ('is_tuple',            2),   58:  ('test_arity',          3),
    59:  ('select_val',          3),   60:  ('select_tuple_arity',  3),
    61:  ('jump',                1),   62:  ('catch',               2),
    63:  ('catch_end',           1),   64:  ('move',                2),
    65:  ('get_list',            3),   66:  ('get_tuple_element',   3),
    67:  ('set_tuple_element',   3),   68:  ('put_string',          3),
    69:  ('put_list',            3),   70:  ('put_tuple',           2),
    71:  ('put',                 1),   72:  ('badmatch',            1),
    73:  ('if_end',              0),   74:  ('case_end',            1),
    75:  ('call_fun',            1),   76:  ('make_fun2',           1),
    77:  ('is_function',         2),   78:  ('call_ext_only',       2),
    # Bit-string matching (R7B+)
    79:  ('bs_start_match2',     5),   80:  ('bs_get_integer2',     7),
    81:  ('bs_get_float2',       7),   82:  ('bs_get_binary2',      7),
    83:  ('bs_skip_bits2',       5),   84:  ('bs_test_tail2',       3),
    85:  ('bs_save2',            2),   86:  ('bs_restore2',         2),
    87:  ('bs_init2',            6),   88:  ('bs_put_integer',      5),
    89:  ('bs_put_binary',       5),   90:  ('bs_put_float',        5),
    91:  ('bs_put_string',       2),   92:  ('bs_need_buf',         1),
    # Float operations (R7B+)
    93:  ('fclearerror',         0),   94:  ('fcheckerror',         1),
    95:  ('fmove',               2),   96:  ('fconv',               2),
    97:  ('fadd',                4),   98:  ('fsub',                4),
    99:  ('fmul',                4),   100: ('fdiv',                4),
    101: ('fnegate',             3),
    # Try/catch new style (R11B+)
    103: ('try',                 2),   104: ('try_end',             1),
    105: ('try_case',            1),   106: ('try_case_end',        1),
    107: ('raise',               2),
    # Bit-string misc
    108: ('bs_init_bits',        6),   109: ('bs_bits_to_bytes2',   2),
    # Apply BIF (R12B+)
    110: ('apply',               1),   111: ('apply_last',          2),
    # More type checks
    112: ('is_boolean',          2),   113: ('is_function2',        3),
    # Unicode bit syntax (R14B+)
    115: ('bs_get_utf8',         5),   116: ('bs_skip_utf8',        4),
    117: ('bs_get_utf16',        5),   118: ('bs_skip_utf16',       4),
    119: ('bs_get_utf32',        5),   120: ('bs_skip_utf32',       4),
    121: ('bs_utf8_size',        3),   122: ('bs_put_utf8',         3),
    123: ('bs_utf16_size',       3),   124: ('bs_put_utf16',        3),
    125: ('bs_put_utf32',        3),
    126: ('on_load',             0),   127: ('recv_mark',           1),
    128: ('recv_set',            1),
    # GC-BIF calls (R16B+): arithmetic and stdlib BIFs with GC notification
    129: ('gc_bif1',             5),   130: ('gc_bif2',             6),
    131: ('gc_bif3',             7),
    # Bit-string misc (OTP 17+)
    132: ('is_bitstr',           2),   133: ('bs_context_to_binary', 1),
    134: ('bs_test_unit',        3),   135: ('bs_match_string',     4),
    136: ('bs_init_writable',    0),   137: ('bs_append',           8),
    138: ('bs_private_append',   6),   139: ('trim',                2),
    # OTP 20+
    153: ('put_tuple2',          2),   154: ('swap',                2),
    # OTP 21+
    156: ('make_fun3',           2),   157: ('init_yregs',          1),
    # OTP 24+ receive markers
    158: ('recv_marker_bind',    2),   159: ('recv_marker_clear',   1),
    160: ('recv_marker_reserve', 1),   161: ('recv_marker_use',     1),
    # OTP 25+
    163: ('call_fun2',           3),   164: ('nif_start',           0),
    165: ('badrecord',           1),
    # OTP 26+
    166: ('update_record',       5),
}

# Opcodes that produce no security-relevant IR (stack/GC bookkeeping)
_BEAM_SKIP: frozenset = frozenset({
    16,   # test_heap
    18,   # deallocate
    93,   # fclearerror
    94,   # fcheckerror
    95, 96, 97, 98, 99, 100, 101,   # float arithmetic
    108, 109,                        # bs_init_bits misc
    116, 118, 120,                   # bs_skip_utf*
    121, 122, 123, 124, 125,         # bs_utf*_size, bs_put_utf*
    126,                             # on_load
    127, 128,                        # recv_mark/set
    133, 134, 135, 136,              # bs_context / bs_test_unit / bs_match_string / bs_init_writable
    139,                             # trim
    157,                             # init_yregs
    158, 159, 160, 161,              # recv markers
    164,                             # nif_start
})

# Module-level dicts used by BEAMLifter._emit (hoisted to avoid per-call allocation)
_BEAM_ARITH: Dict[int, str] = {
    27: '+', 28: '-', 29: '*', 30: '/', 31: 'div',
    32: 'rem', 33: 'band', 34: 'bor', 35: 'bxor', 36: 'bsl', 37: 'bsr',
}
_BEAM_CMP: Dict[int, str] = {39: '<', 40: '>=', 41: '==', 42: '/=', 43: '=:=', 44: '=/='}
_BEAM_TYPES: Dict[int, str] = {
    45: 'integer', 46: 'float', 47: 'number', 48: 'atom',
    49: 'pid', 50: 'reference', 51: 'port', 52: 'nil',
    53: 'binary', 54: 'constant', 55: 'list', 56: 'nonempty_list',
    57: 'tuple', 112: 'boolean', 132: 'bitstring',
}


@dataclass
class _BEAMTerm:
    """A decoded BEAM compact-term operand."""
    tag: int
    val: int = 0
    ext: Any = None   # payload for Z-extended terms

    def fmt(self, atoms: List[str], lits: List[str]) -> str:
        if self.tag == _CT_U:
            return str(self.val)
        if self.tag == _CT_I:
            return str(self.val)
        if self.tag == _CT_A:
            if self.val == 0:
                return '[]'
            i = self.val - 1
            return f"'{atoms[i]}'" if i < len(atoms) else f"?a{self.val}"
        if self.tag == _CT_X:
            return f"X{self.val}"
        if self.tag == _CT_Y:
            return f"Y{self.val}"
        if self.tag == _CT_F:
            return f"L{self.val}" if self.val else "fail"
        if self.tag == _CT_H:
            try:
                return repr(chr(self.val))
            except (ValueError, OverflowError):
                return f"${self.val:#x}"
        # _CT_Z extended
        if self.val == _CZ_FLOAT:
            return str(self.ext)
        if self.val == _CZ_LITERAL:
            idx = self.ext
            return lits[idx] if isinstance(idx, int) and idx < len(lits) else f"?lit{idx}"
        if self.val == _CZ_LIST and isinstance(self.ext, list):
            parts = [
                f"{v.fmt(atoms, lits)} -> {lbl.fmt(atoms, lits)}"
                for v, lbl in self.ext
            ]
            return '[' + ', '.join(parts) + ']'
        return f"z{self.val}:{self.ext}"


def _ct_read(data: bytes, pos: int) -> Tuple[_BEAMTerm, int]:
    """Read one compact-term operand. Return (term, new_pos)."""
    if pos >= len(data):
        raise ValueError(f"EOF at compact-term read pos={pos}")
    b0 = data[pos]; pos += 1
    tag = b0 & 7

    if not (b0 & 8):
        # 4-bit small value in bits 7:4
        val = b0 >> 4
    elif not (b0 & 16):
        # 11-bit: upper 3 bits from b0 bits 7:5, lower 8 from next byte
        b1 = data[pos]; pos += 1
        val = ((b0 & 0xE0) << 3) | b1
    else:
        # Multi-byte: (b0 >> 5) + 2 bytes, big-endian
        n = (b0 >> 5) + 2
        val = int.from_bytes(data[pos:pos + n], 'big')
        pos += n

    # Sign-extend integers
    if tag == _CT_I:
        if b0 & 8:  # not small
            bits = (((b0 >> 5) + 2) * 8) if (b0 & 16) else 11
            if val >= (1 << (bits - 1)):
                val -= (1 << bits)
        elif val >= 8:            # 4-bit small signed: 8-15 map to -8..-1
            val -= 16

    # Z-extended handling
    if tag == _CT_Z:
        if val == _CZ_FLOAT:
            fv = struct.unpack('>d', data[pos:pos + 8])[0]
            return _BEAMTerm(_CT_Z, _CZ_FLOAT, fv), pos + 8
        if val == _CZ_LIST:
            cnt_t, pos = _ct_read(data, pos)
            count = cnt_t.val
            pairs: List[Any] = []
            for _ in range(count // 2):
                vt, pos = _ct_read(data, pos)
                lt, pos = _ct_read(data, pos)
                pairs.append((vt, lt))
            return _BEAMTerm(_CT_Z, _CZ_LIST, pairs), pos
        if val == _CZ_FR:
            idx_t, pos = _ct_read(data, pos)
            return _BEAMTerm(_CT_X, idx_t.val), pos
        if val == _CZ_ALLOC:
            cnt_t, pos = _ct_read(data, pos)
            for _ in range(cnt_t.val):
                _, pos = _ct_read(data, pos)
                _, pos = _ct_read(data, pos)
            return _BEAMTerm(_CT_Z, _CZ_ALLOC, None), pos
        if val == _CZ_LITERAL:
            idx_t, pos = _ct_read(data, pos)
            return _BEAMTerm(_CT_Z, _CZ_LITERAL, idx_t.val), pos
        if val == _CZ_TYPED:
            reg_t, pos = _ct_read(data, pos)
            _, pos = _ct_read(data, pos)   # type annotation (skip)
            return reg_t, pos
        return _BEAMTerm(_CT_Z, val, None), pos

    return _BEAMTerm(tag, val), pos


@dataclass
class _BEAMInsn:
    """One decoded BEAM instruction."""
    op:   int
    name: str
    args: List[_BEAMTerm]


class BEAMLifter:
    """Decode BEAM Code chunk bytes into function-level pseudo-IR.

    Usage::
        ctx = BeamContext.from_path('module.beam')
        raw  = Path('module.beam').read_bytes()
        code = _split_chunks(raw).get('Code', b'')
        lifter = BEAMLifter.from_context(ctx, code)
        print(lifter.lift())
    """

    def __init__(
        self,
        atoms:   List[str],
        imports: List[BeamImport],
        literals: List[str],
        module:  str = "",
    ) -> None:
        self._atoms   = atoms
        self._imports = imports
        self._lits    = literals
        self._module  = module
        self._insns:  List[_BEAMInsn] = []
        self._funcs:  List[Tuple[str, int, int]] = []   # (name, arity, insn_start_idx)
        self._partial = False   # True when decode stopped on unknown opcode

    @classmethod
    def from_context(cls, ctx: 'BeamContext', code_bytes: bytes) -> 'BEAMLifter':
        lifter = cls(ctx.atoms, ctx.imports, ctx.literals, ctx.module_name)
        lifter._decode(code_bytes)
        return lifter

    # ------------------------------------------------------------------
    # Decoder
    # ------------------------------------------------------------------

    def _decode(self, code_bytes: bytes) -> None:
        """Parse the Code chunk instruction stream and locate function boundaries.

        Code chunk layout: sub_size(4) version(4) max_opcode(4) label_count(4)
        function_count(4) [instructions start at byte 20].
        """
        if len(code_bytes) < 20:
            return
        pos  = 20
        data = code_bytes
        insns = self._insns

        while pos < len(data):
            op = data[pos]; pos += 1
            entry = _BEAM_OPS.get(op)
            if entry is None:
                insns.append(_BEAMInsn(op, f'<unknown:{op}>', []))
                self._partial = True
                break
            name, arity = entry
            args: List[_BEAMTerm] = []
            ok = True
            for _ in range(arity):
                try:
                    term, pos = _ct_read(data, pos)
                    args.append(term)
                except Exception:
                    ok = False
                    break
            insns.append(_BEAMInsn(op, name, args))
            if not ok:
                self._partial = True
                break

        # Scan for func_info boundaries: label(N) func_info(Mod Name Arity)
        for i in range(len(insns) - 1):
            if insns[i].op == 1 and insns[i + 1].op == 2:
                fi = insns[i + 1]
                if len(fi.args) >= 3 and fi.args[1].tag == _CT_A:
                    fn_atom = fi.args[1].val
                    arity_val = fi.args[2].val
                    fn = (self._atoms[fn_atom - 1]
                          if 0 < fn_atom <= len(self._atoms) else f"?f{fn_atom}")
                    self._funcs.append((fn, arity_val, i))

    # ------------------------------------------------------------------
    # IR emitter
    # ------------------------------------------------------------------

    def _f(self, term: _BEAMTerm) -> str:
        return term.fmt(self._atoms, self._lits)

    def _imp(self, idx: int) -> str:
        if 0 <= idx < len(self._imports):
            imp = self._imports[idx]
            return f"'{imp.module}':'{imp.function}'/{imp.arity}"
        return f"?imp{idx}"

    def _emit(self, insn: _BEAMInsn) -> Optional[str]:  # noqa: C901
        """Return one IR line for insn, or None to suppress."""
        op, name, a = insn.op, insn.name, insn.args

        def _a(n: int) -> str:
            return self._f(a[n]) if n < len(a) else '?'

        # Labels and headers
        if op == 1:
            return f"L{a[0].val}:" if a else None
        if op in (2, 3):        # func_info, int_code_end
            return None

        # Calls
        if op == 4:             # call Arity Label
            return f"call {_a(1)}  % arity={_a(0)}"
        if op == 5:             # call_last Arity Label Dealloc
            return f"tailcall {_a(1)}  % arity={_a(0)}"
        if op == 6:             # call_only Arity Label
            return f"tailcall {_a(1)}  % arity={_a(0)}"
        if op == 7:             # call_ext Arity ImportIdx
            return f"call {self._imp(a[1].val if len(a) > 1 else 0)}  % arity={_a(0)}"
        if op == 8:             # call_ext_last Arity ImportIdx Dealloc
            return f"tailcall {self._imp(a[1].val if len(a) > 1 else 0)}  % arity={_a(0)}"
        if op == 78:            # call_ext_only Arity ImportIdx
            return f"tailcall {self._imp(a[1].val if len(a) > 1 else 0)}  % arity={_a(0)}"
        if op == 75:            # call_fun Arity  (fn is in X[Arity])
            ar = a[0].val if a else 0
            return f"call_fun X{ar}  % arity={ar}"
        if op == 163:           # call_fun2 Tag Arity Fun  (OTP 25+)
            return f"call_fun2 {_a(2)}  % arity={_a(1)}"
        if op == 110:           # apply Arity
            return f"apply X0 X1 {_a(0)}"
        if op == 111:           # apply_last Arity Dealloc
            return f"apply_last X0 X1 {_a(0)}"

        # Return and messaging
        if op == 19:
            return "return X0"
        if op == 20:
            return "X0 ! X1  % -> X0"
        if op == 21:
            return "remove_message"
        if op == 22:
            return "timeout"
        if op == 23:            # loop_rec Fail MsgRef
            return f"loop_rec {_a(0)} {_a(1)}"
        if op == 24:
            return f"loop_rec_end {_a(0)}"
        if op == 25:
            return f"wait {_a(0)}"
        if op == 26:
            return f"wait_timeout {_a(0)} {_a(1)}"

        # Stack frame (suppress most noise, keep meaningful init)
        if op in (12, 13, 14, 15):
            return f"% {name} {' '.join(self._f(x) for x in a)}"
        if op == 17:            # init Y  (clear to nil)
            return f"Y{a[0].val if a else '?'} = nil"

        # Data movement
        if op == 64:            # move Src Dst
            return f"{_a(1)} = {_a(0)}"
        if op == 154:           # swap Reg1 Reg2  (OTP 20+)
            return f"swap {_a(0)} {_a(1)}"

        # List construction/deconstruction
        if op == 65:            # get_list Src Head Tail
            return f"[{_a(1)} | {_a(2)}] = {_a(0)}"
        if op == 69:            # put_list Head Tail Dst
            return f"{_a(2)} = [{_a(0)} | {_a(1)}]"

        # Tuple construction/deconstruction
        if op == 66:            # get_tuple_element Src Idx Dst
            return f"{_a(2)} = {_a(0)}[{_a(1)}]"
        if op == 67:            # set_tuple_element Src Tuple Idx
            return f"{_a(1)}[{_a(2)}] = {_a(0)}"
        if op == 153:           # put_tuple2 Dst Elements  (OTP 20+)
            return f"{_a(0)} = {{{_a(1)}}}"

        # Arithmetic (old style, m_plus etc. -- obsolete in OTP 20+)
        if op in _BEAM_ARITH:
            return f"{_a(3)} = {_a(2)} {_BEAM_ARITH[op]} {_a(1)}  % fail={_a(0)}"
        if op == 38:            # int_bnot Fail Src Dst
            return f"{_a(2)} = bnot {_a(1)}  % fail={_a(0)}"

        # GC-BIF calls: arithmetic and stdlib in OTP 20+ (gc_bif1/2/3)
        if op == 129:           # gc_bif1 Fail Live BifIdx Arg Dst
            return f"{_a(4)} = {self._imp(a[2].val if len(a) > 2 else 0)}({_a(3)})  % fail={_a(0)}"
        if op == 130:           # gc_bif2 Fail Live BifIdx Arg1 Arg2 Dst
            return (f"{_a(5)} = {self._imp(a[2].val if len(a) > 2 else 0)}"
                    f"({_a(3)}, {_a(4)})  % fail={_a(0)}")
        if op == 131:           # gc_bif3 Fail Live BifIdx Arg1 Arg2 Arg3 Dst
            return (f"{_a(6)} = {self._imp(a[2].val if len(a) > 2 else 0)}"
                    f"({_a(3)}, {_a(4)}, {_a(5)})  % fail={_a(0)}")

        # Old-style BIF calls (bif0/bif1/bif2 -- pre-OTP 20 mostly)
        if op == 9:             # bif0 BifIdx Dst  (no fail label)
            return f"{_a(1)} = {self._imp(a[0].val if a else 0)}()"
        if op == 10:            # bif1 Fail BifIdx Arg Dst
            return f"{_a(3)} = {self._imp(a[1].val if len(a) > 1 else 0)}({_a(2)})  % fail={_a(0)}"
        if op == 11:            # bif2 Fail BifIdx Arg1 Arg2 Dst
            return (f"{_a(4)} = {self._imp(a[1].val if len(a) > 1 else 0)}"
                    f"({_a(2)}, {_a(3)})  % fail={_a(0)}")

        # Comparison tests (fail is first arg)
        if op in _BEAM_CMP:
            return f"if {_a(1)} {_BEAM_CMP[op]} {_a(2)}: goto {_a(0)}"

        # Type tests (fail is first arg)
        if op in _BEAM_TYPES:
            return f"if not is_{_BEAM_TYPES[op]}({_a(1)}): goto {_a(0)}"
        if op == 58:            # test_arity Fail Src Arity
            return f"if tuple_size({_a(1)}) /= {_a(2)}: goto {_a(0)}"
        if op == 77:            # is_function Fail Term
            return f"if not is_function({_a(1)}): goto {_a(0)}"
        if op == 113:           # is_function2 Fail Term Arity
            return f"if not is_function({_a(1)}, {_a(2)}): goto {_a(0)}"

        # Control flow
        if op == 59:            # select_val Src Fail {list}
            return f"select {_a(0)} {_a(2)}  % default={_a(1)}"
        if op == 60:            # select_tuple_arity Src Fail {list}
            return f"select_arity {_a(0)} {_a(2)}  % default={_a(1)}"
        if op == 61:
            return f"goto {_a(0)}"

        # Exception handling
        if op == 62:            # catch Dst Label  (old style)
            return f"catch {_a(0)} -> {_a(1)}"
        if op == 63:            # catch_end Dst
            return f"catch_end {_a(0)}"
        if op == 103:           # try Dst Label
            return f"try {_a(0)} -> {_a(1)}"
        if op == 104:
            return f"try_end {_a(0)}"
        if op == 105:
            return f"try_case {_a(0)}"
        if op == 106:           # try_case_end Val
            return f"erlang:error({{try_clause, {_a(0)}}})"
        if op == 107:           # raise Stacktrace ExcVal
            return f"raise {_a(0)} {_a(1)}"

        # Error atoms
        if op == 72:
            return f"erlang:error({{badmatch, {_a(0)}}})"
        if op == 73:
            return "erlang:error(if_clause)"
        if op == 74:
            return f"erlang:error({{case_clause, {_a(0)}}})"
        if op == 165:
            return f"erlang:error({{badrecord, {_a(0)}}})"

        # Higher-order / closures
        if op == 76:            # make_fun2 FunIdx
            return f"X0 = make_fun {_a(0)}"
        if op == 156:           # make_fun3 FunIdx Env  (OTP 21+)
            return f"X0 = make_fun {_a(0)} env={_a(1)}"

        # Bit-string construction
        if op == 87:            # bs_init2 Fail Size Words Regs Flags Dst
            return f"{_a(5)} = bs_init  % size={_a(1)}"
        if op == 88:            # bs_put_integer Fail Size Flags Src
            return f"  bs_put_integer {_a(3)} size={_a(1)}"
        if op == 89:            # bs_put_binary Fail Size Flags Src
            return f"  bs_put_binary {_a(3)} size={_a(1)}"
        if op == 91:            # bs_put_string Len Offset
            return f"  bs_put_string sz={_a(0)}"
        if op == 137:           # bs_append Fail Size Extra Live Unit Src Flags Dst
            return f"{_a(7)} = bs_append {_a(5)}  % size={_a(1)}"
        if op == 138:           # bs_private_append Fail Size Unit Src Flags Dst
            return f"{_a(5)} = bs_private_append {_a(3)}  % size={_a(1)}"

        # OTP 26 record update
        if op == 166:           # update_record Hint Size Src Dst Updates
            return f"{_a(3)} = update_record({_a(2)}, ...)"

        # Unknown / not decoded
        if op >= 1 and name.startswith('<unknown'):
            return f"% decode_error: opcode {op}"

        # Silently skip known noise opcodes
        if op in _BEAM_SKIP:
            return None

        # Remaining known opcodes that have no concise IR -- emit raw
        args_str = ' '.join(self._f(x) for x in a)
        return f"% {name} {args_str}"

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def lift(self) -> str:
        """Return pseudo-IR for all decoded functions as a single string."""
        if not self._insns:
            return f"% BEAM module: {self._module or '?'}\n% no instructions decoded\n"

        # Compute function boundary ranges
        func_ranges: List[Tuple[str, int, int, int]] = []
        for fi, (fn, ar, start) in enumerate(self._funcs):
            end = self._funcs[fi + 1][2] if fi + 1 < len(self._funcs) else len(self._insns)
            func_ranges.append((fn, ar, start, end))

        note = "  % partial decode" if self._partial else ""
        out: List[str] = [
            f"% BEAM module: {self._module or '?'}{note}",
            f"% {len(func_ranges)} function(s)",
            "",
        ]

        for fn, ar, start, end in func_ranges:
            out.append(f"% {fn}/{ar}")
            out.append("{")
            pending_tuple: Optional[Tuple[str, List[str]]] = None  # (dst, [elems])

            for i in range(start, end):
                insn = self._insns[i]

                # Accumulate put_tuple + put... sequences into a single tuple literal
                if insn.op == 70:   # put_tuple Arity Dst
                    dst = self._f(insn.args[1]) if len(insn.args) > 1 else '?'
                    pending_tuple = (dst, [])
                    continue
                if insn.op == 71 and pending_tuple is not None:   # put Val
                    pending_tuple[1].append(self._f(insn.args[0]) if insn.args else '?')
                    continue
                if pending_tuple is not None and insn.op != 71:
                    dst, elems = pending_tuple
                    out.append(f"  {dst} = {{{', '.join(elems)}}}")
                    pending_tuple = None

                line = self._emit(insn)
                if line is None:
                    continue
                # Labels dedented slightly so they stand out; instructions indented
                if line.endswith(':') and not line.startswith('%'):
                    out.append("  " + line)
                else:
                    out.append("  " + line)

            # Flush any incomplete tuple at end of function
            if pending_tuple is not None:
                dst, elems = pending_tuple
                out.append(f"  {dst} = {{{', '.join(elems)}}}")

            out.append("}")
            out.append("")

        return "\n".join(out) + "\n"
