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

import struct
import zlib
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

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
        lines = [
            f"BeamContext: {Path(self.path).name}",
            f"  module     : {self.module_name}",
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

def sweep_beam_dir(directory: str, dangerous_only: bool = False) -> List[BeamContext]:
    """
    Parse all .beam files under directory and return BeamContext list.
    If dangerous_only=True, only returns modules with at least one dangerous import.
    """
    results = []
    for beam_path in Path(directory).rglob("*.beam"):
        try:
            ctx = BeamContext.from_path(str(beam_path))
        except Exception:
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
) -> List[BeamDiffEntry]:
    """Compare dangerous imports across two directories of BEAM files.

    Returns only modules where the dangerous-import set changed.
    Use min_severity to filter low-signal tiers (e.g., SEVERITY_NETWORK to
    exclude DISPATCH noise from erlang:apply).

    Example:
        diff = sweep_beam_diff('/tmp/rmq311', '/tmp/rmq312',
                               min_severity=SEVERITY_NETWORK)
        print(fmt_sweep_diff(diff))
    """
    def index(directory: str) -> dict:
        out = {}
        for ctx in sweep_beam_dir(directory):
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
