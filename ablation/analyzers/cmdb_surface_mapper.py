"""
cmdb_surface_mapper.py — CMDB attack surface mapper for x86-64 FortiWeb/FortiOS binaries.

Phase 0.5 of the Fortinet RE methodology: enumerate every cmf_query_create() call site,
identify the CMDB table being accessed, then determine which tables have callers that
also call exec-class sinks in the same function.

Analysis direction: FORWARD from CMDB field reads toward exec sinks.
This complements backward TaintTracker analysis by identifying which table IDs are
attacker-reachable inputs, then targeting TaintTracker only on those callers.

Limitations (by design — Phase 0.5 triage tool, not verified data-flow):
  - Co-location heuristic: a function that queries table T and calls system() is
    flagged. The data flow from the field read to the sink argument is NOT verified.
    Use SinkArgClassifier + TaintTracker to confirm actual data flow.
  - One level deep: a function that reads a field and passes it to a helper which
    calls system() will NOT be detected. No interprocedural reach analysis.
  - x86-64 ET_DYN/ET_EXEC ELF only.
  - rdi table_id extraction: resolves immediate constants only (mov edi, imm).
    Register-propagated or global-loaded table IDs are reported as table_id=None
    and excluded from the surface map.

Usage:
    from ablation.analyzers.cmdb_surface_mapper import CMDBSurfaceMapper

    mapper = CMDBSurfaceMapper.from_path('/path/to/cmdbsvr')
    surface = mapper.map()
    print(CMDBSurfaceMapper.report(surface))

    # With vendor-specific sinks or additional known tables
    mapper = CMDBSurfaceMapper.from_path(
        '/path/to/binary',
        extra_sinks={'fadcsystem', 'fadcpopen', 'sys_vdom_exec'},
        extra_tables={0x427c: 'automation_action_DefaultScript'},
    )
"""

from __future__ import annotations

import struct
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

_CS_OK = False
try:
    import capstone
    _CS_OK = True
except ImportError:
    pass

_LIEF_OK = False
try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    pass


# ── Default exec sinks ───────────────────────────────────────────────────────

_DEFAULT_EXEC_SINKS: Set[str] = {
    "system", "popen", "execve", "execvp", "execl", "execlp",
    "fadcsystem", "fadcpopen", "sys_vdom_exec",
}

# CMDB accessor symbols (PLT names as capstone sees them)
_CMDB_CREATE  = "cmf_query_create"
_CMDB_UPDATE  = "cmf_query_update"
_CMDB_GET_STR = "cmf_query_get_string"
_CMDB_GET_INT = "cmf_query_get_int"
_CMDB_GET_PTR = "cmf_query_get"
_CMDB_APPEND  = "cmf_query_table_append_nondeletable"
_CMDB_ACCESSORS = {_CMDB_UPDATE, _CMDB_GET_STR, _CMDB_GET_INT, _CMDB_GET_PTR, _CMDB_APPEND}

# Confirmed table IDs from binary analysis.  Source annotations indicate which
# binary+version the ID was confirmed from.  Do not add entries without
# disassembly evidence — speculative names mislead reports.
_CONFIRMED_TABLES: Dict[int, str] = {
    0x427c: "automation_action_DefaultScript",  # confirmed: cmdbsvr FortiWeb 7.4.3
    0x4290: "automation_action_Script",         # confirmed: cmdbsvr FortiWeb 7.4.3
    0x6000: "auth_saml",                        # confirmed: libcmdb_plugin FortiWeb 7.4.3
    0x226:  "automation_action_exec",           # confirmed: cmdbsvr FortiWeb 7.4.3
}

# EM_X86_64 value in ELF header
_EM_X86_64 = 0x3E


# ── Internal data types ──────────────────────────────────────────────────────

class CMDBTableEntry:
    """One CMDB table's surface entry."""
    __slots__ = ("name", "callers", "field_read_count", "reaches_exec", "exec_func_va",
                 "exec_call_va", "exec_sink_name")

    def __init__(self, name: str) -> None:
        self.name = name
        self.callers: List[int] = []
        self.field_read_count = 0
        # True when any caller also directly calls an exec sink (co-location only).
        self.reaches_exec = False
        # VA of the function that co-locates the exec sink call.
        self.exec_func_va: Optional[int] = None
        # VA of the call instruction to the exec sink.
        self.exec_call_va: Optional[int] = None
        self.exec_sink_name: Optional[str] = None


# ── CMDBSurfaceMapper ────────────────────────────────────────────────────────

class CMDBSurfaceMapper:
    """
    Map CMDB table IDs to exec-sink reach for x86-64 ELF binaries.

    Construct via from_path() or from_context(); call map() to run analysis.
    """

    def __init__(
        self,
        data: bytes,
        path: str = "",
        extra_sinks: Optional[Set[str]] = None,
        extra_tables: Optional[Dict[int, str]] = None,
        verbose: bool = False,
    ) -> None:
        if not _CS_OK:
            raise ImportError("capstone is required")
        if not _LIEF_OK:
            raise ImportError("lief is required")

        self._data = data
        self._path = path
        self._verbose = verbose
        self._exec_sinks: Set[str] = _DEFAULT_EXEC_SINKS | (extra_sinks or set())
        self._known_tables: Dict[int, str] = dict(_CONFIRMED_TABLES)
        if extra_tables:
            self._known_tables.update(extra_tables)

        # Populated during map()
        self._plt: Dict[int, str] = {}    # VA -> symbol name
        self._plt_rev: Dict[str, int] = {} # symbol name -> VA
        self._func_starts: List[int] = []  # sorted VAs
        self._text_sections: List[Tuple[int, int, int]] = []  # (va, file_off, size)
        self._binary: Optional[object] = None

    # ── constructors ────────────────────────────────────────────────────────

    @classmethod
    def from_path(
        cls,
        binary_path: str,
        extra_sinks: Optional[Set[str]] = None,
        extra_tables: Optional[Dict[int, str]] = None,
        verbose: bool = False,
    ) -> "CMDBSurfaceMapper":
        path = Path(binary_path)
        data = path.read_bytes()
        obj = cls(data, str(path), extra_sinks=extra_sinks,
                  extra_tables=extra_tables, verbose=verbose)
        try:
            obj._binary = _lief.parse(str(path))
        except Exception as exc:
            raise ValueError(f"lief failed to parse {path}: {exc}") from exc
        return obj

    @classmethod
    def from_context(
        cls,
        ctx,
        extra_sinks: Optional[Set[str]] = None,
        extra_tables: Optional[Dict[int, str]] = None,
        verbose: bool = False,
    ) -> "CMDBSurfaceMapper":
        """Accept a BinaryContext whose .xg attribute is a built XRefGraph."""
        xg = ctx.xg
        obj = cls(xg.data, xg.path, extra_sinks=extra_sinks,
                  extra_tables=extra_tables, verbose=verbose)
        obj._binary = xg._binary
        # Reuse already-built PLT and func_starts from XRefGraph
        obj._plt = dict(xg._plt)
        obj._plt_rev = {v: k for k, v in obj._plt.items()}
        obj._func_starts = sorted(xg._func_starts)
        obj._text_sections = obj._resolve_text_sections()
        return obj

    # ── public API ───────────────────────────────────────────────────────────

    def map(self) -> Dict[int, CMDBTableEntry]:
        """
        Run the CMDB surface analysis.

        Returns a dict keyed by table_id (int) → CMDBTableEntry.
        """
        self._validate_arch()
        if not self._plt:
            self._build_plt()
        if not self._func_starts:
            self._build_func_starts()
        self._text_sections = self._resolve_text_sections()

        create_va = self._plt_rev.get(_CMDB_CREATE)
        if create_va is None:
            if self._verbose:
                print(f"[cmdb_mapper] {Path(self._path).name}: "
                      f"cmf_query_create absent from PLT — not a CMDB binary")
            return {}

        accessor_vas: Set[int] = {
            self._plt_rev[s] for s in _CMDB_ACCESSORS if s in self._plt_rev
        }
        exec_va_to_name: Dict[int, str] = {
            self._plt_rev[s]: s
            for s in self._exec_sinks if s in self._plt_rev
        }

        if self._verbose:
            print(f"[cmdb_mapper] {Path(self._path).name}")
            print(f"  cmf_query_create  @ plt {hex(create_va)}")
            print(f"  exec sinks found: {list(exec_va_to_name.values())}")
            print(f"  functions to scan: {len(self._func_starts)}")

        surface: Dict[int, CMDBTableEntry] = {}

        sorted_starts = self._func_starts  # already sorted
        n = len(sorted_starts)

        for idx, func_va in enumerate(sorted_starts):
            # Compute disassembly window: from func_va to next function start,
            # capped at 8192 bytes.
            next_va = sorted_starts[idx + 1] if idx + 1 < n else func_va + 8192
            window = min(next_va - func_va, 8192)
            if window <= 0:
                continue

            try:
                file_off = self._va_to_file_offset(func_va)
            except ValueError:
                continue

            chunk = self._data[file_off: file_off + window]
            if not chunk:
                continue

            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            md.detail = False
            try:
                insns = list(md.disasm(chunk, func_va))
            except capstone.CsError:
                continue

            # Single pass: collect all call sites in this function
            creates: List[int] = []   # table_ids discovered
            reads:   int = 0          # count of accessor calls
            execs:   List[Tuple[int, str]] = []  # (call_va, sink_name)

            for i, insn in enumerate(insns):
                if insn.mnemonic != "call":
                    continue
                try:
                    target = int(insn.op_str, 16)
                except ValueError:
                    continue

                if target == create_va:
                    table_id = self._extract_rdi(insns, i)
                    if table_id is not None:
                        creates.append(table_id)
                elif target in accessor_vas:
                    reads += 1
                elif target in exec_va_to_name:
                    execs.append((insn.address, exec_va_to_name[target]))

            if not creates:
                continue

            for table_id in creates:
                if table_id not in surface:
                    name = self._known_tables.get(table_id, f"table_{hex(table_id)}")
                    surface[table_id] = CMDBTableEntry(name)
                entry = surface[table_id]
                if func_va not in entry.callers:
                    entry.callers.append(func_va)
                entry.field_read_count += reads
                if execs and not entry.reaches_exec:
                    entry.reaches_exec = True
                    entry.exec_func_va = func_va
                    entry.exec_call_va = execs[0][0]
                    entry.exec_sink_name = execs[0][1]

        return surface

    # ── report ───────────────────────────────────────────────────────────────

    @staticmethod
    def report(surface: Dict[int, CMDBTableEntry]) -> str:
        lines = [
            "",
            "CMDB SURFACE MAP",
            "=" * 60,
            "  NOTE: 'reaches exec' = co-location only. Not verified data flow.",
            "        Use SinkArgClassifier + TaintTracker to confirm.",
            "",
        ]
        if not surface:
            lines.append("  (no CMDB tables found — binary may not use cmf_query_create)")
            return "\n".join(lines)

        hits = sorted(surface.items(), key=lambda x: (not x[1].reaches_exec, x[0]))
        exec_count = sum(1 for _, e in hits if e.reaches_exec)
        lines.append(f"  Tables mapped: {len(hits)}   Callers reach exec sink: {exec_count}")
        lines.append("")

        for table_id, entry in hits:
            flag = "  [!! REACHES EXEC SINK (co-location) !!]" if entry.reaches_exec else ""
            lines.append(f"  Table {hex(table_id):12s}  {entry.name}{flag}")
            caller_str = ", ".join(hex(v) for v in entry.callers[:6])
            if len(entry.callers) > 6:
                caller_str += f", … (+{len(entry.callers)-6})"
            lines.append(f"    Callers ({len(entry.callers)}): {caller_str}")
            if entry.field_read_count:
                lines.append(f"    Field reads (co-located): {entry.field_read_count}")
            if entry.reaches_exec:
                lines.append(
                    f"    EXEC PATH: func {hex(entry.exec_func_va)} → "
                    f"call {hex(entry.exec_call_va)} → {entry.exec_sink_name}()"
                )
            lines.append("")

        return "\n".join(lines)

    # ── internal helpers ─────────────────────────────────────────────────────

    def _validate_arch(self) -> None:
        """Raise ValueError if binary is not x86-64."""
        if len(self._data) < 20:
            raise ValueError("data too short to be a valid ELF")
        if self._data[:4] != b'\x7fELF':
            raise ValueError("not an ELF binary")
        e_machine = struct.unpack_from('<H', self._data, 18)[0]
        if e_machine != _EM_X86_64:
            raise ValueError(
                f"CMDBSurfaceMapper requires x86-64 (e_machine=0x{_EM_X86_64:x}), "
                f"got 0x{e_machine:x}"
            )

    def _resolve_text_sections(self) -> List[Tuple[int, int, int]]:
        """Return list of (vaddr, file_offset, size) for executable sections."""
        sections = []
        if self._binary is not None:
            try:
                for sect in self._binary.sections:
                    if sect.name in ('.text', '.plt.sec'):
                        sections.append((
                            int(sect.virtual_address),
                            int(sect.offset),
                            int(sect.size),
                        ))
            except Exception:
                pass
        if not sections:
            # Fallback: treat entire file as text at VA=0 (PIE identity-mapped)
            sections = [(0, 0, len(self._data))]
        return sections

    def _va_to_file_offset(self, va: int) -> int:
        """Convert a virtual address to a file byte offset using section table."""
        for vaddr, file_off, size in self._text_sections:
            if vaddr <= va < vaddr + size:
                return file_off + (va - vaddr)
        raise ValueError(f"VA 0x{va:x} not covered by any known text section")

    def _build_plt(self) -> None:
        """Extract PLT symbol map from XRefGraph (reuse its logic via a temporary graph)."""
        from ablation.analyzers.xref_graph import XRefGraph
        xg = XRefGraph(self._data, self._path)
        xg._binary = self._binary
        xg._extract_plt()
        self._plt = dict(xg._plt)
        self._plt_rev = {v: k for k, v in self._plt.items()}

    def _build_func_starts(self) -> None:
        """Extract function starts via XRefGraph."""
        from ablation.analyzers.xref_graph import XRefGraph
        xg = XRefGraph(self._data, self._path)
        xg._binary = self._binary
        try:
            xg.build()
        except Exception as exc:
            raise ValueError(
                f"XRefGraph.build() failed for {self._path}: {exc}"
            ) from exc
        self._plt = dict(xg._plt)
        self._plt_rev = {v: k for k, v in self._plt.items()}
        self._func_starts = sorted(xg._func_starts)

    @staticmethod
    def _extract_rdi(insns: list, call_idx: int) -> Optional[int]:
        """
        Walk backward from call_idx (up to 20 instructions) and return the
        most recently loaded immediate value in rdi/edi.

        Recognizes:
          mov edi, <imm>   /   mov rdi, <imm>
          xor edi, edi     (table_id = 0)

        Returns None if no immediate rdi load is found.  Callers with
        register-propagated or memory-loaded table IDs will be excluded from
        the surface map (conservative — avoids false entries).
        """
        for i in range(call_idx - 1, max(call_idx - 20, -1), -1):
            insn = insns[i]
            op = insn.op_str
            mnem = insn.mnemonic

            # xor edi, edi → table_id = 0
            if mnem == "xor" and op in ("edi, edi", "rdi, rdi"):
                return 0

            if mnem in ("mov", "lea") and op.startswith(("rdi,", "edi,")):
                parts = op.split(",", 1)
                if len(parts) == 2:
                    val_str = parts[1].strip()
                    try:
                        return int(val_str, 16)
                    except ValueError:
                        pass
                    # Decimal fallback (capstone sometimes emits decimal immediates)
                    try:
                        return int(val_str, 10)
                    except ValueError:
                        pass
        return None


# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import json as _json

    ap = argparse.ArgumentParser(description="CMDB surface mapper for x86-64 ELF binaries")
    ap.add_argument("binary")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text report")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    mapper = CMDBSurfaceMapper.from_path(args.binary, verbose=args.verbose)
    surface = mapper.map()

    if args.json:
        out = {}
        for tid, e in surface.items():
            out[hex(tid)] = {
                "name": e.name,
                "callers": [hex(v) for v in e.callers],
                "field_read_count": e.field_read_count,
                "reaches_exec": e.reaches_exec,
                "exec_func_va": hex(e.exec_func_va) if e.exec_func_va else None,
                "exec_call_va": hex(e.exec_call_va) if e.exec_call_va else None,
                "exec_sink_name": e.exec_sink_name,
            }
        print(_json.dumps(out, indent=2))
    else:
        print(CMDBSurfaceMapper.report(surface))
