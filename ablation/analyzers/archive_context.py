"""
archive_context.py: cross-object query engine for Unix ar (.a) archives.

Why this exists:
  ArArchiveScanner runs SinkArgClassifier on each member for exec-class sinks.
  RE analysis of static libraries often needs different cross-cutting queries:
    - Which functions in any member call both symbol_A and symbol_B?
    - Which members define symbol X?
    - Which functions call symbol Y anywhere in the library?
  These cannot be answered per-member; they require an archive-level index.
  Gap ID: RELO-GAP-003 (solidDB VxWorks PPC440 solidac.a analysis).

  The solidac.a corpus (666 .o files) required a manual member-by-member scan
  to find rpc0http.o as the only .o calling both rpc_ses_read and strcpy in the
  same function.  co_reference_scan(sym_a, sym_b) automates this.

Usage:
    from ablation.analyzers.archive_context import ArchiveContext

    arc = ArchiveContext.from_path('lib/solidac.a')
    print(arc.summary())

    # Which functions call both rpc_ses_read AND strcpy?
    for obj, fn in arc.co_reference_scan('rpc_ses_read', 'strcpy'):
        print(f'  {obj}::{fn}')

    # All callers of strcpy across the archive
    for obj, fn in arc.find_callers('strcpy'):
        print(f'  {obj}::{fn}')

    # Per-object context for deeper analysis
    ctx = arc.get('rpc0http.o')
    if ctx:
        print(ctx.disasm('rpc_http_svc_get'))
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ablation.analyzers.relo_object_context import ReloObjectContext

_AR_MAGIC    = b'!<arch>\n'
_MBR_HDR_SZ  = 60
_MBR_END     = b'\x60\x0a'


class ArchiveContext:
    """
    Cross-object query engine for Unix ar (.a) static archives.

    Parses the archive index, lazy-builds ReloObjectContext for ELF32 members,
    and exposes archive-level queries such as co_reference_scan() and
    find_callers().
    """

    def __init__(self, data: bytes, path: str = '<buffer>') -> None:
        self.path = path
        self._data = data
        self._member_names: List[str] = []          # ELF32 member names in order
        self._member_data: Dict[str, bytes] = {}    # raw bytes per member
        self._ctx_cache: Dict[str, ReloObjectContext] = {}
        self._parse_index()

    @classmethod
    def from_path(cls, path: str) -> 'ArchiveContext':
        return cls(Path(path).read_bytes(), path)

    # ── AR parsing ────────────────────────────────────────────────────────────

    def _parse_index(self) -> None:
        data = self._data
        if not data.startswith(_AR_MAGIC):
            return

        pos = len(_AR_MAGIC)
        long_name_table: Optional[bytes] = None

        while pos + _MBR_HDR_SZ <= len(data):
            hdr = data[pos:pos + _MBR_HDR_SZ]
            if len(hdr) < _MBR_HDR_SZ:
                break

            raw_name = hdr[0:16].rstrip()
            raw_size = hdr[48:58].rstrip()
            end_chars = hdr[58:60]

            if end_chars != _MBR_END:
                break

            try:
                size = int(raw_size)
            except ValueError:
                break

            pos += _MBR_HDR_SZ
            member_data = data[pos:pos + size]
            pos += size + (size % 2)

            name = raw_name.decode('ascii', errors='replace').rstrip('/')

            # GNU long name table
            if raw_name.rstrip() == b'//':
                long_name_table = member_data
                continue
            # GNU / BSD symbol tables
            if raw_name.rstrip() in (b'/', b'__.SYMDEF', b'__.SYMDEF SORTED'):
                continue
            # Thin archive range markers
            if raw_name.rstrip() == b'/SYM64/':
                continue

            # Resolve GNU long names: '/N' where N is offset into //
            if name.startswith('/') and name[1:].isdigit() and long_name_table:
                off = int(name[1:])
                end = long_name_table.find(b'/\n', off)
                if end >= 0:
                    name = long_name_table[off:end].decode('ascii', errors='replace')

            name = name.rstrip()

            # Only index ELF32 members (first 5 bytes: \x7fELF + ELFCLASS32)
            if len(member_data) >= 5 and member_data[:4] == b'\x7fELF' and member_data[4] == 1:
                if name not in self._member_data:
                    self._member_names.append(name)
                self._member_data[name] = member_data

    # ── Member access ─────────────────────────────────────────────────────────

    def members(self) -> List[str]:
        """Names of all ELF32 members in the archive."""
        return list(self._member_names)

    def get(self, name: str) -> Optional[ReloObjectContext]:
        """
        Return the ReloObjectContext for member `name`, building it lazily.
        Returns None if the member is not found.
        """
        if name in self._ctx_cache:
            return self._ctx_cache[name]
        data = self._member_data.get(name)
        if data is None:
            return None
        ctx = ReloObjectContext(data, f'{self.path}::{name}')
        self._ctx_cache[name] = ctx
        return ctx

    def get_all(self) -> List[Tuple[str, ReloObjectContext]]:
        """Return (name, context) for all ELF32 members."""
        return [(n, self.get(n)) for n in self._member_names if self.get(n) is not None]

    # ── Archive-level queries ─────────────────────────────────────────────────

    def co_reference_scan(self, sym_a: str, sym_b: str) -> List[Tuple[str, str]]:
        """
        Find functions that reference both sym_a and sym_b in the same function.

        Returns list of (object_name, function_name).  Only considers members that
        import both symbols at the object level first (fast pre-filter), then
        checks individual functions.

        Typical use: co_reference_scan('rpc_ses_read', 'strcpy') to find
        functions that both read network data and copy it — the read+strcpy pattern.
        """
        results: List[Tuple[str, str]] = []
        for obj_name in self._member_names:
            ctx = self.get(obj_name)
            if ctx is None:
                continue
            # Fast pre-filter: object must import both
            if not (ctx.has_import(sym_a) and ctx.has_import(sym_b)):
                continue
            # Per-function check
            for fn in ctx.functions():
                calls = ctx.calls_in(fn.name)
                sym_names = {c.sym_name for c in calls}
                if sym_a in sym_names and sym_b in sym_names:
                    results.append((obj_name, fn.name))
        return results

    def find_callers(self, sym: str) -> List[Tuple[str, str]]:
        """
        Find all (object_name, function_name) pairs that call sym across the archive.

        Pre-filters by object-level import check for performance.
        """
        results: List[Tuple[str, str]] = []
        for obj_name in self._member_names:
            ctx = self.get(obj_name)
            if ctx is None:
                continue
            if not ctx.has_import(sym):
                continue
            for fn_name in ctx.functions_calling(sym):
                results.append((obj_name, fn_name))
        return results

    def find_definitions(self, sym: str) -> List[Tuple[str, str]]:
        """
        Find all (object_name, sym) pairs where sym is defined (exported) by the member.
        """
        results: List[Tuple[str, str]] = []
        for obj_name in self._member_names:
            ctx = self.get(obj_name)
            if ctx is None:
                continue
            if sym in ctx.exports():
                results.append((obj_name, sym))
        return results

    def imports_of(self, obj_name: str) -> List[str]:
        """All external symbols imported by the named member."""
        ctx = self.get(obj_name)
        return ctx.imports() if ctx else []

    def exports_of(self, obj_name: str) -> List[str]:
        """All exported symbols defined by the named member."""
        ctx = self.get(obj_name)
        return ctx.exports() if ctx else []

    def summary(self) -> str:
        total = len(self._member_names)
        return (f'ArchiveContext({Path(self.path).name}): '
                f'{total} ELF32 members')
