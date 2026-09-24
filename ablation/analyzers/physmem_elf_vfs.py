"""
Physical Memory ELF VFS Extractor
-----------------------------------
Reconstructs ELF binaries from physical memory dumps (QEMU ELF core format)
without page table walking.

Method: VFS-index-by-content-proximity
  1. Scan dump for all ELF64 x86_64 EXEC/DYN headers -> build VFS index
  2. For each target string: find dump offset, check all ELF PT_LOAD
     windows for coverage (physical contiguity)
  3. For non-contiguous cases: proximity heuristic -- closest ELF with
     PT_LOAD layout matching /proc/maps file offsets and sizes
  4. Confirm via local_offset string match in the rodata PT_LOAD
  5. Extract the confirmed binary

CET endbr64 detection:
  Modern gcc/clang CET-compiled binaries start functions with endbr64
  (f3 0f 1e fa) instead of push rbp; mov rbp, rsp (55 48 89 e5).
  Both must be detected as function prologues.

Usage (standalone):
  python3 physmem_elf_vfs.py --dump /tmp/memory-dump.elf --out /tmp/bins
  python3 physmem_elf_vfs.py --dump /tmp/memory-dump.elf --search 'sdnproxy'
  python3 physmem_elf_vfs.py --dump /tmp/memory-dump.elf --index /tmp/elf-index.json

Usage (from ablation):
  from modules.physmem_elf_vfs import PhysmemVFS
  vfs = PhysmemVFS('/tmp/memory-dump.elf')
  vfs.build_index()
  hit = vfs.find_owner(file_offset=0xcadd0928)  # string offset
  vfs.extract_binary(hit, '/tmp/bins/sdnproxy')
  funcs = vfs.extract_functions(hit)  # CET-aware disassembly
"""

import argparse
import hashlib
import json
import mmap
import os
import re
import struct
from pathlib import Path
from typing import Iterator, Optional

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

# CET-aware function prologue patterns
PROLOGUES = [
    b'\xf3\x0f\x1e\xfa',  # endbr64 (CET indirect branch tracking)
    b'\x55\x48\x89\xe5',  # push rbp; mov rbp, rsp (classic frame)
    b'\x55\x41\x57',      # push rbp; push r15 (gcc common variant)
    b'\x53\x55\x48',      # push rbx; push rbp (another variant)
]
PROLOGUE_MIN_LEN = min(len(p) for p in PROLOGUES)

ELF_MAGIC = b'\x7fELF\x02\x01'  # ELF64 little-endian


class PhysmemRegion:
    """One PT_LOAD segment of the outer ELF core file."""
    def __init__(self, phys_start: int, phys_end: int, file_offset: int):
        self.phys_start = phys_start
        self.phys_end = phys_end
        self.file_offset = file_offset

    def contains_phys(self, phys: int) -> bool:
        return self.phys_start <= phys < self.phys_end

    def phys_to_file(self, phys: int) -> int:
        return self.file_offset + (phys - self.phys_start)

    def file_to_phys(self, file_off: int) -> int:
        return self.phys_start + (file_off - self.file_offset)


class ElfSegment:
    """One PT_LOAD segment of an embedded ELF binary."""
    def __init__(self, p_offset: int, p_vaddr: int, p_filesz: int, p_flags: int):
        self.p_offset = p_offset   # file offset within the ELF
        self.p_vaddr = p_vaddr
        self.p_filesz = p_filesz
        self.p_flags = p_flags
        self.is_exec = bool(p_flags & 1)
        self.is_write = bool(p_flags & 2)
        self.is_read = bool(p_flags & 4)

    def contains_local(self, local_off: int) -> bool:
        return self.p_offset <= local_off < self.p_offset + self.p_filesz

    def local_to_va(self, local_off: int) -> int:
        return self.p_vaddr + (local_off - self.p_offset)


class ElfCandidate:
    """Embedded ELF binary found in the dump."""
    def __init__(self, dump_offset: int, e_type: int, segments: list[ElfSegment]):
        self.dump_offset = dump_offset
        self.e_type = e_type        # 2=EXEC, 3=DYN/PIE
        self.segments = segments
        self.name: str = ''
        self.confirmed_string: Optional[tuple[int, int]] = None  # (local_off, va)

    @property
    def text_segment(self) -> Optional[ElfSegment]:
        for seg in self.segments:
            if seg.is_exec and seg.p_filesz > 4096:
                return seg
        return None

    @property
    def total_size(self) -> int:
        if not self.segments:
            return 0
        return max(seg.p_offset + seg.p_filesz for seg in self.segments)

    def covers_local(self, local_off: int) -> Optional[tuple[ElfSegment, int]]:
        for seg in self.segments:
            if seg.contains_local(local_off):
                return seg, seg.local_to_va(local_off)
        return None

    def phys_seg_start_guess(self, seg: ElfSegment) -> int:
        """Guessed physical start of a segment if contiguous with header."""
        return self.dump_offset + seg.p_offset

    def to_dict(self) -> dict:
        return {
            'dump_offset': hex(self.dump_offset),
            'e_type': self.e_type,
            'name': self.name,
            'segments': [
                {
                    'p_offset': hex(s.p_offset),
                    'p_vaddr': hex(s.p_vaddr),
                    'p_filesz': hex(s.p_filesz),
                    'flags': ('r' if s.is_read else '-') +
                             ('w' if s.is_write else '-') +
                             ('x' if s.is_exec else '-'),
                }
                for s in self.segments
            ],
        }


def _parse_elf_candidate(data: bytes, dump_offset: int) -> Optional[ElfCandidate]:
    """Parse ELF header and PT_LOAD entries from raw bytes at dump_offset."""
    if len(data) < 64:
        return None
    try:
        e_type = struct.unpack_from('<H', data, 16)[0]
        e_machine = struct.unpack_from('<H', data, 18)[0]
        if e_machine != 62 or e_type not in (2, 3):
            return None
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phnum = struct.unpack_from('<H', data, 56)[0]
        if e_phnum == 0 or e_phnum > 64 or e_phoff > 0x10000:
            return None

        segments = []
        for i in range(e_phnum):
            off = e_phoff + i * 56
            if off + 56 > len(data):
                break
            p_type = struct.unpack_from('<I', data, off)[0]
            p_flags = struct.unpack_from('<I', data, off + 4)[0]
            p_offset, p_vaddr, _, p_filesz = struct.unpack_from('<QQQQ', data, off + 8)
            if p_type == 1 and p_filesz > 0:
                segments.append(ElfSegment(p_offset, p_vaddr, p_filesz, p_flags))

        if not segments:
            return None
        return ElfCandidate(dump_offset, e_type, segments)
    except Exception:
        return None


class PhysmemVFS:
    """
    Virtual filesystem index over a physical memory ELF core dump.

    Core concept: the dump is treated as an unindexed collection of ELF
    binaries. This class builds a catalog (VFS index) of all embedded ELF
    headers and their PT_LOAD segments, enabling:
      - String-offset to owning ELF lookup (with contiguity check)
      - Proximity-based ownership for non-contiguous segment layouts
      - CET-aware function extraction from the binary's code segment
    """

    def __init__(self, dump_path: str):
        self.dump_path = Path(dump_path)
        self._fd = open(dump_path, 'rb')
        self._mm = mmap.mmap(self._fd.fileno(), 0, access=mmap.ACCESS_READ)
        self._size = self.dump_path.stat().st_size
        self._regions: list[PhysmemRegion] = []
        self._index: list[ElfCandidate] = []
        self._index_built = False
        self._parse_outer_core()

    def close(self):
        self._mm.close()
        self._fd.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _parse_outer_core(self):
        """Parse the outer ELF core's physical memory region map."""
        hdr = self._mm[:4096]
        e_phoff = struct.unpack_from('<Q', hdr, 32)[0]
        e_phnum = struct.unpack_from('<H', hdr, 56)[0]
        full = self._mm[:e_phoff + e_phnum * 56]
        for i in range(e_phnum):
            off = e_phoff + i * 56
            p_type = struct.unpack_from('<I', full, off)[0]
            p_offset, _, p_paddr, p_filesz = struct.unpack_from('<QQQQ', full, off + 8)
            if p_type == 1 and p_filesz > 0:
                self._regions.append(
                    PhysmemRegion(p_paddr, p_paddr + p_filesz, p_offset)
                )
        self._regions.sort(key=lambda r: r.phys_start)

    def file_offset_to_phys(self, file_off: int) -> Optional[int]:
        for r in self._regions:
            if r.file_offset <= file_off < r.file_offset + (r.phys_end - r.phys_start):
                return r.file_to_phys(file_off)
        return None

    def phys_to_file_offset(self, phys: int) -> Optional[int]:
        for r in self._regions:
            if r.contains_phys(phys):
                return r.phys_to_file(phys)
        return None

    def build_index(self, progress: bool = True) -> int:
        """Scan the full dump for embedded ELF64 x86_64 EXEC/DYN headers."""
        self._index = []
        pos = 0
        n = 0
        while pos < self._size:
            idx = self._mm.find(ELF_MAGIC, pos, min(self._size, pos + 0x20000000))
            if idx < 0:
                if pos + 0x20000000 >= self._size:
                    break
                pos += 0x20000000
                continue
            pos = idx + 4
            hdr = bytes(self._mm[idx:idx + 8192])
            cand = _parse_elf_candidate(hdr, idx)
            if cand:
                self._index.append(cand)
                n += 1
        self._index_built = True
        if progress:
            print(f'VFS index: {n} ELF64 x86_64 binaries')
        return n

    def load_index(self, path: str):
        """Load pre-built index from JSON."""
        with open(path) as f:
            raw = json.load(f)
        self._index = []
        for entry in raw:
            segs = [
                ElfSegment(
                    int(s['p_offset'], 16),
                    int(s['p_vaddr'], 16),
                    int(s['p_filesz'], 16),
                    (4 if 'r' in s['flags'] else 0) |
                    (2 if 'w' in s['flags'] else 0) |
                    (1 if 'x' in s['flags'] else 0),
                )
                for s in entry['segments']
            ]
            c = ElfCandidate(int(entry['dump_offset'], 16), entry['e_type'], segs)
            c.name = entry.get('name', '')
            self._index.append(c)
        self._index_built = True

    def save_index(self, path: str):
        with open(path, 'w') as f:
            json.dump([c.to_dict() for c in self._index], f, indent=2)

    def find_owner_contiguous(self, file_offset: int) -> list[tuple[ElfCandidate, ElfSegment, int]]:
        """
        Find ELF candidates where file_offset falls within a PT_LOAD segment,
        assuming the segment is physically contiguous with the ELF header.

        This is the fast path: works when pages are physically adjacent.
        local_offset = file_offset - elf.dump_offset must fall within a segment.
        """
        matches = []
        for cand in self._index:
            local = file_offset - cand.dump_offset
            if local < 0:
                continue
            result = cand.covers_local(local)
            if result:
                seg, va = result
                matches.append((cand, seg, va))
        return matches

    def find_owner_proximity(
        self,
        file_offset: int,
        proc_maps_text_foff: Optional[int] = None,
        proc_maps_text_sz: Optional[int] = None,
        proc_maps_rodata_foff: Optional[int] = None,
        window_bytes: int = 100 * 1024 * 1024,
    ) -> list[tuple[ElfCandidate, int]]:
        """
        Find ELF candidates near file_offset whose PT_LOAD layout matches
        known /proc/maps file offsets (non-contiguous case).

        Proximity heuristic: score candidates by:
          1. Closeness to file_offset
          2. PT_LOAD file-offset match to /proc/maps data

        Returns list of (candidate, distance_bytes) sorted by score.
        """
        candidates = []
        lo = max(0, file_offset - window_bytes)
        hi = min(self._size, file_offset + window_bytes)

        for cand in self._index:
            if not (lo <= cand.dump_offset <= hi):
                continue
            dist = abs(cand.dump_offset - file_offset)
            score = dist

            if proc_maps_text_foff is not None:
                # Check if any exec segment has the expected file offset
                for seg in cand.segments:
                    if seg.is_exec:
                        if abs(seg.p_offset - proc_maps_text_foff) <= 0x1000:
                            score = max(0, score - 5_000_000)
                        if proc_maps_text_sz and abs(seg.p_filesz - proc_maps_text_sz) <= 0x2000:
                            score = max(0, score - 2_000_000)

            if proc_maps_rodata_foff is not None:
                for seg in cand.segments:
                    if seg.is_read and not seg.is_exec and not seg.is_write:
                        if abs(seg.p_offset - proc_maps_rodata_foff) <= 0x1000:
                            score = max(0, score - 3_000_000)

            candidates.append((cand, score))

        candidates.sort(key=lambda x: x[1])
        return candidates

    def confirm_candidate(
        self,
        cand: ElfCandidate,
        rodata_dump_offset: int,
        expected_local_offset: Optional[int] = None,
    ) -> bool:
        """
        Confirm that cand owns the rodata region at rodata_dump_offset.

        Computes the dump_base for the rodata segment by:
          dump_base_rodata = rodata_dump_offset - expected_offset_within_rodata_seg

        If expected_local_offset not given, finds the r-- segment closest to
        the rodata_dump_offset and checks alignment.
        """
        for seg in cand.segments:
            if seg.is_read and not seg.is_exec and not seg.is_write and seg.p_filesz > 1024:
                # Try: assume rodata pages are at rodata_dump_offset .. rodata_dump_offset+p_filesz
                # and the local_offset inside this segment is rodata_dump_offset - (cand.dump_offset + seg.p_offset)
                # For contiguous: this works directly
                local = rodata_dump_offset - cand.dump_offset
                if seg.contains_local(local):
                    off_within = local - seg.p_offset
                    if expected_local_offset is not None:
                        return abs(off_within - (expected_local_offset - seg.p_offset)) < 0x10
                    return True
        return False

    def extract_binary(self, cand: ElfCandidate, out_path: str) -> int:
        """
        Extract the binary to out_path. Extracts all contiguous PT_LOAD data
        from cand.dump_offset to cand.dump_offset + cand.total_size.
        Returns bytes written.
        """
        end = cand.dump_offset + cand.total_size + 4096
        end = min(end, self._size)
        blob = bytes(self._mm[cand.dump_offset:end])
        with open(out_path, 'wb') as f:
            f.write(blob)
        os.chmod(out_path, 0o755)
        return len(blob)

    def extract_functions(
        self,
        cand: ElfCandidate,
        max_funcs: int = 1000,
    ) -> list[dict]:
        """
        CET-aware function extraction from the binary's executable PT_LOAD.

        Detects both:
          endbr64 (f3 0f 1e fa) -- CET/IBT compiled
          push rbp; mov rbp, rsp (55 48 89 e5) -- classic frame

        Returns list of {'addr': va, 'asm': [lines], 'calls': [targets]}.
        """
        if not HAS_CAPSTONE:
            raise ImportError('capstone required for function extraction')

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        funcs = []
        for seg in cand.segments:
            if not seg.is_exec or seg.p_filesz < 64:
                continue
            start = cand.dump_offset + seg.p_offset
            end_pos = min(start + seg.p_filesz, self._size)
            code = bytes(self._mm[start:end_pos])

            i_off = 0
            while i_off < len(code) - PROLOGUE_MIN_LEN and len(funcs) < max_funcs:
                found_prologue = False
                for pr in PROLOGUES:
                    if code[i_off:i_off + len(pr)] == pr:
                        found_prologue = True
                        break

                if found_prologue:
                    chunk = code[i_off:i_off + 512]
                    insns = list(md.disasm(chunk, seg.p_vaddr + i_off))
                    if len(insns) >= 5:
                        calls = [
                            ins.op_str for ins in insns
                            if ins.mnemonic in ('call', 'jmp') and ins.op_str.startswith('0x')
                        ]
                        asm_lines = [
                            f'{ins.mnemonic} {ins.op_str}'
                            for ins in insns[:40]
                        ]
                        funcs.append({
                            'addr': seg.p_vaddr + i_off,
                            'dump_offset': start + i_off,
                            'asm': asm_lines,
                            'calls': calls[:8],
                        })
                    i_off += 4
                else:
                    i_off += 1

        return funcs

    def find_proc_maps(self, window: int = 2 * 1024 * 1024) -> list[dict]:
        """
        Scan the dump for /proc/pid/maps text data.
        Returns list of parsed maps entries with path, VA ranges, file offsets.
        """
        MAPS_RE = re.compile(
            rb'([0-9a-f]+)-([0-9a-f]+) ([r-][w-][x-][ps]) ([0-9a-f]+) \S+ \d+ *(.*)'
        )
        result = []
        pos = 0
        # Search for lines that look like maps entries
        while pos < self._size:
            idx = self._mm.find(b'/usr/bin/', pos, min(self._size, pos + 0x40000000))
            if idx < 0:
                if pos + 0x40000000 >= self._size:
                    break
                pos += 0x40000000
                continue
            pos = idx + 4
            # Look backward for the start of the maps line
            line_start = max(0, idx - 100)
            chunk = bytes(self._mm[line_start:idx + 200])
            for m in MAPS_RE.finditer(chunk):
                try:
                    entry = {
                        'va_start': int(m.group(1), 16),
                        'va_end': int(m.group(2), 16),
                        'perms': m.group(3).decode(),
                        'file_off': int(m.group(4), 16),
                        'path': m.group(5).decode().strip(),
                        'dump_offset': line_start + m.start(),
                    }
                    if entry['path']:
                        result.append(entry)
                except Exception:
                    pass

        # Deduplicate by (path, va_start, file_off)
        seen = set()
        deduped = []
        for e in result:
            key = (e['path'], e['va_start'], e['file_off'])
            if key not in seen:
                seen.add(key)
                deduped.append(e)
        return deduped

    def find_strings(self, pattern: str, encoding: str = 'ascii') -> list[tuple[int, str]]:
        """Find all occurrences of a string pattern in the dump. Returns (file_offset, context)."""
        query = pattern.encode(encoding) if isinstance(pattern, str) else pattern
        results = []
        pos = 0
        while True:
            idx = self._mm.find(query, pos)
            if idx < 0:
                break
            ctx_raw = bytes(self._mm[max(0, idx - 20):idx + len(query) + 40])
            ctx = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx_raw)
            results.append((idx, ctx))
            pos = idx + 1
        return results


def main():
    ap = argparse.ArgumentParser(description='Physical memory ELF VFS extractor')
    ap.add_argument('--dump', required=True, help='ELF core dump path')
    ap.add_argument('--out', default='/tmp/physmem-bins', help='Output directory')
    ap.add_argument('--index', help='Load/save VFS index JSON path')
    ap.add_argument('--search', help='Search for string and show owning ELF')
    ap.add_argument('--extract-all', action='store_true', help='Extract all found ELFs')
    ap.add_argument('--proc-maps', action='store_true', help='Scan for /proc/pid/maps data')
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    with PhysmemVFS(args.dump) as vfs:
        if args.index and Path(args.index).exists():
            print(f'Loading index from {args.index}')
            vfs.load_index(args.index)
        else:
            print('Building VFS index...')
            n = vfs.build_index()
            if args.index:
                vfs.save_index(args.index)
                print(f'Index saved -> {args.index}')

        if args.proc_maps:
            print('\nScanning for /proc/pid/maps data...')
            maps = vfs.find_proc_maps()
            by_path: dict[str, list] = {}
            for e in maps:
                by_path.setdefault(e['path'], []).append(e)
            for path in sorted(by_path):
                print(f'\n{path}:')
                for e in by_path[path]:
                    perm = e['perms']
                    print(f'  {perm} VA=0x{e["va_start"]:x}-0x{e["va_end"]:x} foff=0x{e["file_off"]:x}')

        if args.search:
            print(f'\nSearching for {args.search!r}...')
            hits = vfs.find_strings(args.search)
            for off, ctx in hits[:10]:
                print(f'  file_offset=0x{off:x}: {ctx}')
                owners = vfs.find_owner_contiguous(off)
                for cand, seg, va in owners[:2]:
                    flag_s = ('r' if seg.is_read else '-') + ('w' if seg.is_write else '-') + ('x' if seg.is_exec else '-')
                    print(f'    -> ELF@0x{cand.dump_offset:x} VA=0x{va:x} seg={flag_s}')

        if args.extract_all:
            print(f'\nExtracting all {len(vfs._index)} ELFs...')
            manifest = {}
            for i, cand in enumerate(vfs._index):
                name = cand.name or f'elf_0x{cand.dump_offset:x}'
                out = os.path.join(args.out, name)
                sz = vfs.extract_binary(cand, out)
                digest = hashlib.sha256(open(out, 'rb').read()).hexdigest()[:12]
                manifest[name] = {'size': sz, 'digest': digest, 'dump_offset': hex(cand.dump_offset)}
            mpath = os.path.join(args.out, 'manifest.json')
            with open(mpath, 'w') as f:
                json.dump(manifest, f, indent=2)
            print(f'Manifest -> {mpath}')


# ---------------------------------------------------------
# VM RE helpers -- process-aware analysis (from vm_re_helper pattern, 2026-09-16)
# Designed to work with PhysmemVFS index + /proc/maps text extracted from the dump
# ---------------------------------------------------------

import re as _re

def parse_proc_maps(maps_text: str) -> list:
    """Parse /proc/<pid>/maps text into structured region dicts."""
    LINE_RE = _re.compile(
        r'^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+(\S+)\s+(\d+)\s*(.*)$'
    )
    regions = []
    for ln in maps_text.splitlines():
        m = LINE_RE.match(ln.strip())
        if not m:
            continue
        start, end, perms, offset, dev, inode, path = m.groups()
        regions.append({
            'start':  int(start, 16),
            'end':    int(end, 16),
            'perms':  perms,
            'offset': int(offset, 16),
            'dev':    dev,
            'inode':  int(inode),
            'path':   path.strip() or None,
        })
    return regions


def group_maps_by_binary(regions: list) -> dict:
    """Group /proc/maps regions by path substring, excluding anon/heap/stack."""
    bins: dict = {}
    for r in regions:
        p = r.get('path')
        if not p or p.startswith('['):
            continue
        bins.setdefault(p, []).append(r)
    return bins


def match_elf_to_maps(elf_candidates: list, maps_regions: list) -> 'ElfCandidate | None':
    """
    Score each ElfCandidate by how many of its PT_LOAD file offsets appear in maps_regions.
    Returns the best-matching candidate (typically unambiguous for score >= 2).

    elf_candidates: list of ElfCandidate objects from PhysmemVFS._index
    maps_regions: list of region dicts from parse_proc_maps() filtered to one binary
    """
    map_offsets = {r['offset'] for r in maps_regions if r.get('path')}

    best = None
    best_score = 0
    for cand in elf_candidates:
        elf_offsets = {seg.p_offset for seg in cand.segments}
        score = len(map_offsets & elf_offsets)
        if score > best_score:
            best = cand
            best_score = score
    return best


def rank_functions(funcs: list) -> list:
    """
    Rank FunctionRecord-like dicts by size_score + 2*call_score.
    funcs: list of dicts with keys 'asm' (list of str) and 'calls' (list of str).
    Returns sorted list of {'fn': func_dict, 'score': int} descending.
    """
    ranked = []
    for fn in funcs:
        size_score = len(fn.get('asm', []))
        call_score = len(fn.get('calls', []))
        ranked.append({'fn': fn, 'score': size_score + 2 * call_score})
    return sorted(ranked, key=lambda x: x['score'], reverse=True)


def get_arg_setup(insns: list, call_idx: int) -> dict:
    """
    Backward slice from a CALL instruction to find last register writes before it.
    insns: list of capstone CsInsn objects.
    call_idx: index of the call instruction in insns.
    Returns dict {reg_name: CsInsn} for rdi/rsi/rdx/rcx/r8/r9.
    """
    interesting = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')
    reg_state: dict = {}
    i = call_idx - 1
    while i >= 0:
        ins = insns[i]
        if ins.mnemonic in ('ret', 'jmp', 'call'):
            break
        if ins.mnemonic in ('mov', 'lea') and ',' in ins.op_str:
            dst, _ = ins.op_str.split(',', 1)
            dst = dst.strip()
            if dst in interesting and dst not in reg_state:
                reg_state[dst] = ins
        i -= 1
    return reg_state


def analyze_calls_to_targets(insns: list, targets: list) -> list:
    """
    Find call sites in a function's disassembly that target specific callees.
    Returns list of dicts with call_addr, target, arg_setup (reg -> insn text).
    """
    targets_set = set(targets)
    results = []
    for idx, ins in enumerate(insns):
        if ins.mnemonic != 'call':
            continue
        try:
            tgt = int(ins.op_str, 16)
        except (ValueError, TypeError):
            continue
        if tgt not in targets_set:
            continue
        reg_state = get_arg_setup(insns, idx)
        results.append({
            'call_addr': ins.address,
            'target':    tgt,
            'arg_setup': {r: f'{i.mnemonic} {i.op_str}' for r, i in reg_state.items()},
        })
    return results


def diff_call_args(call_info: list) -> str:
    """
    Format argument differences across multiple call sites to the same targets.
    Useful for auth-present vs auth-absent path comparison.
    """
    by_target: dict = {}
    for ci in call_info:
        by_target.setdefault(ci['target'], []).append(ci)

    lines = []
    for tgt, calls in sorted(by_target.items()):
        lines.append(f'target 0x{tgt:x}:')
        for ci in calls:
            lines.append(f'  call at 0x{ci["call_addr"]:x}')
            for reg, inst in sorted(ci['arg_setup'].items()):
                lines.append(f'    {reg}: {inst}')
        lines.append('')
    return '\n'.join(lines)


if __name__ == '__main__':
    main()
