"""
win16_mz_dos_sweep.py — Security sweep for 16-bit real-mode MS-DOS MZ executables.

Handles large-model DOS programs with multiple code segments (typical of WfW 3.11
network utilities: ARP.EXE, PING.EXE, TRACERT.EXE, etc.).

GAP-G fix: prior to this module, Ablation had no loader for real-mode MZ DOS
executables. These binaries appeared in TCP/IP-32 3.11a and could not be swept.
"""

import argparse
import os
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

try:
    import capstone
    CS_ARCH_X86  = capstone.CS_ARCH_X86
    CS_MODE_16   = capstone.CS_MODE_16
    CS_GRP_CALL  = capstone.x86.X86_GRP_CALL
    CS_GRP_RET   = capstone.x86.X86_GRP_RET
    CS_GRP_JUMP  = capstone.x86.X86_GRP_JUMP
except ImportError:
    raise ImportError("capstone required: pip install capstone")


# ──────────────────────────────────────────────────────────────────────────────
# MZ binary loader
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class MZHeader:
    last_page_extra: int   # bytes in last page (0 = full 512)
    page_count:      int
    reloc_count:     int
    header_paragraphs: int # header size in 16-byte paragraphs
    initial_ss:      int
    initial_sp:      int
    checksum:        int
    initial_ip:      int
    initial_cs:      int   # CS relative to load segment
    reloc_table_off: int
    overlay_number:  int

    @property
    def code_offset(self) -> int:
        return self.header_paragraphs * 16

    @property
    def image_size(self) -> int:
        base = (self.page_count - 1) * 512
        return base + (self.last_page_extra or 512)


@dataclass
class MZReloc:
    offset: int   # offset within segment
    segment: int  # segment (paragraph, relative to load)


class MZBinary:
    """Load and decode a real-mode MZ DOS executable."""

    def __init__(self, path: str):
        self.path = path
        self.data = open(path, 'rb').read()
        self._hdr: Optional[MZHeader] = None
        self._relocs: Optional[List[MZReloc]] = None

    def header(self) -> MZHeader:
        if self._hdr is None:
            d = self.data
            magic = d[0:2]
            if magic not in (b'MZ', b'ZM'):
                raise ValueError(f"Not an MZ binary: {magic!r}")
            self._hdr = MZHeader(
                last_page_extra  = struct.unpack_from('<H', d, 2)[0],
                page_count       = struct.unpack_from('<H', d, 4)[0],
                reloc_count      = struct.unpack_from('<H', d, 6)[0],
                header_paragraphs= struct.unpack_from('<H', d, 8)[0],
                initial_ss       = struct.unpack_from('<H', d, 14)[0],
                initial_sp       = struct.unpack_from('<H', d, 16)[0],
                checksum         = struct.unpack_from('<H', d, 18)[0],
                initial_ip       = struct.unpack_from('<H', d, 20)[0],
                initial_cs       = struct.unpack_from('<H', d, 22)[0],
                reloc_table_off  = struct.unpack_from('<H', d, 24)[0],
                overlay_number   = struct.unpack_from('<H', d, 26)[0],
            )
        return self._hdr

    def relocs(self) -> List[MZReloc]:
        if self._relocs is None:
            hdr = self.header()
            off = hdr.reloc_table_off
            self._relocs = []
            for i in range(hdr.reloc_count):
                o = struct.unpack_from('<H', self.data, off + i * 4)[0]
                s = struct.unpack_from('<H', self.data, off + i * 4 + 2)[0]
                self._relocs.append(MZReloc(o, s))
        return self._relocs

    def code_bytes(self) -> bytes:
        hdr = self.header()
        co  = hdr.code_offset
        return self.data[co : co + hdr.image_size - co]

    def entry_offset(self) -> int:
        """Flat code-section byte offset of CS:IP entrypoint."""
        hdr = self.header()
        # CS paragraph × 16 + IP, relative to start of code section
        return hdr.initial_cs * 16 + hdr.initial_ip

    def segment_bases_from_relocs(self):
        """Return the unique set of CS-relative paragraph values from reloc table."""
        return sorted({r.segment for r in self.relocs()})


# ──────────────────────────────────────────────────────────────────────────────
# DOS-specific security profiles
# ──────────────────────────────────────────────────────────────────────────────

# INT 21h AH values that introduce external data
DOS_NET_INT21_AH = {
    0x3F,  # Read from file/handle (stdin or socket fd)
    0x0A,  # Buffered stdin input (gets-like)
    0x01,  # Character input (stdin)
    0x08,  # Character input without echo
}

# rep movs without size check in preceding 12 instructions
REPMOVSB = b'\xf3\xa4'   # rep movsb
REPMOVSW = b'\xf3\xa5'   # rep movsw
REPMOVSD = b'\xf3\xa5'   # rep movsd (won't appear in 16-bit but guard anyway)


def _score_function(insns) -> dict:
    """
    Score a list of capstone instructions against DOS network-client profiles.

    Returns a dict of {profile: score} where score is 0.0–1.0.
    """
    scores = {}
    mnems = [i.mnemonic for i in insns]
    ops   = [i.op_str   for i in insns]
    bytes_list = [i.bytes for i in insns]

    # ── Profile: dos_unbounded_copy ──────────────────────────────────────────
    # rep movsb/movsw with no cmp/jbe/jl guard in 12-insn window AND
    # CX not loaded from a compile-time constant (constant CX = bounded by design).
    rep_idx = [j for j, m in enumerate(mnems) if m in ('rep movsb','rep movsw',
               'rep stosd','rep stosw','rep stosb') or
               (m == 'rep' and j+1 < len(mnems) and mnems[j+1] in ('movsb','movsw'))]
    for ri in rep_idx:
        win_m = mnems[max(0, ri-12):ri]
        win_o = ops[max(0, ri-12):ri]
        has_guard = any(m in ('cmp','test','jbe','jle','jge','jl','jg','jb',
                               'ja','jae','jne','je') for m in win_m)
        if has_guard:
            continue
        # Skip if CX was loaded from a compile-time constant (e.g. mov cx, 8)
        cx_from_const = False
        for wm, wo in zip(win_m, win_o):
            if wm == 'mov' and wo.strip().startswith('cx,'):
                after_comma = wo.split(',', 1)[1].strip()
                # Immediate literal: decimal or 0xNN — no brackets, no register names
                if after_comma.startswith('0x') or (after_comma.isdigit()):
                    cx_from_const = True
                    break
        if not cx_from_const:
            scores['dos_unbounded_copy'] = max(scores.get('dos_unbounded_copy', 0.0), 0.55)

    # ── Profile: dos_int21_recv_path ─────────────────────────────────────────
    # INT 21h present + AH loaded from external (mov ah, [mem]) within 8 insns
    for j, (m, o) in enumerate(zip(mnems, ops)):
        if m == 'int' and '0x21' in o:
            window_m = mnems[max(0, j-8):j]
            window_o = ops[max(0, j-8):j]
            for wm, wo in zip(window_m, window_o):
                if wm == 'mov' and 'ah' in wo and '[' in wo:
                    # AH loaded from memory — possibly from external buffer
                    scores['dos_int21_recv_path'] = max(
                        scores.get('dos_int21_recv_path', 0.0), 0.40)
                if wm == 'mov' and 'ah,' in wo:
                    try:
                        ah_val_str = wo.split('ah,')[1].strip().replace('0x','')
                        ah_val = int(ah_val_str, 16) if ah_val_str else -1
                        if ah_val in DOS_NET_INT21_AH:
                            scores['dos_int21_recv_path'] = max(
                                scores.get('dos_int21_recv_path', 0.0), 0.35)
                    except (ValueError, IndexError):
                        pass

    # ── Profile: dos_fixed_stack_alloc ───────────────────────────────────────
    # sub sp, N where N > 0x100 bytes — large stack allocation near external input
    for m, o in zip(mnems, ops):
        if m == 'sub' and 'sp,' in o and o.strip().startswith('sp'):
            try:
                val_s = o.split(',')[1].strip()
                val = int(val_s, 16) if '0x' in val_s else int(val_s)
                if val > 0x100:
                    scores['dos_fixed_stack_alloc'] = max(
                        scores.get('dos_fixed_stack_alloc', 0.0), 0.30)
            except (ValueError, IndexError):
                pass

    return scores


# ──────────────────────────────────────────────────────────────────────────────
# Function start recovery (call-target BFS + prologue scan)
# ──────────────────────────────────────────────────────────────────────────────

def _find_near_call_targets(code: bytes, max_offset: int) -> set:
    """Collect all NEAR CALL (E8 rel16) targets within code as flat offsets."""
    targets = set()
    i = 0
    while i < len(code) - 2:
        if code[i] == 0xE8:   # CALL rel16
            rel = struct.unpack_from('<h', code, i + 1)[0]
            target = (i + 3 + rel) & 0xFFFF
            if 0 < target < max_offset:
                targets.add(target)
        i += 1
    return targets


def _scan_prologues(code: bytes) -> set:
    """16-bit function prologue patterns: push bp; mov bp, sp."""
    starts = set()
    i = 0
    while i < len(code) - 3:
        # push bp (55) ; mov bp, sp (89 e5) or (8b ec)
        if code[i] == 0x55 and code[i+1] == 0x89 and code[i+2] == 0xE5:
            starts.add(i)
        elif code[i] == 0x55 and code[i+1] == 0x8B and code[i+2] == 0xEC:
            starts.add(i)
        # enter N, 0  (c8 xx xx 00)
        elif code[i] == 0xC8 and code[i+3] == 0x00:
            starts.add(i)
        i += 1
    return starts


# ──────────────────────────────────────────────────────────────────────────────
# Sweep
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class MZSweepHit:
    offset:  int
    profile: str
    score:   float
    insn_count: int


@dataclass
class MZSweepResult:
    binary:   str
    func_count: int
    hits: List[MZSweepHit] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def sweep(path: str, score_threshold: float = 0.30) -> MZSweepResult:
    result = MZSweepResult(binary=os.path.basename(path), func_count=0)
    try:
        mz   = MZBinary(path)
        hdr  = mz.header()
        code = mz.code_bytes()
    except Exception as e:
        result.errors.append(str(e))
        return result

    # Entry point + call targets + prologues
    entry = mz.entry_offset()
    if entry >= len(code):
        entry = 0
    call_targets = _find_near_call_targets(code, len(code))
    prologue_hits = _scan_prologues(code)
    func_starts  = sorted({entry} | call_targets | prologue_hits)

    md = capstone.Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = True

    result.func_count = len(func_starts)

    for start in func_starts:
        if start >= len(code):
            continue
        # Disassemble up to 256 instructions or first RET/RETF
        end_off = min(start + 0x600, len(code))
        insns   = []
        try:
            for insn in md.disasm(code[start:end_off], start):
                insns.append(insn)
                if len(insns) > 256:
                    break
                if insn.mnemonic in ('ret', 'retf', 'iret', 'iretd', 'hlt'):
                    break
        except Exception:
            continue

        if len(insns) < 3:
            continue

        scores = _score_function(insns)
        for profile, score in scores.items():
            if score >= score_threshold:
                result.hits.append(MZSweepHit(
                    offset    = start,
                    profile   = profile,
                    score     = score,
                    insn_count= len(insns),
                ))

    return result


# ──────────────────────────────────────────────────────────────────────────────
# Report
# ──────────────────────────────────────────────────────────────────────────────

def report(results: List[MZSweepResult], threshold: float) -> str:
    ts = datetime.now().strftime('%Y%m%d_%H%M')
    lines = [
        f"# MZ DOS sweep — Microsoft TCP/IP-32 3.11a",
        f"generated: {ts}   threshold: {threshold}",
        "",
    ]
    total_hits = sum(len(r.hits) for r in results)
    lines.append(f"**{len(results)} binaries | "
                 f"{sum(r.func_count for r in results)} functions | "
                 f"{total_hits} hits ≥ {threshold}**")
    lines.append("")
    lines.append("| Binary | Functions | Hits | Top score | Top profile |")
    lines.append("|--------|-----------|------|-----------|-------------|")
    for r in results:
        if r.hits:
            top = max(r.hits, key=lambda h: h.score)
            lines.append(f"| {r.binary} | {r.func_count} | {len(r.hits)} | "
                         f"{top.score:.4f} | {top.profile} |")
        else:
            lines.append(f"| {r.binary} | {r.func_count} | 0 | — | — |")
    lines.append("")
    for r in results:
        if not r.hits:
            continue
        lines.append(f"## {r.binary}")
        for h in sorted(r.hits, key=lambda x: -x.score):
            lines.append(f"  offset=0x{h.offset:04x}  score={h.score:.4f}  "
                         f"profile={h.profile}  insns={h.insn_count}")
        lines.append("")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description='MZ DOS security sweep')
    ap.add_argument('paths', nargs='+')
    ap.add_argument('--threshold', type=float, default=0.30)
    ap.add_argument('--vendor',  default='unknown')
    ap.add_argument('--product', default='unknown')
    ap.add_argument('--version', default='unknown')
    args = ap.parse_args()

    results = []
    for p in args.paths:
        print(f"  sweeping {os.path.basename(p)} ...", flush=True)
        results.append(sweep(p, args.threshold))

    rpt = report(results, args.threshold)
    print(rpt)

    ts = datetime.now().strftime('%Y%m%d_%H%M')
    out = (Path(__file__).parent.parent /
           f"reports/sweep_mz_{args.vendor}_{args.product}_{args.version}_{ts}.md")
    out.parent.mkdir(exist_ok=True)
    out.write_text(rpt)
    print(f"\nreport: {out}", file=sys.stderr)


if __name__ == '__main__':
    main()
