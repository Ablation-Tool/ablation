"""
window_analyzer.py: LLM-native bulk disassembly window for stripped ELF RE.

Motivation: per-instruction disassembly calls fragment LLM context across dozens of
round trips. This module dumps a configurable-size window (default 1536 bytes) centered
on any target VA, resolves PLT call targets and .rodata strings inline, and marks
function start heuristics (endbr64, CET stub patterns). One call = one annotated
chunk the LLM can pattern-match in a single pass.

Core workflow:
    wa = WindowAnalyzer.from_path('/path/to/binary')
    lines = wa.dump(va=0x41366, window=1536)
    # lines is a list of annotated instruction strings

    # Or dump to formatted text block:
    text = wa.dump_text(va=0x41366, window=1536)

Annotation format per instruction line:
    0x41366: call 0x3000          ; PLT -> target_func
    0x41371: lea  rdi, [rip+0x...]  ; "==diff==> %s:%d loading cli context fail"
    0x41290: endbr64               ; [FUNC_START]

The module reuses XRefGraph's PLT and string resolution when available.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import capstone

try:
    import lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False

_RIP_RE = re.compile(r'\[rip [+-] (0x[0-9a-f]+)\]')
_ARM32_PC_RE = re.compile(r'\[pc,\s*#(-?(?:0x[0-9a-fA-F]+|\d+))\]')
_ENDBR64 = bytes([0xf3, 0x0f, 0x1e, 0xfa])
_STD_R2_SAVE = 0xF8410018  # std r2, 0x18(r1) in LE storage — ppc64le ELFv2 TOC save
_MAX_TEXT_SCAN_WORDS = 4_000_000  # ~16 MB .text; guard against adversarially large sections


def _elf_arch(data: bytes) -> str:
    """Return arch string from ELF e_machine or XCOFF magic, respecting byte order."""
    if len(data) < 20:
        return 'x86_64'
    if data[:2] == b'\x01\xdf':   # XCOFF32
        return 'ppc32'
    if data[:2] == b'\x01\xf7':   # XCOFF64
        return 'ppc64'
    if data[:4] != b'\x7fELF':
        return 'x86_64'
    ei_data = data[5]  # ELFDATA2LSB=1, ELFDATA2MSB=2
    bo = '>' if ei_data == 2 else '<'
    e_machine = struct.unpack_from(bo + 'H', data, 18)[0]
    if e_machine == 8:     # EM_MIPS
        return 'mips32' if data[4] == 1 else 'mips64'
    if e_machine == 183:   # EM_AARCH64
        return 'arm64'
    if e_machine == 40:    # EM_ARM
        return 'arm32'
    if e_machine == 3:     # EM_386
        return 'x86_32'
    if e_machine == 20:    # EM_PPC
        return 'ppc32'
    if e_machine == 21:    # EM_PPC64
        return 'ppc64le' if ei_data == 1 else 'ppc64'
    return 'x86_64'


def _parse_rip_target(insn_addr: int, insn_size: int, op_str: str) -> Optional[int]:
    m = _RIP_RE.search(op_str)
    if not m:
        return None
    disp = int(m.group(1), 16)
    if '-' in op_str and '[rip -' in op_str:
        disp = -disp
    return insn_addr + insn_size + disp


# ── Pseudo-C register lifter ──────────────────────────────────────────────────

_ARG_REGS_64 = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
_ARG_REGS_32 = ['edi', 'esi', 'edx', 'ecx', 'r8d', 'r9d']
_ALL_REGS_64 = _ARG_REGS_64 + ['rax', 'rbx', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
# Mapping 32-bit sub-registers to their 64-bit canonical names
_REG32_TO_64 = {
    'eax': 'rax', 'ecx': 'rcx', 'edx': 'rdx', 'ebx': 'rbx',
    'esi': 'rsi', 'edi': 'rdi', 'esp': 'rsp', 'ebp': 'rbp',
    'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11',
    'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15',
}
_REG16_TO_64 = {
    'ax': 'rax', 'cx': 'rcx', 'dx': 'rdx', 'bx': 'rbx',
    'si': 'rsi', 'di': 'rdi', 'sp': 'rsp', 'bp': 'rbp',
}
_REG8_TO_64 = {
    'al': 'rax', 'cl': 'rcx', 'dl': 'rdx', 'bl': 'rbx',
    'sil': 'rsi', 'dil': 'rdi', 'r8b': 'r8', 'r9b': 'r9',
}

def _canonical_reg(name: str) -> Optional[str]:
    if name in _ALL_REGS_64:
        return name
    if name in _REG32_TO_64:
        return _REG32_TO_64[name]
    if name in _REG16_TO_64:
        return _REG16_TO_64[name]
    if name in _REG8_TO_64:
        return _REG8_TO_64[name]
    return None


def _lift_to_pseudo_c(annotated_lines: List[str]) -> List[str]:
    """
    Parse annotated WindowAnalyzer dump lines and emit pseudo-C for each CALL.

    Register state is tracked forward; each CALL line emits a call expression
    with resolved argument names.  String annotations ('; "..."') from the dump
    are used as the value for that register.

    Format of input lines (from WindowAnalyzer.dump()):
        0x41366: lea  rdi, [rip+0x...]  ; "cmd_%s"
        0x4136d: call 0x3000            ; PLT -> system
    """
    # reg → display string (e.g. '"cmd_%s"', '0x80', 'local_10', 'argv_1', '?')
    state: Dict[str, str] = {}
    out: List[str] = []
    branch_mnems = {'jmp', 'je', 'jne', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae',
                    'jb', 'jbe', 'jz', 'jnz', 'js', 'jns', 'jo', 'jno', 'jp',
                    'jnp', 'jecxz', 'jrcxz', 'loop', 'loope', 'loopne'}

    for line in annotated_lines:
        line = line.strip()
        if ':' not in line:
            continue

        # Parse: "0xVADDR: mnemonic operands  ; annotation"
        colon_pos = line.index(':')
        try:
            addr = int(line[:colon_pos], 16)
        except ValueError:
            continue
        rest = line[colon_pos + 1:].strip()

        # Split annotation
        annotation = ''
        if ';' in rest:
            semi_pos = rest.index(';')
            annotation = rest[semi_pos + 1:].strip()
            rest = rest[:semi_pos].strip()

        parts = rest.split(None, 1)
        if not parts:
            continue
        mnem = parts[0].lower()
        ops = parts[1].strip() if len(parts) > 1 else ''

        # ── CALL ──────────────────────────────────────────────────────────────
        if mnem in ('call', 'bl', 'blr'):
            # Resolve function name from annotation
            func_name = ops
            if 'PLT ->' in annotation:
                func_name = annotation.split('PLT ->')[1].split('|')[0].strip().rstrip('"').rstrip()
            elif annotation and not annotation.startswith('"'):
                func_name = annotation.split('|')[0].strip()

            # Build arg list from state at this point
            arg_vals = []
            for reg in _ARG_REGS_64:
                val = state.get(reg, '')
                if val and val != '?':
                    arg_vals.append(val)
                else:
                    break  # stop at first unknown arg (conservative)

            args_str = ', '.join(arg_vals) if arg_vals else '...'
            out.append(f'[{addr:#x}] {func_name}({args_str})')

            # After call: rax = return value; caller-saved regs clobbered
            for reg in ['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']:
                state.pop(reg, None)
            state['rax'] = f'retval_{func_name.split("@")[0]}'
            continue

        # ── MOV / MOVZX / MOVSX ───────────────────────────────────────────────
        if mnem in ('mov', 'movq', 'movzx', 'movsx', 'movsxd'):
            dst, _, src = ops.partition(',')
            dst = dst.strip()
            src = src.strip()
            canonical = _canonical_reg(dst)
            if canonical is None:
                continue
            # Determine value
            val = _resolve_val(src, annotation, state)
            state[canonical] = val
            continue

        # ── LEA ───────────────────────────────────────────────────────────────
        if mnem == 'lea':
            dst, _, src = ops.partition(',')
            dst = dst.strip()
            src = src.strip()
            canonical = _canonical_reg(dst)
            if canonical is None:
                continue
            if annotation.startswith('"'):
                # string annotation — use the string
                val = annotation.split('"')[1] if '"' in annotation else annotation
                state[canonical] = f'"{val}"'
            elif 'rbp' in src or 'rsp' in src:
                # stack local
                val = _stack_name(src)
                state[canonical] = val
            elif 'rip' in src:
                state[canonical] = annotation if annotation else src
            else:
                state[canonical] = src
            continue

        # ── PUSH ──────────────────────────────────────────────────────────────
        if mnem == 'push':
            canonical = _canonical_reg(ops.strip())
            if canonical:
                state['__push__'] = state.get(canonical, '?')
            continue

        # ── XOR reg, reg (zeroing idiom) ──────────────────────────────────────
        if mnem == 'xor':
            dst, _, src = ops.partition(',')
            dst = dst.strip(); src = src.strip()
            if dst == src:
                canonical = _canonical_reg(dst)
                if canonical:
                    state[canonical] = '0'
            continue

        # ── Branches invalidate state (conservative) ──────────────────────────
        if mnem in branch_mnems:
            for reg in list(state.keys()):
                state[reg] = '?'
            continue

    return out


def _resolve_val(src: str, annotation: str, state: Dict[str, str]) -> str:
    """Resolve a MOV source operand to a display string."""
    # Immediate
    if src.startswith('0x') or (src.lstrip('-').isdigit() and src.lstrip('-')):
        return src
    # String annotation from a prior LEA/MOV that loaded rip+...
    if annotation.startswith('"'):
        inner = annotation.strip('"').strip()
        return f'"{inner}"'
    # Register
    canonical = _canonical_reg(src)
    if canonical:
        return state.get(canonical, canonical)
    # Stack local
    if '[rbp' in src or '[rsp' in src:
        return _stack_name(src)
    # rip-relative (should have annotation)
    if '[rip' in src:
        return annotation if annotation else src
    return src


def _stack_name(mem_expr: str) -> str:
    """Convert [rbp-0x10] → local_10, [rbp+0x10] → arg_10, etc."""
    mem_expr = mem_expr.strip().lstrip('[').rstrip(']').strip()
    for base in ('rbp', 'rsp', 'ebp', 'esp'):
        if base in mem_expr:
            rest = mem_expr.replace(base, '').strip()
            if not rest:
                return f'{base}_0'
            sign = '-' if rest.startswith('-') else '+'
            offset = rest.lstrip('+-').strip()
            prefix = 'local' if sign == '-' else 'arg'
            return f'{prefix}_{offset.lstrip("0x") or "0"}'
    return mem_expr


# ── Main class ────────────────────────────────────────────────────────────────

class WindowAnalyzer:
    """
    Bulk window disassembler with inline PLT + string annotation.

    Attributes:
        plt     : va -> symbol name for PLT stubs
        strings : va -> string content for .rodata references
    """

    def __init__(self, data: bytes, base_va: int = 0, path: str = ""):
        self.data = data
        self.base_va = base_va
        self.path = path
        self.arch: str = _elf_arch(data)
        self.plt: Dict[int, str] = {}
        self.strings: Dict[int, str] = {}
        self._text_start: int = 0
        self._text_end: int = 0
        self._md: Optional[capstone.Cs] = None
        self._direct_calls: List[Tuple[int, int, str]] = []
        self._sections = []
        if self.arch in ('mips32', 'mips64') and data:
            self._load_mips()
        elif _LIEF_OK and data:
            self._load_lief()

    @classmethod
    def from_path(cls, path: str) -> "WindowAnalyzer":
        data = Path(path).read_bytes()
        inst = cls(data, path=path)
        return inst

    @classmethod
    def from_bflt(cls, ctx) -> "WindowAnalyzer":
        from ablation.analyzers.bflt_context import BfltBinaryContext
        if not isinstance(ctx, BfltBinaryContext):
            raise TypeError("ctx must be a BfltBinaryContext")
        inst = cls(ctx.memory_image, base_va=ctx.base_va, path=ctx.path)
        inst.arch = 'arm32'
        inst._text_start = ctx.base_va + 0x40
        inst._text_end = ctx.base_va + ctx.source_image.data_start
        inst.plt = dict(ctx.plt)
        inst.strings = dict(ctx.strings)
        inst._sections = []
        inst._is_pie = False
        return inst

    def _load_mips(self) -> None:
        from elftools.elf.elffile import ELFFile
        from io import BytesIO

        elf = ELFFile(BytesIO(self.data))
        loads = [segment for segment in elf.iter_segments() if segment.header.p_type == 'PT_LOAD']
        self.base_va = min((segment.header.p_vaddr for segment in loads), default=0)
        self._is_pie = elf.header.e_type == 'ET_DYN'
        self._mips_sections = list(elf.iter_sections())
        text = elf.get_section_by_name('.text')
        if text is not None:
            self._text_start = text.header.sh_addr
            self._text_end = text.header.sh_addr + text.header.sh_size
        for section in self._mips_sections:
            if section.header.sh_type == 'SHT_DYNSYM':
                for symbol in section.iter_symbols():
                    if symbol.name and symbol.entry.st_value:
                        self.plt[symbol.entry.st_value] = symbol.name
        rodata = elf.get_section_by_name('.rodata')
        if rodata is not None:
            contents = rodata.data()
            start = 0
            while start < len(contents):
                end = contents.find(b'\x00', start)
                if end < 0:
                    break
                value = contents[start:end]
                if len(value) >= 4 and all(0x20 <= byte < 0x7f for byte in value):
                    self.strings[rodata.header.sh_addr + start] = value.decode('ascii')
                start = end + 1

    def _load_lief(self) -> None:
        # XCOFF: use xcoff_parser directly (LIEF does not support XCOFF)
        if self.data[:2] in (b'\x01\xdf', b'\x01\xf7'):
            self._load_xcoff()
            return

        try:
            binary = lief.parse(self.data)
        except Exception:
            return
        if not binary:
            return
        if not isinstance(binary, lief.ELF.Binary):
            return

        try:
            from io import BytesIO
            from elftools.elf.elffile import ELFFile
            elf = ELFFile(BytesIO(self.data))
            self._sections = [
                (section['sh_addr'], section['sh_offset'], section['sh_size'])
                for section in elf.iter_sections()
            ]
        except Exception:
            self._sections = []
        self.base_va = binary.imagebase
        # ET_DYN (PIE executable or shared object): file offsets == VAs for the
        # first PT_LOAD, so the fallback in _va_to_offset must use `va` not
        # `va - base_va`.  Track this so _va_to_offset can choose correctly.
        self._is_pie = "DYN" in str(binary.header.file_type)

        # Locate .text bounds
        text_sec = binary.get_section(".text")
        if text_sec:
            self._text_start = text_sec.virtual_address
            self._text_end = text_sec.virtual_address + text_sec.size

        # Build PLT map via .rela.plt -> .plt.sec stubs
        self._build_plt(binary)

        # Build .rodata string map
        self._build_strings(binary)

    def _load_xcoff(self) -> None:
        """Populate text bounds, plt, and strings from an XCOFF binary.

        XCOFF .o files are relocatable: .text lives at vaddr=0 but at a
        non-zero file offset.  Remap self.data to a VA-image so that
        dump_text(va=0, ...) reads real .text bytes rather than the file header.
        """
        try:
            from ablation.core.xcoff_parser import parse as xcoff_parse
            xb = xcoff_parse(self.path or '<mem>', self.data)
        except Exception:
            return

        # Build a VA-mapped image from XCOFF sections.
        # AIX shared library members store vaddr=0 for all sections; the actual
        # load addresses come from the optional header.  When all vaddrs are 0,
        # fall back to sequential physical layout: sections sorted by their file
        # offset (scnptr), placed end-to-end starting at VA 0.
        if xb.sections:
            data_sections = [s for s in xb.sections if s.size > 0 and s.data]
            all_zero_vaddr = all(s.vaddr == 0 for s in data_sections)

            if all_zero_vaddr and data_sections:
                # Assign VAs sequentially by scnptr order (physical file order)
                ordered = sorted(data_sections, key=lambda s: s.offset)
                va = 0
                for sec in ordered:
                    sec.vaddr = va
                    va += sec.size

            max_va = max(s.vaddr + s.size for s in xb.sections if s.size > 0)
            if max_va > 0:
                image = bytearray(max_va)
                for sec in xb.sections:
                    if sec.data and sec.size > 0:
                        image[sec.vaddr: sec.vaddr + len(sec.data)] = sec.data
                self.data = bytes(image)
                self.base_va = 0

        tsec = xb.text
        if tsec:
            self._text_start = tsec.vaddr
            self._text_end   = tsec.vaddr + tsec.size

        # Export VA → name for annotation
        for sym in xb.exports:
            va = sym.code_va if sym.code_va else sym.va
            if sym.name:
                self.plt[va] = sym.name

        # Strings from .data
        dsec = xb.data
        if dsec and dsec.data:
            start = 0
            buf = dsec.data
            while start < len(buf):
                end = buf.find(b'\x00', start)
                if end < 0:
                    break
                chunk = buf[start:end]
                try:
                    s = chunk.decode('ascii')
                except (UnicodeDecodeError, ValueError):
                    start = end + 1
                    continue
                if len(s) >= 4 and s.isprintable():
                    self.strings[dsec.vaddr + start] = s
                start = end + 1

    def _build_plt(self, binary) -> None:
        if self.arch == 'arm32':
            self._build_plt_arm32(binary)
            return
        if self.arch == 'ppc64le':
            self._build_plt_ppc64le_elfv2(binary)
            return
        if self.arch in ('ppc32', 'ppc64'):
            self._build_plt_ppc32_bss(binary)
            return
        # Map: GOT VA -> symbol name from .rela.plt (ELF64) or .rel.plt (ELF32)
        got_to_sym: Dict[int, str] = {}
        try:
            rela_plt = binary.get_section(".rela.plt")
            if rela_plt:
                rela_data = bytes(rela_plt.content)
                for off in range(0, len(rela_data), 24):
                    if off + 24 > len(rela_data):
                        break
                    r_offset, r_info = struct.unpack_from("<QQ", rela_data, off)
                    sym_idx = r_info >> 32
                    try:
                        sym = binary.dynamic_symbols[sym_idx]
                        got_to_sym[r_offset] = sym.name
                    except (IndexError, Exception):
                        pass
        except Exception:
            pass

        # ELF32: .rel.plt uses 8-byte records (no addend): r_offset(4), r_info(4)
        if self.arch == 'x86_32' and not got_to_sym:
            try:
                rel_plt = binary.get_section(".rel.plt")
                if rel_plt:
                    rel_data = bytes(rel_plt.content)
                    for off in range(0, len(rel_data), 8):
                        if off + 8 > len(rel_data):
                            break
                        r_offset, r_info = struct.unpack_from("<II", rel_data, off)
                        sym_idx = r_info >> 8
                        try:
                            sym = binary.dynamic_symbols[sym_idx]
                            got_to_sym[r_offset] = sym.name
                        except (IndexError, Exception):
                            pass
            except Exception:
                pass

        if self.arch == 'arm64':
            self._build_plt_arm64(binary, got_to_sym)
            return

        if self.arch == 'x86_32':
            self._build_plt_x86_32(binary, got_to_sym)
            return

        # Walk .plt.sec: each entry = endbr64 (4) + jmp [rip+disp] (6) or similar
        for sec_name in (".plt.sec", ".plt", ".plt.got"):
            try:
                sec = binary.get_section(sec_name)
            except Exception:
                sec = None
            if not sec:
                continue
            sec_data = bytes(sec.content)
            sec_va = sec.virtual_address
            for off in range(0, len(sec_data), 16):
                stub_va = sec_va + off
                chunk = sec_data[off:off + 16]
                if len(chunk) < 6:
                    break
                # CET stub: f3 0f 1e fa ff 25 xx xx xx xx
                start = 0
                if chunk[:4] == _ENDBR64:
                    start = 4
                if len(chunk) < start + 6:
                    continue
                if chunk[start:start + 2] == b'\xff\x25':  # jmp [rip+disp]
                    disp = struct.unpack_from("<i", chunk, start + 2)[0]
                    got_va = stub_va + start + 6 + disp
                    if got_va in got_to_sym:
                        self.plt[stub_va] = got_to_sym[got_va]
                elif chunk[start:start + 2] == b'\xff\xa3':  # jmp [rbx+disp] unlikely
                    pass

    def _build_plt_arm32(self, binary) -> None:
        names = []
        try:
            rel_plt = binary.get_section('.rel.plt')
            if rel_plt:
                content = bytes(rel_plt.content)
                for off in range(0, len(content) - 7, 8):
                    _, r_info = struct.unpack_from('<II', content, off)
                    try:
                        names.append(binary.dynamic_symbols[r_info >> 8].name)
                    except Exception:
                        names.append('')
        except Exception:
            pass

        if names:
            try:
                plt_sec = binary.get_section('.plt')
            except Exception:
                plt_sec = None
            if plt_sec:
                plt_va = int(plt_sec.virtual_address)
                for index, name in enumerate(names):
                    if name:
                        self.plt[plt_va + 20 + index * 12] = name
                return

        try:
            for relocation in binary.relocations:
                if not relocation.has_symbol:
                    continue
                if 'JUMP_SLOT' in str(relocation.type) and relocation.symbol.name:
                    self.plt[relocation.address] = relocation.symbol.name
        except Exception:
            pass

    def _build_plt_x86_32(self, binary, got_to_sym: Dict[int, str]) -> None:
        # i386 PLT: each stub is 16 bytes, first stub is PLT[0] trampoline (skip it).
        # Stub n: ff 25 <abs_got_va 4 bytes> (JMP [abs_addr]) or push + jmp pattern.
        for sec_name in (".plt",):
            try:
                sec = binary.get_section(sec_name)
            except Exception:
                sec = None
            if not sec:
                continue
            sec_data = bytes(sec.content)
            sec_va = sec.virtual_address
            # PLT[0] is the lazy-bind trampoline (16 bytes); skip it
            for off in range(16, len(sec_data), 16):
                stub_va = sec_va + off
                chunk = sec_data[off:off + 16]
                if len(chunk) < 6:
                    break
                # JMP [abs_addr]: ff 25 xx xx xx xx
                if chunk[:2] == b'\xff\x25':
                    got_va = struct.unpack_from("<I", chunk, 2)[0]
                    if got_va in got_to_sym:
                        self.plt[stub_va] = got_to_sym[got_va]

    def _build_plt_arm64(self, binary, got_to_sym: Dict[int, str]) -> None:
        # ARM64 PLT stub: adrp x16, page / ldr x17, [x16, #off] / br x17 (12 bytes, padded to 16)
        # GOT VA = ADRP page result + LDR immediate offset
        try:
            plt_sec = binary.get_section(".plt")
        except Exception:
            plt_sec = None
        if not plt_sec:
            return

        sec_data = bytes(plt_sec.content)
        sec_va = plt_sec.virtual_address
        # PLT[0] is the lazy-binding trampoline; skip it
        for i in range(1, len(sec_data) // 16):
            off = i * 16
            stub_va = sec_va + off
            if off + 16 > len(sec_data):
                break
            w0, w1, w2, w3 = struct.unpack_from("<IIII", sec_data, off)
            # ARM64 PLT stub: ADRP x16 / LDR x17, [x16, #imm] / ADD x16, x16, #imm / BR x17
            # ADRP x16: (w & 0x9f00001f) == 0x90000010
            if (w0 & 0x9f00001f) != 0x90000010:
                continue
            # LDR x17, [x16, #imm12]: 64-bit unsigned-offset, Rn=x16, Rt=x17
            if (w1 & 0xFFC003FF) != 0xF9400211:
                continue
            # BR x17 is the 4th instruction (w3)
            if w3 != 0xD61F0220:
                continue
            # Decode ADRP imm: sign-extend 21-bit (immhi:immlo) << 12
            immlo = (w0 >> 29) & 0x3
            immhi = (w0 >> 5) & 0x7ffff
            imm21 = (immhi << 2) | immlo
            if imm21 & (1 << 20):
                imm21 -= (1 << 21)
            adrp_page = (stub_va & ~0xfff) + (imm21 << 12)
            # Decode LDR imm12 (scaled by 8 for 64-bit loads)
            ldr_imm12 = (w1 >> 10) & 0xfff
            got_slot_va = adrp_page + ldr_imm12 * 8
            if got_slot_va in got_to_sym:
                self.plt[stub_va] = got_to_sym[got_slot_va]

    def _build_plt_ppc32_bss(self, binary) -> None:
        """BSS PLT for PPC32/PPC64 SYSV ABI.

        Stubs are written at load time by glibc, not stored in the ELF file.
        Recover stub_va → symbol by correlating .rela.plt entry order with BL
        targets in .text that land in the .plt VA range.  Stub size is always
        8 bytes (2 words) for the glibc SYSV PPC32 BSS PLT; resolver_size is
        inferred as (first_observed_consecutive_stub_va - plt_va).  The algorithm
        is correct when stub index 0 is called from .text (the common case in
        firmware with many imports).
        """
        bo = '>' if (len(self.data) > 5 and self.data[5] == 2) else '<'

        # 1. Build index → sym_name from .rela.plt (Elf32_Rela: r_offset, r_info, r_addend)
        index_to_sym: List[str] = []
        try:
            rela_plt = binary.get_section('.rela.plt')
            if rela_plt is None:
                return
            rela_data = bytes(rela_plt.content)
            dyn_syms = list(binary.dynamic_symbols)
            for off in range(0, len(rela_data), 12):
                if off + 12 > len(rela_data):
                    break
                _, r_info, _ = struct.unpack_from(bo + 'III', rela_data, off)
                sym_idx = r_info >> 8
                try:
                    sym = dyn_syms[sym_idx] if sym_idx < len(dyn_syms) else None
                    index_to_sym.append(sym.name if sym and sym.name else '')
                except Exception:
                    index_to_sym.append('')
        except Exception:
            return
        if not index_to_sym:
            return

        # 2. Get .plt section VA (BSS — no file content)
        try:
            plt_sec = binary.get_section('.plt')
        except Exception:
            return
        if plt_sec is None:
            return
        plt_va = plt_sec.virtual_address
        stub_size = 8
        plt_est_end = plt_va + 512 + len(index_to_sym) * stub_size

        # 3. Scan .text for BL targets in [plt_va, plt_est_end)
        try:
            text_sec = binary.get_section('.text')
        except Exception:
            return
        if text_sec is None:
            return
        text_data = bytes(text_sec.content)
        if not text_data:
            return
        text_va = text_sec.virtual_address
        bl_targets: set = set()
        for i in range(0, len(text_data) - 3, 4):
            w = struct.unpack_from(bo + 'I', text_data, i)[0]
            if (w & 0xFC000003) != 0x48000001:  # BL (opcode 18, AA=0, LK=1)
                continue
            li = (w >> 2) & 0xFFFFFF
            if li >= 0x800000:
                li -= 0x1000000
            target_va = text_va + i + li * 4
            if plt_va <= target_va < plt_est_end:
                bl_targets.add(target_va)
        if not bl_targets:
            return

        # 4. Find first stub VA: smallest BL target T where T+stub_size is also observed.
        #    That T is stub index 0 (assuming it is called from .text).
        sorted_t = sorted(bl_targets)
        target_set = set(sorted_t)
        first_stub_va = None
        for t in sorted_t:
            if (t + stub_size) in target_set:
                first_stub_va = t
                break
        if first_stub_va is None:
            return  # no consecutive stub pair observed; cannot determine index 0

        # 5. Map each rela.plt index to its stub VA
        resolver_size = first_stub_va - plt_va
        for idx, sym_name in enumerate(index_to_sym):
            if sym_name:
                self.plt[plt_va + resolver_size + idx * stub_size] = sym_name

    def _build_plt_ppc64le_elfv2(self, binary) -> None:
        """PLT stub resolver for ppc64le ELFv2 (OpenPOWER Linux, POWER8+).

        ELFv2 places PLT stubs in .text, not in .plt (which is NOBITS at runtime).
        Each stub is four instructions:
            std  r2, 0x18(r1)   ; save TOC
            ld   r12, OFF(r2)   ; load function pointer from GOT via TOC offset
            mtctr r12           ; move to CTR
            bctr                ; branch

        TOC_BASE = .got_va + 0x8000 (ppc64le ELFv2 ABI convention).
        Stubs are identified by the ld r12, OFF(r2) pattern; the stub VA is
        the preceding std r2 instruction (which callers branch to).
        """
        got_to_sym: Dict[int, str] = {}
        try:
            for rel in binary.relocations:
                if rel.symbol and rel.symbol.name:
                    got_to_sym[rel.address] = rel.symbol.name.split('@')[0]
        except Exception:
            return
        if not got_to_sym:
            return

        got_sec = binary.get_section('.got')
        if got_sec is None:
            return
        toc_base = got_sec.virtual_address + 0x8000

        text_sec = binary.get_section('.text')
        if text_sec is None:
            return
        text_data = bytes(text_sec.content)
        if not text_data:
            return
        text_va = text_sec.virtual_address
        n = len(text_data) // 4

        n = min(n, _MAX_TEXT_SCAN_WORDS)

        for i in range(1, n):
            word = struct.unpack_from('<I', text_data, i * 4)[0]
            # ld r12, OFF(r2): opcode 58 (0x3A), RS=12, RA=2, DS-form, XO=0
            if (word >> 26) != 58:
                continue
            if ((word >> 21) & 0x1F) != 12:
                continue
            if ((word >> 16) & 0x1F) != 2:
                continue
            if (word & 0x3) != 0:
                continue
            # Verify preceding instruction is std r2, 0x18(r1)
            prev = struct.unpack_from('<I', text_data, (i - 1) * 4)[0]
            if prev != _STD_R2_SAVE:
                continue
            # Compute GOT VA from TOC-relative signed displacement
            ds_raw = (word >> 2) & 0x3FFF
            if ds_raw & 0x2000:
                ds_raw -= 0x4000
            disp = ds_raw * 4
            got_va = toc_base + disp
            sym = got_to_sym.get(got_va)
            if sym:
                stub_va = text_va + (i - 1) * 4
                self.plt[stub_va] = sym

    def _build_strings(self, binary) -> None:
        for sec_name in (".rodata", ".data.rel.ro", ".data"):
            try:
                sec = binary.get_section(sec_name)
            except Exception:
                sec = None
            if not sec:
                continue
            sec_data = bytes(sec.content)
            sec_va = sec.virtual_address
            i = 0
            while i < len(sec_data):
                start = i
                while i < len(sec_data) and 0x20 <= sec_data[i] < 0x7f:
                    i += 1
                if i - start >= 4:
                    s = sec_data[start:i].decode("ascii", errors="replace")
                    self.strings[sec_va + start] = s
                else:
                    i = start + 1

    def _cs(self) -> capstone.Cs:
        if self._md is None:
            if self.arch == 'arm32':
                self._md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            elif self.arch == 'arm64':
                self._md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            elif self.arch == 'x86_32':
                self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif self.arch in ('mips32', 'mips64'):
                mode = capstone.CS_MODE_MIPS32 if self.arch == 'mips32' else capstone.CS_MODE_MIPS64
                endian = capstone.CS_MODE_BIG_ENDIAN if self.data[5] == 2 else capstone.CS_MODE_LITTLE_ENDIAN
                self._md = capstone.Cs(capstone.CS_ARCH_MIPS, mode | endian)
            elif self.arch == 'ppc64le':
                self._md = capstone.Cs(capstone.CS_ARCH_PPC,
                                       capstone.CS_MODE_64 | capstone.CS_MODE_LITTLE_ENDIAN)
            elif self.arch in ('ppc32', 'ppc64'):
                ppc_mode = capstone.CS_MODE_32 if self.arch == 'ppc32' else capstone.CS_MODE_64
                self._md = capstone.Cs(capstone.CS_ARCH_PPC, ppc_mode | capstone.CS_MODE_BIG_ENDIAN)
            else:
                self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self._md.detail = False
            if self.arch == 'arm32':
                self._md.skipdata = True
        return self._md

    def _va_to_offset(self, va: int) -> int:
        if self.arch in ('mips32', 'mips64'):
            for section in getattr(self, '_mips_sections', []):
                start = section.header.sh_addr
                if start <= va < start + section.header.sh_size:
                    return section.header.sh_offset + va - start
            return va if getattr(self, '_is_pie', False) else va - self.base_va
        if not _LIEF_OK or not self.base_va:
            return va
        for s_va, s_off, s_sz in self._sections:
            if s_va <= va < s_va + s_sz:
                return s_off + (va - s_va)
        # PIE (ET_DYN): file offsets equal VAs in the first PT_LOAD segment, so
        # the correct fallback when no section matches is `va`, not `va - base_va`.
        # Non-PIE executables (ET_EXEC) with a fixed load address (e.g. 0x400000)
        # need `va - base_va` to convert back to a file offset.
        if getattr(self, '_is_pie', False):
            return va
        return va - self.base_va

    def _read_u32_le(self, va: int) -> Optional[int]:
        offset = self._va_to_offset(va)
        if offset < 0 or offset + 4 > len(self.data):
            return None
        return struct.unpack_from('<I', self.data, offset)[0]

    def dump(
        self,
        va: int,
        window: int = 1536,
        align_back: int = 0,
    ) -> List[str]:
        """
        Disassemble starting from `va` (or a prologue before it) and return
        annotated instruction strings.

        Args:
            va        : center/start VA to disassemble from
            window    : bytes to disassemble (default 1536 = 1.5KB)
            align_back: bytes before va to include.  When > 0, automatically
                        searches backward for an ENDBR64 / push-rbp prologue
                        marker within `align_back` bytes and starts there,
                        eliminating misaligned decode from raw-offset subtraction.
                        Pass align_back=0 to disable alignment and start exactly at va.

        The prologue search is arch-gated: x86_64 only (ENDBR64 → push rbp fallback).
        Other architectures fall back to the plain va − align_back offset.
        """
        if align_back > 0:
            # Auto-align: find the nearest function prologue instead of raw subtraction.
            # This is the "FunctionBoundaryAligner" fix wired into the CALL scan path.
            start_va = self.align_to_func_start(va, search_back=align_back)
            # Extend window so it always covers va (prologue may be further back than align_back).
            window = max(window, va - start_va + 64)
        else:
            start_va = va
        offset = self._va_to_offset(start_va)
        chunk = self.data[offset:offset + window]
        if not chunk:
            return [f"; no data at va=0x{start_va:x} offset=0x{offset:x}"]

        lines: List[str] = []
        self._direct_calls = []
        md = self._cs()
        for insn in md.disasm(chunk, start_va):
            mnemonic = insn.mnemonic
            op_str = insn.op_str
            addr = insn.address
            line = f"0x{addr:x}: {mnemonic:<8} {op_str}"
            annotations: List[str] = []

            # Mark function starts (x86_64: endbr64 probe; arm32/arm64: push/stp prologue)
            if self.arch == 'x86_64' and bytes(insn.bytes[:4]) == _ENDBR64:
                annotations.append("[FUNC_START]")
            elif self.arch in ('arm32', 'arm64') and mnemonic in ('push', 'stp', 'stmdb', 'stmfd'):
                if 'lr' in op_str.lower() or 'x29' in op_str.lower():
                    annotations.append("[FUNC_START?]")

            if self.arch == 'x86_64':
                call_mnems = {'call'}
            elif self.arch == 'ppc64le':
                call_mnems = {'bl', 'bctrl'}
            elif self.arch in ('mips32', 'mips64'):
                call_mnems = {'jal', 'jalr'}
            else:
                call_mnems = {'bl', 'blx', 'blr'}
            if mnemonic.lower().split('.')[0] in call_mnems:
                try:
                    target_text = op_str.strip().split(',')[0].strip().lstrip('#')
                    target = int(target_text, 0)
                except ValueError:
                    target = None
                if target is not None:
                    self._direct_calls.append((addr, target, self.plt.get(target, '')))
                    if target in self.plt:
                        annotations.append(f"PLT -> {self.plt[target]}")
                    elif target in self.strings:
                        annotations.append(f"-> {self.strings[target]!r}")

            if self.arch == 'x86_64' and mnemonic in ("lea", "mov") and "[rip" in op_str:
                rip_target = _parse_rip_target(addr, insn.size, op_str)
                if rip_target is not None and rip_target in self.strings:
                    s = self.strings[rip_target]
                    snippet = s[:64] + "..." if len(s) > 64 else s
                    annotations.append(f'"{snippet}"')
            elif self.arch == 'arm32' and mnemonic == 'ldr':
                match = _ARM32_PC_RE.search(op_str)
                if match:
                    literal = addr + 8 + int(match.group(1), 0)
                    pointer = self._read_u32_le(literal)
                    if pointer in self.strings:
                        s = self.strings[pointer]
                        snippet = s[:64] + "..." if len(s) > 64 else s
                        annotations.append(f'"{snippet}"')

            if annotations:
                line += "  ; " + " | ".join(annotations)
            lines.append(line)

        return lines

    def dump_text(
        self,
        va: int,
        window: int = 1536,
        align_back: int = 0,
        header: bool = True,
    ) -> str:
        """Return dump as a single formatted string block."""
        lines = self.dump(va, window=window, align_back=align_back)
        if header:
            tag = f"window: {window}B @ 0x{va:x} (back={align_back})"
            sep = "-" * len(tag)
            return "\n".join([sep, tag, sep] + lines)
        return "\n".join(lines)

    def find_func_starts(self, va: int, window: int = 1536, align_back: int = 0) -> List[int]:
        """Return VAs of function start candidates in the window."""
        starts = []
        for line in self.dump(va, window=window, align_back=align_back):
            if "[FUNC_START" in line:
                try:
                    addr_str = line.split(":")[0]
                    starts.append(int(addr_str, 16))
                except ValueError:
                    pass
        return starts

    def calls_in_window(self, va: int, window: int = 1536, align_back: int = 0) -> List[Tuple[int, int, str]]:
        """Return direct call sites, targets, and known PLT labels."""
        self._direct_calls = []
        self.dump(va, window=window, align_back=align_back)
        return list(self._direct_calls)

    def align_to_func_start(self, call_site_va: int, search_back: int = 512) -> int:
        """
        Search backward from `call_site_va` for a function prologue marker and
        return its VA. Resolves the garbled-disassembly problem: backward scanning
        from an arbitrary offset produces misaligned instruction decode.

        Prologue search order (x86_64):
          1. ENDBR64 (f3 0f 1e fa) — CET control-flow integrity marker, always aligned
          2. push rbp (55) — classic frame pointer prologue

        Returns `call_site_va - search_back` as a last-resort fallback (no alignment,
        same as plain dump) so callers always get a valid start VA.
        """
        if self.arch in ('arm32', 'arm64'):
            return call_site_va - search_back
        try:
            with open(self.path, 'rb') as f:
                raw = f.read()
        except OSError:
            return call_site_va - search_back

        va_base = self._load_va()
        call_off = call_site_va - va_base
        search_start = max(0, call_off - search_back)
        window = raw[search_start:call_off]

        # Prefer ENDBR64 (guaranteed aligned on compilers that emit CET)
        _ENDBR64 = b'\xf3\x0f\x1e\xfa'
        pos = window.rfind(_ENDBR64)
        if pos >= 0:
            return va_base + search_start + pos

        # Fallback: rightmost `push rbp` (0x55) in the search window
        pos = window.rfind(b'\x55')
        if pos >= 0:
            return va_base + search_start + pos

        return call_site_va - search_back

    def dump_caller_context(
        self,
        call_site_va: int,
        search_back: int = 512,
        max_insns: int = 30,
    ) -> List[str]:
        """
        Convenience wrapper: disassemble the function containing `call_site_va`
        and return the last `max_insns` instructions.

        Delegates to dump(align_back=search_back) which now auto-aligns to the
        nearest function prologue (ENDBR64 / push rbp) in the search window.
        """
        lines = self.dump(call_site_va, window=search_back, align_back=search_back)
        return lines[-max_insns:] if len(lines) > max_insns else lines

    def dump_pseudo_c(
        self,
        va: int,
        window: int = 1536,
        align_back: int = 0,
    ) -> List[str]:
        """
        Produce simplified pseudo-C lines for each CALL instruction in the window.

        Tracks register state (rdi/rsi/rdx/rcx/r8/r9 + rax) forward through
        the annotated dump, then emits one pseudo-C line per CALL showing the
        resolved argument values.

        Single-basic-block only: no cross-BB tracking. Register state is
        carried linearly; any branch resets uncertain registers to '?'.

        Example output (from raw ASM):
            [0x41366] system("cmd_%s %s")   // ARG_REGS: rdi="cmd_%s %s"
            [0x413d2] snprintf(buf, 0x80, "%d: %s", local_10, arg_0)

        Returns a list of pseudo-C strings, one per annotated CALL.
        """
        raw_lines = self.dump(va, window=window, align_back=align_back)
        return _lift_to_pseudo_c(raw_lines)

    def dump_pseudo_c_text(
        self,
        va: int,
        window: int = 1536,
        align_back: int = 0,
    ) -> str:
        """Return dump_pseudo_c() as a single newline-joined string."""
        lines = self.dump_pseudo_c(va, window=window, align_back=align_back)
        return '\n'.join(lines) if lines else '(no calls in window)'

    def _load_va(self) -> int:
        """Return the load VA (first PT_LOAD p_vaddr) for file-offset arithmetic."""
        try:
            import lief as _lief
            binary = _lief.parse(self.path)
            if binary is None:
                return 0
            for seg in binary.segments:
                if str(getattr(seg, 'type', '')).endswith('LOAD') and seg.virtual_address:
                    return seg.virtual_address - seg.file_offset
        except Exception:
            pass
        return 0
