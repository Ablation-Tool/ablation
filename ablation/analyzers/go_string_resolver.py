"""
go_string_resolver.py -- Go 1.17+ AMD64 string resolution for Ablation

Go strings in .rodata are NOT NUL-terminated. Each string is a (data_ptr, length)
pair in Go's calling convention. The Go AMD64 register ABI (1.17+) passes:
  rax = data pointer (first argument to any string-consuming function)
  rbx = string length (second argument)

Call-site pattern:
  lea rax, [rip + disp]   ; rax = &string_data[0] in .rodata
  mov ebx, N              ; rbx = exact byte count
  call <string consumer>  ; os/exec.Command, fmt.Println, etc.

The `lea` and `mov ebx` may be separated by up to 3 non-clobbering instructions
(e.g., setting up other arguments). This module detects the pattern and reads the
correct bytes, eliminating false NUL-scan truncation.

Usage:
    from modules.go_string_resolver import GoStringResolver

    # From ELF parser segments (list of dicts with p_vaddr, p_offset, p_filesz)
    resolver = GoStringResolver(binary_data, elf_parser.phdrs)

    # Scan a disassembled function (list of capstone instructions)
    strings = resolver.scan_instructions(instrs)
    # -> {string_va: (text, length), ...}

    # Or scan a single call site you already found
    s, length = resolver.read_at(string_va, known_length)
"""

import struct
from typing import Optional

try:
    import capstone
    import capstone.x86 as x86
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

# x86_64 register IDs for rax/eax and rbx/ebx (capstone constants)
_RAX_REGS = None
_RBX_REGS = None

def _init_reg_sets():
    global _RAX_REGS, _RBX_REGS
    if not HAVE_CAPSTONE or _RAX_REGS is not None:
        return
    _RAX_REGS = frozenset([
        x86.X86_REG_RAX, x86.X86_REG_EAX, x86.X86_REG_AX, x86.X86_REG_AL,
    ])
    _RBX_REGS = frozenset([
        x86.X86_REG_RBX, x86.X86_REG_EBX, x86.X86_REG_BX, x86.X86_REG_BL,
    ])


class GoStringResolver:
    """
    Resolves Go 1.17+ AMD64 string literals from .rodata using the
    lea rax / mov ebx length-hint pattern.

    Accepts a binary blob plus a list of PT_LOAD segment dicts. Each dict
    must have at minimum: p_vaddr, p_offset, p_filesz. p_type is optional
    (defaults to PT_LOAD). Segments where p_vaddr == 0 and p_offset == 0
    are skipped automatically (ELF header pseudo-segment).
    """

    PT_LOAD = 1

    def __init__(self, binary_data: bytes, segments: list,
                 fallback_max_len: int = 256, window: int = 4):
        """
        binary_data: full binary file bytes
        segments: list of segment dicts (p_vaddr, p_offset, p_filesz [, p_type])
        fallback_max_len: max bytes to return when no length hint is available
                          (NUL-scan fallback cap)
        window: how many instructions after a `lea rax` to look for `mov ebx`
        """
        self.data = binary_data
        self.fallback_max_len = fallback_max_len
        self.window = window

        # Keep only PT_LOAD segments with non-zero file content, skip ELF header seg
        self._load_segs = []
        for seg in segments:
            p_type = seg.get('p_type', self.PT_LOAD)
            if p_type != self.PT_LOAD:
                continue
            p_filesz = seg.get('p_filesz', 0)
            p_vaddr = seg.get('p_vaddr', 0)
            p_offset = seg.get('p_offset', 0)
            if p_filesz == 0:
                continue
            if p_vaddr == 0 and p_offset == 0:
                continue
            self._load_segs.append({
                'p_vaddr': p_vaddr,
                'p_offset': p_offset,
                'p_filesz': p_filesz,
            })

        if HAVE_CAPSTONE:
            _init_reg_sets()

    # ------------------------------------------------------------------
    # VA -> file offset translation
    # ------------------------------------------------------------------

    def vaddr_to_file_offset(self, va: int) -> Optional[int]:
        """Translate a virtual address to a file byte offset via PT_LOAD segments."""
        for seg in self._load_segs:
            seg_start = seg['p_vaddr']
            seg_end = seg_start + seg['p_filesz']
            if seg_start <= va < seg_end:
                return va - seg_start + seg['p_offset']
        return None

    # ------------------------------------------------------------------
    # String reading
    # ------------------------------------------------------------------

    def read_at(self, va: int, length: int) -> tuple:
        """
        Read exactly `length` bytes at VA, return (text, length).
        Returns (None, 0) on failure (unmapped VA, out-of-bounds, decode error).
        """
        if length < 0:
            return (None, 0)
        if length == 0:
            return ('', 0)
        foff = self.vaddr_to_file_offset(va)
        if foff is None:
            return (None, 0)
        end = foff + length
        if end > len(self.data):
            return (None, 0)
        try:
            text = self.data[foff:end].decode('utf-8', errors='replace')
            return (text, length)
        except Exception:
            return (None, 0)

    def read_nul_terminated(self, va: int, max_len: Optional[int] = None) -> tuple:
        """
        Fallback: read a NUL-terminated string at VA (up to max_len bytes).
        Returns (text, length) or (None, 0).
        """
        cap = max_len if max_len is not None else self.fallback_max_len
        foff = self.vaddr_to_file_offset(va)
        if foff is None:
            return (None, 0)
        end = min(foff + cap, len(self.data))
        chunk = self.data[foff:end]
        nul = chunk.find(b'\x00')
        if nul < 0:
            return (None, 0)
        try:
            text = chunk[:nul].decode('utf-8', errors='replace')
            return (text, nul)
        except Exception:
            return (None, 0)

    # ------------------------------------------------------------------
    # Instruction-stream scanner
    # ------------------------------------------------------------------

    def scan_instructions(self, instructions: list) -> dict:
        """
        Scan a capstone instruction list for Go string load patterns.

        Detects:
          lea rax, [rip + disp]      ; string pointer
          (up to self.window non-clobbering instructions)
          mov ebx/rbx, N             ; exact byte length

        Also handles:
          xor ebx, ebx / xor rbx, rbx  -> length 0, emit empty string
          mov rbx, N (64-bit imm)       -> same treatment as mov ebx, N
          Any lea rax or mov rax,...    -> invalidates previous pending lea

        Returns dict: {string_va: (text, length)}
        Results with text=None are excluded (VA resolution failed).
        """
        if not HAVE_CAPSTONE:
            return {}

        results = {}
        pending = None  # (string_va, insn_index) -- set when lea rax found

        for idx, insn in enumerate(instructions):
            mnem = insn.mnemonic

            # Check if this instruction invalidates the pending lea
            if pending is not None:
                age = idx - pending[1]
                if age > self.window:
                    # Window expired without finding a length hint; try NUL fallback
                    text, length = self.read_nul_terminated(pending[0])
                    if text is not None:
                        results[pending[0]] = (text, length)
                    pending = None

            # --- LEA RAX, [RIP + disp] ---
            if mnem == 'lea' and HAVE_CAPSTONE and hasattr(insn, 'operands'):
                ops = insn.operands
                if len(ops) == 2:
                    dst, src = ops[0], ops[1]
                    if (dst.type == x86.X86_OP_REG and
                            dst.reg in _RAX_REGS and
                            src.type == x86.X86_OP_MEM and
                            src.mem.base == x86.X86_REG_RIP and
                            src.mem.index == x86.X86_REG_INVALID):
                        string_va = insn.address + insn.size + src.mem.disp
                        pending = (string_va, idx)
                        continue

            # --- MOV RAX/EAX, anything -> clobbers rax, invalidate pending ---
            if pending is not None and mnem in ('mov', 'movabs', 'movq', 'movl', 'xor', 'lea'):
                if hasattr(insn, 'operands') and insn.operands:
                    dst_op = insn.operands[0]
                    if dst_op.type == x86.X86_OP_REG and dst_op.reg in _RAX_REGS:
                        if mnem != 'lea' or insn.operands[0].reg not in _RAX_REGS:
                            text, length = self.read_nul_terminated(pending[0])
                            if text is not None:
                                results[pending[0]] = (text, length)
                            pending = None

            # --- XOR EBX, EBX / XOR RBX, RBX -> length 0 ---
            if pending is not None and mnem == 'xor':
                if hasattr(insn, 'operands') and len(insn.operands) == 2:
                    d, s = insn.operands[0], insn.operands[1]
                    if (d.type == x86.X86_OP_REG and d.reg in _RBX_REGS and
                            s.type == x86.X86_OP_REG and s.reg in _RBX_REGS):
                        results[pending[0]] = ('', 0)
                        pending = None
                        continue

            # --- MOV EBX/RBX, imm -> length hint ---
            if pending is not None and mnem in ('mov', 'movabs'):
                if hasattr(insn, 'operands') and len(insn.operands) == 2:
                    dst_op, src_op = insn.operands[0], insn.operands[1]
                    if (dst_op.type == x86.X86_OP_REG and
                            dst_op.reg in _RBX_REGS and
                            src_op.type == x86.X86_OP_IMM):
                        length = src_op.imm
                        if 0 < length <= self.fallback_max_len * 4:
                            text, actual_len = self.read_at(pending[0], length)
                            if text is not None:
                                results[pending[0]] = (text, actual_len)
                        elif length == 0:
                            results[pending[0]] = ('', 0)
                        pending = None
                        continue

        # Flush any remaining pending lea at end of instruction stream
        if pending is not None:
            text, length = self.read_nul_terminated(pending[0])
            if text is not None:
                results[pending[0]] = (text, length)

        return results

    # ------------------------------------------------------------------
    # Convenience: disassemble a function and scan it
    # ------------------------------------------------------------------

    def scan_function(self, func_va: int, func_file_offset: int,
                       func_size: int = 0x2000) -> dict:
        """
        Disassemble func_size bytes starting at func_file_offset (mapped at func_va)
        and scan for Go string loads. Returns {string_va: (text, length)}.
        Requires capstone.
        """
        if not HAVE_CAPSTONE:
            return {}
        code = self.data[func_file_offset: func_file_offset + func_size]
        if not code:
            return {}
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True
        instrs = list(cs.disasm(code, func_va))
        return self.scan_instructions(instrs)

    # ------------------------------------------------------------------
    # Bulk scan: scan multiple functions and merge results
    # ------------------------------------------------------------------

    def scan_functions(self, funcs: list, va_to_fileoff_fn=None) -> dict:
        """
        Scan a list of function dicts.
        Each dict needs: 'va', 'fileoff' (or 'file_offset'), 'size' (optional).
        va_to_fileoff_fn: optional callable(va) -> fileoff (overrides dict lookup).

        Returns merged {string_va: (text, length)} across all functions.
        """
        results = {}
        for fn in funcs:
            va = fn.get('va', 0)
            if not va:
                continue
            if va_to_fileoff_fn:
                foff = va_to_fileoff_fn(va)
            else:
                foff = fn.get('fileoff') or fn.get('file_offset')
            if foff is None:
                foff = self.vaddr_to_file_offset(va)
            if foff is None:
                continue
            size = fn.get('size', 0x2000)
            found = self.scan_function(va, foff, size)
            results.update(found)
        return results

    # ------------------------------------------------------------------
    # Standalone helper: resolve a single call site
    # ------------------------------------------------------------------

    def resolve_call_site(self, instructions: list, call_index: int,
                           lookback: int = 8) -> Optional[tuple]:
        """
        Given a list of instructions and the index of a call instruction,
        look backwards up to `lookback` instructions for the lea rax / mov ebx
        pair and return (string_va, text, length) or None.

        Useful for resolving arguments to a specific os/exec.Command call site
        without scanning an entire function.
        """
        start = max(0, call_index - lookback)
        window_insns = instructions[start:call_index]

        # Find the last lea rax, [rip+X] before the call
        lea_idx = None
        string_va = None
        for i in range(len(window_insns) - 1, -1, -1):
            insn = window_insns[i]
            if insn.mnemonic == 'lea' and hasattr(insn, 'operands') and len(insn.operands) == 2:
                dst, src = insn.operands[0], insn.operands[1]
                if (dst.type == x86.X86_OP_REG and dst.reg in _RAX_REGS and
                        src.type == x86.X86_OP_MEM and
                        src.mem.base == x86.X86_REG_RIP and
                        src.mem.index == x86.X86_REG_INVALID):
                    string_va = insn.address + insn.size + src.mem.disp
                    lea_idx = i
                    break

        if string_va is None:
            return None

        # Find mov ebx, N after the lea (within the window)
        for insn in window_insns[lea_idx + 1:]:
            if insn.mnemonic in ('mov', 'movabs') and hasattr(insn, 'operands') and len(insn.operands) == 2:
                dst_op, src_op = insn.operands[0], insn.operands[1]
                if (dst_op.type == x86.X86_OP_REG and dst_op.reg in _RBX_REGS and
                        src_op.type == x86.X86_OP_IMM):
                    length = src_op.imm
                    text, actual_len = self.read_at(string_va, length)
                    if text is not None:
                        return (string_va, text, actual_len)
            if insn.mnemonic == 'xor' and hasattr(insn, 'operands') and len(insn.operands) == 2:
                d, s = insn.operands[0], insn.operands[1]
                if (d.type == x86.X86_OP_REG and d.reg in _RBX_REGS and
                        s.type == x86.X86_OP_REG and s.reg == d.reg):
                    return (string_va, '', 0)

        # No length hint found; try NUL fallback
        text, length = self.read_nul_terminated(string_va)
        if text is not None:
            return (string_va, text, length)
        return None


# ------------------------------------------------------------------
# Module-level helpers for quick use without instantiation
# ------------------------------------------------------------------

def build_resolver_from_elf(binary_data: bytes, elf_parser) -> 'GoStringResolver':
    """
    Build a GoStringResolver from an existing ELFParser instance.
    Reads phdrs from elf_parser.phdrs (list of dicts from core/elf_parser.py).
    """
    segments = []
    for phdr in elf_parser.phdrs:
        segments.append({
            'p_type':   phdr.get('p_type', 1),
            'p_vaddr':  phdr.get('p_vaddr', 0),
            'p_offset': phdr.get('p_offset', 0),
            'p_filesz': phdr.get('p_filesz', 0),
        })
    return GoStringResolver(binary_data, segments)


def resolve_go_strings_in_function(binary_data: bytes, segments: list,
                                    func_va: int, func_fileoff: int,
                                    func_size: int = 0x2000) -> dict:
    """
    One-shot: build resolver, disassemble a function, return string dict.
    segments: list of dicts with p_vaddr, p_offset, p_filesz.
    Returns {string_va: (text, length)}.
    """
    resolver = GoStringResolver(binary_data, segments)
    return resolver.scan_function(func_va, func_fileoff, func_size)


def resolve_go_strings_from_instructions(binary_data: bytes, segments: list,
                                          instructions: list,
                                          window: int = 4) -> dict:
    """
    One-shot: given a pre-disassembled instruction list (capstone),
    resolve all Go string loads.
    Returns {string_va: (text, length)}.
    """
    resolver = GoStringResolver(binary_data, segments, window=window)
    return resolver.scan_instructions(instructions)


# ------------------------------------------------------------------
# Self-test: validate on a synthetic instruction stream
# ------------------------------------------------------------------

def _selftest():
    """Quick smoke test -- no binary needed, tests pattern detection logic."""
    if not HAVE_CAPSTONE:
        print("[!] capstone not installed -- skipping selftest")
        return

    import capstone

    # Build a tiny synthetic function:
    #   lea rax, [rip + 0x10]   ; 7 bytes: 48 8d 05 10 00 00 00
    #   mov ebx, 5              ; 5 bytes: bb 05 00 00 00
    #   ret                     ; 1 byte:  c3
    # Immediately after ret (at offset 13), embed "hello" (5 bytes)
    code = (
        b'\x48\x8d\x05\x06\x00\x00\x00'  # lea rax, [rip+6]  ; at addr 0, size 7, next=7, target=7+6=13
        b'\xbb\x05\x00\x00\x00'           # mov ebx, 5        ; at addr 7, size 5
        b'\xc3'                            # ret               ; at addr 12
        b'hello'                           # string at file offset 13
    )
    # Synthetic segment: va=0x1000, offset=0x1000, filesz=len(code)
    # so va 0x100d = file offset 0x100d
    base_va = 0x1000
    segments = [{'p_vaddr': base_va, 'p_offset': base_va, 'p_filesz': len(code)}]

    # The binary data needs the string at the resolved file offset
    # lea rax, [rip+6]: rip = 0x1000+7 = 0x1007, target VA = 0x1007+6 = 0x100d
    # file offset for 0x100d = 0x100d - 0x1000 + 0x1000 = 0x100d
    # We need code at file offset 0x100d == index 13 = "hello" -- correct
    binary_data = b'\x00' * base_va + code  # pad so file offsets match VAs

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True
    instrs = list(cs.disasm(code, base_va))

    resolver = GoStringResolver(binary_data, segments)
    results = resolver.scan_instructions(instrs)

    target_va = 0x100d
    if target_va in results:
        text, length = results[target_va]
        assert text == 'hello', f"expected 'hello', got {text!r}"
        assert length == 5, f"expected 5, got {length}"
        print(f"[+] selftest PASS: VA 0x{target_va:x} -> {text!r} (len {length})")
    else:
        print(f"[!] selftest FAIL: VA 0x{target_va:x} not found in results: {results}")


if __name__ == '__main__':
    _selftest()
