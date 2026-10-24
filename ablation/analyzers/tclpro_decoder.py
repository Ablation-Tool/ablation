"""
tclpro_decoder.py: TclPro ByteCode 1.x disassembler and string extractor.

Why this exists (gap IDs: TCLPRO-GAP-001, TCLPRO-GAP-002):

  1. TCLPRO-GAP-001 — Installer and appliance logic locked in bytecodes.
     BitRock installers, network appliance management interfaces (Cisco,
     Juniper, Huawei), and some IoT firmware distribute Tcl logic as TclPro
     1.x compiled bytecodes.  Ablation had no way to recover the plaintext
     Tcl commands, variable names, or control flow — making it impossible to
     audit what these runtimes do (install hooks, network callbacks, shell
     exec sinks).

  2. TCLPRO-GAP-002 — tbcload.so reverse-engineered encoding not captured.
     During IDA Pro 9.4 SP1 crack analysis, tbcload.so was disassembled to
     confirm the char-0x21 encoding and the TclPro ByteCode 1.3 header
     format.  This module captures those findings as a reusable tool so
     future targets with TclPro bytecodes don't require re-RE of tbcload.

TclPro ByteCode 1.x format (confirmed from tbcload.so rodata + disassembly):

  Header line (ASCII):
    TclPro ByteCode <fmt_ver> <byte_order> <tcl_maj>.<tcl_min> <bc_maj>.<bc_min>\\n
    e.g.: "TclPro ByteCode 1 0 1.3 8.3\\n"
          fmt_ver=1, byte_order=0, tcl_maj=1, tcl_min=3, bc_maj=8, bc_min=3

  Parameter line (space-separated ints):
    <nprocs> <ncmds> <nbytes> <nsrcbytes> <nfwdrefs> <...>\\n
    nbytes = number of encoded body characters

  Body (nbytes printable chars):
    Encoding: decoded_byte = char - 0x21 (33)
    Escape: if char == '~' (0x7E): next_char decoded_byte = next_char - 0x21 + 94
    Values 0-93 → single chars '!' (0x21) through '~' (0x7E)
    Values 94-127 → two chars: '~' + (value-94+'!')
    This was confirmed by: tbcload.so .rodata has NO lookup table → computed
    transform; __ctype_b_loc imported for whitespace-skip only.

  Literal table (after body):
    <nliterals>\\n
    Repeated nliterals times:
      <type>\\n       # 'i' = integer, 'x' = external string, 'd' = double
      [<length>\\n]   # for type 'x': number of chars in encoded value (optional)
      <value>\\n      # the literal value (strings may be encoded)

  Procedure definitions follow the literal table.

Tcl 8.3 bytecode instruction set (bc_maj=8, bc_min=3):
  See TCL_83_OPCODES dict in this module.  Compatible with Tcl 8.5 targets
  (tbcload.so compiled against Tcl 8.5a7 handles 8.3-format bytecodes).

Usage:
    from ablation.analyzers.tclpro_decoder import TclProDecoder

    # Decode from raw bytes (e.g. extracted from MetaKit blob)
    dec = TclProDecoder.from_bytes(bytecode_blob)
    print(dec.report())
    print(dec.get_strings())      # all literal strings

    # Disassemble body to opcode list
    for offset, opname, operand in dec.disassemble():
        print(f'  {offset:4d}: {opname:<24} {operand}')

    # Find strings that mention exec/system/network patterns
    shell_refs = dec.find_strings_matching(r'system|exec|socket|http')

    # With MetaKit blob index
    parser = MetaKitParser.from_path('/path/to/installer.run')
    for label, blob in parser.iter_files():
        if blob.startswith(b'TclPro ByteCode'):
            dec = TclProDecoder.from_bytes(blob)
            print(f'{label}: {dec.report()}')
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

# ── Tcl 8.3 opcode table ──────────────────────────────────────────────────
# From tcl8.3.2/generic/tclCompile.h, cross-checked with tbcload.so disasm.
# Format: {opcode_byte: (name, n_operand_bytes)}
# Operands: 0=none, 1=one byte, 4=four bytes, -1=inline count (CONCAT1)
TCL_83_OPCODES: Dict[int, Tuple[str, int]] = {
    0x00: ('DONE',              0),
    0x01: ('PUSH1',             1),  # push literal[operand]
    0x02: ('PUSH4',             4),  # push literal[operand]
    0x03: ('POP',               0),
    0x04: ('DUP',               0),
    0x05: ('CONCAT1',           1),  # concat operand items
    0x06: ('INVOKE_STK1',       1),  # invoke stack[0] with operand args
    0x07: ('INVOKE_STK4',       4),
    0x08: ('EVAL_STK',          0),
    0x09: ('EXPR_STK',          0),
    0x0A: ('LOAD_SCALAR1',      1),
    0x0B: ('LOAD_SCALAR4',      4),
    0x0C: ('LOAD_SCALAR_STK',   0),
    0x0D: ('LOAD_ARRAY1',       1),
    0x0E: ('LOAD_ARRAY4',       4),
    0x0F: ('LOAD_ARRAY_STK',    0),
    0x10: ('LOAD_STK',          0),
    0x11: ('STORE_SCALAR1',     1),
    0x12: ('STORE_SCALAR4',     4),
    0x13: ('STORE_SCALAR_STK',  0),
    0x14: ('STORE_ARRAY1',      1),
    0x15: ('STORE_ARRAY4',      4),
    0x16: ('STORE_ARRAY_STK',   0),
    0x17: ('STORE_STK',         0),
    0x18: ('INCR_SCALAR1',      1),
    0x19: ('INCR_SCALAR4',      4),
    0x1A: ('INCR_SCALAR1_IMM',  2),  # var_idx + imm_incr
    0x1B: ('INCR_SCALAR4_IMM',  5),
    0x1C: ('INCR_ARRAY1',       1),
    0x1D: ('INCR_ARRAY4',       4),
    0x1E: ('INCR_ARRAY1_IMM',   2),
    0x1F: ('INCR_ARRAY4_IMM',   5),
    0x20: ('INCR_STK',          0),
    0x21: ('INCR_STK_IMM',      1),
    0x22: ('JUMP1',             1),  # signed offset
    0x23: ('JUMP4',             4),
    0x24: ('JUMP_FALSE1',       1),
    0x25: ('JUMP_FALSE4',       4),
    0x26: ('JUMP_TRUE1',        1),
    0x27: ('JUMP_TRUE4',        4),
    0x28: ('LAND',              0),
    0x29: ('LOR',               0),
    0x2A: ('BITOR',             0),
    0x2B: ('BITXOR',            0),
    0x2C: ('BITAND',            0),
    0x2D: ('EQ',                0),
    0x2E: ('NEQ',               0),
    0x2F: ('LT',                0),
    0x30: ('GT',                0),
    0x31: ('LE',                0),
    0x32: ('GE',                0),
    0x33: ('MOD',               0),
    0x34: ('LSHIFT',            0),
    0x35: ('RSHIFT',            0),
    0x36: ('UPLUS',             0),
    0x37: ('UMINUS',            0),
    0x38: ('BITNOT',            0),
    0x39: ('LNOT',              0),
    0x3A: ('CALL_BUILTIN_FUNC1', 1),
    0x3B: ('CALL_FUNC1',        1),
    0x3C: ('TRY_CVT_TO_NUMERIC', 0),
    0x3D: ('BREAK',             0),
    0x3E: ('CONTINUE',          0),
    0x3F: ('FOREACH_START4',    4),
    0x40: ('FOREACH_STEP4',     4),
    0x41: ('BEGIN_CATCH4',      4),
    0x42: ('END_CATCH',         0),
    0x43: ('PUSH_RESULT',       0),
    0x44: ('PUSH_RETURN_CODE',  0),
    0x45: ('STR_EQ',            0),
    0x46: ('STR_NEQ',           0),
    0x47: ('STR_CMP',           0),
    0x48: ('STR_LEN',           0),
    0x49: ('STR_INDEX',         0),
    0x4A: ('STR_MATCH',         0),
    0x4B: ('LIST',              1),   # LIST n
    0x4C: ('LIST_INDEX',        0),
    0x4D: ('LIST_LENGTH',       0),
    0x4E: ('APPEND_STK',        1),
    0x4F: ('APPEND_ARRAY_STK',  1),
    0x50: ('LAPPEND_STK',       1),
    0x51: ('LAPPEND_ARRAY_STK', 1),
    0x52: ('STR_UPPER',         0),
    0x53: ('STR_LOWER',         0),
    0x54: ('STR_TRIM',          0),
    0x55: ('STR_TRIMLEFT',      0),
    0x56: ('STR_TRIMRIGHT',     0),
    0x57: ('REG_EXP',           1),
    0x58: ('EQ_INT',            0),
    0x59: ('OVER',              1),
    0x5A: ('NEQ_INT',           0),
    0x5B: ('POP_ONE_FOR_TAILCALL', 0),
    # Tcl 8.5 additions (bc_maj=8, bc_min >= 5)
    0x5C: ('ADD',               0),
    0x5D: ('SUB',               0),
    0x5E: ('MUL',               0),
    0x5F: ('DIV',               0),
    0x60: ('LINDEX_IMM',        4),
    0x61: ('START_CMD',         1),
    0x62: ('END_CATCH_V2',      0),
    0x63: ('RETURN_IMM',        2),
    0x64: ('EXPAND_STKTOP',     4),
    0x65: ('INVOKE_REPLACE',    1),
}

# Security-relevant opcodes for quick screening
_EXEC_OPCODES = frozenset({
    0x06,   # INVOKE_STK1 — command invocation (may invoke system/exec)
    0x07,   # INVOKE_STK4
    0x08,   # EVAL_STK — dynamic eval (highest risk)
    0x09,   # EXPR_STK
})

# Patterns for security-relevant literal strings
_SECURITY_PATTERNS = re.compile(
    r'(?:exec\b|system\b|open\b.*\||\|.*\bopen\b|socket\b|http://|ftp://|'
    r'chmod|chown|install|rm\b|mv\b|wget\b|curl\b|eval\b|source\b|'
    r'registry\b|HKEY|popen\b)',
    re.IGNORECASE,
)


@dataclass
class TclProHeader:
    fmt_ver: int       # format version (1)
    byte_order: int    # 0 = big-endian, 1 = little-endian
    tcl_major: int     # Tcl version that COMPILED the bytecodes
    tcl_minor: int
    bc_major: int      # Tcl bytecode instruction set version
    bc_minor: int
    nprocs: int        # number of procedures
    ncmds: int         # number of commands
    nbytes: int        # encoded body length in characters
    nsrcbytes: int     # source bytes (for error messages)
    nfwdrefs: int


@dataclass
class TclProLiteral:
    type_code: str     # 'i' = integer, 'x' = string, 'd' = double
    value: str         # decoded string value


@dataclass
class TclProInstruction:
    offset: int        # byte offset within decoded body
    opcode: int
    name: str
    operand: Optional[int] = None
    operand_bytes: int = 0


class TclProDecoder:
    """
    Decodes TclPro ByteCode 1.x streams to instructions and literal strings.

    Supports format versions 1.3 (Tcl 8.3 bytecodes, used in BitRock Linux/
    Windows installers) and 1.7 (Tcl 8.5 bytecodes, used in Mac installers).
    """

    def __init__(self, raw: bytes):
        self._raw = raw
        self._header: Optional[TclProHeader] = None
        self._body_bytes: Optional[bytes] = None
        self._literals: Optional[List[TclProLiteral]] = None
        self._instructions: Optional[List[TclProInstruction]] = None
        self._parse_error: str = ''
        self._parsed = False

    @classmethod
    def from_bytes(cls, data: bytes) -> 'TclProDecoder':
        """Create decoder from raw bytecoded blob."""
        dec = cls(data)
        dec._parse()
        return dec

    @classmethod
    def from_context(cls, ctx) -> 'List[TclProDecoder]':
        """
        Find all TclPro ByteCode blobs in a binary and return decoders for each.
        Useful for binaries that contain bytecodes in their data sections.
        """
        try:
            path = ctx.path
            with open(path, 'rb') as fh:
                data = fh.read()
        except OSError:
            return []
        return cls.find_all_in_blob(data)

    @classmethod
    def find_all_in_blob(cls, data: bytes) -> 'List[TclProDecoder]':
        """Find all TclPro ByteCode headers in an arbitrary blob."""
        results = []
        pos = 0
        marker = b'TclPro ByteCode'
        while pos < len(data):
            idx = data.find(marker, pos)
            if idx < 0:
                break
            dec = cls(data[idx:])
            dec._parse()
            if dec._header is not None:
                results.append(dec)
            pos = idx + len(marker)
        return results

    # ── public API ───────────────────────────────────────────────────────────

    @property
    def valid(self) -> bool:
        """True if the bytecode was parsed without errors."""
        return self._parsed and self._header is not None and not self._parse_error

    @property
    def header(self) -> Optional[TclProHeader]:
        return self._header

    @property
    def version(self) -> str:
        """Human-readable version string, e.g. '1.3/8.3'."""
        if self._header is None:
            return 'unknown'
        h = self._header
        return f'{h.fmt_ver}.{h.tcl_minor}/{h.bc_major}.{h.bc_minor}'

    def get_strings(self) -> List[str]:
        """Return all string literals from the literal table."""
        lits = self._get_literals()
        return [L.value for L in lits if L.type_code == 'x']

    def get_integers(self) -> List[int]:
        """Return all integer literals from the literal table."""
        lits = self._get_literals()
        result = []
        for L in lits:
            if L.type_code == 'i':
                try:
                    result.append(int(L.value))
                except ValueError:
                    pass
        return result

    def find_strings_matching(self, pattern: str) -> List[str]:
        """Return string literals matching the given regex pattern."""
        rx = re.compile(pattern, re.IGNORECASE)
        return [s for s in self.get_strings() if rx.search(s)]

    def security_strings(self) -> List[str]:
        """Return strings that match exec/network/install security patterns."""
        return [s for s in self.get_strings() if _SECURITY_PATTERNS.search(s)]

    def disassemble(self) -> List[TclProInstruction]:
        """Return decoded instruction list."""
        return self._get_instructions()

    def has_eval_stk(self) -> bool:
        """True if the bytecode contains EVAL_STK (dynamic eval — high risk)."""
        return any(i.opcode == 0x08 for i in self._get_instructions())

    def report(self) -> str:
        """One-line summary."""
        if not self.valid:
            return f'TclProDecoder: invalid ({self._parse_error})\n'
        h = self._header
        lits = self._get_literals()
        strings = [L.value for L in lits if L.type_code == 'x']
        sec = self.security_strings()
        insns = self._get_instructions()
        return (
            f'TclProDecoder: version={self.version} procs={h.nprocs} '
            f'cmds={h.ncmds} body={h.nbytes}B '
            f'literals={len(lits)} strings={len(strings)} '
            f'security_hits={len(sec)} '
            f'eval_stk={self.has_eval_stk()}\n'
        )

    def dump(self) -> str:
        """Full disassembly with literal annotations."""
        lines = [self.report()]
        if not self.valid:
            return ''.join(lines)

        strings = self.get_strings()
        lines.append('Literals:')
        for i, L in enumerate(self._get_literals()):
            lines.append(f'  [{i:3d}] {L.type_code} {repr(L.value[:80])}')

        lines.append('\nBody:')
        for insn in self._get_instructions():
            ann = ''
            if insn.operand is not None:
                if insn.name in ('PUSH1', 'PUSH4', 'INVOKE_STK1', 'INVOKE_STK4'):
                    if 0 <= insn.operand < len(strings):
                        ann = f'  ; {repr(strings[insn.operand][:60])}'
                elif insn.name in ('JUMP1', 'JUMP4', 'JUMP_FALSE1', 'JUMP_FALSE4',
                                   'JUMP_TRUE1', 'JUMP_TRUE4', 'BEGIN_CATCH4'):
                    target = insn.offset + insn.operand_bytes + 1 + insn.operand
                    ann = f'  ; → {target}'
            op_str = f'{insn.operand}' if insn.operand is not None else ''
            lines.append(f'  {insn.offset:4d}: {insn.name:<24} {op_str}{ann}')

        if self.security_strings():
            lines.append('\nSecurity-relevant strings:')
            for s in self.security_strings():
                lines.append(f'  {repr(s[:100])}')

        return '\n'.join(lines) + '\n'

    # ── internal parsing ────────────────────────────────────────────────────

    def _parse(self) -> None:
        if self._parsed:
            return
        self._parsed = True
        try:
            self._do_parse()
        except Exception as e:
            self._parse_error = str(e)

    def _do_parse(self) -> None:
        raw = self._raw
        if not raw.startswith(b'TclPro ByteCode'):
            self._parse_error = 'no TclPro ByteCode header'
            return

        # Find first newline (end of header line)
        nl1 = raw.find(b'\n')
        if nl1 < 0:
            self._parse_error = 'no newline after header'
            return
        header_line = raw[:nl1].decode('ascii', errors='replace')

        # Parse header: "TclPro ByteCode <fmt_ver> <byte_order> <tcl_maj>.<tcl_min> <bc_maj>.<bc_min>"
        m = re.match(
            r'TclPro ByteCode\s+(\d+)\s+(\d+)\s+(\d+)\.(\d+)\s+(\d+)\.(\d+)',
            header_line,
        )
        if not m:
            self._parse_error = f'malformed header: {repr(header_line[:60])}'
            return

        fmt_ver, byte_order = int(m.group(1)), int(m.group(2))
        tcl_major, tcl_minor = int(m.group(3)), int(m.group(4))
        bc_major, bc_minor = int(m.group(5)), int(m.group(6))

        # Find second newline (end of parameter line)
        nl2 = raw.find(b'\n', nl1 + 1)
        if nl2 < 0:
            self._parse_error = 'no parameter line'
            return
        param_line = raw[nl1 + 1:nl2].decode('ascii', errors='replace')

        # Parse parameters: space-separated integers
        params = param_line.split()
        if len(params) < 3:
            self._parse_error = f'too few parameters: {param_line!r}'
            return
        nprocs = int(params[0])
        ncmds  = int(params[1])
        nbytes = int(params[2])
        nsrcbytes = int(params[3]) if len(params) > 3 else 0
        nfwdrefs  = int(params[4]) if len(params) > 4 else 0

        self._header = TclProHeader(
            fmt_ver=fmt_ver, byte_order=byte_order,
            tcl_major=tcl_major, tcl_minor=tcl_minor,
            bc_major=bc_major, bc_minor=bc_minor,
            nprocs=nprocs, ncmds=ncmds, nbytes=nbytes,
            nsrcbytes=nsrcbytes, nfwdrefs=nfwdrefs,
        )

        # Body starts after the second newline
        body_start = nl2 + 1
        if body_start + nbytes > len(raw):
            self._parse_error = f'body truncated: need {nbytes}, have {len(raw) - body_start}'
            return

        body_chars = raw[body_start:body_start + nbytes]
        self._body_bytes = self._decode_body(body_chars)

        # Literal table starts after body + newline
        lit_start = body_start + nbytes
        if lit_start < len(raw) and raw[lit_start:lit_start + 1] == b'\n':
            lit_start += 1
        self._parse_literals(raw[lit_start:])

    @staticmethod
    def _decode_body(body_chars: bytes) -> bytes:
        """
        Decode TclPro ByteCode body: char - 0x21 with '~' escape.

        Encoding (confirmed from tbcload.so analysis, no lookup table):
          Values 0-93:   single char, char = value + 0x21 ('!' through '~')
          Values 94-127: two chars: '~' (0x7E) + (value - 94 + 0x21)
          0x7E is never used as a direct opcode because it's the escape marker.
        """
        result = bytearray()
        i = 0
        while i < len(body_chars):
            c = body_chars[i]
            if c == 0x7E:  # '~' escape
                if i + 1 < len(body_chars):
                    c2 = body_chars[i + 1]
                    result.append((c2 - 0x21) + 94)
                    i += 2
                else:
                    i += 1
            elif c >= 0x21:  # '!' and above
                result.append(c - 0x21)
                i += 1
            else:
                # Control characters / space are whitespace — skip
                i += 1
        return bytes(result)

    def _parse_literals(self, data: bytes) -> None:
        """Parse the literal table following the bytecode body."""
        self._literals = []
        lines = data.split(b'\n')
        i = 0

        # First line should be the literal count
        while i < len(lines) and not lines[i].strip():
            i += 1
        if i >= len(lines):
            return

        try:
            nliterals = int(lines[i].strip())
        except (ValueError, IndexError):
            return
        i += 1

        parsed = 0
        while i < len(lines) and parsed < nliterals:
            # Type line
            if i >= len(lines):
                break
            type_line = lines[i].strip().decode('ascii', errors='replace')
            i += 1

            if not type_line:
                continue

            type_code = type_line[0] if type_line else 'x'

            if type_code == 'i':
                # Integer: next line is the value
                if i < len(lines):
                    val = lines[i].strip().decode('ascii', errors='replace')
                    i += 1
                    self._literals.append(TclProLiteral(type_code='i', value=val))
                    parsed += 1
            elif type_code == 'd':
                # Double: next line is the value
                if i < len(lines):
                    val = lines[i].strip().decode('ascii', errors='replace')
                    i += 1
                    self._literals.append(TclProLiteral(type_code='d', value=val))
                    parsed += 1
            elif type_code == 'x':
                # External string: possibly followed by length, then value
                # Try to read the value directly (it may or may not have a length prefix)
                val_bytes = b''
                if i < len(lines):
                    candidate = lines[i]
                    # Check if this line is a length integer
                    stripped = candidate.strip()
                    try:
                        length = int(stripped)
                        i += 1
                        # Next line(s) are the value of exactly 'length' chars
                        # But it might span multiple lines if value has newlines
                        if i < len(lines):
                            val_bytes = lines[i]
                            i += 1
                    except ValueError:
                        # Not a length: this IS the value
                        val_bytes = stripped
                        i += 1
                val_str = val_bytes.decode('utf-8', errors='replace')
                self._literals.append(TclProLiteral(type_code='x', value=val_str))
                parsed += 1
            else:
                # Unknown type: skip one line
                if i < len(lines):
                    i += 1

    def _get_literals(self) -> List[TclProLiteral]:
        if self._literals is None:
            self._parse()
        return self._literals or []

    def _get_instructions(self) -> List[TclProInstruction]:
        if self._instructions is not None:
            return self._instructions
        self._instructions = []
        if self._body_bytes is None:
            return self._instructions

        body = self._body_bytes
        pos = 0
        while pos < len(body):
            opcode = body[pos]
            name, n_operand = TCL_83_OPCODES.get(opcode, (f'UNK_{opcode:02x}', 0))

            operand = None
            if n_operand == 1 and pos + 1 < len(body):
                operand = body[pos + 1]
            elif n_operand == 2 and pos + 2 < len(body):
                operand = struct.unpack('>H', body[pos + 1:pos + 3])[0]
            elif n_operand == 4 and pos + 4 < len(body):
                operand = struct.unpack('>I', body[pos + 1:pos + 5])[0]
            elif n_operand == 5 and pos + 5 < len(body):
                # 4-byte var index + 1-byte immediate increment
                operand = struct.unpack('>I', body[pos + 1:pos + 5])[0]

            self._instructions.append(TclProInstruction(
                offset=pos,
                opcode=opcode,
                name=name,
                operand=operand,
                operand_bytes=n_operand,
            ))
            pos += 1 + n_operand

        return self._instructions
