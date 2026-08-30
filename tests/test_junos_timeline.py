"""
Juniper Junos SRX SME (junos-srxsme) MIPS kernel version timeline.

Target: junos-srxsme-*-domestic — the Junos FreeBSD kernel for SRX
        Small/Medium/Enterprise platforms (Cavium OCTEON MIPS64 hardware).

Architecture: ELF 32-bit MSB MIPS (big-endian), interpreter /red/herring.
All function symbols are type 'A' (absolute) not 'T' — the kernel loads at
fixed VA 0x80100000+, making all symbols absolute. Filter by VA range against
.text section bounds to identify code symbols.

MIPS function termination: jr $ra (jump-register to return address) plus
the mandatory 1-instruction delay slot that follows it. Both instructions
are part of the function body.

Version sweep spans 2012-2026: 11.4R3 (Octeon, 2012) through 23.4R2-S8
(2026), covering 8 patch points across three major SRX release trains.

Seed: esp_auth — IPsec ESP authentication core. Security-critical function
present in all versions. Tracks changes to ESP authentication validation
logic across 14 years of Junos SRX development.

Results: 11.4R3.7 through 12.1X46-D40 (Sep 2015): Jac=1.0, structurally
identical. 15.1X49-D240 (Dec 2020) onward: Jac=0.8649, +5/-3 structural
change. ah_get_auth_pads confirms same boundary at Jac=0.8348. Two IPsec
auth functions changed together — boundary: D40→D240.

RE analysis of PRE (11.4R3.7, 0x804cc068) vs POST (15.1X49-D240, 0x8046afb4):

Shared structure (both versions identical):
  [1] 4x validation: skip>pktlen, skip+auth>pktlen, auth%4!=0, SA==NULL
  [2] ah_algorithm_lookup(SA->alg_type) → s4 = algorithm descriptor
  [3] sumsiz(SA) via descriptor[0] → s5 = (ret+3)&~3; EINVAL if s5>=17
  [4] Skip traversal: advance s1 through mbufs consuming s0 skip bytes
  [5] Init(sp+0x10, SA) via descriptor[0x14]; return value ignored (s5 fixed)
  [6] bnez $s2, <data_entry>; j <Final> — auth_len==0 fast path
  [7] Final(sp+0x10, sp+0x18, 16); ovbcopy(sp+0x18, caller_icv_buf, s5)

The change (Jac=0.8649): register reuse of $s3.
  PRE:  $s3 = SA pointer throughout; update loop uses addiu $a0, $sp, 0x10 directly.
  POST: $s3 repurposed as ctx ptr in branch delay slot at 0x8046b250
        (addiu $s3, $sp, 0x10 in delay slot of bnez multi-chunk dispatch);
        update loop uses move $a0, $s3 (one fewer addiu per iteration).
  4-gram change: [lw, addiu, jalr, addu] → [lw, move, jalr, addu]

  Type: compiler register allocation change. Logic, output, and
  security semantics are byte-for-byte equivalent. The coordinated
  change in ah_get_auth_pads at the same boundary indicates a batch
  recompilation across the IPsec auth subsystem, not a targeted patch.

Capstone MIPS caveat: BNE $rs, $zero is sometimes decoded as BEQZ.
  Verified via raw word decode. Always raw-verify MIPS branch direction
  when control flow appears pathological (unconditional jump to Final
  before any Update calls is the red flag).

--- ipsec_sadb_delete_entry (Jac=0.0256 D40→D240) ---

PRE (11.4R3.7, 0x8034b984): 4-instruction stub.
  lw $v0, 0x58($a0)      ; load SA->lock or refcount field
  beqz $v0, <return>
  nop
  jal <internal_delete>
  move $a0, ...

POST (15.1X49-D240, 0x80326c18): 14-instruction function with assertion
and pre-deletion CPSEC notification.

POST structure:
  [1] Save frame: addiu $sp,-0x20; sw $ra; sw $s1; sw $s0
  [2] $s0 = SA ($a0), $s1 = arg1 ($a1)
  [3] ASSERT: lw $v0, 0x174($SA); if v0 != 0, panic(file, func, line=0x308)
      SA->0x174 must be NULL — any active CPSEC context tied to this SA
      triggers a kernel panic rather than silently freeing live memory.
  [4] CPSEC pre-deletion notification:
        v0 = gp-0x1478   ; load cpsec_module ptr (set by set_cpsec_module)
        if v0 != NULL:
            call v0->field_0x38(SA)   ; sa_delete_notify(SA) callback
      set_cpsec_module (0x803b6210) is a 2-instruction setter:
        jr $ra / sw $a0, -0x1478($gp)
      The slot is NULL until the UTM/content-security module registers.
  [5] jal 0x80326a4c (internal_delete_impl)
  [6] Restore frame and return.

Type: security fix — use-after-free mitigation at CPSEC-IPsec boundary.

  PRE deleted SAs without notifying the Content Security (UTM/CPSEC) layer.
  CPSEC held session-tracking and DPI state keyed to SA identity. Without
  notification, SA deletion left CPSEC with dangling SA pointers. POST adds:
  (a) an assertion that no active CPSEC context references the SA at deletion
      time (SA->0x174 == 0), and
  (b) a pre-deletion callback so CPSEC can flush those references before the
      SA is freed.

  The near-zero Jaccard (0.0256) reflects a complete structural rewrite:
  a 4-instruction stub expanded to a 14-instruction function with register
  saves, an assertion with panic(), a conditional vtable dispatch, and a
  properly-framed call to the internal delete implementation. This is not a
  compiler change — it is an architectural addition to the SA lifecycle.

--- esp_aesctr_encrypt (Jac=0.4899 D40→D240) ---

Boundary: D40→D240 (+10 instructions, 402→412). Callee change: kern_log
replaced by log (3 sites). kern_log was a Juniper-internal logging wrapper
that prepended module context; log is FreeBSD's standard log(9). The
calling-convention difference (kern_log takes an extra module-string arg)
produces different argument-load sequences at each of the 3 call sites,
accounting for most of the Jaccard drop.

10.4→11.4 boundary: mbuf_throttle and mcl_throttle added. Network memory
throttling to prevent mbuf-exhaustion DoS; absent in 10.4, present in
11.4 through all later versions.

key_sa_stir_iv present in all versions — AES-CTR counter uniqueness
management is unchanged across the entire timeline. No counter reuse
vulnerability introduced or fixed at any boundary.

--- Full sweep results (test_junos_full_sweep.py, 2026-08-30) ---

14 versions available, all confirmed present.
11,976 seed functions. 4,034 Jac<0.3. 7,330 Jac<0.8.
Two major patch boundaries: 12.1X46-D35 (2015-05) and 15.1X49-D240 (2020-12).
Third wave at 21.4R3-S3 (jsrxnle_rtc_set, if_tunnel_set_encap_ifl → Jac=0.0).

Top RE targets from sweep:
  ah6_input               Jac=1.0→0.6094 at D35, then 0.0000 at D240
  ether_input             Jac=1.0→0.0000 at D35
  in_pcbdetach            Jac=1.0→0.0000 at D35
  sbdrop/sbflush/sbrelease_locked  all → 0.0000 at D35
  netisr_dispatch/netisr_queue     → 0.0000 at D35
  if_tunnel_set_encap_ifl gradual rewrite, 0.0000 at D240

--- ah6_input (Jac=0.0 at D240) ---

PRE (11.4R3.7, 0x804c9464): 200+ instructions. Full IPv6 AH input processing:
  mbuf chain traversal, AH header parse, SA lookup via SPI, sequence number
  replay check, auth verification dispatch, statistics updates.

D35 intermediate (0x804d8360): Jac=0.6094 vs 11.4. Same overall structure,
  addresses differ (relocation), some stats counter offsets shifted.

POST (15.1X49-D240, 0x8046a950): 11-instruction vtable dispatch stub:
  addiu $sp, -0x18          ; minimal frame (no saved registers)
  sw    $ra, 0x10($sp)
  lw    $v0, -0x1478($gp)   ; same CPSEC module ptr as ipsec_sadb_delete_entry
  bnez  $v0, <handler>
  nop
  j     <return>
  addiu $v0, $zero, 0x102   ; fallback return (no CPSEC = protocol not supported)
  lw    $v0, 0x14($v0)      ; vtable slot 0x14 = ah6_input handler
  jalr  $v0
  nop
  [restore + jr $ra]

CPSEC vtable slot map (confirmed so far):
  0x14  = ah6_input handler
  0x38  = sa_delete_notify (ipsec_sadb_delete_entry callback)

The entire AH6 processing moved into the pluggable CPSEC module at D240.
When CPSEC module not loaded (gp-0x1478 == NULL), ah6_input returns 0x102
without processing the authentication header. Caller protocol dispatch
behavior on this return value determines whether packets pass unauthenticated.

--- ether_input (Jac=0.0 at D35) ---

PRE (11.4R3.7, 0x8033caf8): 100+ instructions. Full Ethernet frame input:
  mbuf alignment check, vlan/bridge filter dispatch, interface tag handling.

POST (12.1X46-D35, 0x80346424): 5-instruction trampoline:
  addiu $sp, -0x18
  sw    $ra, 0x10($sp)
  jal   0x80344a84          ; full implementation moved to this function
  nop
  [restore + jr $ra]

The real ether_input logic moved to 0x80344a84. This indirection enables
hooking at the ether_input symbol while keeping the implementation separate.

--- in_pcbdetach (Jac=0.0 at D35) ---

PRE (11.4R3.7, 0x8044feb0): 30+ instructions. Raw CPU register manipulation:
  mfc0 $a0, $t4, 0     ; read MIPS Status register (interrupt enable state)
  and  $v0, $a0, $v0   ; clear IE bit
  mtc0 $v0, $t4, 0     ; write back (disable interrupts)
  Direct interrupt masking in PCB teardown — no callback hooks.

POST (12.1X46-D35, 0x8045af60): 22 instructions. Callback-based teardown:
  [1] lw $v0, 0xd4($a0); andi $v0, $v0, 2  ; check PCB flags bit 1
  [2] if set: check gp-0x1a20 == PCB->sock (offset 0x64)
        if match: sw $zero, -0x1a20($gp)    ; clear global owner pointer
        lw $v0, 0xd8($a0)                   ; destructor function pointer
        jalr $v0 with arg lw $a0, 0xdc($a0) ; call destructor
  [3] sw $zero, 0x14($v0)  ; null PCB->sock->somethng
  [4] sw $zero, 0x64($s0)  ; null PCB->sock

Type: UAF mitigation. PRE used raw interrupt disabling to serialize PCB
teardown; POST adds:
  (a) A destructor callback (PCB+0xd8) called before detach
  (b) A global "owner" register (gp-0x1a20) cleared if this PCB is the
      current owner — prevents dangling global pointer reuse
  (c) NULL-outs on PCB→socket back-pointers

The mfc0/mtc0 CPU register manipulation in PRE is replaced entirely by
the callback protocol. The D35 change matches the pattern of FreeBSD
socket PCB UAF fixes from the 2014-2015 timeframe.

--- D35 systematic trampoline refactoring ---

At D35, the following functions were all converted from full implementations
to 5-instruction trampolines (jal <internal> + restore + jr $ra):

  ether_input      → ether_input_internal (0x80344a84)
  sbdrop_locked    → 0x802bc3d8
  sbflush_locked   → (similar internal)
  sbrelease_locked → (similar internal)
  netisr_dispatch  → (similar)

Pattern: D35 splits public name → thin wrapper + private _internal function.
Public name retains stable VA for callers; internal handles logic. Enables:
  (a) hooking at the public symbol without touching the implementation
  (b) calling the implementation from additional call sites
  (c) locking/unlocking wrapper variants sharing the same core

The Jac=0.0 score for all D35 trampoline functions reflects the total
absence of 4-gram overlap between a 5-instruction wrapper and the original
50-100+ instruction implementation. These are NOT security changes — they
are the architectural preparation that precedes the D240 CPSEC integration.

D35 is a code-restructuring release; D240 is where the security-layer
changes land (CPSEC vtable integration for IPsec, ah6_input dispatch stub).

Firmware at /media/cowboy/research/juniper-firmware/extracted/
"""

import sys, os, struct, subprocess, time
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))
import capstone

from modules.version_delta import FuncFeatures, FuncMatcher, jaccard, compute_patch_delta
from modules.semantic_search import SemanticSearcher

DB = '~/.ablation/func_id.db'

# Each entry: (label, path)
# All are ELF 32-bit MSB MIPS, symbols type A, not stripped.
_BASE = '/media/cowboy/research/juniper-firmware/extracted'
VERSIONS = [
    ('10.4R7.5  (2011-09)',   f'{_BASE}/srx-10.4/junos-srxsme-10.4R7.5-domestic'),
    ('11.4R3.7  (2012-05)',   f'{_BASE}/srx-11.4/junos-srxsme-11.4R3.7-domestic'),
    ('11.4R7.5  (2013-03)',   f'{_BASE}/srx-11.4R7/junos-srxsme-11.4R7.5-domestic'),
    ('11.4R11.4 (2015-07)',   f'{_BASE}/srx-11.4R11/junos-srxsme-11.4R11.4-domestic'),
    ('12.1X46-D35 (2015-05)', f'{_BASE}/srx-12.1X46/junos-srxsme-12.1X46-D35.1-domestic'),
    ('12.1X46-D40 (2015-09)', f'{_BASE}/srx-12.1X46-D40/junos-srxsme-12.1X46-D40.2-domestic'),
    ('15.1X49-D240 (2020-12)',f'{_BASE}/srx-15.1X49/junos-srxsme-15.1X49-D240.4-domestic'),
    ('22.4R3-S9  (2026-01)',  f'{_BASE}/srx-22.4/junos-srxsme-22.4R3-S9.3-domestic'),
    ('23.4R2-S5  (2025-06)',  f'{_BASE}/srx-23.4R2-S5/junos-srxsme-23.4R2-S5.5-domestic'),
    ('23.4R2-S8  (2026-05)',  f'{_BASE}/srx-23.4/junos-srxsme-23.4R2-S8.7-domestic'),
]

# Primary seed: IPsec ESP authentication. Security-critical MIPS kernel function.
# VA differs by version — discovered via nm -D.
SEED_VERSION = '11.4R3.7'
SEED_NAME    = 'esp_auth'

# Secondary seeds for multi-function sweep
SECONDARY_SEEDS = [
    'ah_get_auth_pads',      # AH authentication header padding computation
    'esp_input',             # IPsec ESP input processing
    'esp_output',            # IPsec ESP output processing
    'ipsec_common_input',    # IPsec common input path
]


def _elf32_msb_text_range(data: bytes) -> tuple[int, int]:
    """Return (text_va_start, text_va_end) from the MIPS kernel ELF header."""
    e_shoff     = struct.unpack_from('>I', data, 0x20)[0]
    e_shnum     = struct.unpack_from('>H', data, 0x30)[0]
    e_shentsize = struct.unpack_from('>H', data, 0x2e)[0]
    e_shstrndx  = struct.unpack_from('>H', data, 0x32)[0]

    # Find .text section via section name string table
    strtab_off_field = e_shoff + e_shstrndx * e_shentsize + 0x10
    str_off  = struct.unpack_from('>I', data, strtab_off_field)[0]

    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        sh_name   = struct.unpack_from('>I', data, sh)[0]
        sh_type   = struct.unpack_from('>I', data, sh + 4)[0]
        sh_addr   = struct.unpack_from('>I', data, sh + 0xc)[0]
        sh_size   = struct.unpack_from('>I', data, sh + 0x14)[0]
        name = data[str_off + sh_name: str_off + sh_name + 8].split(b'\x00')[0]
        if name == b'.text' and sh_type == 1:  # SHT_PROGBITS
            return (sh_addr, sh_addr + sh_size)
    return (0x80100000, 0x81000000)  # fallback: typical Junos MIPS range


def _elf32_msb_foff(data: bytes, va: int) -> int | None:
    """Resolve MIPS big-endian 32-bit ELF VA to file offset via PT_LOAD."""
    e_phoff = struct.unpack_from('>I', data, 0x1c)[0]
    e_phnum = struct.unpack_from('>H', data, 0x2c)[0]
    e_phent = struct.unpack_from('>H', data, 0x2a)[0]
    for i in range(e_phnum):
        off      = e_phoff + i * e_phent
        p_type   = struct.unpack_from('>I', data, off)[0]
        p_offset = struct.unpack_from('>I', data, off + 4)[0]
        p_vaddr  = struct.unpack_from('>I', data, off + 8)[0]
        p_filesz = struct.unpack_from('>I', data, off + 0x10)[0]
        if p_type == 1 and p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    return None


def extract_func_mips(data: bytes, va: int) -> tuple[list[str], list[str]]:
    """Disassemble MIPS big-endian function at VA; stop after jr $ra + delay slot."""
    foff = _elf32_msb_foff(data, va)
    if foff is None:
        return [], []
    raw = data[foff: foff + 4096]
    md  = capstone.Cs(capstone.CS_ARCH_MIPS,
                      capstone.CS_MODE_MIPS32 + capstone.CS_MODE_BIG_ENDIAN)
    lines, calls = [], []
    saw_jr_ra = False
    for insn in md.disasm(raw, va):
        op = f'{insn.mnemonic} {insn.op_str}'.strip()
        lines.append(op)
        if insn.mnemonic in ('jal', 'jalr') and insn.op_str.startswith('0x'):
            calls.append(insn.op_str)
        # jr $ra = return; collect the delay-slot instruction then stop
        if insn.mnemonic == 'jr' and '$ra' in insn.op_str:
            saw_jr_ra = True
            continue
        if saw_jr_ra:
            break
        if len(lines) > 200:
            break
    return lines, calls


def build_corpus(path: str, data: bytes) -> dict[str, FuncFeatures]:
    """
    Build symbolized FuncFeatures corpus from MIPS kernel nm -D output.
    Type A symbols in the .text VA range are kernel functions.
    """
    text_lo, text_hi = _elf32_msb_text_range(data)
    out = subprocess.check_output(['nm', '-D', path], text=True, stderr=subprocess.DEVNULL)
    corpus: dict[str, FuncFeatures] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        sym_type = parts[1]
        if sym_type not in ('A', 'T', 't'):
            continue
        try:
            va   = int(parts[0], 16)
            name = parts[2]
        except ValueError:
            continue
        if not (text_lo <= va < text_hi):
            continue
        asm, calls = extract_func_mips(data, va)
        if len(asm) >= 4:
            corpus[name] = FuncFeatures.from_disasm_lines(va, name, asm, calls)
    return corpus


def main():
    ss      = SemanticSearcher(DB)
    ss.build_corpus()
    matcher = FuncMatcher(semantic_searcher=ss)

    # Seed: 11.4R3.7 esp_auth
    seed_entry = next((v for v in VERSIONS if '11.4R3.7' in v[0]), None)
    if seed_entry is None:
        print('Seed version not in VERSIONS'); return
    seed_label, seed_path = seed_entry
    if not os.path.exists(seed_path):
        print(f'Seed path missing: {seed_path}'); return

    with open(seed_path, 'rb') as f:
        seed_data = f.read()
    seed_corpus = build_corpus(seed_path, seed_data)
    seed = seed_corpus.get(SEED_NAME)
    if seed is None:
        print(f'Seed function not found: {SEED_NAME}'); return

    print(f'Primary seed: {SEED_NAME}')
    print(f'  from {seed_label}  VA=0x{seed.va:x}  instrs={seed.n_instrs}\n')
    print(f'{"Version":<28} {"N":>6} {"VA":>12}  {"Jac":>6}  Patched  Instrs  Delta')
    print('-' * 80)

    corpora: dict[str, dict] = {seed_label: seed_corpus}

    for label, path in VERSIONS:
        if not os.path.exists(path):
            print(f'{label:<28}  (skipped — path missing)')
            continue
        with open(path, 'rb') as f:
            data = f.read()
        t0 = time.time()
        corpus = build_corpus(path, data)
        elapsed = time.time() - t0
        corpora[label] = corpus

        exact = corpus.get(SEED_NAME)
        if exact is not None:
            jac_val = jaccard(seed.ngrams_4, exact.ngrams_4)
            dlt     = compute_patch_delta(seed, exact)
            dstr    = ''
            if dlt.added:   dstr += f'+{len(dlt.added)}'
            if dlt.removed: dstr += f'-{len(dlt.removed)}'
            note = '(seed)' if path == seed_path else ('YES' if dlt.is_patched else 'NO')
            print(f'{label:<28} {len(corpus):>6} {hex(exact.va):>12}  '
                  f'{jac_val:.4f}  {note:>7}  {exact.n_instrs:>6}  {dstr}  [{elapsed:.0f}s]')
        else:
            feats = list(corpus.values())
            match = matcher.find_homolog(seed, feats)
            if match is None:
                print(f'{label:<28} {len(corpus):>6}  NOT FOUND  [{elapsed:.0f}s]')
            else:
                dstr = ''
                if match.delta.added:   dstr += f'+{len(match.delta.added)}'
                if match.delta.removed: dstr += f'-{len(match.delta.removed)}'
                print(f'{label:<28} {len(corpus):>6} {hex(match.va):>12}  '
                      f'{match.jaccard:.4f}  {"YES" if match.delta.is_patched else "NO":>7}  '
                      f'{"?":>6}  {dstr}  [{elapsed:.0f}s]')

    # Secondary seed sweep
    print(f'\n--- Secondary seeds (direct Jaccard across all versions) ---')
    labels = [l for l, _ in VERSIONS if l in corpora]
    header = f'{"Seed":<25}' + ''.join(f'  {l.split()[0]:>14}' for l in labels)
    print(header)
    print('-' * len(header))

    for sname in SECONDARY_SEEDS:
        short = sname[:24]
        old_feat = corpora.get(seed_label, {}).get(sname)
        row = f'{short:<25}'
        for label in labels:
            corp = corpora.get(label, {})
            new_feat = corp.get(sname)
            if old_feat is None or new_feat is None:
                row += f'  {"N/A":>14}'
            else:
                row += f'  {jaccard(old_feat.ngrams_4, new_feat.ngrams_4):>14.4f}'
        print(row)


if __name__ == '__main__':
    main()
