"""
Honeywell Tridium Niagara Framework native layer patch attribution.

Target: libnre.so (Niagara Runtime Engine) — the JNI native layer
        handling authentication, session management, and platform services.

Key findings:
  getSupportedAuthenticationTypes0 in libnre.so was rewritten between
  4.10.10.40 and 4.13.x — 73 instructions → 29, Jaccard 1.0 → 0.1375.
  The dynamic PAM/auth-module lookup (repe cmpsb string comparisons,
  vtable dispatch for auth-type detection) was replaced with a hardcoded
  static response. Change is invisible from Java decompilation alone.

  Cross-platform: QNX ARM Thumb 4.11.0 = pre-patch (44 instrs, conditional
  logic present). Windows nre.dll uses a 4-instruction vtable trampoline on
  ALL versions — the Windows DLL never carries the implementation inline;
  follow the jmp target to reach the actual method body.

  Boundary (Linux/QNX): between 4.12.x and 4.13.0.186.

Approach: symbolized corpus (nm -D) instead of prologue scan.
For any binary with exported symbols, nm-based corpus construction is
more accurate than prologue pattern matching — bypasses the prologue
scanner limitation where functions start with push r13 (41 55).

Adjust VERSIONS paths to match your extracted dist locations.
"""

import sys, os, time, struct, subprocess
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))
import capstone

from modules.version_delta import FuncFeatures, FuncMatcher, jaccard, compute_patch_delta
from modules.semantic_search import SemanticSearcher

DB = '~/.ablation/func_id.db'

# Extracted libnre.so paths.
# Linux x64: unzip -p <supervisor>.zip "dist/<ver>/nre-core-linux-x64.dist" > core.dist &&
#            unzip -j core.dist "libnre.so" -d <outdir>/
# QNX ARM:   unzip -p <emea>.zip "dist/<ver>/nre-core-qnx7-armle-v7.dist" > core.dist &&
#            unzip -j core.dist "zip/nre-core-update.tar.gz" -d tmp/ &&
#            tar xzf tmp/nre-core-update.tar.gz nre-core-update/nrecore.tar.gz -C tmp/ &&
#            tar xzf tmp/nre-core-update/nrecore.tar.gz libnre.so -C <outdir>/
VERSIONS = [
    # (label, path, arch)  arch: 'x86_64' | 'arm_thumb' | 'arm'
    ('4.11.0.142 QNX/ARM', '/tmp/niagara-extract/4110142-qnx/native/libnre.so', 'arm_thumb'),
    ('4.12.0.156 QNX/ARM', '/tmp/niagara-extract/4120156-qnx/native/libnre.so', 'arm_thumb'),
    ('4.10.10.40 Linux',   '/tmp/niagara-extract/41010040/native/libnre.so',    'x86_64'),   # pre-patch
    ('4.13.0.186 Linux',   '/tmp/niagara-extract/4130186/native/libnre.so',     'x86_64'),   # boundary
    ('4.13.2.18  Linux',   '/tmp/niagara-extract/4132018/native/libnre.so',     'x86_64'),   # PATCHED
    ('4.13.3.48  Linux',   '/tmp/niagara-extract/4133348/native/libnre.so',     'x86_64'),   # PATCHED
    ('4.14.0.162 Linux',   '/tmp/niagara-extract/4140162/native/libnre.so',     'x86_64'),   # PATCHED
]

# Primary seed: auth type handler — 73→29 instrs, jac 1.0→0.1375 at patch boundary
SEED_VERSION = '4.10.10.40'
SEED_NAME    = ('Java_com_tridium_nre_platform_NativePlatformProvider'
                '_getSupportedAuthenticationTypes0')

# Secondary seeds for multi-function sweep
SECONDARY_SEEDS = [
    'Java_com_tridium_nre_platform_NativePlatformProvider_isPasswordValid0',
    'Java_com_tridium_nre_platform_NativePlatformProvider_getPasswordHash0',
    'Java_com_tridium_nre_platform_NativePlatformProvider_setKeyMaterial0',
    '_ZN16NreLauncherLinux9buildArgsEiPPc',
]


def _elf_class(data: bytes) -> int:
    """1 = 32-bit ELF, 2 = 64-bit ELF."""
    return data[4]


def _file_offset(data: bytes, va: int) -> int:
    """Resolve ELF VA to file offset; handles both ELF32 and ELF64."""
    if _elf_class(data) == 1:  # 32-bit
        va = va & ~1  # strip Thumb bit
        e_phoff     = struct.unpack_from('<I', data, 0x1c)[0]
        e_phnum     = struct.unpack_from('<H', data, 0x2c)[0]
        e_phentsize = struct.unpack_from('<H', data, 0x2a)[0]
        for i in range(e_phnum):
            off      = e_phoff + i * e_phentsize
            p_type   = struct.unpack_from('<I', data, off)[0]
            p_flags  = struct.unpack_from('<I', data, off + 4)[0]
            p_offset = struct.unpack_from('<I', data, off + 8)[0]
            p_vaddr  = struct.unpack_from('<I', data, off + 0xc)[0]
            p_filesz = struct.unpack_from('<I', data, off + 0x10)[0]
            if p_type == 1 and (p_flags & 0x1) and p_vaddr <= va < p_vaddr + p_filesz:
                return p_offset + (va - p_vaddr)
        return va
    else:  # 64-bit
        e_phoff     = struct.unpack_from('<Q', data, 0x20)[0]
        e_phnum     = struct.unpack_from('<H', data, 0x38)[0]
        e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
        for i in range(e_phnum):
            off      = e_phoff + i * e_phentsize
            p_type   = struct.unpack_from('<I', data, off)[0]
            p_flags  = struct.unpack_from('<I', data, off + 4)[0]
            p_offset = struct.unpack_from('<Q', data, off + 8)[0]
            p_vaddr  = struct.unpack_from('<Q', data, off + 0x10)[0]
            p_filesz = struct.unpack_from('<Q', data, off + 0x20)[0]
            if p_type == 1 and (p_flags & 0x1) and p_vaddr <= va < p_vaddr + p_filesz:
                return p_offset + (va - p_vaddr)
        return va


def extract_func(data: bytes, va: int, arch: str = 'x86_64') -> tuple[list[str], list[str]]:
    is_thumb = arch == 'arm_thumb'
    va_clean = va & ~1 if is_thumb else va
    fo  = _file_offset(data, va_clean)
    raw = data[fo: fo + 4096]

    if arch == 'x86_64':
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        ret_mnemonics = ('ret', 'retq', 'retn')
        jmp_mnemonics = ('jmp', 'jmpq')
        call_prefix   = '0x'
    elif is_thumb:
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        ret_mnemonics = ()  # ARM uses bx lr / pop {pc}
        jmp_mnemonics = ('b',)
        call_prefix   = ''

    lines, calls = [], []
    for insn in md.disasm(raw, va_clean):
        op = f'{insn.mnemonic} {insn.op_str}'.strip()
        lines.append(op)
        if arch == 'x86_64':
            if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
                calls.append(insn.op_str)
            if insn.mnemonic in ret_mnemonics:
                break
            if insn.mnemonic in jmp_mnemonics:
                try:
                    if abs(int(insn.op_str, 16) - va_clean) > 0x20000:
                        break
                except ValueError:
                    break
        else:  # ARM Thumb
            if insn.mnemonic in ('bl', 'blx') and insn.op_str.startswith('#0x'):
                calls.append(insn.op_str[1:])
            if insn.mnemonic == 'bx' and 'lr' in insn.op_str:
                break
            if insn.mnemonic == 'pop' and 'pc' in insn.op_str:
                break
        if len(lines) > 150:
            break
    return lines, calls


def build_corpus(path: str, data: bytes, arch: str = 'x86_64') -> dict[str, FuncFeatures]:
    """Build FuncFeatures keyed by symbol name from exported text symbols."""
    out = subprocess.check_output(['nm', '-D', path], text=True, stderr=subprocess.DEVNULL)
    corpus: dict[str, FuncFeatures] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == 'T':
            try:
                va   = int(parts[0], 16)
                name = parts[2]
                asm, calls = extract_func(data, va, arch)
                if len(asm) >= 4:
                    corpus[name] = FuncFeatures.from_disasm_lines(va & ~1, name, asm, calls)
            except Exception:
                pass
    return corpus


def main():
    ss      = SemanticSearcher(DB)
    ss.build_corpus()
    matcher = FuncMatcher(semantic_searcher=ss)

    # Seed: x86-64 Linux 4.10.10.40 (pre-patch)
    seed_entry = next((v for v in VERSIONS if '4.10.10.40' in v[0]), None)
    if seed_entry is None:
        print('Seed version not in VERSIONS list'); return
    seed_label, seed_path, seed_arch = seed_entry
    if not os.path.exists(seed_path):
        print(f'Seed path missing: {seed_path}'); return
    with open(seed_path, 'rb') as f:
        seed_data = f.read()
    seed_corpus = build_corpus(seed_path, seed_data, seed_arch)
    seed = seed_corpus.get(SEED_NAME)
    if seed is None:
        print(f'Seed function not found in {seed_label}: {SEED_NAME}'); return

    short_name = SEED_NAME.split('_')[-1].replace('0', '')
    print(f'Primary seed: {short_name}')
    print(f'  from {seed_label}  VA=0x{seed.va:x}  instrs={seed.n_instrs}\n')
    print(f'{"Version":<25} {"Arch":<9} {"N":>5} {"VA":>10}  {"Jac":>6}  Patched  Instrs  Delta')
    print('-' * 85)

    for label, path, arch in VERSIONS:
        if not os.path.exists(path):
            print(f'{label:<25}  (skipped — path missing)')
            continue
        with open(path, 'rb') as f:
            data = f.read()
        corpus = build_corpus(path, data, arch)

        exact = corpus.get(SEED_NAME)
        if exact is not None:
            if arch == 'arm_thumb':
                # QNX/Windows ARM exported JNI = vtable dispatch trampoline on all
                # versions: load vtable → slot 0x29c → bx r3. Not directly comparable
                # to x86-64 via Jaccard. Follow vtable slot for real implementation.
                print(f'{label:<25} {arch:<9} {len(corpus):>5} {hex(exact.va):>10}  '
                      f'{"N/A":>7}  {"trampoline":>7}  {exact.n_instrs:>6}  (vtable dispatch)')
            else:
                jac_val = jaccard(seed.ngrams_4, exact.ngrams_4)
                dlt     = compute_patch_delta(seed, exact)
                dstr    = (f'+{len(dlt.added)}' if dlt.added else '') + \
                          (f'-{len(dlt.removed)}' if dlt.removed else '')
                note = '(seed)' if path == seed_path else ('YES' if dlt.is_patched else 'NO')
                print(f'{label:<25} {arch:<9} {len(corpus):>5} {hex(exact.va):>10}  '
                      f'{jac_val:.4f}  {note:>7}  {exact.n_instrs:>6}  {dstr}')
        else:
            feats = list(corpus.values())
            match = matcher.find_homolog(seed, feats)
            if match is None:
                print(f'{label:<25} {arch:<9} {len(corpus):>5}  NOT FOUND')
            else:
                dstr = (f'+{len(match.delta.added)}' if match.delta.added else '') + \
                       (f'-{len(match.delta.removed)}' if match.delta.removed else '')
                print(f'{label:<25} {arch:<9} {len(corpus):>5} {hex(match.va):>10}  '
                      f'{match.jaccard:.4f}  {"YES" if match.delta.is_patched else "NO":>7}  '
                      f'{match.n_instrs if hasattr(match,"n_instrs") else "?":>6}  {dstr}')

    # Secondary seed sweep (x86-64 Linux only — cross-arch Jaccard not meaningful)
    linux_versions = [(l, p, a) for l, p, a in VERSIONS if a == 'x86_64']
    print(f'\n--- Secondary seeds (direct Jaccard, Linux x86-64) ---')
    header = f'{"Seed":<40}' + ''.join(f'  {l.split()[0]:>9}' for l, _, _ in linux_versions)
    print(header)
    print('-' * len(header))

    corpora: dict[str, dict] = {}
    for label, path, arch in linux_versions:
        if not os.path.exists(path): continue
        with open(path, 'rb') as f: data = f.read()
        corpora[label] = build_corpus(path, data, arch)

    for sname in SECONDARY_SEEDS:
        short = sname.split('_')[-1].replace('0', '') if '_' in sname else sname[-30:]
        old_feat = corpora.get(seed_label, {}).get(sname)
        row = f'{short:<40}'
        for label, _, _ in linux_versions:
            corp = corpora.get(label, {})
            new_feat = corp.get(sname)
            if old_feat is None or new_feat is None:
                row += f'  {"N/A":>9}'
            else:
                jac_val = jaccard(old_feat.ngrams_4, new_feat.ngrams_4)
                row += f'  {jac_val:>9.4f}'
        print(row)


if __name__ == '__main__':
    main()
