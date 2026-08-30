"""
Honeywell Tridium Niagara Framework native layer patch attribution.

Target: libnre.so (Niagara Runtime Engine) — the JNI native layer
        handling authentication, session management, and platform services.

Key finding: getSupportedAuthenticationTypes0 in libnre.so was rewritten
between 4.10.10.40 and 4.13.x — 73 instructions → 29, Jaccard 1.0 → 0.1375.
The dynamic PAM/auth-module lookup (including repe cmpsb string comparisons
against auth type names) was replaced with a hardcoded static response.
This change is invisible from Java decompilation alone.

Approach: symbolized corpus (nm -D) instead of prologue scan.
For any binary with exported symbols, nm-based corpus construction is
more accurate than prologue pattern matching.

Adjust VERSIONS paths to match your extracted dist locations.
"""

import sys, os, time, struct, subprocess
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))
import capstone

from modules.version_delta import FuncFeatures, FuncMatcher, jaccard, compute_patch_delta
from modules.semantic_search import SemanticSearcher

DB = '~/.ablation/func_id.db'

# Extracted libnre.so paths. Run extract_niagara_dists.sh or extract manually:
#   unzip -p <supervisor>.zip "dist/<ver>/nre-core-linux-x64.dist" | \
#     unzip -j /dev/stdin "libnre.so" -d <outdir>/
VERSIONS = [
    ('4.10.10.40', '/tmp/niagara-extract/41010040/native/libnre.so'),   # pre-patch
    ('4.13.0.186', '/tmp/niagara-extract/4130186/native/libnre.so'),    # boundary candidate
    ('4.13.2.18',  '/tmp/niagara-extract/4132018/native/libnre.so'),    # boundary candidate
    ('4.13.3.48',  '/tmp/niagara-extract/4133348/native/libnre.so'),    # PATCHED
    ('4.14.0.162', '/tmp/niagara-extract/4140162/native/libnre.so'),    # PATCHED
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


def _file_offset(data: bytes, va: int) -> int:
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


def extract_func(data: bytes, va: int) -> tuple[list[str], list[str]]:
    fo  = _file_offset(data, va)
    raw = data[fo: fo + 4096]
    md  = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    lines, calls = [], []
    for insn in md.disasm(raw, va):
        op = f'{insn.mnemonic} {insn.op_str}'.strip()
        lines.append(op)
        if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
            calls.append(insn.op_str)
        if insn.mnemonic in ('ret', 'retq', 'retn'):
            break
        if insn.mnemonic in ('jmp', 'jmpq'):
            try:
                if abs(int(insn.op_str, 16) - va) > 0x20000:
                    break
            except ValueError:
                break
    return lines, calls


def build_corpus(path: str, data: bytes) -> dict[str, FuncFeatures]:
    """Build FuncFeatures keyed by symbol name from exported text symbols."""
    out = subprocess.check_output(['nm', '-D', path], text=True, stderr=subprocess.DEVNULL)
    corpus: dict[str, FuncFeatures] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == 'T':
            try:
                va   = int(parts[0], 16)
                name = parts[2]
                asm, calls = extract_func(data, va)
                if len(asm) >= 4:
                    corpus[name] = FuncFeatures.from_disasm_lines(va, name, asm, calls)
            except Exception:
                pass
    return corpus


def main():
    ss      = SemanticSearcher(DB)
    ss.build_corpus()
    matcher = FuncMatcher(semantic_searcher=ss)

    # Load seed corpus
    seed_path = dict(VERSIONS)[SEED_VERSION]
    if not os.path.exists(seed_path):
        print(f'Seed path missing: {seed_path}')
        return
    with open(seed_path, 'rb') as f:
        seed_data = f.read()
    seed_corpus = build_corpus(seed_path, seed_data)
    seed = seed_corpus.get(SEED_NAME)
    if seed is None:
        print(f'Seed function not found in {SEED_VERSION}: {SEED_NAME}')
        return

    short_name = SEED_NAME.split('_')[-1].replace('0', '')
    print(f'Primary seed: {short_name}')
    print(f'  from {SEED_VERSION}  VA=0x{seed.va:x}  instrs={seed.n_instrs}\n')
    print(f'{"Version":<15} {"N":>5} {"VA":>10}  {"Jac":>6}  {"Sem":>6}  {"Conf":<8}  Patched  Delta')
    print('-' * 80)

    for label, path in VERSIONS:
        if not os.path.exists(path):
            print(f'{label:<15}  (skipped — path missing)')
            continue
        with open(path, 'rb') as f:
            data = f.read()
        t0     = time.time()
        corpus = build_corpus(path, data)
        feats  = list(corpus.values())

        # Check if exact-name match exists (symbolized path)
        exact = corpus.get(SEED_NAME)
        if exact is not None:
            jac_val = jaccard(seed.ngrams_4, exact.ngrams_4)
            dlt     = compute_patch_delta(seed, exact)
            dstr    = (f'+{len(dlt.added)}' if dlt.added else '') + \
                      (f'-{len(dlt.removed)}' if dlt.removed else '')
            elapsed = time.time() - t0
            print(f'{label:<15} {len(feats):>5} {hex(exact.va):>10}  '
                  f'{jac_val:.4f}  {"(sym)":>6}  {"EXACT":<8}  '
                  f'{"YES" if dlt.is_patched else "NO":>7}  {dstr}')
        else:
            # Fall back to homolog search
            match = matcher.find_homolog(seed, feats)
            elapsed = time.time() - t0
            if match is None:
                print(f'{label:<15} {len(feats):>5}  NOT FOUND')
            else:
                dstr = (f'+{len(match.delta.added)}' if match.delta.added else '') + \
                       (f'-{len(match.delta.removed)}' if match.delta.removed else '')
                print(f'{label:<15} {len(feats):>5} {hex(match.va):>10}  '
                      f'{match.jaccard:.4f}  {match.semantic_score:.4f}  '
                      f'{match.confidence:<8}  '
                      f'{"YES" if match.delta.is_patched else "NO":>7}  {dstr}')

    # Secondary seed sweep
    print(f'\n--- Secondary seeds (direct Jaccard, symbolized) ---')
    print(f'{"Seed":<40} {"4.10.10":>8}  {"4.13.3":>8}  {"4.14.0":>8}')
    print('-' * 70)

    corpora: dict[str, dict] = {}
    for label, path in VERSIONS:
        if not os.path.exists(path): continue
        with open(path, 'rb') as f: data = f.read()
        corpora[label] = build_corpus(path, data)

    for sname in SECONDARY_SEEDS:
        short = sname.split('_')[-1].replace('0', '') if '_' in sname else sname[-30:]
        old_feat = corpora.get('4.10.10.40', {}).get(sname)
        row = f'{short:<40}'
        for label, _ in VERSIONS:
            corp = corpora.get(label, {})
            new_feat = corp.get(sname)
            if old_feat is None or new_feat is None:
                row += f'  {"N/A":>8}'
            else:
                jac_val = jaccard(old_feat.ngrams_4, new_feat.ngrams_4)
                row += f'  {jac_val:>8.4f}'
        print(row)


if __name__ == '__main__':
    main()
