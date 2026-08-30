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

Adjust VERSIONS paths to match your extracted junos-srxsme-*-domestic files.
"""

import sys, os, struct, subprocess, time
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))
import capstone

from modules.version_delta import FuncFeatures, FuncMatcher, jaccard, compute_patch_delta
from modules.semantic_search import SemanticSearcher

DB = '~/.ablation/func_id.db'

# Each entry: (label, path)
# All are ELF 32-bit MSB MIPS, symbols type A, not stripped.
VERSIONS = [
    ('11.4R3.7  (2012-05)',  '/tmp/junos-extract/srx-11.4/junos-srxsme-11.4R3.7-domestic'),
    ('11.4R7.5  (2013-03)',  '/tmp/junos-extract/srx-11.4R7/junos-srxsme-11.4R7.5-domestic'),
    ('11.4R11.4 (2015-07)',  '/tmp/junos-extract/srx-11.4R11/junos-srxsme-11.4R11.4-domestic'),
    ('12.1X46-D35 (2015-05)','/tmp/junos-extract/srx-12.1X46/junos-srxsme-12.1X46-D35.1-domestic'),
    ('15.1X49-D240 (2020-12)','/tmp/junos-extract/srx-15.1X49/junos-srxsme-15.1X49-D240.4-domestic'),
    ('22.4R3-S9  (2026-01)', '/tmp/junos-extract/srx-22.4/junos-srxsme-22.4R3-S9.3-domestic'),
    ('23.4R2-S5  (2025-06)', '/tmp/junos-extract/srx-23.4R2-S5/junos-srxsme-23.4R2-S5.5-domestic'),
    ('23.4R2-S8  (2026-05)', '/tmp/junos-extract/srx-23.4/junos-srxsme-23.4R2-S8.7-domestic'),
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
