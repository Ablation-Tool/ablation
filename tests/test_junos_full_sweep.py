"""
Juniper Junos SRX MIPS kernel — full automated function sweep.

Methodology (replicates the Lina approach):
  1. Build nm corpus for every version.
  2. For every function present in the seed version, compute mnemonic
     4-gram Jaccard against every other version where the function exists.
  3. Track the Jaccard trajectory across the 14-version timeline.
  4. Rank by min(Jaccard) — functions that diverge most from the seed are
     the top RE targets.

Memory strategy: seed corpus stays in memory; each non-seed version is loaded,
processed, then explicitly freed before the next version loads.
Peak: ~500MB (seed + one version). Was: ~3.5GB (all 14 at once, caused OOM).

Seed: 11.4R3.7 (2012-05), earliest well-populated version.
Output: ranked outlier table + full trajectory → tests/junos_sweep_results.txt
"""

import sys, os, struct, subprocess, time, gc
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))
import capstone

_BASE = '/media/cowboy/research/juniper-firmware/extracted'

VERSIONS = [
    ('10.4R7.5',     f'{_BASE}/srx-10.4/junos-srxsme-10.4R7.5-domestic'),
    ('11.4R3.7',     f'{_BASE}/srx-11.4/junos-srxsme-11.4R3.7-domestic'),        # seed
    ('11.4R7.5',     f'{_BASE}/srx-11.4R7/junos-srxsme-11.4R7.5-domestic'),
    ('11.4R11.4',    f'{_BASE}/srx-11.4R11/junos-srxsme-11.4R11.4-domestic'),
    ('12.1X46-D35',  f'{_BASE}/srx-12.1X46/junos-srxsme-12.1X46-D35.1-domestic'),
    ('12.1X46-D40',  f'{_BASE}/srx-12.1X46-D40/junos-srxsme-12.1X46-D40.2-domestic'),
    ('15.1X49-D240', f'{_BASE}/srx-15.1X49/junos-srxsme-15.1X49-D240.4-domestic'),
    ('21.4R3-S3',    f'{_BASE}/srx-21.4R3-S3/junos-srxsme-21.4R3-S3.4-domestic'),
    ('21.4R3-S4',    f'{_BASE}/srx-21.4R3-S4/junos-srxsme-21.4R3-S4.9-domestic'),
    ('22.4R3-S9',    f'{_BASE}/srx-22.4/junos-srxsme-22.4R3-S9.3-domestic'),
    ('23.4R2-S3',    f'{_BASE}/srx-23.4R2-S3/junos-srxsme-23.4R2-S3.9-domestic'),
    ('23.4R2-S5',    f'{_BASE}/srx-23.4R2-S5/junos-srxsme-23.4R2-S5.5-domestic'),
    ('23.4R2-S7',    f'{_BASE}/srx-23.4R2-S7/junos-srxsme-23.4R2-S7.4-domestic'),
    ('23.4R2-S8',    f'{_BASE}/srx-23.4/junos-srxsme-23.4R2-S8.7-domestic'),
]

SEED_LABEL = '11.4R3.7'
TOP_N      = 50


# ── ELF helpers ──────────────────────────────────────────────────────────────

def _text_range(data):
    """Return (lo_va, hi_va) for .text section; fallback to kernel VA range."""
    e_shoff = struct.unpack_from('>I', data, 0x20)[0]
    e_shnum = struct.unpack_from('>H', data, 0x30)[0]
    e_shent = struct.unpack_from('>H', data, 0x2e)[0]
    e_shstr = struct.unpack_from('>H', data, 0x32)[0]
    str_sh  = e_shoff + e_shstr * e_shent
    str_off = struct.unpack_from('>I', data, str_sh + 0x10)[0]
    for i in range(e_shnum):
        sh      = e_shoff + i * e_shent
        sh_type = struct.unpack_from('>I', data, sh + 4)[0]
        sh_addr = struct.unpack_from('>I', data, sh + 0xc)[0]
        sh_size = struct.unpack_from('>I', data, sh + 0x14)[0]
        n_off   = struct.unpack_from('>I', data, sh)[0]
        name    = data[str_off + n_off: str_off + n_off + 8].split(b'\x00')[0]
        if name == b'.text' and sh_type == 1:
            return sh_addr, sh_addr + sh_size
    return 0x80100000, 0x81000000


def _foff(data, va):
    """Resolve MIPS VA to file offset via PT_LOAD segments."""
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


def _build_corpus(path, data):
    """
    Return {name: (va, frozenset_of_4grams)} for all text-range functions.

    Uses nm -D for symbol discovery; falls back on symbol types A/T/t
    filtered to the .text VA range (MIPS kernel absolute symbols are type A).
    """
    lo, hi = _text_range(data)
    out = subprocess.check_output(['nm', '-D', path], text=True, stderr=subprocess.DEVNULL)
    md  = capstone.Cs(capstone.CS_ARCH_MIPS,
                      capstone.CS_MODE_MIPS32 + capstone.CS_MODE_BIG_ENDIAN)
    corpus = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) != 3 or p[1] not in ('A', 'T', 't'):
            continue
        try:
            va = int(p[0], 16)
        except ValueError:
            continue
        if not (lo <= va < hi):
            continue
        name = p[2]
        fo = _foff(data, va)
        if fo is None:
            continue
        mnems = []
        saw_jr = False
        for insn in md.disasm(data[fo: fo + 1604], va):
            mnems.append(insn.mnemonic)
            if insn.mnemonic == 'jr' and '$ra' in insn.op_str:
                saw_jr = True
                continue
            if saw_jr:
                break
            if len(mnems) > 400:
                break
        if len(mnems) < 6:
            continue
        grams = frozenset(zip(mnems, mnems[1:], mnems[2:], mnems[3:]))
        corpus[name] = (va, grams)
    return corpus


def _jaccard(a, b):
    if not a and not b: return 1.0
    if not a or not b:  return 0.0
    return len(a & b) / len(a | b)


# ── Main sweep ────────────────────────────────────────────────────────────────

def main():
    available = [(lbl, path) for lbl, path in VERSIONS if os.path.exists(path)]
    print(f'Versions available: {len(available)}/{len(VERSIONS)}')
    for lbl, path in VERSIONS:
        print(f'  [{"OK" if os.path.exists(path) else "MISSING"}] {lbl}')
    print()

    # ── Build seed corpus (stays in memory throughout) ────────────────────────
    seed_entry = next(((l, p) for l, p in available if l == SEED_LABEL), None)
    if seed_entry is None:
        print(f'Seed {SEED_LABEL} not available'); return

    print(f'Building seed corpus ({SEED_LABEL})...')
    t0 = time.time()
    seed_data = open(seed_entry[1], 'rb').read()
    seed = _build_corpus(seed_entry[1], seed_data)
    del seed_data; gc.collect()
    print(f'  {SEED_LABEL:<18} {len(seed):>5} functions  ({time.time()-t0:.0f}s)\n')

    # Per-function tracking: {fname: {lbl: jaccard_or_None}}
    # Seed version = 1.0 by definition
    func_rows = {fname: {SEED_LABEL: 1.0} for fname in seed}

    non_seed = [(l, p) for l, p in available if l != SEED_LABEL]
    labels   = [lbl for lbl, _ in available]

    print('Streaming non-seed versions (load → compute → free)...')
    for lbl, path in non_seed:
        t0 = time.time()
        data   = open(path, 'rb').read()
        corpus = _build_corpus(path, data)
        del data; gc.collect()
        print(f'  {lbl:<18} {len(corpus):>5} functions  ({time.time()-t0:.0f}s)')

        for fname, (_, seed_grams) in seed.items():
            entry = corpus.get(fname)
            func_rows[fname][lbl] = (
                None if entry is None else _jaccard(seed_grams, entry[1])
            )
        del corpus; gc.collect()

    # ── Rank ──────────────────────────────────────────────────────────────────
    results = []
    for fname, row in func_rows.items():
        vals = [v for v in row.values() if v is not None]
        if len(vals) < 3:
            continue
        min_jac    = min(vals)
        drop_count = sum(1 for v in vals if v < 0.9)
        results.append((min_jac, drop_count, fname, row))
    results.sort(key=lambda x: (x[0], -x[1]))

    # ── Print top N ───────────────────────────────────────────────────────────
    ver_headers = ''.join(f'  {lbl[:12]:>12}' for lbl in labels)
    print(f'\n{"Function":<40}  {"MinJac":>7}  {"Drops":>5}' + ver_headers)
    print('-' * (40 + 7 + 5 + 5 + len(labels) * 14))

    for min_jac, drops, fname, row in results[:TOP_N]:
        traj = ''
        for lbl in labels:
            v = row.get(lbl)
            if v is None:
                traj += f'  {"---":>12}'
            elif lbl == SEED_LABEL:
                traj += f'  {"(seed)":>12}'
            else:
                traj += f'  {v:>12.4f}'
        print(f'{fname:<40}  {min_jac:>7.4f}  {drops:>5}{traj}')

    print(f'\nTotal swept: {len(results)}'
          f'  |  Jac<0.3: {sum(1 for j,*_ in results if j<0.3)}'
          f'  |  Jac<0.5: {sum(1 for j,*_ in results if j<0.5)}'
          f'  |  Jac<0.8: {sum(1 for j,*_ in results if j<0.8)}')

    # ── Write full results ────────────────────────────────────────────────────
    out_path = os.path.join(os.path.dirname(__file__), 'junos_sweep_results.txt')
    with open(out_path, 'w') as f:
        f.write(f'Junos SRX MIPS full sweep — seed {SEED_LABEL}\n')
        f.write(f'{"Function":<40}  {"MinJac":>7}  {"Drops":>5}' + ver_headers + '\n')
        f.write('-' * 200 + '\n')
        for min_jac, drops, fname, row in results:
            traj = ''.join(
                f'  {"---":>12}' if row.get(lbl) is None
                else f'  {"(seed)":>12}' if lbl == SEED_LABEL
                else f'  {row[lbl]:>12.4f}'
                for lbl in labels
            )
            f.write(f'{fname:<40}  {min_jac:>7.4f}  {drops:>5}{traj}\n')
    print(f'\nFull results → {out_path}')


if __name__ == '__main__':
    main()
