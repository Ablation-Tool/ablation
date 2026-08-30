"""
Juniper Junos SRX MIPS kernel — full automated function sweep.

Methodology (replicates the Lina approach):
  1. Build nm corpus for every version.
  2. For every function present in the seed version, compute mnemonic
     4-gram Jaccard against every other version where the function exists.
  3. Track the Jaccard trajectory across the 15-version timeline.
  4. Rank by min(Jaccard) — functions that diverge most from the seed are
     the top RE targets.

Seed: 11.4R3.7 (2012-05), the earliest well-populated version.

Output: ranked outlier table + per-function trajectory for the top N.
"""

import sys, os, struct, subprocess, time
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))
import capstone

_BASE = '/media/cowboy/research/juniper-firmware/extracted'

VERSIONS = [
    ('10.4R7.5',   f'{_BASE}/srx-10.4/junos-srxsme-10.4R7.5-domestic'),
    ('11.4R3.7',   f'{_BASE}/srx-11.4/junos-srxsme-11.4R3.7-domestic'),        # seed
    ('11.4R7.5',   f'{_BASE}/srx-11.4R7/junos-srxsme-11.4R7.5-domestic'),
    ('11.4R11.4',  f'{_BASE}/srx-11.4R11/junos-srxsme-11.4R11.4-domestic'),
    ('12.1X46-D35',f'{_BASE}/srx-12.1X46/junos-srxsme-12.1X46-D35.1-domestic'),
    ('12.1X46-D40',f'{_BASE}/srx-12.1X46-D40/junos-srxsme-12.1X46-D40.2-domestic'),
    ('15.1X49-D240',f'{_BASE}/srx-15.1X49/junos-srxsme-15.1X49-D240.4-domestic'),
    ('21.4R3-S3',  f'{_BASE}/srx-21.4R3-S3/junos-srxsme-21.4R3-S3.4-domestic'),
    ('21.4R3-S4',  f'{_BASE}/srx-21.4R3-S4/junos-srxsme-21.4R3-S4.9-domestic'),
    ('22.4R3-S9',  f'{_BASE}/srx-22.4/junos-srxsme-22.4R3-S9.3-domestic'),
    ('23.4R2-S3',  f'{_BASE}/srx-23.4R2-S3/junos-srxsme-23.4R2-S3.9-domestic'),
    ('23.4R2-S5',  f'{_BASE}/srx-23.4R2-S5/junos-srxsme-23.4R2-S5.5-domestic'),
    ('23.4R2-S7',  f'{_BASE}/srx-23.4R2-S7/junos-srxsme-23.4R2-S7.4-domestic'),
    ('23.4R2-S8',  f'{_BASE}/srx-23.4/junos-srxsme-23.4R2-S8.7-domestic'),
]

SEED_LABEL = '11.4R3.7'
TOP_N      = 50    # print top N outliers by min Jaccard


# ── ELF helpers ──────────────────────────────────────────────────────────────

def _text_range(data):
    e_shoff = struct.unpack_from('>I', data, 0x20)[0]
    e_shnum = struct.unpack_from('>H', data, 0x30)[0]
    e_shent = struct.unpack_from('>H', data, 0x2e)[0]
    e_shstr = struct.unpack_from('>H', data, 0x32)[0]
    str_off = struct.unpack_from('>I', data, e_shoff + e_shstr * e_shent + 0x10)[0]
    for i in range(e_shnum):
        sh = e_shoff + i * e_shent
        sh_type = struct.unpack_from('>I', data, sh + 4)[0]
        sh_addr = struct.unpack_from('>I', data, sh + 0xc)[0]
        sh_size = struct.unpack_from('>I', data, sh + 0x14)[0]
        name = data[str_off + struct.unpack_from('>I', data, sh)[0]:
                    str_off + struct.unpack_from('>I', data, sh)[0] + 8].split(b'\x00')[0]
        if name == b'.text' and sh_type == 1:
            return sh_addr, sh_addr + sh_size
    return 0x80100000, 0x81000000


def _foff(data, va):
    e_phoff = struct.unpack_from('>I', data, 0x1c)[0]
    e_phnum = struct.unpack_from('>H', data, 0x2c)[0]
    e_phent = struct.unpack_from('>H', data, 0x2a)[0]
    for i in range(e_phnum):
        off = e_phoff + i * e_phent
        if struct.unpack_from('>I', data, off)[0] == 1:
            p_offset = struct.unpack_from('>I', data, off + 4)[0]
            p_vaddr  = struct.unpack_from('>I', data, off + 8)[0]
            p_filesz = struct.unpack_from('>I', data, off + 0x10)[0]
            if p_vaddr <= va < p_vaddr + p_filesz:
                return p_offset + (va - p_vaddr)
    return None


def _build_corpus(path, data):
    """Return {name: (va, frozenset_of_4grams)} for all text-range functions."""
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
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


# ── Main sweep ────────────────────────────────────────────────────────────────

def main():
    available = [(lbl, path) for lbl, path in VERSIONS if os.path.exists(path)]
    print(f'Versions available: {len(available)}/{len(VERSIONS)}')
    for lbl, path in VERSIONS:
        status = 'OK' if os.path.exists(path) else 'MISSING'
        print(f'  [{status}] {lbl}')
    print()

    # Build corpora
    corpora = {}
    for lbl, path in available:
        t0 = time.time()
        data = open(path, 'rb').read()
        c = _build_corpus(path, data)
        print(f'  {lbl:<18} {len(c):>5} functions  ({time.time()-t0:.0f}s)')
        corpora[lbl] = c

    seed = corpora.get(SEED_LABEL)
    if seed is None:
        print(f'Seed {SEED_LABEL} not available'); return

    labels = [lbl for lbl, _ in available]
    seed_idx = labels.index(SEED_LABEL)

    print(f'\nSeed: {SEED_LABEL}  ({len(seed)} functions)')
    print(f'Sweeping {len(seed)} seed functions against {len(labels)-1} other versions...\n')

    # For each seed function, compute Jaccard against every other version
    results = []
    for fname, (seed_va, seed_grams) in seed.items():
        row = {}   # label → jaccard
        for lbl in labels:
            if lbl == SEED_LABEL:
                row[lbl] = 1.0
                continue
            c = corpora.get(lbl, {})
            entry = c.get(fname)
            if entry is None:
                row[lbl] = None   # absent
            else:
                row[lbl] = _jaccard(seed_grams, entry[1])
        # Only rank functions present in at least 3 non-seed versions
        present = [v for v in row.values() if v is not None]
        if len(present) < 3:
            continue
        min_jac   = min(present)
        # Score = min Jaccard weighted by number of versions where it drops below 0.9
        drop_count = sum(1 for v in present if v is not None and v < 0.9)
        results.append((min_jac, drop_count, fname, row))

    results.sort(key=lambda x: (x[0], -x[1]))  # lowest min_jac first

    # Print trajectory table for top N
    ver_headers = ''.join(f'  {lbl[:12]:>12}' for lbl in labels)
    print(f'{"Function":<35}  {"MinJac":>7}  {"Drops":>5}' + ver_headers)
    print('-' * (35 + 7 + 5 + 5 + len(labels) * 14))

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
        print(f'{fname:<35}  {min_jac:>7.4f}  {drops:>5}{traj}')

    print(f'\nTotal swept: {len(results)}  |  Jac<0.5: {sum(1 for j,*_ in results if j<0.5)}'
          f'  |  Jac<0.8: {sum(1 for j,*_ in results if j<0.8)}')

    # Write full results to file for later RE targeting
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
