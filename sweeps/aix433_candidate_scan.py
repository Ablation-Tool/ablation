#!/usr/bin/env python3 -I
"""
aix433_candidate_scan.py — streaming exec-sink candidate scanner for AIX 4.3.3 ML11

Scans aix433ml11.tar.gz + aixpost433ml11.tar.gz in memory (no /tmp extraction).
For each BFF → each XCOFF32 binary → checks LOADER section imports for exec-class
and overflow-class sinks.

Usage:
    python3 -I sweeps/aix433_candidate_scan.py
"""
import sys, io, tarfile, struct
sys.path.insert(0, '/home/cowboy/ablation')

from ablation.analyzers.aix_bff_extractor import AixBffExtractor
from ablation.core.xcoff_parser import parse

EXEC_SINKS = {
    'system', 'popen', 'execve', 'execl', 'execle', 'execlp',
    'execv', 'execvp', 'execvpe', 'fork', 'vfork', 'popen',
}
OVERFLOW_SINKS = {
    'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf',
    'scanf', 'sscanf', 'fscanf', 'getwd',
}
INTERESTING_SINKS = EXEC_SINKS | OVERFLOW_SINKS

ARCHIVES = [
    '/media/cowboy/research/IBM-RE/AIX-4.3.3-ML11/aix433ml11.tar.gz',
    '/media/cowboy/research/IBM-RE/AIX-4.3.3-ML11/aixpost433ml11.tar.gz',
]

# Binaries already fully analyzed
ALREADY_DONE = {
    'acledit', 'libauthm.a', 'shr.o', 'rpc.rwalld', 'rwalld',
    'yppasswd', 'rwhod', 'enroll', 'timedc', 'trpt', 'gettable',
    'ruptime', 'hostid',
}

def get_imports(xcoff_bytes, name_hint):
    try:
        xb = parse(name_hint, data=xcoff_bytes)
        return {sym.name for sym in xb.imports}
    except Exception:
        return set()

def scan_archive(path):
    print(f'[+] Scanning {path}', flush=True)
    candidates = []  # (bff_name, xcoff_name, sinks_found)
    bff_count = 0
    xcoff_count = 0

    try:
        tf = tarfile.open(path, 'r:gz')
    except Exception as e:
        print(f'    ERROR opening tar: {e}')
        return candidates

    for member in tf.getmembers():
        if not member.name.endswith('.bff'):
            continue
        bff_count += 1
        if bff_count % 100 == 0:
            print(f'    {bff_count} BFFs scanned, {xcoff_count} XCOFFs found, {len(candidates)} candidates ...', flush=True)

        try:
            fobj = tf.extractfile(member)
            if fobj is None:
                continue
            bff_data = fobj.read()
        except Exception:
            continue

        extractor = AixBffExtractor(bff_data)
        try:
            for xcoff_name, xcoff_bytes in extractor.extract():
                xcoff_count += 1
                base = xcoff_name.split('/')[-1]
                if base in ALREADY_DONE:
                    continue
                imports = get_imports(xcoff_bytes, xcoff_name)
                interesting = imports & INTERESTING_SINKS
                if interesting:
                    exec_found = interesting & EXEC_SINKS
                    overflow_found = interesting & OVERFLOW_SINKS
                    candidates.append({
                        'bff': member.name,
                        'binary': xcoff_name,
                        'exec': sorted(exec_found),
                        'overflow': sorted(overflow_found),
                        'size': len(xcoff_bytes),
                    })
        except Exception:
            continue

    tf.close()
    print(f'    Done: {bff_count} BFFs, {xcoff_count} XCOFFs, {len(candidates)} candidates')
    return candidates


def main():
    all_candidates = []
    for arch in ARCHIVES:
        all_candidates.extend(scan_archive(arch))

    # Deduplicate by binary basename
    seen = {}
    for c in all_candidates:
        base = c['binary'].split('/')[-1]
        if base not in seen:
            seen[base] = c
        else:
            # Merge exec/overflow lists
            seen[base]['exec'] = sorted(set(seen[base]['exec']) | set(c['exec']))
            seen[base]['overflow'] = sorted(set(seen[base]['overflow']) | set(c['overflow']))

    # Sort: exec-class first (higher risk), then by binary name
    sorted_cands = sorted(seen.values(), key=lambda c: (0 if c['exec'] else 1, c['binary']))

    print(f'\n=== CANDIDATE SUMMARY ({len(sorted_cands)} unique binaries) ===\n')
    for i, c in enumerate(sorted_cands, 1):
        print(f'  {i:3d}. {c["binary"]:<40s}  exec={c["exec"]}  overflow={c["overflow"]}')

    return sorted_cands


if __name__ == '__main__':
    results = main()
    print(f'\n[DONE] {len(results)} candidates')
