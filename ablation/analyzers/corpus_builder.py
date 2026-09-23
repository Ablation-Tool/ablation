"""
corpus_builder.py -- Populate func_id.db with ANGR_INFERRED function records.

Enables SemanticSearcher.build_corpus() for binaries with no prior RE coverage,
such as libips.so.new / libav.so.new (FortiOS 8.0.0).

For each function in a binary (discovered via eh_frame FDE entries):
  - name      : 'fn_0x<va>' (stripped, no symbols)
  - role      : heuristically inferred from callee PLT names
  - call_targets : PLT names where resolved, else '0x<va>' hex strings
  - string_xrefs : string CONTENTS referenced via RIP-relative LEA (via xref index)
  - notes     : short role description for vuln_notes in describe_function()

Resulting DB rows are picked up by SemanticSearcher.build_corpus() (confidence
filter: CONFIRMED or ANGR_INFERRED) and encoded by all-mpnet-base-v2.

Usage:
    # Build corpus for a single binary
    cb = CorpusBuilder('~/.ablation/func_id.db')
    count = cb.build('/path/to/libips.so.new', product='libips', version='8.0.0')
    print(f'Indexed {count} functions')

    # Then run semantic search:
    from ablation.analyzers.semantic_search import SemanticSearcher
    searcher = SemanticSearcher('~/.ablation/func_id.db')
    n = searcher.build_corpus()
    results = searcher.query('SCTP chunk length underflow integer wrap', top_k=10)
"""

from __future__ import annotations

import json
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Role heuristics based on callee PLT names ────────────────────────────────

# PLT name -> role tag (first match wins)
_ROLE_HINTS: List[Tuple[List[str], str]] = [
    (['malloc', 'calloc', 'realloc', 'free', 'strdup'],    'HEAP_ALLOC'),
    (['strcpy', 'strncpy', 'strlcpy', 'strcat', 'strncat'], 'BUFFER_COPY'),
    (['memcpy', 'memmove', 'memset', 'bzero'],              'MEMORY_OP'),
    (['sprintf', 'snprintf', 'vsnprintf', 'fprintf'],       'FORMAT_STRING'),
    (['socket', 'bind', 'listen', 'accept', 'connect',
      'recv', 'recvfrom', 'send', 'sendto'],                'NETWORK_IO'),
    (['fopen', 'fread', 'fwrite', 'fclose', 'open',
      'read', 'write', 'close'],                            'FILE_IO'),
    (['pthread_mutex_lock', 'pthread_mutex_unlock',
      'sem_wait', 'sem_post'],                              'SYNCHRONIZATION'),
    (['EVP_', 'AES_', 'RSA_', 'SHA', 'MD5',
      'HMAC', 'hpke_', 'strap_'],                          'CRYPTO'),
    (['printf', 'fprintf', 'syslog', 'log_'],               'LOGGING'),
    (['tcl_eval', 'tcl_createinterp', 'tcl_getvar'],        'TCL_INTERP'),
    (['Tcl_Eval', 'Tcl_CreateInterp', 'Tcl_GetVar'],        'TCL_INTERP'),
]

# String content substrings -> role override
_STR_ROLE_HINTS: List[Tuple[str, str]] = [
    ('sctp', 'SCTP_HANDLER'),
    ('SCTP', 'SCTP_HANDLER'),
    ('diameter', 'DIAMETER_HANDLER'),
    ('Diameter', 'DIAMETER_HANDLER'),
    ('radius', 'RADIUS_HANDLER'),
    ('RADIUS', 'RADIUS_HANDLER'),
    ('http', 'HTTP_HANDLER'),
    ('HTTP', 'HTTP_HANDLER'),
    ('ssl', 'TLS_HANDLER'),
    ('SSL', 'TLS_HANDLER'),
    ('tls', 'TLS_HANDLER'),
    ('TLS', 'TLS_HANDLER'),
    ('ipsec', 'IPSEC_HANDLER'),
    ('IPsec', 'IPSEC_HANDLER'),
    ('gre', 'GRE_HANDLER'),
    ('GRE', 'GRE_HANDLER'),
    ('dns', 'DNS_HANDLER'),
    ('DNS', 'DNS_HANDLER'),
    ('ips_decode', 'IPS_DECODER'),
    ('ips_dsct', 'IPS_DISSECTOR'),
    ('av_', 'AV_SCANNER'),
]


def _infer_role(callee_labels: List[str], string_contents: List[str]) -> str:
    """Infer function role from callee names and referenced strings."""
    callee_lower = [c.lower() for c in callee_labels]

    # String-based role detection (more specific, check first)
    for frag, role in _STR_ROLE_HINTS:
        if any(frag in s for s in string_contents):
            return role

    # Callee-based role detection
    for hints, role in _ROLE_HINTS:
        for hint in hints:
            if any(hint.lower() in c for c in callee_lower):
                return role

    return 'UNKNOWN'


def _build_notes(callee_labels: List[str], string_contents: List[str],
                 callee_count: int) -> str:
    """Build notes text for describe_function vuln_notes field."""
    parts = []
    if callee_count > 0:
        parts.append(f'{callee_count} callees')
    sinks = {'strcpy', 'strcat', 'sprintf', 'system', 'popen', 'exec'}
    sink_calls = [c for c in callee_labels if any(s in c.lower() for s in sinks)]
    if sink_calls:
        parts.append(f"sinks: {' '.join(sink_calls[:4])}")
    proto_strings = [s for s in string_contents
                     if any(p in s.lower() for p in ['sctp', 'diameter', 'radius', 'http', 'gre', 'dns'])]
    if proto_strings:
        parts.append(f"proto: {' '.join(proto_strings[:3])}")
    return '; '.join(parts)


class CorpusBuilder:
    """
    Populates func_id.db with ANGR_INFERRED records for a binary.

    One instance per func_id.db path. Call build() for each binary you want
    indexed. Subsequent calls to SemanticSearcher.build_corpus() will pick up
    the inserted records (confidence='ANGR_INFERRED').
    """

    def __init__(self, db_path: str = '~/.ablation/func_id.db'):
        self.db_path = str(Path(db_path).expanduser())

    def build(
        self,
        binary_path: str,
        product: str = '',
        version: str = '',
        arch: str = 'x86-64',
        force_rebuild_ctx: bool = False,
        progress: bool = True,
    ) -> int:
        """Build corpus for binary_path and insert records into func_id.db.

        Args:
            binary_path : path to ELF binary
            product     : product name (e.g. 'libips', 'libav')
            version     : version string (e.g. '8.0.0')
            arch        : architecture (default 'x86-64')
            force_rebuild_ctx : force BinaryContext rebuild (clears cache)
            progress    : print progress dots

        Returns number of function records inserted.
        """
        from ablation.analyzers.binary_context import BinaryContext
        from ablation.analyzers.func_id_db import FuncDB, BinaryRecord, FuncRecord

        t0 = time.time()
        binary_path = str(Path(binary_path).expanduser())
        binary_name = Path(binary_path).name

        if progress:
            print(f'[corpus_builder] loading BinaryContext for {binary_name}...')

        ctx = BinaryContext.load_or_build(binary_path, force_rebuild=force_rebuild_ctx)

        # Ensure xref index is populated (may be missing in old caches)
        if not ctx._str_xref_idx:
            if progress:
                print(f'[corpus_builder] building RIP-relative xref index...')
            ctx.build_xref_index(binary_path)

        if progress:
            print(f'[corpus_builder] {len(ctx.func_starts)} functions, '
                  f'{len(ctx.strings)} strings, '
                  f'{sum(len(v) for v in ctx._str_xref_idx.values())} xref pairs')

        with FuncDB.open(self.db_path) as db:
            # Register binary
            sha = ctx.sha256
            path_hint = str(Path(binary_path).resolve())
            if not product:
                product = binary_name.split('.')[0]

            db.add_binary(BinaryRecord(
                sha256=sha,
                path_hint=path_hint,
                product=product,
                arch=arch,
                version=version,
                notes=f'ANGR_INFERRED corpus build; {len(ctx.func_starts)} funcs',
            ))

            # Build function records
            records: List[FuncRecord] = []
            for func_va in ctx.func_starts:
                callee_pairs = ctx.callees_of(func_va)       # [(va, label), ...]
                callee_labels = [
                    label if label else f'0x{va:x}'
                    for va, label in callee_pairs
                ]
                str_pairs = ctx.strings_in_func(func_va)     # [(sva, content), ...]
                str_contents = [content for _, content in str_pairs]

                role = _infer_role(callee_labels, str_contents)
                notes = _build_notes(callee_labels, str_contents, len(callee_labels))

                # call_targets: PLT names first, then hex VAs
                call_targets_for_db = callee_labels[:16]

                # string_xrefs: store contents (not VAs) so BERT gets semantic text
                string_xrefs_for_db = [c[:80] for c in str_contents[:12]]

                records.append(FuncRecord(
                    binary_sha256=sha,
                    va=func_va,
                    name=f'fn_0x{func_va:x}',
                    role=role,
                    confidence='ANGR_INFERRED',
                    call_targets=call_targets_for_db,
                    string_xrefs=string_xrefs_for_db,
                    notes=notes,
                ))

            db._batch_add_funcs(records)

            elapsed = time.time() - t0
            if progress:
                print(f'[corpus_builder] inserted {len(records)} records in {elapsed:.1f}s')

            return len(records)

    def build_multi(
        self,
        binaries: List[Tuple[str, str, str]],
        progress: bool = True,
    ) -> Dict[str, int]:
        """Build corpus for multiple binaries.

        Args:
            binaries: list of (binary_path, product, version) tuples
        Returns dict of binary_name -> count.
        """
        results = {}
        for binary_path, product, version in binaries:
            name = Path(binary_path).name
            try:
                count = self.build(binary_path, product=product,
                                   version=version, progress=progress)
                results[name] = count
            except Exception as exc:
                results[name] = -1
                if progress:
                    print(f'[corpus_builder] ERROR on {name}: {exc}')
        return results

    def status(self) -> Dict[str, int]:
        """Return summary of current func_id.db contents."""
        from ablation.analyzers.func_id_db import FuncDB
        with FuncDB.open(self.db_path) as db:
            return db.summary()


def build_fortios_corpus(
    libips_path: str,
    libav_path: str,
    db_path: str = '~/.ablation/func_id.db',
    version: str = '8.0.0',
) -> Dict[str, int]:
    """Convenience function: build corpus for FortiOS 8.x libips + libav.

    Run this once after loading libips.so.new and libav.so.new. Then
    SemanticSearcher.build_corpus() returns the full function set.

    Example:
        counts = build_fortios_corpus(
            '/path/to/libips.so.new',
            '/path/to/libav.so.new',
        )
        print(counts)  # {'libips.so.new': 8234, 'libav.so.new': 6891}
    """
    cb = CorpusBuilder(db_path)
    return cb.build_multi([
        (libips_path, 'libips', version),
        (libav_path,  'libav',  version),
    ])
