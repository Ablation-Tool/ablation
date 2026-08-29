#!/usr/bin/env python3
"""
func_id_db.py — Function Identity Database for ablation.

Stores confirmed function names, roles, and signatures across Cisco binary
versions. When ablation encounters a new binary, it matches unknown functions
against this database by:
  1. Byte-pattern signature (exact or fuzzy via wildcard bytes)
  2. Call-graph neighborhood (who calls whom)
  3. Struct field access offsets (for struct-pointer-heavy init functions)
  4. String xrefs (error messages, format strings anchored to function)

Pre-seeded from confirmed RE work:
  - lina x86-64: 17+ versions, RADIUS/AAA/HPKE functions, gp_obj offsets
  - AnyConnect vpnagentd: STRAP/HPKE/IPC classes, TOCTOU pair
  - cisco_re_engine: auth_hunt string signatures

Usage:
    db = FuncDB.open('~/.ablation/func_id.db')
    matches = db.match_by_sig(binary_bytes, va)
    matches = db.match_by_struct_offset('gp_name', 0x2b0)
    db.add(FuncRecord(...))
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Connection settings applied at every open (not stored in file)
# ─────────────────────────────────────────────────────────────────────────────

_PRAGMAS = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA cache_size   = -8000;
PRAGMA temp_store   = MEMORY;
"""

# ─────────────────────────────────────────────────────────────────────────────
# Schema  (version tracked in user_version)
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMA_VERSION = 2

_DDL = """
CREATE TABLE IF NOT EXISTS binaries (
    id          INTEGER PRIMARY KEY,
    sha256      TEXT    NOT NULL UNIQUE,
    path_hint   TEXT    NOT NULL DEFAULT '',
    product     TEXT    NOT NULL DEFAULT '',
    arch        TEXT    NOT NULL DEFAULT 'x86-64',
    version     TEXT    NOT NULL DEFAULT '',
    notes       TEXT    NOT NULL DEFAULT '',
    added_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS functions (
    id              INTEGER PRIMARY KEY,
    binary_id       INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    va              INTEGER NOT NULL,
    name            TEXT    NOT NULL,
    demangled       TEXT    NOT NULL DEFAULT '',
    role            TEXT    NOT NULL DEFAULT 'UNKNOWN',
    confidence      TEXT    NOT NULL DEFAULT 'CANDIDATE'
                    CHECK(confidence IN ('CONFIRMED','ANGR_INFERRED','CANDIDATE')),
    sig_bytes       TEXT    NOT NULL DEFAULT '',
    sig_mask        TEXT    NOT NULL DEFAULT '',
    sig_len         INTEGER NOT NULL DEFAULT 0,
    call_targets    TEXT    NOT NULL DEFAULT '[]',
    callers         TEXT    NOT NULL DEFAULT '[]',
    string_xrefs    TEXT    NOT NULL DEFAULT '[]',
    struct_accesses TEXT    NOT NULL DEFAULT '[]',
    notes           TEXT    NOT NULL DEFAULT '',
    version_str     TEXT    NOT NULL DEFAULT '',
    UNIQUE(binary_id, va)
);

-- FK index: every join on binary_id needs this
CREATE INDEX IF NOT EXISTS idx_functions_binary_id ON functions(binary_id);
-- Common query columns
CREATE INDEX IF NOT EXISTS idx_functions_name       ON functions(name);
CREATE INDEX IF NOT EXISTS idx_functions_role       ON functions(role) WHERE role != 'UNKNOWN';
CREATE INDEX IF NOT EXISTS idx_functions_sig_prefix ON functions(sig_bytes) WHERE sig_len > 0;
-- Partial index for confirmed-only lookups
CREATE INDEX IF NOT EXISTS idx_functions_confirmed
    ON functions(name, role) WHERE confidence = 'CONFIRMED';

-- Struct identity is independent of any function.
-- version_str NOT NULL DEFAULT '' so UNIQUE constraint works without NULL ambiguity.
CREATE TABLE IF NOT EXISTS struct_fields (
    id          INTEGER PRIMARY KEY,
    struct_name TEXT    NOT NULL,
    field_name  TEXT    NOT NULL,
    offset      INTEGER NOT NULL,
    width       INTEGER NOT NULL DEFAULT 8,
    version_str TEXT    NOT NULL DEFAULT '',
    binary_id   INTEGER REFERENCES binaries(id) ON DELETE SET NULL,
    confidence  TEXT    NOT NULL DEFAULT 'CONFIRMED'
                CHECK(confidence IN ('CONFIRMED','CANDIDATE')),
    notes       TEXT    NOT NULL DEFAULT '',
    UNIQUE(struct_name, field_name, version_str)
);

CREATE INDEX IF NOT EXISTS idx_struct_fields_binary_id
    ON struct_fields(binary_id) WHERE binary_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_struct_fields_lookup
    ON struct_fields(struct_name, offset);

-- call_chains: chain identity.  Steps are in call_chain_steps.
CREATE TABLE IF NOT EXISTS call_chains (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    binary_id   INTEGER REFERENCES binaries(id) ON DELETE SET NULL,
    vuln_class  TEXT    NOT NULL DEFAULT '',
    notes       TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_call_chains_binary_id
    ON call_chains(binary_id) WHERE binary_id IS NOT NULL;

-- Normalized step list: replaces chain_json TEXT blob (1NF fix).
-- WITHOUT ROWID because the composite PK is the only meaningful key.
CREATE TABLE IF NOT EXISTS call_chain_steps (
    chain_id    INTEGER NOT NULL REFERENCES call_chains(id) ON DELETE CASCADE,
    step_order  INTEGER NOT NULL,
    func_va     INTEGER NOT NULL,
    func_name   TEXT    NOT NULL DEFAULT '',
    role        TEXT    NOT NULL DEFAULT '',
    note        TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (chain_id, step_order)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_call_chain_steps_chain
    ON call_chain_steps(chain_id);
"""

# ─────────────────────────────────────────────────────────────────────────────
# Role taxonomy
# ─────────────────────────────────────────────────────────────────────────────

ROLES = {
    'AAA_DISPATCH',
    'RADIUS_PARSER',
    'RADIUS_ATTR_HANDLER',
    'RADIUS_DISPATCH',
    'TACACS_PARSER',
    'CRYPTO_HPKE',
    'CRYPTO_OPENSSL',
    'CRYPTO_STRAP',
    'CRYPTO_IPC',
    'FILE_IO',
    'TIMER',
    'STRUCT_INIT',
    'STRUCT_ACCESSOR',
    'SAML_HANDLER',
    'CSTP_HANDLER',
    'DTLS_HANDLER',
    'PLT_LIBC',
    'UNKNOWN',
}

# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BinaryRecord:
    sha256: str
    path_hint: str = ''
    product: str = ''
    arch: str = 'x86-64'
    version: str = ''
    notes: str = ''
    id: Optional[int] = field(default=None, repr=False)


@dataclass
class FuncRecord:
    binary_sha256: str
    va: int
    name: str
    role: str = 'UNKNOWN'
    confidence: str = 'CANDIDATE'
    demangled: str = ''
    sig_bytes: str = ''
    sig_mask: str = ''
    call_targets: list = field(default_factory=list)
    callers: list = field(default_factory=list)
    string_xrefs: list = field(default_factory=list)
    struct_accesses: list = field(default_factory=list)
    notes: str = ''
    id: Optional[int] = field(default=None, repr=False)


@dataclass
class StructField:
    struct_name: str
    field_name: str
    offset: int
    binary_sha256: str
    width: int = 8
    version_str: str = ''
    confidence: str = 'CONFIRMED'
    notes: str = ''


@dataclass
class CallChain:
    name: str
    binary_sha256: str
    chain: list          # [{'va': int, 'name': str, 'role': str, 'note': str}, ...]
    vuln_class: str = ''
    notes: str = ''


# ─────────────────────────────────────────────────────────────────────────────
# DB
# ─────────────────────────────────────────────────────────────────────────────

class FuncDB:
    def __init__(self, path: str):
        self._path = Path(path).expanduser()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(str(self._path), check_same_thread=False)
        self._con.row_factory = sqlite3.Row
        # PRAGMAs must run before DDL; executescript auto-commits first
        self._con.executescript(_PRAGMAS)
        self._con.executescript(_DDL)
        self._con.commit()
        self._apply_migrations()

    def _apply_migrations(self):
        cur_ver = self._con.execute('PRAGMA user_version').fetchone()[0]
        if cur_ver < _SCHEMA_VERSION:
            self._con.execute(f'PRAGMA user_version = {_SCHEMA_VERSION}')
            self._con.commit()

    @classmethod
    def open(cls, path: str = '~/.ablation/func_id.db') -> 'FuncDB':
        return cls(path)

    def close(self):
        self._con.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    # ── binary registry ──────────────────────────────────────────────────────

    def add_binary(self, rec: BinaryRecord) -> int:
        with self._con:
            self._con.execute(
                'INSERT OR IGNORE INTO binaries'
                '(sha256,path_hint,product,arch,version,notes) VALUES(?,?,?,?,?,?)',
                (rec.sha256, rec.path_hint, rec.product, rec.arch, rec.version, rec.notes)
            )
        row = self._con.execute(
            'SELECT id FROM binaries WHERE sha256=?', (rec.sha256,)
        ).fetchone()
        return row['id']

    def binary_id(self, sha256: str) -> Optional[int]:
        row = self._con.execute(
            'SELECT id FROM binaries WHERE sha256=?', (sha256,)
        ).fetchone()
        return row['id'] if row else None

    def sha256_of(self, path: str) -> str:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    # ── function records ─────────────────────────────────────────────────────

    def add_func(self, rec: FuncRecord) -> int:
        bid = self.binary_id(rec.binary_sha256)
        if bid is None:
            raise ValueError(f'Binary {rec.binary_sha256[:12]}... not registered')
        ver_row = self._con.execute(
            'SELECT version FROM binaries WHERE id=?', (bid,)
        ).fetchone()
        version_str = ver_row['version'] if ver_row else ''
        with self._con:
            cur = self._con.execute(
                'INSERT OR REPLACE INTO functions'
                '(binary_id,va,name,demangled,role,confidence,sig_bytes,sig_mask,sig_len,'
                ' call_targets,callers,string_xrefs,struct_accesses,notes,version_str)'
                ' VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (bid, rec.va, rec.name, rec.demangled, rec.role, rec.confidence,
                 rec.sig_bytes, rec.sig_mask, len(rec.sig_bytes) // 2,
                 json.dumps(rec.call_targets), json.dumps(rec.callers),
                 json.dumps(rec.string_xrefs), json.dumps(rec.struct_accesses),
                 rec.notes, version_str)
            )
        return cur.lastrowid

    def add_struct_field(self, sf: StructField) -> int:
        bid = self.binary_id(sf.binary_sha256)
        with self._con:
            cur = self._con.execute(
                'INSERT OR REPLACE INTO struct_fields'
                '(struct_name,field_name,offset,width,version_str,binary_id,confidence,notes)'
                ' VALUES(?,?,?,?,?,?,?,?)',
                (sf.struct_name, sf.field_name, sf.offset, sf.width,
                 sf.version_str, bid, sf.confidence, sf.notes)
            )
        return cur.lastrowid

    def add_call_chain(self, cc: CallChain) -> int:
        bid = self.binary_id(cc.binary_sha256)
        with self._con:
            cur = self._con.execute(
                'INSERT OR IGNORE INTO call_chains(name,binary_id,vuln_class,notes)'
                ' VALUES(?,?,?,?)',
                (cc.name, bid, cc.vuln_class, cc.notes)
            )
            chain_id = cur.lastrowid
            if chain_id == 0:
                chain_id = self._con.execute(
                    'SELECT id FROM call_chains WHERE name=?', (cc.name,)
                ).fetchone()['id']
                self._con.execute(
                    'DELETE FROM call_chain_steps WHERE chain_id=?', (chain_id,)
                )
            self._con.executemany(
                'INSERT INTO call_chain_steps'
                '(chain_id,step_order,func_va,func_name,role,note) VALUES(?,?,?,?,?,?)',
                [
                    (chain_id, i, step.get('va', 0), step.get('name', ''),
                     step.get('role', ''), step.get('note', ''))
                    for i, step in enumerate(cc.chain)
                ]
            )
        return chain_id

    # ── batch import helpers ──────────────────────────────────────────────────

    def _batch_add_funcs(self, recs: list[FuncRecord]):
        """Insert a list of FuncRecords in a single transaction using executemany."""
        rows = []
        for rec in recs:
            bid = self.binary_id(rec.binary_sha256)
            if bid is None:
                continue
            ver_row = self._con.execute(
                'SELECT version FROM binaries WHERE id=?', (bid,)
            ).fetchone()
            version_str = ver_row['version'] if ver_row else ''
            rows.append((
                bid, rec.va, rec.name, rec.demangled, rec.role, rec.confidence,
                rec.sig_bytes, rec.sig_mask, len(rec.sig_bytes) // 2,
                json.dumps(rec.call_targets), json.dumps(rec.callers),
                json.dumps(rec.string_xrefs), json.dumps(rec.struct_accesses),
                rec.notes, version_str
            ))
        if not rows:
            return
        with self._con:
            self._con.executemany(
                'INSERT OR REPLACE INTO functions'
                '(binary_id,va,name,demangled,role,confidence,sig_bytes,sig_mask,sig_len,'
                ' call_targets,callers,string_xrefs,struct_accesses,notes,version_str)'
                ' VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                rows
            )

    def _batch_add_struct_fields(self, sfs: list[tuple]):
        """
        Insert struct fields in a single transaction.
        Each tuple: (struct_name, field_name, offset, width, version_str, binary_id,
                     confidence, notes)
        """
        with self._con:
            self._con.executemany(
                'INSERT OR IGNORE INTO struct_fields'
                '(struct_name,field_name,offset,width,version_str,binary_id,confidence,notes)'
                ' VALUES(?,?,?,?,?,?,?,?)',
                sfs
            )

    # ── matching ─────────────────────────────────────────────────────────────

    def match_by_name(self, name: str) -> list:
        rows = self._con.execute(
            'SELECT f.*, b.sha256 AS binary_sha256, b.product, b.version'
            ' FROM functions f JOIN binaries b ON f.binary_id=b.id'
            ' WHERE f.name=? OR f.demangled=?',
            (name, name)
        ).fetchall()
        return [dict(r) for r in rows]

    def match_by_sig(self, code_bytes: bytes, va: int,
                     window: int = 16, threshold: float = 0.75) -> list:
        """
        Match a window of bytes at va against stored signatures.
        Wildcard mask: 0x00 = skip, 0xff = must match.
        Loads only confirmed functions with non-empty sigs.
        """
        rows = self._con.execute(
            'SELECT f.*, b.sha256 AS binary_sha256, b.product, b.version'
            ' FROM functions f JOIN binaries b ON f.binary_id=b.id'
            " WHERE f.sig_len > 0 AND f.confidence='CONFIRMED'"
        ).fetchall()
        results = []
        for row in rows:
            sig = bytes.fromhex(row['sig_bytes'])
            mask_hex = row['sig_mask']
            mask = bytes.fromhex(mask_hex) if mask_hex else b'\xff' * len(sig)
            match_len = min(len(sig), len(code_bytes), window)
            fixed = sum(1 for m in mask[:match_len] if m == 0xff)
            if fixed == 0:
                continue
            hits = sum(
                1 for i in range(match_len)
                if mask[i] == 0x00 or code_bytes[i] == sig[i]
            )
            score = hits / match_len
            if score >= threshold:
                results.append({**dict(row), 'match_score': round(score, 3)})
        results.sort(key=lambda r: r['match_score'], reverse=True)
        return results

    def match_by_struct_offset(self, field_name: str,
                                offset: int, tolerance: int = 0) -> list:
        rows = self._con.execute(
            'SELECT * FROM struct_fields'
            ' WHERE field_name=? AND ABS(offset-?) <= ?',
            (field_name, offset, tolerance)
        ).fetchall()
        return [dict(r) for r in rows]

    def match_by_role(self, role: str, product: str = '') -> list:
        if product:
            rows = self._con.execute(
                'SELECT f.*, b.sha256 AS binary_sha256, b.product, b.version'
                ' FROM functions f JOIN binaries b ON f.binary_id=b.id'
                ' WHERE f.role=? AND b.product=?',
                (role, product)
            ).fetchall()
        else:
            rows = self._con.execute(
                'SELECT f.*, b.sha256 AS binary_sha256, b.product, b.version'
                ' FROM functions f JOIN binaries b ON f.binary_id=b.id'
                ' WHERE f.role=?',
                (role,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_chain(self, name: str) -> Optional[dict]:
        row = self._con.execute(
            'SELECT * FROM call_chains WHERE name=?', (name,)
        ).fetchone()
        if not row:
            return None
        steps = self._con.execute(
            'SELECT func_va, func_name, role, note FROM call_chain_steps'
            ' WHERE chain_id=? ORDER BY step_order',
            (row['id'],)
        ).fetchall()
        result = dict(row)
        result['chain'] = [dict(s) for s in steps]
        return result

    def struct_layout(self, struct_name: str, version_str: str = '') -> dict:
        if version_str:
            rows = self._con.execute(
                'SELECT field_name, offset FROM struct_fields'
                ' WHERE struct_name=? AND version_str=?',
                (struct_name, version_str)
            ).fetchall()
        else:
            rows = self._con.execute(
                'SELECT field_name, offset FROM struct_fields WHERE struct_name=?',
                (struct_name,)
            ).fetchall()
        return {r['field_name']: r['offset'] for r in rows}

    # ── import from RE modules ────────────────────────────────────────────────

    def import_lina_offsets(self):
        """Seed from SymbolicOffsetRegression.CONFIRMED in regression.py."""
        try:
            import sys
            sys.path.insert(0, str(Path(__file__).parent))
            from regression import SymbolicOffsetRegression
        except ImportError:
            print('[-] regression.py not importable — skipping lina offset seed')
            return 0

        confirmed = SymbolicOffsetRegression.CONFIRMED
        rows = []
        for version, fields in confirmed.items():
            placeholder_sha = hashlib.sha256(f'lina_{version}'.encode()).hexdigest()
            self.add_binary(BinaryRecord(
                sha256=placeholder_sha,
                path_hint=f'lina_{version}',
                product='lina',
                arch='x86-64',
                version=version,
                notes='placeholder; offsets from SymbolicOffsetRegression.CONFIRMED',
            ))
            bid = self.binary_id(placeholder_sha)
            for field_name, offset in fields.items():
                if not isinstance(offset, int):
                    continue
                width = 8 if field_name.endswith('_ptr') else 4
                rows.append((
                    'gp_obj', field_name, offset, width,
                    version, bid, 'CONFIRMED',
                    'from SymbolicOffsetRegression.CONFIRMED',
                ))
        self._batch_add_struct_fields(rows)
        return len(rows)

    def import_confirmed_functions(self):
        """Seed confirmed function records from cisco_asa_lina_re.py constants."""
        try:
            import sys
            sys.path.insert(0, str(Path(__file__).parent))
            import cisco_asa_lina_re as _lina
        except ImportError:
            print('[-] cisco_asa_lina_re not importable — skipping')
            return 0

        count = 0

        # ── lina 9.14.2.14 ───────────────────────────────────────────────────
        v3 = '9.14.2.14'
        sha3 = hashlib.sha256(f'lina_{v3}'.encode()).hexdigest()
        self.add_binary(BinaryRecord(
            sha256=sha3, path_hint=f'lina_{v3}', product='lina',
            arch='x86-64', version=v3,
        ))

        lina_914_funcs = [
            FuncRecord(sha3, 0xa22f7,  'SysUtils__SetTextFileContents',
                       role='FILE_IO', confidence='CONFIRMED',
                       notes='writes ac_strap.dat 0644; TOCTOU write side'),
            FuncRecord(sha3, 0xa232a,  'chmod_ac_strap_dat',
                       role='FILE_IO', confidence='CONFIRMED',
                       notes='chmod(path,0600); ~51 bytes after SetTextFileContents'),
            FuncRecord(sha3, 0x102c700,'mgd_timer_stop',
                       role='TIMER', confidence='CONFIRMED',
                       notes='type gate: +0x2a == 0x42; CALL *rax dispatch'),
            FuncRecord(sha3, 0x102b22c,'mgd_timer_stop_inner',
                       role='TIMER', confidence='CONFIRMED',
                       notes='rsi = *(*(A+0x18)+0x20)'),
            FuncRecord(sha3, 0x102ab00,'mgd_timer_dispatch_1',
                       role='TIMER', confidence='CONFIRMED'),
            FuncRecord(sha3, 0x102cc10,'mgd_timer_dispatch_2',
                       role='TIMER', confidence='CONFIRMED',
                       notes='CALL *rax — fake struct primitive'),
            FuncRecord(sha3, 0x1184232,'gp_obj_struct_init',
                       role='STRUCT_INIT', confidence='CONFIRMED',
                       notes='REMaQE target for offset extraction'),
        ]

        _ROLE_MAP = {
            'ldap_class_to_radius_class': 'AAA_DISPATCH',
            'attr_add_shim_class':        'RADIUS_ATTR_HANDLER',
            'attr_list_add_impl':         'RADIUS_ATTR_HANDLER',
            'attr_list_find_by_type':     'RADIUS_ATTR_HANDLER',
            'malloc_wrapper':             'PLT_LIBC',
            'aaa_debug_log':              'AAA_DISPATCH',
        }
        _NOTES_MAP = {
            'ldap_class_to_radius_class': 'LDAP→RADIUS class attr bridge; attr_type=25 MOV at 0xc61458',
            'attr_add_shim_class':        'shim adds attr type=25; tail-calls attr_list_add_impl',
            'attr_list_add_impl':         'generic attr list add/update; malloc via malloc_wrapper',
            'attr_list_find_by_type':     'iterates attr list, returns node by type field',
            'malloc_wrapper':             'malloc wrapper called by attr_list_add_impl',
            'aaa_debug_log':              'debug logging (facility, level, fmt, ...)',
        }
        if hasattr(_lina, 'CONFIRMED_FUNCTION_ADDRS'):
            for fname, va in _lina.CONFIRMED_FUNCTION_ADDRS.items():
                lina_914_funcs.append(FuncRecord(
                    sha3, va, fname,
                    role=_ROLE_MAP.get(fname, 'UNKNOWN'),
                    confidence='CONFIRMED',
                    notes=_NOTES_MAP.get(fname, ''),
                ))

        self._batch_add_funcs(lina_914_funcs)
        count += len(lina_914_funcs)

        # ── lina 9.16.4.18 ───────────────────────────────────────────────────
        v4 = '9.16.4.18'
        sha4 = hashlib.sha256(f'lina_{v4}'.encode()).hexdigest()
        self.add_binary(BinaryRecord(
            sha256=sha4, path_hint=f'lina_{v4}', product='lina',
            arch='x86-64', version=v4,
            notes='82MB stripped PIE; PT_LOAD delta=0; strcpy PLT 0x886d00',
        ))
        lina_916_funcs = [
            FuncRecord(sha4, 0x212a669,'class_attr_ou_strcpy_site',
                       role='RADIUS_ATTR_HANDLER', confidence='CONFIRMED',
                       notes='lea 0x2b0(%r15),%rdi; call strcpy — OU= into gp_obj+0x2b0'),
            FuncRecord(sha4, 0x886d00, 'plt_strcpy',
                       role='PLT_LIBC', confidence='CONFIRMED',
                       notes='strcpy PLT stub; dynstr idx 395; GOT 0x4483ea8'),
        ]
        self._batch_add_funcs(lina_916_funcs)
        count += len(lina_916_funcs)

        # ── lina 9.22.2.32 ───────────────────────────────────────────────────
        v5 = '9.22.2.32'
        sha5 = hashlib.sha256(f'lina_{v5}'.encode()).hexdigest()
        self.add_binary(BinaryRecord(
            sha256=sha5, path_hint=f'lina_{v5}', product='lina',
            arch='x86-64', version=v5,
        ))
        lina_9222_funcs = [
            FuncRecord(sha5, 0x03a4bda0,'class_attr_parse_fn',
                       role='RADIUS_ATTR_HANDLER', confidence='CONFIRMED',
                       notes='function start (55 48 89 e5) — parses RADIUS Class attr OU='),
            FuncRecord(sha5, 0x03a4bee6,'class_attr_strstr_call',
                       role='RADIUS_ATTR_HANDLER', confidence='CONFIRMED',
                       notes='CALL strstr(attr_value, "OU=")'),
            FuncRecord(sha5, 0x03a4bf1b,'class_attr_semicolon_check',
                       role='RADIUS_ATTR_HANDLER', confidence='CONFIRMED',
                       notes='CMP dl, 0x3b — semicolon delimiter loop'),
            FuncRecord(sha5, 0x03a4bf24,'class_attr_output_buf_lea',
                       role='RADIUS_ATTR_HANDLER', confidence='CONFIRMED',
                       notes='LEA rdi,[rbp-0x241] — 256-byte stack buffer for OU='),
            FuncRecord(sha5, 0x03a4c365,'class_attr_caller_1',
                       role='RADIUS_DISPATCH', confidence='CONFIRMED'),
            FuncRecord(sha5, 0x03a4c3fe,'class_attr_caller_2',
                       role='RADIUS_DISPATCH', confidence='CONFIRMED'),
            FuncRecord(sha5, 0x03a4c5b9,'class_attr_caller_3',
                       role='RADIUS_DISPATCH', confidence='CONFIRMED'),
            FuncRecord(sha5, 0x1a3d8ec, 'class_attr_inline_strcpy_9222232',
                       role='RADIUS_ATTR_HANDLER', confidence='CONFIRMED',
                       notes='inline strcpy(gp_obj+0x2b1, ...); OVERFLOW_DELTA=87'),
        ]
        self._batch_add_funcs(lina_9222_funcs)
        count += len(lina_9222_funcs)

        return count

    def import_anyconnect_functions(self):
        """Seed AnyConnect vpnagentd confirmed RE findings."""
        sha = hashlib.sha256(b'vpnagentd_5.1.15.287_linux64').hexdigest()
        self.add_binary(BinaryRecord(
            sha256=sha,
            path_hint='vpnagentd (Cisco Secure Client 5.1.15.287 linux64)',
            product='vpnagentd',
            arch='x86-64',
            version='5.1.15.287',
            notes='stripped; confirmed via strings + nm + libvpncommoncrypt.so RE',
        ))

        funcs = [
            FuncRecord(sha, 0xa22f7,  'SysUtils::SetTextFileContents',
                       demangled='SysUtils::SetTextFileContents(std::string const&, std::string const&)',
                       role='FILE_IO', confidence='CONFIRMED',
                       string_xrefs=['ac_strap.dat'],
                       notes='creates file 0644 before chmod — TOCTOU write side'),
            FuncRecord(sha, 0xa232a,  'chmod__ac_strap_dat',
                       role='FILE_IO', confidence='CONFIRMED',
                       notes='chmod(path,0600); ~51 bytes from SetTextFileContents'),
            FuncRecord(sha, 0x0, 'CStrapMgr::decryptHPKEMessage',
                       demangled='CStrapMgr::decryptHPKEMessage(std::string const&, std::string&)',
                       role='CRYPTO_HPKE', confidence='CONFIRMED',
                       string_xrefs=['decryptHPKEMessage','hpke_receiver_generate_symkey'],
                       notes='HPKE receiver; decrypts ASA-sent HPKE using ac_strap.dat key'),
            FuncRecord(sha, 0x0, 'CStrapKeyPairLinux::Persist',
                       demangled='CStrapKeyPairLinux::Persist()',
                       role='CRYPTO_STRAP', confidence='CONFIRMED',
                       string_xrefs=['ac_strap.dat','BEGIN PRIVATE KEY'],
                       notes='writes EC private key (secp256r1/384r1/521r1) to ac_strap.dat'),
            FuncRecord(sha, 0x0, 'CStrapKeyPair::SignNonceAndPubKey',
                       demangled='CStrapKeyPair::SignNonceAndPubKey(std::string const&, std::string&)',
                       role='CRYPTO_STRAP', confidence='CONFIRMED',
                       string_xrefs=['X-AnyConnect-STRAP-Verify'],
                       notes='signs nonce+pubkey for STRAP-Verify; auth bypass if key exfiltrated'),
            FuncRecord(sha, 0x0, 'CObfuscationMgr::PublicEncrypt',
                       demangled='CObfuscationMgr::PublicEncrypt(std::string const&, std::string&)',
                       role='CRYPTO_IPC', confidence='CONFIRMED',
                       notes='RSA IPC channel encrypt vpnagentd<->vpnui; key in /proc/<pid>/mem'),
            FuncRecord(sha, 0x0, 'CObfuscationMgr::PrivateDecrypt',
                       demangled='CObfuscationMgr::PrivateDecrypt(std::string const&, std::string&)',
                       role='CRYPTO_IPC', confidence='CONFIRMED',
                       notes='RSA IPC channel decrypt; companion to PublicEncrypt'),
        ]
        self._batch_add_funcs(funcs)

        self.add_call_chain(CallChain(
            name='TOCTOU_ac_strap_dat',
            binary_sha256=sha,
            chain=[
                {'va': 0xa22f7, 'name': 'SysUtils::SetTextFileContents',
                 'role': 'FILE_IO', 'note': 'creates file 0644'},
                {'va': 0xa232a, 'name': 'chmod__ac_strap_dat',
                 'role': 'FILE_IO', 'note': 'chmod 0600 — ~51 byte window'},
            ],
            vuln_class='TOCTOU',
            notes='inotify IN_CREATE on parent dir catches key in 0644 window; '
                  'fix = open()+fchmod(fd)',
        ))

        return len(funcs)

    def import_lina_call_chains(self):
        """Seed confirmed lina call chains."""
        sha = hashlib.sha256(b'lina_9.14.2.14').hexdigest()
        self.add_call_chain(CallChain(
            name='mgd_timer_stop_dispatch',
            binary_sha256=sha,
            chain=[
                {'va': 0x102c700, 'name': 'mgd_timer_stop',
                 'role': 'TIMER', 'note': 'type gate: +0x2a must == 0x42'},
                {'va': 0x102b22c, 'name': 'mgd_timer_stop_inner',
                 'role': 'TIMER', 'note': 'rsi = *(*(A+0x18)+0x20)'},
                {'va': 0x102ab00, 'name': 'mgd_timer_dispatch_1',
                 'role': 'TIMER', 'note': ''},
                {'va': 0x102cc10, 'name': 'mgd_timer_dispatch_2',
                 'role': 'TIMER', 'note': 'CALL *rax — fake struct primitive'},
            ],
            vuln_class='TYPE_CONFUSION',
            notes='gp_obj+0x308 = mgd_timer handle; corrupt via RADIUS Class attr overflow '
                  '(delta=88 for 9.12-9.22.1.x, delta=87 for 9.22.2.32+)',
        ))
        return 1

    def seed_all(self) -> dict:
        return {
            'lina_offsets':     self.import_lina_offsets(),
            'confirmed_funcs':  self.import_confirmed_functions(),
            'anyconnect_funcs': self.import_anyconnect_functions(),
            'lina_call_chains': self.import_lina_call_chains(),
        }

    # ── query helpers ─────────────────────────────────────────────────────────

    def summary(self) -> dict:
        return {
            'binaries':         self._con.execute('SELECT COUNT(*) FROM binaries').fetchone()[0],
            'functions':        self._con.execute('SELECT COUNT(*) FROM functions').fetchone()[0],
            'struct_fields':    self._con.execute('SELECT COUNT(*) FROM struct_fields').fetchone()[0],
            'call_chains':      self._con.execute('SELECT COUNT(*) FROM call_chains').fetchone()[0],
            'call_chain_steps': self._con.execute('SELECT COUNT(*) FROM call_chain_steps').fetchone()[0],
            'schema_version':   self._con.execute('PRAGMA user_version').fetchone()[0],
        }

    def export_json(self) -> dict:
        chains = []
        for row in self._con.execute('SELECT * FROM call_chains'):
            r = dict(row)
            steps = self._con.execute(
                'SELECT func_va,func_name,role,note FROM call_chain_steps'
                ' WHERE chain_id=? ORDER BY step_order', (r['id'],)
            ).fetchall()
            r['chain'] = [dict(s) for s in steps]
            chains.append(r)
        return {
            'binaries':      [dict(r) for r in self._con.execute('SELECT * FROM binaries')],
            'functions':     [dict(r) for r in self._con.execute('SELECT * FROM functions')],
            'struct_fields': [dict(r) for r in self._con.execute('SELECT * FROM struct_fields')],
            'call_chains':   chains,
        }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _cli():
    import argparse, sys

    ap = argparse.ArgumentParser(description='Ablation function identity database')
    ap.add_argument('--db', default='~/.ablation/func_id.db')
    sub = ap.add_subparsers(dest='cmd')

    sub.add_parser('seed',    help='Seed DB from all confirmed RE sources')
    sub.add_parser('summary', help='Print DB row counts')

    qp = sub.add_parser('query', help='Query by name/role/offset')
    qp.add_argument('--name')
    qp.add_argument('--role')
    qp.add_argument('--struct')
    qp.add_argument('--field')
    qp.add_argument('--offset', type=lambda x: int(x, 0))
    qp.add_argument('--tolerance', type=int, default=0)

    sub.add_parser('export', help='Export full DB as JSON')

    args = ap.parse_args()
    if not args.cmd:
        ap.print_help(); return

    with FuncDB.open(args.db) as db:
        if args.cmd == 'seed':
            counts = db.seed_all()
            for src, n in counts.items():
                print(f'  {src}: {n}')
            print(f'DB: {db.summary()}')

        elif args.cmd == 'summary':
            for k, v in db.summary().items():
                print(f'  {k}: {v}')

        elif args.cmd == 'query':
            if args.name:
                results = db.match_by_name(args.name)
            elif args.role:
                results = db.match_by_role(args.role)
            elif args.struct and args.field:
                results = db.match_by_struct_offset(
                    args.field, args.offset or 0, args.tolerance)
            else:
                ap.print_help(); return
            print(json.dumps(results, indent=2))

        elif args.cmd == 'export':
            print(json.dumps(db.export_json(), indent=2))


if __name__ == '__main__':
    _cli()
