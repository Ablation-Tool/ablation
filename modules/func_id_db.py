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

DB schema is SQLite. CLI: ablation --func-db-query / --func-db-add / --func-db-import.

Usage:
    db = FuncDB.open('~/.ablation/func_id.db')
    matches = db.match_by_sig(binary_bytes, va)
    matches = db.match_by_struct_offset('gp_name', 0x2b0)
    db.add(FuncRecord(...))
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import struct
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS binaries (
    id          INTEGER PRIMARY KEY,
    sha256      TEXT UNIQUE NOT NULL,
    path_hint   TEXT,
    product     TEXT,        -- 'lina' | 'vpnagentd' | 'libvpncommoncrypt' | ...
    arch        TEXT,        -- 'x86-64' | 'arm64' | 'arm32'
    version     TEXT,        -- '9.14.2.14' | '5.1.15.287' | ...
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS functions (
    id              INTEGER PRIMARY KEY,
    binary_id       INTEGER REFERENCES binaries(id),
    va              INTEGER,             -- virtual address in this binary
    name            TEXT NOT NULL,       -- inferred or confirmed name
    demangled       TEXT,                -- C++ demangled form if applicable
    role            TEXT,                -- see ROLES below
    confidence      TEXT DEFAULT 'CANDIDATE',  -- CONFIRMED | ANGR_INFERRED | CANDIDATE
    sig_bytes       TEXT,                -- hex of first N bytes (with ?? wildcards)
    sig_mask        TEXT,                -- hex mask: ff=exact, 00=wildcard
    sig_len         INTEGER,
    call_targets    TEXT,                -- JSON list of called va's (within binary)
    callers         TEXT,                -- JSON list of caller va's
    string_xrefs    TEXT,                -- JSON list of nearby string literals
    struct_accesses TEXT,                -- JSON list of {field, offset, width, op}
    notes           TEXT,
    version_str     TEXT                 -- denorm copy of binary version for fast queries
);

CREATE TABLE IF NOT EXISTS struct_fields (
    id          INTEGER PRIMARY KEY,
    struct_name TEXT NOT NULL,           -- 'gp_obj' | 'mgd_timer' | 'CStrapMgr' | ...
    field_name  TEXT NOT NULL,           -- 'gp_name' | 'dns_ptr' | 'wins_ptr' | ...
    offset      INTEGER NOT NULL,
    width       INTEGER,                 -- bytes
    version_str TEXT,
    binary_id   INTEGER REFERENCES binaries(id),
    confidence  TEXT DEFAULT 'CONFIRMED',
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS call_chains (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,           -- 'mgd_timer_stop_dispatch' | 'TOCTOU_ac_strap' | ...
    binary_id   INTEGER REFERENCES binaries(id),
    chain_json  TEXT NOT NULL,           -- JSON ordered list of {va, name, role, note}
    vuln_class  TEXT,                    -- 'TOCTOU' | 'UAF' | 'OVERFLOW' | 'TYPE_CONFUSION' | ...
    notes       TEXT
);

CREATE INDEX IF NOT EXISTS idx_func_name    ON functions(name);
CREATE INDEX IF NOT EXISTS idx_func_role    ON functions(role);
CREATE INDEX IF NOT EXISTS idx_func_sig     ON functions(sig_bytes);
CREATE INDEX IF NOT EXISTS idx_struct_field ON struct_fields(struct_name, field_name, version_str);
CREATE INDEX IF NOT EXISTS idx_binary_sha   ON binaries(sha256);
"""

# ─────────────────────────────────────────────────────────────────────────────
# Role taxonomy
# ─────────────────────────────────────────────────────────────────────────────

ROLES = {
    'AAA_DISPATCH',        # top-level AAA dispatcher
    'RADIUS_PARSER',       # parses RADIUS attribute TLVs
    'RADIUS_ATTR_HANDLER', # handles one specific attribute type
    'TACACS_PARSER',
    'CRYPTO_HPKE',         # HPKE encrypt/decrypt
    'CRYPTO_OPENSSL',      # OpenSSL wrapper
    'CRYPTO_STRAP',        # STRAP key lifecycle
    'CRYPTO_IPC',          # IPC encryption (CObfuscationMgr)
    'FILE_IO',             # file write/read (SetTextFileContents class)
    'TIMER',               # mgd_timer, watchdog
    'STRUCT_INIT',         # gp_obj / session-struct initializer
    'STRUCT_ACCESSOR',     # getter/setter for named struct field
    'SAML_HANDLER',
    'CSTP_HANDLER',
    'DTLS_HANDLER',
    'PLT_LIBC',            # PLT stub classified by libfunc_db
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
    sig_bytes: str = ''       # e.g. '554889e5415741564155'
    sig_mask: str = ''        # e.g. 'ffffffffffffffffffffffff'
    call_targets: list = field(default_factory=list)
    callers: list = field(default_factory=list)
    string_xrefs: list = field(default_factory=list)
    struct_accesses: list = field(default_factory=list)  # [{field, offset, width, op}, ...]
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
        self._con = sqlite3.connect(str(self._path))
        self._con.row_factory = sqlite3.Row
        self._con.executescript(_DDL)
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
        cur = self._con.execute(
            'INSERT OR IGNORE INTO binaries(sha256,path_hint,product,arch,version,notes)'
            ' VALUES(?,?,?,?,?,?)',
            (rec.sha256, rec.path_hint, rec.product, rec.arch, rec.version, rec.notes)
        )
        self._con.commit()
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
        self._con.commit()
        return cur.lastrowid

    def add_struct_field(self, sf: StructField) -> int:
        bid = self.binary_id(sf.binary_sha256)
        cur = self._con.execute(
            'INSERT OR REPLACE INTO struct_fields'
            '(struct_name,field_name,offset,width,version_str,binary_id,confidence,notes)'
            ' VALUES(?,?,?,?,?,?,?,?)',
            (sf.struct_name, sf.field_name, sf.offset, sf.width,
             sf.version_str, bid, sf.confidence, sf.notes)
        )
        self._con.commit()
        return cur.lastrowid

    def add_call_chain(self, cc: CallChain) -> int:
        bid = self.binary_id(cc.binary_sha256)
        cur = self._con.execute(
            'INSERT OR REPLACE INTO call_chains(name,binary_id,chain_json,vuln_class,notes)'
            ' VALUES(?,?,?,?,?)',
            (cc.name, bid, json.dumps(cc.chain), cc.vuln_class, cc.notes)
        )
        self._con.commit()
        return cur.lastrowid

    # ── matching ─────────────────────────────────────────────────────────────

    def match_by_name(self, name: str) -> list:
        rows = self._con.execute(
            'SELECT f.*, b.sha256, b.product, b.version FROM functions f'
            ' JOIN binaries b ON f.binary_id=b.id'
            ' WHERE f.name=? OR f.demangled=?',
            (name, name)
        ).fetchall()
        return [dict(r) for r in rows]

    def match_by_sig(self, code_bytes: bytes, va: int,
                     window: int = 16, threshold: float = 0.75) -> list:
        """
        Match a window of bytes at va against stored signatures.

        For each candidate in the DB, compute the fraction of non-wildcard
        bytes that match exactly. Return candidates above threshold.

        Wildcard mask: sig_mask byte 0x00 = skip; 0xff = must match.
        """
        code_hex = code_bytes.hex()
        rows = self._con.execute(
            'SELECT f.*, b.sha256, b.product, b.version FROM functions f'
            ' JOIN binaries b ON f.binary_id=b.id'
            ' WHERE f.sig_bytes != "" AND f.sig_len > 0'
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
                'SELECT f.*, b.sha256, b.product, b.version FROM functions f'
                ' JOIN binaries b ON f.binary_id=b.id'
                ' WHERE f.role=? AND b.product=?',
                (role, product)
            ).fetchall()
        else:
            rows = self._con.execute(
                'SELECT f.*, b.sha256, b.product, b.version FROM functions f'
                ' JOIN binaries b ON f.binary_id=b.id WHERE f.role=?',
                (role,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_chain(self, name: str) -> Optional[dict]:
        row = self._con.execute(
            'SELECT * FROM call_chains WHERE name=?', (name,)
        ).fetchone()
        if not row:
            return None
        r = dict(row)
        r['chain'] = json.loads(r['chain_json'])
        return r

    def struct_layout(self, struct_name: str, version_str: str = '') -> dict:
        """Return {field_name: offset} for a struct across all or one version."""
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
        count = 0
        for version, fields in confirmed.items():
            # Register a placeholder binary for each version (no actual binary required)
            placeholder_sha = hashlib.sha256(f'lina_{version}'.encode()).hexdigest()
            self.add_binary(BinaryRecord(
                sha256=placeholder_sha,
                path_hint=f'lina_{version}',
                product='lina',
                arch='x86-64',
                version=version,
                notes='placeholder — no binary loaded; offsets from SymbolicOffsetRegression.CONFIRMED',
            ))
            for field_name, offset in fields.items():
                if not isinstance(offset, int):
                    continue
                self.add_struct_field(StructField(
                    struct_name='gp_obj',
                    field_name=field_name,
                    offset=offset,
                    binary_sha256=placeholder_sha,
                    width=8 if field_name.endswith('_ptr') else 4,
                    version_str=version,
                    confidence='CONFIRMED',
                    notes='from SymbolicOffsetRegression.CONFIRMED',
                ))
                count += 1
        return count

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

        # ── lina 9.12.4.29 class_attr functions ──────────────────────────────
        v = '9.12.4.29'
        sha = hashlib.sha256(f'lina_{v}'.encode()).hexdigest()
        self.add_binary(BinaryRecord(
            sha256=sha, path_hint=f'lina_{v}', product='lina',
            arch='x86-64', version=v,
        ))
        if hasattr(_lina, 'CONFIRMED_9222232_ADDRS'):
            addrs = _lina.CONFIRMED_9222232_ADDRS
        else:
            addrs = {}

        # lina 9.12 — class_attr strcpy site (from code comment at line ~891)
        self.add_func(FuncRecord(
            binary_sha256=sha,
            va=0x212a669,
            name='class_attr_ou_strcpy_site',
            role='RADIUS_ATTR_HANDLER',
            confidence='CONFIRMED',
            notes='lea 0x2b0(%r15),%rdi; call strcpy — RADIUS Class attr OU= write to gp_obj+0x2b0',
        ))
        count += 1

        # ── lina 9.22.2.32 confirmed addresses ───────────────────────────────
        v2 = '9.22.2.32'
        sha2 = hashlib.sha256(f'lina_{v2}'.encode()).hexdigest()
        self.add_binary(BinaryRecord(
            sha256=sha2, path_hint=f'lina_{v2}', product='lina',
            arch='x86-64', version=v2,
        ))
        confirmed_9222232 = {
            'class_attr_parse_fn':        (0x03a4bda0, 'RADIUS_ATTR_HANDLER',
                'function start (55 48 89 e5 prologue) — parses RADIUS Class attr OU='),
            'class_attr_strstr_call':     (0x03a4bee6, 'RADIUS_ATTR_HANDLER',
                'CALL strstr(attr_value, "OU=") — OU= substring search'),
            'class_attr_semicolon_check': (0x03a4bf1b, 'RADIUS_ATTR_HANDLER',
                'CMP dl, 0x3b — semicolon delimiter loop'),
            'class_attr_output_buf_lea':  (0x03a4bf24, 'RADIUS_ATTR_HANDLER',
                'LEA rdi,[rbp-0x241] — 256-byte stack buffer for parsed OU='),
            'class_attr_caller_1':        (0x03a4c365, 'RADIUS_DISPATCH', ''),
            'class_attr_caller_2':        (0x03a4c3fe, 'RADIUS_DISPATCH', ''),
            'class_attr_caller_3':        (0x03a4c5b9, 'RADIUS_DISPATCH', ''),
        }
        for fname, (va, role, notes) in confirmed_9222232.items():
            self.add_func(FuncRecord(
                binary_sha256=sha2, va=va, name=fname,
                role=role, confidence='CONFIRMED', notes=notes,
            ))
            count += 1

        # ── TOCTOU pair (address from session-state; version anchor = 9.14.2.14 era) ──
        v3 = '9.14.2.14'
        sha3 = hashlib.sha256(f'lina_{v3}'.encode()).hexdigest()
        toctou_funcs = [
            FuncRecord(
                binary_sha256=sha3, va=0xa22f7,
                name='SysUtils__SetTextFileContents',
                role='FILE_IO', confidence='CONFIRMED',
                notes='writes ac_strap.dat with 0644 permissions before chmod — TOCTOU write side',
            ),
            FuncRecord(
                binary_sha256=sha3, va=0xa232a,
                name='chmod_ac_strap_dat',
                role='FILE_IO', confidence='CONFIRMED',
                notes='chmod(path,0600) called 51 bytes after SetTextFileContents — TOCTOU window',
            ),
        ]
        for rec in toctou_funcs:
            self.add_func(rec)
            count += 1

        # ── mgd_timer_stop dispatch chain ────────────────────────────────────
        mgd_funcs = [
            FuncRecord(
                binary_sha256=sha3, va=0x102c700,
                name='mgd_timer_stop',
                role='TIMER', confidence='CONFIRMED',
                notes='mgd_timer_stop — reads timer type byte at +0x2a, gates CALL *rax dispatch',
            ),
            FuncRecord(
                binary_sha256=sha3, va=0x102b22c,
                name='mgd_timer_stop_inner',
                role='TIMER', confidence='CONFIRMED',
                notes='inner: rsi = *(*(A+0x18)+0x20) = *(B+0x20)',
            ),
            FuncRecord(
                binary_sha256=sha3, va=0x102ab00,
                name='mgd_timer_dispatch_1',
                role='TIMER', confidence='CONFIRMED', notes='',
            ),
            FuncRecord(
                binary_sha256=sha3, va=0x102cc10,
                name='mgd_timer_dispatch_2',
                role='TIMER', confidence='CONFIRMED',
                notes='final dispatch — CALL *rax',
            ),
        ]
        for rec in mgd_funcs:
            self.add_func(rec)
            count += 1

        # ── angr target function ──────────────────────────────────────────────
        self.add_func(FuncRecord(
            binary_sha256=sha3, va=0x1184232,
            name='gp_obj_struct_init',
            role='STRUCT_INIT', confidence='CONFIRMED',
            notes='lina 9.14.2.14 gp_obj init block; REMaQE target for offset extraction',
        ))
        count += 1

        # ── CONFIRMED_FUNCTION_ADDRS (9.14.2.14) — pulled from lina_re module ──
        _ROLE_MAP = {
            'ldap_class_to_radius_class': ('AAA_DISPATCH',    'LDAP→RADIUS class attribute bridge; attr_type=25 MOV at 0xc61458'),
            'attr_add_shim_class':        ('RADIUS_ATTR_HANDLER', 'shim adds attr type=25 (Class) to attr list; tail-calls attr_list_add_impl'),
            'attr_list_add_impl':         ('RADIUS_ATTR_HANDLER', 'generic attribute list add/update; allocates node via malloc_wrapper'),
            'attr_list_find_by_type':     ('RADIUS_ATTR_HANDLER', 'iterates attr list, returns node matching type field'),
            'malloc_wrapper':             ('PLT_LIBC',            'malloc wrapper called by attr_list_add_impl for node allocation'),
            'aaa_debug_log':              ('AAA_DISPATCH',         'debug logging (facility, level, fmt, ...)'),
        }
        if hasattr(_lina, 'CONFIRMED_FUNCTION_ADDRS'):
            for fname, va in _lina.CONFIRMED_FUNCTION_ADDRS.items():
                role, notes = _ROLE_MAP.get(fname, ('UNKNOWN', ''))
                self.add_func(FuncRecord(
                    binary_sha256=sha3, va=va, name=fname,
                    role=role, confidence='CONFIRMED', notes=notes,
                ))
                count += 1

        # ── 9.16.4.18 OU= handler ────────────────────────────────────────────
        v4 = '9.16.4.18'
        sha4 = hashlib.sha256(f'lina_{v4}'.encode()).hexdigest()
        self.add_binary(BinaryRecord(
            sha256=sha4, path_hint=f'lina_{v4}', product='lina',
            arch='x86-64', version=v4,
            notes='82MB stripped PIE; PT_LOAD delta=0; strcpy PLT 0x886d00',
        ))
        for rec in [
            FuncRecord(sha4, 0x212a669, 'class_attr_ou_strcpy_site',
                       role='RADIUS_ATTR_HANDLER', confidence='CONFIRMED',
                       notes='lea 0x2b0(%r15),%rdi; call strcpy — OU= into gp_obj+0x2b0'),
            FuncRecord(sha4, 0x886d00,  'plt_strcpy',
                       role='PLT_LIBC', confidence='CONFIRMED',
                       notes='strcpy PLT stub; dynstr idx 395; GOT 0x4483ea8'),
        ]:
            self.add_func(rec)
            count += 1

        # ── 9.22.2.32 inline strcpy site (gp_obj+0x2b1) ─────────────────────
        v5 = '9.22.2.32'
        sha5 = hashlib.sha256(f'lina_{v5}'.encode()).hexdigest()
        self.add_binary(BinaryRecord(
            sha256=sha5, path_hint=f'lina_{v5}', product='lina',
            arch='x86-64', version=v5,
        ))
        self.add_func(FuncRecord(
            sha5, 0x1a3d8ec, 'class_attr_inline_strcpy_9222232',
            role='RADIUS_ATTR_HANDLER', confidence='CONFIRMED',
            notes='inline strcpy(gp_obj+0x2b1, reg_entry+0x2c1); OVERFLOW_DELTA=87',
        ))
        count += 1

        return count

    def import_anyconnect_functions(self):
        """Seed AnyConnect vpnagentd confirmed RE findings from SESSION-STATE."""
        # Binary: Cisco Secure Client 5.1.15.287 linux64 vpnagentd (stripped)
        # SHA256 placeholder — actual binary at /tmp scratchpad or VDT/tools/cisco/
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
            FuncRecord(
                binary_sha256=sha, va=0xa22f7,
                name='SysUtils::SetTextFileContents',
                demangled='SysUtils::SetTextFileContents(std::string const&, std::string const&)',
                role='FILE_IO', confidence='CONFIRMED',
                string_xrefs=['ac_strap.dat'],
                notes='writes ac_strap.dat; creates file 0644 before chmod — TOCTOU write side',
            ),
            FuncRecord(
                binary_sha256=sha, va=0xa232a,
                name='chmod__ac_strap_dat',
                role='FILE_IO', confidence='CONFIRMED',
                notes='chmod(path, 0600) — TOCTOU race window ~51 bytes from SetTextFileContents',
            ),
            FuncRecord(
                binary_sha256=sha, va=0x0,
                name='CStrapMgr::decryptHPKEMessage',
                demangled='CStrapMgr::decryptHPKEMessage(std::string const&, std::string&)',
                role='CRYPTO_HPKE', confidence='CONFIRMED',
                string_xrefs=['decryptHPKEMessage', 'hpke_receiver_generate_symkey'],
                notes='HPKE receiver — decrypts ASA-sent HPKE messages using ac_strap.dat key',
            ),
            FuncRecord(
                binary_sha256=sha, va=0x0,
                name='CStrapKeyPairLinux::Persist',
                demangled='CStrapKeyPairLinux::Persist()',
                role='CRYPTO_STRAP', confidence='CONFIRMED',
                string_xrefs=['ac_strap.dat', 'BEGIN PRIVATE KEY'],
                notes='writes EC private key (secp256r1/384r1/521r1) to ac_strap.dat — calls SetTextFileContents',
            ),
            FuncRecord(
                binary_sha256=sha, va=0x0,
                name='CStrapKeyPair::SignNonceAndPubKey',
                demangled='CStrapKeyPair::SignNonceAndPubKey(std::string const&, std::string&)',
                role='CRYPTO_STRAP', confidence='CONFIRMED',
                string_xrefs=['X-AnyConnect-STRAP-Verify'],
                notes='signs nonce+pubkey for X-AnyConnect-STRAP-Verify header — STRAP auth bypass if key exfiltrated',
            ),
            FuncRecord(
                binary_sha256=sha, va=0x0,
                name='CObfuscationMgr::PublicEncrypt',
                demangled='CObfuscationMgr::PublicEncrypt(std::string const&, std::string&)',
                role='CRYPTO_IPC', confidence='CONFIRMED',
                notes='RSA IPC channel encryption vpnagentd<->vpnui; key recoverable from /proc/<pid>/mem',
            ),
            FuncRecord(
                binary_sha256=sha, va=0x0,
                name='CObfuscationMgr::PrivateDecrypt',
                demangled='CObfuscationMgr::PrivateDecrypt(std::string const&, std::string&)',
                role='CRYPTO_IPC', confidence='CONFIRMED',
                notes='RSA IPC channel decryption; companion to PublicEncrypt',
            ),
        ]
        count = 0
        for rec in funcs:
            self.add_func(rec)
            count += 1

        # Call chain: TOCTOU
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
            notes='inotify IN_CREATE on parent dir catches key in 0644 window; fix = open()+fchmod(fd)',
        ))

        return count

    def import_lina_call_chains(self):
        """Seed confirmed lina call chains from cisco_asa_lina_re.py."""
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
        """Run all import_* methods. Returns count per source."""
        return {
            'lina_offsets':       self.import_lina_offsets(),
            'confirmed_funcs':    self.import_confirmed_functions(),
            'anyconnect_funcs':   self.import_anyconnect_functions(),
            'lina_call_chains':   self.import_lina_call_chains(),
        }

    # ── query helpers ─────────────────────────────────────────────────────────

    def summary(self) -> dict:
        return {
            'binaries':       self._con.execute('SELECT COUNT(*) FROM binaries').fetchone()[0],
            'functions':      self._con.execute('SELECT COUNT(*) FROM functions').fetchone()[0],
            'struct_fields':  self._con.execute('SELECT COUNT(*) FROM struct_fields').fetchone()[0],
            'call_chains':    self._con.execute('SELECT COUNT(*) FROM call_chains').fetchone()[0],
        }

    def export_json(self) -> dict:
        """Full export for inspection / git-tracking."""
        return {
            'binaries':      [dict(r) for r in self._con.execute('SELECT * FROM binaries')],
            'functions':     [dict(r) for r in self._con.execute('SELECT * FROM functions')],
            'struct_fields': [dict(r) for r in self._con.execute('SELECT * FROM struct_fields')],
            'call_chains':   [dict(r) for r in self._con.execute('SELECT * FROM call_chains')],
        }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _cli():
    import argparse, sys

    ap = argparse.ArgumentParser(description='Ablation function identity database')
    ap.add_argument('--db', default='~/.ablation/func_id.db', help='DB path')
    sub = ap.add_subparsers(dest='cmd')

    sub.add_parser('seed',    help='Seed DB from all confirmed RE sources')
    sub.add_parser('summary', help='Print DB row counts')

    qp = sub.add_parser('query', help='Query functions by name/role/offset')
    qp.add_argument('--name',   help='Function name (exact)')
    qp.add_argument('--role',   help='Role (e.g. RADIUS_PARSER)')
    qp.add_argument('--struct', help='Struct name (with --field and --offset)')
    qp.add_argument('--field',  help='Struct field name')
    qp.add_argument('--offset', type=lambda x: int(x, 0), help='Field offset (hex ok)')
    qp.add_argument('--tolerance', type=int, default=0)

    ep = sub.add_parser('export', help='Export full DB as JSON to stdout')

    args = ap.parse_args()
    if not args.cmd:
        ap.print_help(); return

    with FuncDB.open(args.db) as db:
        if args.cmd == 'seed':
            counts = db.seed_all()
            for src, n in counts.items():
                print(f'  {src}: {n} records')
            print(f'DB: {db.summary()}')

        elif args.cmd == 'summary':
            s = db.summary()
            for k, v in s.items():
                print(f'  {k}: {v}')

        elif args.cmd == 'query':
            if args.name:
                results = db.match_by_name(args.name)
            elif args.role:
                results = db.match_by_role(args.role)
            elif args.struct and args.field:
                results = db.match_by_struct_offset(args.field, args.offset or 0, args.tolerance)
            else:
                ap.print_help(); return
            print(json.dumps(results, indent=2))

        elif args.cmd == 'export':
            print(json.dumps(db.export_json(), indent=2))


if __name__ == '__main__':
    _cli()
