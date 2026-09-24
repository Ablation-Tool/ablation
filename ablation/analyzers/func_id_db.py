#!/usr/bin/env python3
"""
func_id_db.py — Function Identity Database for ablation.

Stores confirmed function names, roles, and signatures across binary versions.
When ablation encounters a new binary, it matches unknown functions against this
database by:
  1. Byte-pattern signature (exact or fuzzy via wildcard bytes)
  2. Call-graph neighborhood (who calls whom)
  3. Struct field access offsets (for struct-pointer-heavy init functions)
  4. String xrefs (error messages, format strings anchored to function)

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

    def seed_all(self) -> dict:
        """Seed DB from any available target-specific RE modules.

        Override this in a subclass or call add_binary() / _batch_add_funcs()
        directly to populate the DB with confirmed findings from your own RE work.
        """
        return {}

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
