"""
finding_registry.py: cross-target confirmed finding store.

Every confirmed vulnerability finding from any RE engagement registers here.
The registry grows with each engagement: a confirmed finding from one target becomes
a query seed for future sweeps on new binaries automatically.

Storage:
    ~/.ablation/findings.db  : SQLite, user-local, not committed to git
    ablation/data/seed_corpus.json: shipped seed patterns from published CVEs

Usage:
    from ablation.analyzers.finding_registry import FindingRegistry

    reg = FindingRegistry()
    print(reg.stats())

    # After model is loaded, build embeddings for seed entries:
    reg.build_embeddings(model)

    # Find patterns similar to a function embedding:
    hits = reg.find_similar(func_embedding, top_k=8)

    # Register a newly confirmed finding:
    reg.register(
        vendor="my-vendor", product="my-target", version="1.0",
        title="batchPCRERegexMatch command injection via PHP exec",
        description="PHP_EXEC | calls: exec | vuln: ...",
        cwe_class="CWE-78", severity="CRITICAL",
        embedding=func_vec, func_addr=0x1234, binary="fcems_server",
    )

CLI:
    python3 -m ablation.analyzers.finding_registry stats
    python3 -m ablation.analyzers.finding_registry list [--vendor my-vendor]
    python3 -m ablation.analyzers.finding_registry register --interactive
"""

import json
import sqlite3
import struct
import sys
from pathlib import Path
from typing import Optional

import numpy as np

_DEFAULT_DB = Path.home() / ".ablation" / "findings.db"
_SEED_PATH = Path(__file__).parent.parent / "data" / "seed_corpus.json"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor      TEXT    NOT NULL,
    product     TEXT    NOT NULL,
    version     TEXT,
    binary      TEXT,
    func_addr   INTEGER,
    cwe_class   TEXT,
    severity    TEXT,
    title       TEXT    NOT NULL,
    description TEXT,
    embedding   BLOB,
    source      TEXT,
    confirmed   INTEGER DEFAULT 1,
    created_at  TEXT    DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cwe    ON findings(cwe_class);
CREATE INDEX IF NOT EXISTS idx_vendor ON findings(vendor);
CREATE INDEX IF NOT EXISTS idx_conf   ON findings(confirmed);
"""


class FindingRegistry:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or _DEFAULT_DB)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(str(self.db_path))
        self._con.executescript(_SCHEMA)
        self._con.commit()
        self._load_seed_corpus()

    # ── seed corpus ───────────────────────────────────────────────────────────

    def _load_seed_corpus(self):
        if not _SEED_PATH.exists():
            return
        already = self._con.execute(
            "SELECT COUNT(*) FROM findings WHERE source='seed'"
        ).fetchone()[0]
        if already > 0:
            return
        entries = json.loads(_SEED_PATH.read_text())
        for e in entries:
            self._con.execute(
                """INSERT INTO findings
                   (vendor, product, version, cwe_class, severity, title, description, source)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    e.get("vendor", "generic"),
                    e.get("product", "firmware"),
                    e.get("version"),
                    e.get("cwe"),
                    e.get("severity"),
                    e["title"],
                    e.get("description"),
                    "seed",
                ),
            )
        self._con.commit()

    def build_embeddings(self, model) -> int:
        """Compute and store embeddings for all entries that lack them.

        Call this once after the SentenceTransformer model is loaded.
        Returns the count of entries updated.
        """
        rows = self._con.execute(
            "SELECT id, title, description FROM findings WHERE embedding IS NULL AND description IS NOT NULL"
        ).fetchall()
        if not rows:
            return 0
        texts = [f"{r[1]} | {r[2]}" for r in rows]
        vecs = model.encode(texts, normalize_embeddings=True, batch_size=64, show_progress_bar=False)
        for (row_id, _, _), vec in zip(rows, vecs):
            self._con.execute(
                "UPDATE findings SET embedding=? WHERE id=?",
                (vec.astype(np.float32).tobytes(), row_id),
            )
        self._con.commit()
        return len(rows)

    # ── write ─────────────────────────────────────────────────────────────────

    def register(
        self,
        vendor: str,
        product: str,
        title: str,
        description: str,
        cwe_class: str,
        severity: str,
        embedding: Optional[np.ndarray] = None,
        func_addr: int = 0,
        version: str = "",
        binary: str = "",
        source: str = "",
        confirmed: bool = True,
    ) -> int:
        emb_blob = None
        if embedding is not None:
            v = embedding.astype(np.float32)
            v = v / (np.linalg.norm(v) + 1e-9)
            emb_blob = v.tobytes()
        cur = self._con.execute(
            """INSERT INTO findings
               (vendor, product, version, binary, func_addr, cwe_class, severity,
                title, description, embedding, source, confirmed)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                vendor, product, version or None, binary or None,
                func_addr or None, cwe_class, severity,
                title, description, emb_blob, source or None,
                1 if confirmed else 0,
            ),
        )
        self._con.commit()
        return cur.lastrowid

    # ── read ──────────────────────────────────────────────────────────────────

    def find_similar(
        self,
        embedding: np.ndarray,
        top_k: int = 10,
        min_sim: float = 0.70,
        confirmed_only: bool = False,
    ) -> list:
        """Return findings whose stored embedding is cosine-similar to `embedding`.

        Returns list of dicts sorted by similarity descending.
        """
        clause = "WHERE embedding IS NOT NULL"
        if confirmed_only:
            clause += " AND confirmed=1"
        rows = self._con.execute(
            f"SELECT id, vendor, product, cwe_class, severity, title, description, embedding FROM findings {clause}"
        ).fetchall()
        if not rows:
            return []

        q = embedding.astype(np.float32)
        q = q / (np.linalg.norm(q) + 1e-9)

        results = []
        for row in rows:
            raw = row[7]
            if len(raw) % 4 != 0:
                continue
            emb = np.frombuffer(raw, dtype=np.float32).copy()
            emb = emb / (np.linalg.norm(emb) + 1e-9)
            if emb.shape != q.shape:
                continue
            sim = float(q @ emb)
            if sim >= min_sim:
                results.append(
                    {
                        "id": row[0],
                        "vendor": row[1],
                        "product": row[2],
                        "cwe": row[3],
                        "severity": row[4],
                        "title": row[5],
                        "description": row[6],
                        "similarity": sim,
                    }
                )

        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:top_k]

    def prior_queries(self, top_n: int = 20) -> list:
        """Return description strings of confirmed findings for use as sweep query seeds.

        Deduplicated by CWE class so one class contributes one query.
        """
        rows = self._con.execute(
            """SELECT cwe_class, title, description
               FROM findings
               WHERE confirmed=1 AND description IS NOT NULL
               GROUP BY cwe_class
               ORDER BY cwe_class, id DESC
               LIMIT ?""",
            (top_n,),
        ).fetchall()
        out = []
        for cwe, title, desc in rows:
            label = f"{cwe} | {title}" if cwe else title
            out.append(f"{label}: {desc}")
        return out

    def stats(self) -> dict:
        total = self._con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        has_emb = self._con.execute(
            "SELECT COUNT(*) FROM findings WHERE embedding IS NOT NULL"
        ).fetchone()[0]
        by_vendor = dict(
            self._con.execute(
                "SELECT vendor, COUNT(*) FROM findings GROUP BY vendor ORDER BY COUNT(*) DESC"
            ).fetchall()
        )
        by_cwe = dict(
            self._con.execute(
                "SELECT cwe_class, COUNT(*) FROM findings WHERE cwe_class IS NOT NULL GROUP BY cwe_class ORDER BY COUNT(*) DESC"
            ).fetchall()
        )
        return {
            "total": total,
            "with_embedding": has_emb,
            "by_vendor": by_vendor,
            "by_cwe": by_cwe,
            "db": str(self.db_path),
        }

    def list_findings(self, vendor: Optional[str] = None, limit: int = 100) -> list:
        if vendor:
            rows = self._con.execute(
                "SELECT id, vendor, product, cwe_class, severity, title, created_at FROM findings WHERE vendor=? ORDER BY id DESC LIMIT ?",
                (vendor, limit),
            ).fetchall()
        else:
            rows = self._con.execute(
                "SELECT id, vendor, product, cwe_class, severity, title, created_at FROM findings ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        keys = ("id", "vendor", "product", "cwe", "severity", "title", "created_at")
        return [dict(zip(keys, r)) for r in rows]

    def search(self, query: str, model, top_k: int = 10, min_sim: float = 0.60) -> list:
        """Semantic search: encode query string, return similar findings from corpus."""
        qvec = model.encode(query, normalize_embeddings=True)
        return self.find_similar(qvec, top_k=top_k, min_sim=min_sim)

    def unsynced_findings(self) -> list:
        """Return findings that have not yet been written to seed_corpus.json (source != 'seed')."""
        rows = self._con.execute(
            """SELECT id, vendor, product, version, cwe_class, severity, title, description, source, created_at
               FROM findings WHERE source != 'seed' ORDER BY id"""
        ).fetchall()
        keys = ("id", "vendor", "product", "version", "cwe", "severity", "title", "description", "source", "created_at")
        return [dict(zip(keys, r)) for r in rows]

    def mark_synced(self, finding_id: int):
        """Mark a finding as synced to seed corpus by updating its source to 'seed'."""
        self._con.execute("UPDATE findings SET source='seed' WHERE id=?", (finding_id,))
        self._con.commit()

    def close(self):
        self._con.close()


# ── interactive registration helper ──────────────────────────────────────────

def _interactive_register(reg: FindingRegistry) -> None:
    print("Register confirmed finding (Ctrl-C to abort)")
    try:
        vendor = input("  vendor   : ").strip()
        product = input("  product  : ").strip()
        version = input("  version  : ").strip()
        binary = input("  binary   : ").strip()
        func_addr_s = input("  func_addr (hex, or blank): ").strip()
        func_addr = int(func_addr_s, 16) if func_addr_s else 0
        cwe_class = input("  cwe_class: ").strip()
        severity = input("  severity [CRITICAL/HIGH/MEDIUM/LOW]: ").strip().upper()
        title = input("  title    : ").strip()
        print("  description (one line): ", end="")
        description = input().strip()
        fid = reg.register(
            vendor=vendor, product=product, version=version,
            binary=binary, func_addr=func_addr, cwe_class=cwe_class,
            severity=severity, title=title, description=description,
            source="manual",
        )
        print(f"  Registered id={fid}")
    except KeyboardInterrupt:
        print("\n  Aborted.")


# ── CLI ───────────────────────────────────────────────────────────────────────

def _commit_findings(reg: FindingRegistry, seed_path: Path, dry_run: bool = False) -> int:
    """
    Append unsynced local findings to seed_corpus.json and mark them synced.
    Returns count of findings written.
    """
    unsynced = reg.unsynced_findings()
    if not unsynced:
        print("Nothing to sync: all local findings already in seed corpus.")
        return 0

    print(f"{len(unsynced)} unsynced finding(s) to append to {seed_path}:")
    for f in unsynced:
        print(f"  [{f['id']}] {f['vendor']}/{f['product']} {f['cwe'] or '?'} {f['severity'] or '?'}: {f['title']}")

    if dry_run:
        print("(dry-run, not writing)")
        return len(unsynced)

    confirm = input(f"\nAppend {len(unsynced)} findings to {seed_path.name}? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return 0

    # Load existing corpus
    existing = json.loads(seed_path.read_text()) if seed_path.exists() else []

    new_entries = []
    for f in unsynced:
        entry = {
            "vendor": f["vendor"],
            "product": f["product"],
        }
        if f.get("version"):
            entry["version"] = f["version"]
        if f.get("cwe"):
            entry["cwe"] = f["cwe"]
        if f.get("severity"):
            entry["severity"] = f["severity"]
        entry["title"] = f["title"]
        if f.get("description"):
            entry["description"] = f["description"]
        new_entries.append(entry)

    combined = existing + new_entries
    seed_path.write_text(json.dumps(combined, indent=2))

    # Mark as synced in DB
    for f in unsynced:
        reg.mark_synced(f["id"])

    print(f"Wrote {len(new_entries)} entries to {seed_path}. Total: {len(combined)}.")
    print("Review seed_corpus.json, then commit + push.")
    return len(new_entries)


def _cli():
    import argparse

    ap = argparse.ArgumentParser(prog="finding_registry", description="Ablation finding registry")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("stats", help="Print corpus statistics")

    lp = sub.add_parser("list", help="List findings")
    lp.add_argument("--vendor", default=None)
    lp.add_argument("--limit", type=int, default=50)

    sub.add_parser("register", help="Interactively register a confirmed finding")

    sp = sub.add_parser("search", help="Semantic search across the corpus")
    sp.add_argument("query", help="Search query string")
    sp.add_argument("--top", type=int, default=8)
    sp.add_argument("--min-sim", type=float, default=0.55)

    cp = sub.add_parser("commit", help="Sync unsynced local findings to seed_corpus.json")
    cp.add_argument("--dry-run", action="store_true", help="Show what would be written without writing")

    args = ap.parse_args()
    reg = FindingRegistry()

    if args.cmd == "stats" or args.cmd is None:
        s = reg.stats()
        print(f"Total findings : {s['total']}")
        print(f"With embedding : {s['with_embedding']}")
        print(f"DB path        : {s['db']}")
        print(f"\nBy vendor:")
        for v, n in s["by_vendor"].items():
            print(f"  {v:<20} {n}")
        print(f"\nBy CWE class:")
        for c, n in s["by_cwe"].items():
            print(f"  {c:<12} {n}")

    elif args.cmd == "list":
        findings = reg.list_findings(vendor=args.vendor, limit=args.limit)
        for f in findings:
            sev = f["severity"] or "?"
            cwe = f["cwe"] or "?"
            print(f"[{f['id']:4d}] {f['vendor']:<12} {f['product']:<20} {cwe:<10} {sev:<8} {f['title']}")

    elif args.cmd == "register":
        _interactive_register(reg)

    elif args.cmd == "search":
        from sentence_transformers import SentenceTransformer
        print(f"Loading model for semantic search ...")
        model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
        reg.build_embeddings(model)
        hits = reg.search(args.query, model, top_k=args.top, min_sim=args.min_sim)
        if not hits:
            print(f"No matches above {args.min_sim:.2f}")
        else:
            print(f"\n{len(hits)} match(es) for: {args.query!r}\n")
            for h in hits:
                print(f"  sim={h['similarity']:.4f}  [{h['severity'] or '?'}] {h['cwe'] or '?'}")
                print(f"  {h['vendor']}/{h['product']}: {h['title']}")
                if h.get('description'):
                    print(f"  {h['description'][:100]}")
                print()

    elif args.cmd == "commit":
        seed_path = Path(__file__).parent.parent / "data" / "seed_corpus.json"
        _commit_findings(reg, seed_path, dry_run=args.dry_run)

    reg.close()


if __name__ == "__main__":
    _cli()
