from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
from html.parser import HTMLParser
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess


SUPPORTED = {".pdf", ".html", ".txt", ".md"}
MAX_DOCUMENT_TEXT = 64 * 1024 * 1024
MAX_TEXT_FILE = 16 * 1024 * 1024
MAX_PAGE_TEXT = 2 * 1024 * 1024


def _clip(value, limit=90):
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value)).strip()
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _pdf_text(path):
    info = subprocess.run(["/usr/bin/pdfinfo", str(path)], capture_output=True, timeout=30, check=False)
    match = re.search(rb"^Pages:\s+(\d+)", info.stdout, re.MULTILINE)
    total = int(match.group(1)) if match else None
    result = subprocess.run(["/usr/bin/pdftotext", "-layout", str(path), "-"], capture_output=True, timeout=90, check=False)
    status = "indexed" if result.returncode == 0 else "error"
    error = result.stderr.decode("utf-8", "replace")[:500]
    text = result.stdout
    if len(text) > MAX_DOCUMENT_TEXT:
        text = text[:MAX_DOCUMENT_TEXT]
        status = "truncated"
        error = "document text was bounded to 64 MiB"
    pages = [page.decode("utf-8", "replace").strip() for page in text.split(b"\f")]
    while pages and not pages[-1]:
        pages.pop()
    if any(len(page.encode("utf-8")) > MAX_PAGE_TEXT for page in pages):
        pages = [page.encode("utf-8")[:MAX_PAGE_TEXT].decode("utf-8", "replace") for page in pages]
        status = "truncated"
        error = "one or more pages were bounded to 2 MiB"
    if not any(pages):
        status = "no_text"
    return pages, total or len(pages), status, error


class _HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.ignored = False

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.ignored = True

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.ignored = False

    def handle_data(self, data):
        if not self.ignored:
            self.parts.append(data)

    def text(self):
        return re.sub(r"\s+", " ", " ".join(self.parts)).strip()


def _plain_text(path):
    with path.open("rb") as handle:
        raw = handle.read(MAX_TEXT_FILE + 1)
    status = "truncated" if len(raw) > MAX_TEXT_FILE else "indexed"
    error = "text file was bounded to 16 MiB" if status == "truncated" else ""
    text = raw[:MAX_TEXT_FILE].decode("utf-8", "replace").strip()
    if path.suffix.lower() == ".html":
        parser = _HTMLText()
        parser.feed(text)
        parser.close()
        text = parser.text()
    return text, status, error


class ManualLibrary:
    def __init__(self, path=None):
        self.path = Path(path).expanduser() if path else None
        self.available = bool(self.path and self.path.is_file())

    @staticmethod
    def _documents(roots, excluded=()):
        documents = []
        unsupported = 0
        excluded = {Path(path).resolve() for path in excluded}
        for root in roots:
            root = Path(root).expanduser()
            if not root.exists():
                raise ValueError(f"library root does not exist: {root}")
            files = [root] if root.is_file() else sorted(root.rglob("*"))
            for path in files:
                if path.resolve() in excluded:
                    continue
                if not path.is_file() or path.is_symlink():
                    continue
                if path.suffix.lower() not in SUPPORTED:
                    unsupported += 1
                    continue
                documents.append((root, path))
        return documents, unsupported

    @classmethod
    def index(cls, roots, database):
        roots = [Path(root).expanduser() for root in roots]
        if not roots:
            raise ValueError("at least one library root is required")
        database = Path(database).expanduser()
        if database.exists():
            raise FileExistsError(database)
        database.parent.mkdir(parents=True, exist_ok=True)
        temporary = database.with_name(database.name + ".tmp")
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        connection = sqlite3.connect(temporary)
        indexed = 0
        unsupported = 0
        try:
            connection.executescript("""
                CREATE TABLE documents (
                    id INTEGER PRIMARY KEY,
                    source_root TEXT NOT NULL,
                    path TEXT NOT NULL UNIQUE,
                    source_group TEXT NOT NULL,
                    title TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    pages_total INTEGER NOT NULL,
                    pages_with_text INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    error TEXT NOT NULL
                );
                CREATE VIRTUAL TABLE pages_fts USING fts5(
                    text, doc_id UNINDEXED, page UNINDEXED, tokenize='unicode61'
                );
                CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            """)
            documents, unsupported = cls._documents(roots, excluded=(database, temporary))
            for root, path in documents:
                kind = path.suffix.lower().lstrip(".")
                if kind == "pdf":
                    pages, total, status, error = _pdf_text(path)
                else:
                    text, status, error = _plain_text(path)
                    pages = [text] if text else []
                    total = 1 if text else 0
                    if not text:
                        status = "no_text"
                text_pages = [page for page in pages if page]
                source_group = root.name if root.is_dir() else root.parent.name
                title = _clip(path.stem.replace("_", " "), 240)
                cursor = connection.execute(
                    "INSERT INTO documents (source_root,path,source_group,title,kind,bytes,sha256,pages_total,pages_with_text,status,error) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (str(root), str(path), source_group, title, kind, path.stat().st_size, _digest(path), total, len(text_pages), status, error),
                )
                for number, text in enumerate(pages, 1):
                    if text:
                        connection.execute("INSERT INTO pages_fts (text,doc_id,page) VALUES (?,?,?)", (text, cursor.lastrowid, number))
                indexed += 1
                if indexed % 10 == 0:
                    print(f"Indexed {indexed} documents", flush=True)
            metadata = {
                "schema_version": "1",
                "indexed_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "unsupported_files": str(unsupported),
                "text_extraction": "pdftotext for PDFs; HTML tags and script/style content removed for HTML; UTF-8 replacement for TXT/MD; no document instructions executed",
            }
            connection.executemany("INSERT INTO metadata (key,value) VALUES (?,?)", metadata.items())
            connection.commit()
            connection.close()
            os.chmod(temporary, 0o600)
            if database.exists():
                raise FileExistsError(database)
            os.replace(temporary, database)
        except Exception:
            connection.close()
            temporary.unlink(missing_ok=True)
            raise
        return cls(database)

    @contextmanager
    def _connection(self):
        if not self.available:
            raise ValueError("no manual index is available; run gem library index first")
        connection = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        try:
            yield connection
        finally:
            connection.close()

    def summary(self):
        if not self.available:
            return {"available": False, "documents": 0, "pages": 0, "message": "Run gem library index with your chosen GEM Books roots."}
        with self._connection() as connection:
            metadata = dict(connection.execute("SELECT key,value FROM metadata"))
            documents, pages, size = connection.execute("SELECT COUNT(*), COALESCE(SUM(pages_with_text),0), COALESCE(SUM(bytes),0) FROM documents").fetchone()
            total_pages = connection.execute("SELECT COALESCE(SUM(pages_total),0) FROM documents").fetchone()[0]
            statuses = dict(connection.execute("SELECT status,COUNT(*) FROM documents GROUP BY status").fetchall())
            groups = [row[0] for row in connection.execute("SELECT DISTINCT source_group FROM documents ORDER BY source_group")]
        return {
            "available": True,
            "documents": documents,
            "pages": pages,
            "pages_total": total_pages,
            "bytes": size,
            "groups": groups,
            "statuses": statuses,
            "unsupported_files": int(metadata.get("unsupported_files", 0)),
            "schema_version": int(metadata.get("schema_version", 0)),
            "indexed_utc": metadata.get("indexed_utc"),
            "database": str(self.path),
            "read_only": True,
        }

    def search(self, query, limit=8):
        if not isinstance(query, str) or not query.strip() or len(query.strip()) > 256:
            raise ValueError("query must contain 1–256 characters")
        if any(ord(character) < 32 or ord(character) == 127 for character in query):
            raise ValueError("query cannot contain control characters")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
            raise ValueError("result limit must be an integer from 1 to 50")
        literal_query = '"' + query.strip().replace('"', '""') + '"'
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT documents.path,documents.source_group,documents.title,pages_fts.page,snippet(pages_fts,0,'[',']',' … ',12) FROM pages_fts JOIN documents ON documents.id=pages_fts.doc_id WHERE pages_fts MATCH ? ORDER BY rank LIMIT ?",
                (literal_query, limit),
            ).fetchall()
        return [{"path": path, "group": group, "title": title, "page": page, "snippet": _clip(snippet, 220)} for path, group, title, page, snippet in rows]


def library_scene(library, query="", results=None):
    from .scene_utils import _line, _scene, _text

    summary = library.summary()
    objects = [
        {"id": "background", "type": "rectangle", "bounds": [0, 0, 1100, 740], "stroke": "black", "fill": "black", "width": 1},
        _text("title", [38, 46], "ZOE OS · MANUAL LIBRARY", 24, "cyan"),
        _text("subtitle", [38, 78], "Original GEM sources, indexed locally. Read, search, and cite without executing content.", 14, "lightgray"),
        _line("library-rule", [38, 104], [1060, 104], "blue", 2),
    ]
    if summary["available"]:
        objects.append(_text("library-stats", [38, 137], f"{summary['documents']} documents · {summary['pages']} text pages · {summary['pages_total']} total pages", 17, "white"))
        objects.append(_text("library-groups", [38, 168], f"{len(summary['groups'])} source groups · {summary['unsupported_files']} unsupported files excluded · read-only index", 12, "lightgray"))
    else:
        objects.append(_text("library-empty", [38, 137], "No index selected. Build one explicitly with gem library index.", 17, "white"))
        objects.append(_text("library-command", [38, 168], "gem library index --root /path/to/GEM/Books --database /path/to/gem.sqlite", 12, "yellow"))
    objects.append(_text("query", [38, 205], f"Search: {_clip(query, 120) or 'enter a term such as VDI, AES, Artline, or drivers'}", 14, "cyan"))
    if results is None:
        objects.append(_text("instructions", [38, 248], "Search the index to see source titles, groups, pages, and snippets.", 15, "lightgray"))
    elif not results:
        objects.append(_text("no-results", [38, 248], "No matching pages. Try a broader query or build the manual index first.", 15, "lightgray"))
    for index, result in enumerate((results or [])[:8]):
        y = 252 + index * 48
        objects.append(_text(f"result-title-{index}", [38, y], f"{index + 1}. {_clip(result['title'], 62)}", 14, "white"))
        objects.append(_text(f"result-source-{index}", [38, y + 20], f"{_clip(result['group'], 24)} · page {result['page']} · {_clip(result['snippet'], 88)}", 11, "lightgray"))
        objects.append(_text(f"result-open-{index}", [950, y], "open source", 11, "cyan"))
    objects.append(_text("scope", [38, 663], "Read-only search · original manuals stay in place · no commands from documents", 13, "red"))
    objects.append(_text("boundary", [38, 693], "Image-only PDFs have no text layer. Unsupported binary/archive formats are reported, not executed.", 12, "lightgray"))
    count = summary["documents"] if summary["available"] else 0
    report_summary = f"{count} documents indexed" if summary["available"] else "No manual index selected"
    if results:
        first = results[0]
        report_summary += f" · first: {first['title']} page {first['page']}"
    scene = _scene("gem-manual-library", 1100, 740, objects, "GEM OS manual library")
    return scene, {"summary": report_summary, "library": summary, "results": results or [], "executed": False}
