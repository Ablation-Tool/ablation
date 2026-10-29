#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import quote, unquote, urlsplit

REPOSITORY = "Ablation-Tool/ablation"
BRANCH = "main"
REPOSITORY_URL = f"https://github.com/{REPOSITORY}"
RAW_URL = f"https://raw.githubusercontent.com/{REPOSITORY}"

LINK_RE = re.compile(
    r"(?P<prefix>!?\[[^\]\n]*\]\(\s*)"
    r"(?P<target><[^>\n]+>|[^\s)]+)"
    r"(?P<suffix>(?:\s+[^)\n]*)?\))"
)
REFERENCE_RE = re.compile(
    r"^(?P<prefix>[ ]{0,3}\[[^\]]+\]:\s*)"
    r"(?P<target><[^>]+>|\S+)(?P<suffix>.*)$"
)
HTML_IMAGE_RE = re.compile(
    r"(?P<prefix><img\b[^>]*\bsrc=)(?P<quote>['\"])(?P<target>.*?)(?P=quote)",
    re.IGNORECASE,
)
CODE_SPAN_RE = re.compile(r"(?P<fence>`+)(?P<body>.*?)(?P=fence)")
FENCE_RE = re.compile(r"^[ ]{0,3}(?P<fence>`{3,}|~{3,})")
CATEGORY_LABELS = {
    "capability-audit": "Capability Audits",
    "company-index": "Company Index",
    "i18n": "Languages",
    "integrations": "Integrations",
    "prompts": "Rubric Library",
    "reference-anomalies": "Known Anomalies",
    "reference-modules": "Module Reference",
    "updates": "Release Updates",
    "workflows": "Workflows",
}


@dataclass(frozen=True)
class Document:
    path: PurePosixPath
    slug: str
    title: str


@dataclass(frozen=True)
class BuildResult:
    documents: int
    pages: int
    categories: int


class WikiPublisher:
    def __init__(self, docs_root: Path, home_template: Path) -> None:
        self.docs_root = docs_root.resolve()
        self.repository_root = self.docs_root.parent
        self.home_template = home_template
        self.documents = self._collect_documents()
        self.by_path = {document.path: document for document in self.documents}
        self.groups: dict[str, list[Document]] = {}
        for document in self.documents:
            group = document.path.parts[0] if len(document.path.parts) > 1 else ""
            self.groups.setdefault(group, []).append(document)
        self.category_slugs = {group: self._category_slug(group) for group in self.groups}
        self._validate_generated_names()

    @staticmethod
    def _slug_component(value: str) -> str:
        value = re.sub(r"[\s_]+", "-", value)
        value = re.sub(r"[^A-Za-z0-9.\-]+", "-", value)
        value = re.sub(r"-{2,}", "-", value).strip("-.")
        if not value:
            return "Document"
        return "-".join(part[:1].upper() + part[1:] for part in value.split("-"))

    @classmethod
    def _page_slug(cls, path: PurePosixPath) -> str:
        if path == PurePosixPath("index.md"):
            return "Documentation-Index"
        if path == PurePosixPath("INDEX.md"):
            return "Document-Library"
        slug = "-".join(cls._slug_component(part) for part in path.with_suffix("").parts)
        if slug in {"Home", "_Sidebar", "_Footer"}:
            return f"Docs-{slug}"
        return slug

    @classmethod
    def _category_slug(cls, group: str) -> str:
        return "Browse" if not group else f"Browse-{cls._slug_component(group)}"

    @staticmethod
    def _title(path: Path, fallback: str) -> str:
        for line in path.read_text(encoding="utf-8").splitlines():
            match = re.match(r"^# ([^#].*?)\s*$", line)
            if match:
                return match.group(1).strip()
        return fallback

    def _collect_documents(self) -> list[Document]:
        documents = []
        used_slugs: dict[str, PurePosixPath] = {}
        paths = sorted(
            self.docs_root.rglob("*.md"),
            key=lambda path: (
                path.relative_to(self.docs_root).as_posix().casefold(),
                path.relative_to(self.docs_root).as_posix(),
            ),
        )
        for path in paths:
            if not path.is_file() or path.is_symlink():
                continue
            relative = PurePosixPath(path.relative_to(self.docs_root).as_posix())
            slug = self._page_slug(relative)
            collision = used_slugs.get(slug.casefold())
            if collision is not None:
                raise ValueError(f"Wiki page collision: {collision} and {relative} both map to {slug}")
            used_slugs[slug.casefold()] = relative
            documents.append(Document(relative, slug, self._title(path, slug)))
        if not documents:
            raise ValueError(f"No Markdown documents found in {self.docs_root}")
        return documents

    def _validate_generated_names(self) -> None:
        used = {document.slug.casefold(): document.path.as_posix() for document in self.documents}
        for group, name in self.category_slugs.items():
            collision = used.get(name.casefold())
            if collision is not None:
                raise ValueError(
                    f"Generated Wiki page collision: {name} is used by {collision} and category {group}"
                )
            used[name.casefold()] = f"category {group or 'root'}"
        for name in ["Home", "_Sidebar"]:
            if name.casefold() in used:
                raise ValueError(f"Generated Wiki page {name} conflicts with {used[name.casefold()]}")

    def _repository_path(self, source: PurePosixPath, target: str) -> PurePosixPath:
        candidate = (self.docs_root / source).parent / unquote(target)
        resolved = candidate.resolve()
        try:
            return PurePosixPath(resolved.relative_to(self.repository_root).as_posix())
        except ValueError as error:
            raise ValueError(f"{source}: link escapes the repository: {target}") from error

    def _rewrite_target(self, source: PurePosixPath, target: str, image: bool = False) -> str:
        if not target or target.startswith(("#", "/", "//")):
            return target
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc:
            return target
        repository_path = self._repository_path(source, parsed.path)
        suffix = (f"?{parsed.query}" if parsed.query else "") + (
            f"#{parsed.fragment}" if parsed.fragment else ""
        )
        if not image and parsed.path.casefold().endswith(".md"):
            try:
                document_path = repository_path.relative_to("docs")
            except ValueError:
                document_path = None
            if document_path is not None:
                document = self.by_path.get(document_path)
                if document is None:
                    raise ValueError(f"{source}: unresolved documentation link: {target}")
                return f"{document.slug}{suffix}"
        if not image:
            candidate = self.repository_root / Path(repository_path)
            if candidate.is_dir():
                parts = repository_path.parts
                if len(parts) == 2 and parts[0] == "docs" and parts[1] in self.category_slugs:
                    return self.category_slugs[parts[1]]
                return f"{REPOSITORY_URL}/tree/{BRANCH}/{quote(repository_path.as_posix(), safe='/')}{suffix}"
        base = RAW_URL if image else f"{REPOSITORY_URL}/blob"
        return f"{base}/{BRANCH}/{quote(repository_path.as_posix(), safe='/')}{suffix}"

    def _rewrite_segment(self, segment: str, source: PurePosixPath) -> str:
        def html_image(match: re.Match[str]) -> str:
            target = self._rewrite_target(source, match.group("target"), image=True)
            return f"{match.group('prefix')}{match.group('quote')}{target}{match.group('quote')}"

        def inline_link(match: re.Match[str]) -> str:
            raw_target = match.group("target")
            target = raw_target[1:-1] if raw_target.startswith("<") else raw_target
            image = match.group("prefix").lstrip().startswith("!")
            rewritten = self._rewrite_target(source, target, image=image)
            return f"{match.group('prefix')}{rewritten}{match.group('suffix')}"

        def reference_link(match: re.Match[str]) -> str:
            raw_target = match.group("target")
            target = raw_target[1:-1] if raw_target.startswith("<") else raw_target
            rewritten = self._rewrite_target(source, target)
            return f"{match.group('prefix')}{rewritten}{match.group('suffix')}"

        segment = HTML_IMAGE_RE.sub(html_image, segment)
        segment = REFERENCE_RE.sub(reference_link, segment)
        return LINK_RE.sub(inline_link, segment)

    def _rewrite_line(self, line: str, source: PurePosixPath) -> str:
        output = []
        position = 0
        for match in CODE_SPAN_RE.finditer(line):
            output.append(self._rewrite_segment(line[position:match.start()], source))
            output.append(match.group(0))
            position = match.end()
        output.append(self._rewrite_segment(line[position:], source))
        return "".join(output)

    def rewrite(self, text: str, source: PurePosixPath) -> str:
        output = []
        fence_character = ""
        fence_length = 0
        for line in text.splitlines(keepends=True):
            marker = FENCE_RE.match(line)
            if fence_character:
                output.append(line)
                if marker:
                    fence = marker.group("fence")
                    remainder = line[marker.end():].strip()
                    if fence[0] == fence_character and len(fence) >= fence_length and not remainder:
                        fence_character = ""
                        fence_length = 0
                continue
            if marker:
                fence = marker.group("fence")
                fence_character = fence[0]
                fence_length = len(fence)
                output.append(line)
                continue
            output.append(self._rewrite_line(line, source))
        return "".join(output)

    def _category_title(self, group: str) -> str:
        if not group:
            return "Core Guides and Project Documents"
        return CATEGORY_LABELS.get(group, group.replace("-", " ").replace("_", " ").title())

    def _category_pages(self) -> dict[str, str]:
        pages = {}
        for group, documents in self.groups.items():
            slug = self.category_slugs[group]
            title = self._category_title(group)
            lines = [
                f"# {title}",
                "",
                f"{len(documents)} document{'s' if len(documents) != 1 else ''}, generated from the latest `main` branch.",
                "",
            ]
            for document in sorted(documents, key=lambda item: (item.title.casefold(), item.slug)):
                lines.append(f"- [{document.title}]({document.slug})")
            lines.extend([
                "",
                f"[Edit this documentation section]({REPOSITORY_URL}/tree/{BRANCH}/docs/{group})",
                "",
            ])
            pages[slug] = "\n".join(lines)
        return pages

    def _sidebar(self) -> str:
        lines = [
            "**[Ablation Documentation](Home)**",
            "",
            "- [Getting Started](Getting-Started)",
            "- [Documentation Index](Documentation-Index)",
            "- [Complete Document Library](Document-Library)",
            "- [Tool Selection](Guide-Tool-Selection)",
            "",
            "### Browse by topic",
            "",
        ]
        for group in sorted(self.groups, key=lambda value: (bool(value), value.casefold())):
            title = self._category_title(group)
            lines.append(f"- [{title}]({self.category_slugs[group]})")
        lines.extend([
            "",
            f"[Edit documentation]({REPOSITORY_URL}/tree/{BRANCH}/docs)",
            "",
        ])
        return "\n".join(lines)

    def build(self, output_root: Path) -> BuildResult:
        if output_root.exists() and any(output_root.iterdir()):
            raise ValueError(f"Output directory is not empty: {output_root}")
        output_root.mkdir(parents=True, exist_ok=True)
        category_pages = self._category_pages()
        for document in self.documents:
            source = self.docs_root / Path(document.path)
            text = source.read_text(encoding="utf-8")
            (output_root / f"{document.slug}.md").write_text(
                self.rewrite(text, document.path), encoding="utf-8"
            )
        for slug, text in category_pages.items():
            (output_root / f"{slug}.md").write_text(text, encoding="utf-8")
        category_links = "\n".join(
            f"- [{self._category_title(group)}]({self.category_slugs[group]}) — "
            f"{len(self.groups[group])} document{'s' if len(self.groups[group]) != 1 else ''}"
            for group in sorted(self.groups, key=lambda value: (bool(value), value.casefold()))
        )
        home = self.home_template.read_text(encoding="utf-8")
        home = home.replace("{{CATEGORY_INDEXES}}", category_links)
        home = home.replace("{{DOCUMENT_COUNT}}", str(len(self.documents)))
        (output_root / "Home.md").write_text(home, encoding="utf-8")
        (output_root / "_Sidebar.md").write_text(self._sidebar(), encoding="utf-8")
        pages = len(self.documents) + len(category_pages) + 2
        return BuildResult(len(self.documents), pages, len(category_pages))


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a navigable GitHub Wiki from docs/")
    parser.add_argument("--docs", type=Path, default=Path("docs"))
    parser.add_argument("--home", type=Path, default=Path(".github/wiki/Home.md"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    publisher = WikiPublisher(args.docs, args.home)
    result = publisher.build(args.output)
    print(
        f"Built {result.pages} Wiki pages from {result.documents} documents "
        f"in {result.categories} categories."
    )


if __name__ == "__main__":
    main()
