#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
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
    def __init__(
        self,
        docs_root: Path,
        home_template: Path,
        navigation_template: Path | None = None,
        sidebar_template: Path | None = None,
    ) -> None:
        self.docs_root = docs_root.resolve()
        self.repository_root = self.docs_root.parent
        self.home_template = home_template
        self.navigation_template = navigation_template or self.repository_root / ".github/wiki/navigation.json"
        self.sidebar_template = sidebar_template or self.repository_root / ".github/wiki/_Sidebar.md"
        self.documents = self._collect_documents()
        self.by_path = {document.path: document for document in self.documents}
        self.groups: dict[str, list[Document]] = {}
        for document in self.documents:
            group = document.path.parts[0] if len(document.path.parts) > 1 else ""
            self.groups.setdefault(group, []).append(document)
        self.navigation = self._load_navigation()
        self.pages = self.navigation["pages"]
        self.page_by_slug = {page["slug"]: page for page in self.pages}
        self.directory_pages = self.navigation["directories"]
        self.parent_pages, self.parent_documents = self._navigation_relationships()
        self._validate_hierarchy()
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

    def _load_navigation(self) -> dict:
        data = json.loads(self.navigation_template.read_text(encoding="utf-8"))
        if not isinstance(data.get("pages"), list) or not data["pages"]:
            raise ValueError("Wiki navigation must contain at least one page")
        if not isinstance(data.get("directories"), dict):
            raise ValueError("Wiki navigation must contain a directories mapping")
        slugs = set()
        for page in data["pages"]:
            slug = page.get("slug", "")
            title = page.get("title", "")
            if not slug or not title or not isinstance(page.get("intro", ""), str):
                raise ValueError(f"Invalid Wiki navigation page: {page!r}")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", slug):
                raise ValueError(f"Invalid Wiki navigation slug: {slug}")
            if slug.casefold() in slugs:
                raise ValueError(f"Duplicate Wiki navigation page: {slug}")
            slugs.add(slug.casefold())
            for section in page.get("sections", []):
                for entry in section.get("entries", []):
                    if ("path" in entry) == ("page" in entry):
                        raise ValueError(f"Navigation entry must have exactly one target: {entry!r}")
                    path = entry.get("path")
                    if path is not None and PurePosixPath(path) not in self.by_path:
                        raise ValueError(f"Navigation target not found: {path}")
            directory = page.get("directory_index")
            if directory is not None and directory not in self.groups:
                raise ValueError(f"Navigation directory not found: {directory}")
        page_slugs = {page["slug"] for page in data["pages"]}
        for page in data["pages"]:
            for section in page.get("sections", []):
                for entry in section.get("entries", []):
                    target = entry.get("page")
                    if target is not None and target not in page_slugs:
                        raise ValueError(f"Navigation page not found: {target}")
        for directory, slug in data["directories"].items():
            if directory not in self.groups:
                raise ValueError(f"Mapped documentation directory not found: {directory}")
            if slug not in page_slugs:
                raise ValueError(f"Directory {directory} maps to unknown page: {slug}")
        return data

    def _navigation_relationships(self) -> tuple[dict[str, str], dict[PurePosixPath, str]]:
        root_pages = {
            "Workflows", "Capabilities", "Reference", "Module-Reference",
            "Architecture-Guide", "Development-Guide", "Releases",
        }
        parent_pages = {slug: "" for slug in root_pages}
        parent_documents = {}
        for page in self.pages:
            for section in page.get("sections", []):
                for entry in section.get("entries", []):
                    if "page" in entry:
                        parent_pages.setdefault(entry["page"], page["slug"])
                    else:
                        parent_documents.setdefault(PurePosixPath(entry["path"]), page["slug"])
        return parent_pages, parent_documents

    def _validate_hierarchy(self) -> None:
        for slug in self.page_by_slug:
            seen = set()
            current = slug
            while current:
                if current in seen:
                    raise ValueError(f"Wiki navigation hierarchy contains a cycle at {current}")
                seen.add(current)
                current = self.parent_pages.get(current, "")

    def _validate_generated_names(self) -> None:
        used = {document.slug.casefold(): document.path.as_posix() for document in self.documents}
        generated = [*self.page_by_slug, *self._module_index_pages(), "Home", "_Sidebar"]
        for name in generated:
            collision = used.get(name.casefold())
            if collision is not None:
                raise ValueError(f"Generated Wiki page collision: {name} is already used by {collision}")
            used[name.casefold()] = "generated navigation"

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
                if len(parts) == 2 and parts[0] == "docs" and parts[1] in self.directory_pages:
                    return f"{self.directory_pages[parts[1]]}{suffix}"
                return f"{REPOSITORY_URL}/tree/{BRANCH}/{quote(repository_path.as_posix(), safe='/')}{suffix}"
        if image and not (self.repository_root / Path(repository_path)).is_file():
            raise ValueError(f"{source}: unresolved image link: {target}")
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

    @staticmethod
    def _heading_anchor(line: str) -> str:
        match = re.match(r"^#{1,6}[ \t]+(.+?)[ \t]*#*[ \t]*$", line)
        if not match:
            return ""
        heading = re.sub(r"<[^>]+>", "", match.group(1))
        heading = re.sub(r"[`*_~]", "", heading)
        heading = re.sub(r"[^\w\- ]", "", heading, flags=re.UNICODE)
        return heading.strip().lower().replace(" ", "-")

    @staticmethod
    def _mermaid_link(source: PurePosixPath, anchor: str) -> str:
        path = quote(f"docs/{source.as_posix()}", safe="/")
        fragment = f"#{anchor}" if anchor else ""
        return (
            f"> [View the rendered Mermaid diagram]({REPOSITORY_URL}/blob/{BRANCH}/{path}{fragment})\n\n"
        )

    def rewrite(self, text: str, source: PurePosixPath) -> str:
        output = []
        fence_character = ""
        fence_length = 0
        mermaid_fence = False
        heading_anchor = ""
        for line in text.splitlines(keepends=True):
            marker = FENCE_RE.match(line)
            if fence_character:
                output.append(line)
                if marker:
                    fence = marker.group("fence")
                    remainder = line[marker.end():].strip()
                    if fence[0] == fence_character and len(fence) >= fence_length and not remainder:
                        if mermaid_fence:
                            output.append("\n</details>\n")
                        fence_character = ""
                        fence_length = 0
                        mermaid_fence = False
                continue
            if marker:
                fence = marker.group("fence")
                fence_character = fence[0]
                fence_length = len(fence)
                language = line[marker.end():].strip().split(maxsplit=1)
                mermaid_fence = bool(language) and language[0].casefold() == "mermaid"
                if mermaid_fence:
                    output.append(self._mermaid_link(source, heading_anchor))
                    output.append("<details><summary>View Mermaid source</summary>\n\n")
                    output.append(f"{line[:marker.start()]}{fence}text\n")
                else:
                    output.append(line)
                continue
            anchor = self._heading_anchor(line)
            if anchor:
                heading_anchor = anchor
            output.append(self._rewrite_line(line, source))
        if mermaid_fence:
            raise ValueError(f"{source}: unclosed Mermaid fence")
        return "".join(output)

    def _fallback_parent(self, path: PurePosixPath) -> str:
        if len(path.parts) > 1:
            return self.directory_pages.get(path.parts[0], "Reference")
        if path in {PurePosixPath("getting-started.md"), PurePosixPath("index.md")}:
            return ""
        if path == PurePosixPath("INDEX.md"):
            return "Module-Reference"
        return "Reference"

    def _breadcrumb_chain(self, parent: str) -> list[str]:
        chain = []
        seen = set()
        current = parent
        while current and current not in seen:
            seen.add(current)
            chain.append(current)
            current = self.parent_pages.get(current, "")
        return list(reversed(chain))

    def _breadcrumb(self, parent: str) -> str:
        links = ["[Home](Home)"]
        links.extend(
            f"[{self.page_by_slug[slug]['title']}]({slug})"
            for slug in self._breadcrumb_chain(parent)
        )
        return " › ".join(links)

    def _with_breadcrumb(self, text: str, document: Document) -> str:
        parent = self.parent_documents.get(document.path, self._fallback_parent(document.path))
        if not parent:
            return text
        breadcrumb = f"*{self._breadcrumb(parent)}*\n\n"
        lines = text.splitlines(keepends=True)
        insertion = 0
        for index, line in enumerate(lines):
            if line.startswith("<a "):
                insertion = index + 1
                continue
            if re.match(r"^# ", line):
                insertion = index + 1
            break
        if insertion < len(lines) and not lines[insertion].strip():
            del lines[insertion]
        return "".join(lines[:insertion]) + breadcrumb + "".join(lines[insertion:])

    def _module_index_pages(self) -> dict[str, str]:
        buckets: dict[str, list[Document]] = {}
        for document in self.groups.get("reference-modules", []):
            match = re.search(r"[A-Za-z0-9]", document.title)
            letter = match.group(0).upper() if match else "#"
            buckets.setdefault(letter, []).append(document)
        pages = {}
        for letter, documents in sorted(buckets.items(), key=lambda item: (item[0] == "#", item[0])):
            slug = "Module-Index-0-9" if letter == "#" else f"Module-Index-{letter}"
            lines = [
                f"# Module Index: {letter}",
                "",
                f"*{self._breadcrumb('Module-Reference')}*",
                "",
                f"{len(documents)} modules. Use curated capability pages for task-focused navigation.",
                "",
            ]
            for document in sorted(documents, key=lambda item: (item.title.casefold(), item.slug)):
                lines.append(f"- [{document.title}]({document.slug})")
            lines.append("")
            pages[slug] = "\n".join(lines)
        return pages

    def _render_directory_index(self, page: dict) -> list[str]:
        directory = page["directory_index"]
        documents = sorted(
            self.groups[directory],
            key=lambda item: (item.title.casefold(), item.slug),
        )
        return [f"- [{document.title}]({document.slug})" for document in documents]

    def _navigation_pages(self) -> dict[str, str]:
        pages = {}
        for page in self.pages:
            slug = page["slug"]
            lines = [f"# {page['title']}", ""]
            parent = self.parent_pages.get(slug, "")
            if parent:
                lines.extend([f"*{self._breadcrumb(parent)}*", ""])
            lines.extend([page["intro"], ""])
            if page.get("module_index"):
                index_links = []
                for index_slug in self._module_index_pages():
                    label = "#" if index_slug == "Module-Index-0-9" else index_slug.removeprefix("Module-Index-")
                    index_links.append(f"[{label}]({index_slug})")
                lines.extend(["## Alphabetical module index", ""])
                for start in range(0, len(index_links), 7):
                    lines.append(" · ".join(index_links[start:start + 7]))
                lines.append("")
            if "directory_index" in page:
                lines.extend(self._render_directory_index(page))
                lines.append("")
            for section in page.get("sections", []):
                lines.extend([f"## {section['title']}", ""])
                for entry in section.get("entries", []):
                    if "path" in entry:
                        document = self.by_path[PurePosixPath(entry["path"])]
                        target = document.slug
                        title = entry.get("title", document.title)
                    else:
                        target = entry["page"]
                        title = entry.get("title", self.page_by_slug[target]["title"])
                    description = entry.get("description", "")
                    suffix = f" - {description}" if description else ""
                    lines.append(f"- **[{title}]({target})**{suffix}")
                lines.append("")
            pages[slug] = "\n".join(lines)
        return pages

    def build(self, output_root: Path) -> BuildResult:
        if output_root.exists() and any(output_root.iterdir()):
            raise ValueError(f"Output directory is not empty: {output_root}")
        output_root.mkdir(parents=True, exist_ok=True)
        navigation_pages = self._navigation_pages()
        module_index_pages = self._module_index_pages()
        for document in self.documents:
            source = self.docs_root / Path(document.path)
            text = source.read_text(encoding="utf-8")
            text = self.rewrite(text, document.path)
            (output_root / f"{document.slug}.md").write_text(
                self._with_breadcrumb(text, document), encoding="utf-8"
            )
        for slug, text in {**navigation_pages, **module_index_pages}.items():
            (output_root / f"{slug}.md").write_text(text, encoding="utf-8")
        category_links = "\n".join(
            f"- [{page['title']}]({page['slug']}) - {page['intro']}" for page in self.pages
        )
        home = self.home_template.read_text(encoding="utf-8")
        home = home.replace("{{CATEGORY_INDEXES}}", category_links)
        home = home.replace("{{DOCUMENT_COUNT}}", str(len(self.documents)))
        (output_root / "Home.md").write_text(home, encoding="utf-8")
        (output_root / "_Sidebar.md").write_text(
            self.sidebar_template.read_text(encoding="utf-8"), encoding="utf-8"
        )
        pages = len(self.documents) + len(navigation_pages) + len(module_index_pages) + 2
        return BuildResult(len(self.documents), pages, len(navigation_pages))


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a navigable GitHub Wiki from docs/")
    parser.add_argument("--docs", type=Path, default=Path("docs"))
    parser.add_argument("--home", type=Path, default=Path(".github/wiki/Home.md"))
    parser.add_argument("--navigation", type=Path, default=Path(".github/wiki/navigation.json"))
    parser.add_argument("--sidebar", type=Path, default=Path(".github/wiki/_Sidebar.md"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    publisher = WikiPublisher(args.docs, args.home, args.navigation, args.sidebar)
    result = publisher.build(args.output)
    print(
        f"Built {result.pages} Wiki pages from {result.documents} documents "
        f"in {result.categories} curated categories."
    )


if __name__ == "__main__":
    main()
