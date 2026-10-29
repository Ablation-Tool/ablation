from pathlib import Path, PurePosixPath

import pytest

from tools.publish_wiki import WikiPublisher


def _write(path: Path, text: str = "# Document\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    docs = tmp_path / "docs"
    home = tmp_path / "Home.md"
    _write(docs / "index.md", "# Documentation Index\n")
    _write(docs / "INDEX.md", "# Complete Library\n")
    _write(docs / "getting-started.md", "# Getting Started\n")
    _write(docs / "overview.md", "# Overview\n")
    _write(docs / "guide-tool-selection.md", "# Tool Selection\n")
    _write(docs / "workflows" / "android.md", "# Android Workflow\n")
    _write(home, "# Ablation\n{{DOCUMENT_COUNT}} documents\n{{CATEGORY_INDEXES}}\n")
    return docs, home


def test_complete_build_and_navigation(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    _write(docs / "reference-modules" / "bflt.md", "# bFLT Loader\n")
    output = tmp_path / "wiki"

    result = WikiPublisher(docs, home).build(output)

    assert result.documents == 7
    assert result.categories == 3
    assert result.pages == len(list(output.glob("*.md"))) == 12
    assert "[bFLT Loader](Reference-Modules-Bflt)" in (output / "Browse-Reference-Modules.md").read_text()
    assert "[Workflows](Browse-Workflows)" in (output / "_Sidebar.md").read_text()
    assert "7 documents" in (output / "Home.md").read_text()
    assert (output / "Documentation-Index.md").exists()
    assert (output / "Document-Library.md").exists()


def test_rewrites_links_without_touching_code(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    _write(tmp_path / "ablation" / "parsers" / "bflt.py", "pass\n")
    _write(tmp_path / "assets" / "logo.png", "image")
    source = """# bFLT

[Workflow](../workflows/android.md#step-1)
[Library](../INDEX.md)
[Source](../../ablation/parsers/bflt.py)
![Logo](../../assets/logo.png)
<img src="../../assets/logo.png">
[External](https://example.com/spec.md)
[Anchor](#local-heading)
[Reference][workflow]

`[Code](../workflows/android.md)`

```markdown
[Fenced](../workflows/android.md)
```

[workflow]: ../workflows/android.md#reference
"""
    path = docs / "reference-modules" / "bflt.md"
    _write(path, source)

    result = WikiPublisher(docs, home).rewrite(source, PurePosixPath("reference-modules/bflt.md"))

    assert "[Workflow](Workflows-Android#step-1)" in result
    assert "[Library](Document-Library)" in result
    assert "[Source](https://github.com/Ablation-Tool/ablation/blob/main/ablation/parsers/bflt.py)" in result
    assert result.count("https://raw.githubusercontent.com/Ablation-Tool/ablation/main/assets/logo.png") == 2
    assert "[External](https://example.com/spec.md)" in result
    assert "[Anchor](#local-heading)" in result
    assert "`[Code](../workflows/android.md)`" in result
    assert "[Fenced](../workflows/android.md)" in result
    assert "[workflow]: Workflows-Android#reference" in result


def test_rejects_duplicate_wiki_names(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    _write(docs / "reference-modules" / "a_b.md")
    _write(docs / "reference-modules" / "a-b.md")

    with pytest.raises(ValueError, match="Wiki page collision"):
        WikiPublisher(docs, home)


def test_rejects_duplicate_category_names(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    _write(docs / "reference_modules" / "one.md")
    _write(docs / "reference-modules" / "two.md")

    with pytest.raises(ValueError, match="Generated Wiki page collision"):
        WikiPublisher(docs, home)


def test_rejects_missing_document_target(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    source = "[Missing](missing.md)\n"
    _write(docs / "reference-modules" / "broken.md", source)

    publisher = WikiPublisher(docs, home)
    with pytest.raises(ValueError, match="unresolved documentation link"):
        publisher.rewrite(source, PurePosixPath("reference-modules/broken.md"))


def test_rejects_missing_image_target(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    source = "![Missing](../../assets/missing.png)\n"
    _write(docs / "reference-modules" / "broken.md", source)

    publisher = WikiPublisher(docs, home)
    with pytest.raises(ValueError, match="unresolved image link"):
        publisher.rewrite(source, PurePosixPath("reference-modules/broken.md"))


def test_rejects_links_outside_repository(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    source = "[Outside](../../../outside.md)\n"
    path = docs / "reference-modules" / "broken.md"
    _write(path, source)

    publisher = WikiPublisher(docs, home)
    with pytest.raises(ValueError, match="escapes the repository"):
        publisher.rewrite(source, PurePosixPath("reference-modules/broken.md"))


def test_replaces_mermaid_with_rendered_diagram_link(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    source = "# bFLT\n\n## How it works\n\n```mermaid\nflowchart TD\n    A --> B\n```\n"
    _write(docs / "reference-modules" / "bflt.md", source)

    result = WikiPublisher(docs, home).rewrite(source, PurePosixPath("reference-modules/bflt.md"))

    expected = (
        "> [View the rendered Mermaid diagram]"
        "(https://github.com/Ablation-Tool/ablation/blob/main/docs/reference-modules/bflt.md#how-it-works)"
    )
    assert expected in result
    assert "```mermaid" not in result
    assert "flowchart TD" not in result


def test_requires_an_empty_output_directory(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    _write(tmp_path / "wiki" / "existing.md")

    with pytest.raises(ValueError, match="not empty"):
        WikiPublisher(docs, home).build(tmp_path / "wiki")
