import json
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
    _write(docs / "reference-modules" / "bflt.md", "# bFLT Loader\n")
    _write(docs / "reference-anomalies" / "arm32.md", "# ARM32 Limitations\n")
    _write(home, "# Ablation\n{{DOCUMENT_COUNT}} documents\n{{CATEGORY_INDEXES}}\n")
    navigation = {
        "directories": {
            "reference-anomalies": "Known-Limitations",
            "reference-modules": "Module-Reference",
            "workflows": "Workflows",
        },
        "sequences": [
            {
                "title": "Guided learning path",
                "steps": ["getting-started.md", "overview.md", "workflows/android.md"],
            }
        ],
        "pages": [
            {
                "slug": "Workflows",
                "title": "Workflows",
                "intro": "Task guides.",
                "sections": [
                    {"title": "Guides", "entries": [{"path": "workflows/android.md"}]},
                ],
            },
            {
                "slug": "Capabilities",
                "title": "Capabilities",
                "intro": "Analysis domains.",
                "sections": [
                    {"title": "Domains", "entries": [{"page": "Capabilities-Firmware"}]},
                ],
            },
            {
                "slug": "Capabilities-Firmware",
                "title": "Firmware Formats",
                "intro": "Executable loaders.",
                "sections": [
                    {"title": "Loaders", "entries": [{"path": "reference-modules/bflt.md"}]},
                ],
            },
            {
                "slug": "Reference",
                "title": "Reference",
                "intro": "Detailed lookup.",
                "sections": [
                    {
                        "title": "Indexes",
                        "entries": [
                            {"page": "Module-Reference"},
                            {"page": "Known-Limitations"},
                        ],
                    },
                ],
            },
            {
                "slug": "Module-Reference",
                "title": "Module Reference",
                "intro": "Direct module lookup.",
                "module_index": True,
                "sections": [],
            },
            {
                "slug": "Known-Limitations",
                "title": "Known Limitations",
                "intro": "Review requirements.",
                "directory_index": "reference-anomalies",
            },
        ],
    }
    _write(tmp_path / ".github" / "wiki" / "navigation.json", json.dumps(navigation))
    _write(
        tmp_path / ".github" / "wiki" / "_Sidebar.md",
        "- [Home](Home)\n- [Workflows](Workflows)\n- [Module Reference](Module-Reference)\n",
    )
    _write(tmp_path / ".github" / "wiki" / "_Footer.md", "[Source](https://example.com)\n")
    return docs, home


def test_complete_build_and_navigation(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    output = tmp_path / "wiki"

    result = WikiPublisher(docs, home).build(output)

    assert result.documents == 8
    assert result.categories == 6
    assert result.pages == len(list(output.glob("*.md"))) == 18
    assert "[bFLT Loader](Reference-Modules-Bflt)" in (output / "Capabilities-Firmware.md").read_text()
    assert "[ARM32 Limitations](Reference-Anomalies-Arm32)" in (output / "Known-Limitations.md").read_text()
    assert "[Workflows](Workflows)" in (output / "_Sidebar.md").read_text()
    assert "[Source](https://example.com)" in (output / "_Footer.md").read_text()
    assert "8 documents" in (output / "Home.md").read_text()
    assert (output / "Documentation-Index.md").exists()
    assert (output / "Document-Library.md").exists()
    assert not (output / "Browse-Reference-Modules.md").exists()
    breadcrumb = "[Home](Home) › [Capabilities](Capabilities) › [Firmware Formats](Capabilities-Firmware)"
    assert breadcrumb in (output / "Reference-Modules-Bflt.md").read_text()


def test_adds_previous_and_next_links_to_sequence_documents(tmp_path: Path):
    docs, home = _fixture(tmp_path)

    WikiPublisher(docs, home).build(tmp_path / "wiki")

    first = (tmp_path / "wiki" / "Getting-Started.md").read_text()
    middle = (tmp_path / "wiki" / "Overview.md").read_text()
    last = (tmp_path / "wiki" / "Workflows-Android.md").read_text()
    unrelated = (tmp_path / "wiki" / "Guide-Tool-Selection.md").read_text()
    assert "Guided learning path** · Step 1 of 3" in first
    assert "Previous:" not in first
    assert "[Next: Overview →](Overview)" in first
    assert "[← Previous: Getting Started](Getting-Started)" in middle
    assert "[Next: Android Workflow →](Workflows-Android)" in middle
    assert "Guided learning path** · Step 3 of 3" in last
    assert "Next:" not in last
    assert "Guided learning path" not in unrelated


def test_rewrites_links_without_touching_code(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    _write(tmp_path / "ablation" / "parsers" / "bflt.py", "pass\n")
    _write(tmp_path / "assets" / "logo.png", "image")
    source = """# bFLT

[Workflow](../workflows/android.md#step-1)
[Library](../INDEX.md)
[Modules](../reference-modules/)
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
    _write(docs / "reference-modules" / "bflt.md", source)

    result = WikiPublisher(docs, home).rewrite(source, PurePosixPath("reference-modules/bflt.md"))

    assert "[Workflow](Workflows-Android#step-1)" in result
    assert "[Library](Document-Library)" in result
    assert "[Modules](Module-Reference)" in result
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


def test_rejects_navigation_collision_with_document(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    _write(docs / "Capabilities.md")

    with pytest.raises(ValueError, match="Generated Wiki page collision"):
        WikiPublisher(docs, home)


def test_rejects_missing_navigation_target(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    navigation_path = tmp_path / ".github" / "wiki" / "navigation.json"
    navigation = json.loads(navigation_path.read_text())
    navigation["pages"][0]["sections"][0]["entries"].append({"path": "workflows/missing.md"})
    navigation_path.write_text(json.dumps(navigation))

    with pytest.raises(ValueError, match="Navigation target not found"):
        WikiPublisher(docs, home)


def test_rejects_missing_template_link_target(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    _write(tmp_path / ".github" / "wiki" / "_Sidebar.md", "[Missing](Not-A-Page)\n")

    with pytest.raises(ValueError, match="Wiki template link not found"):
        WikiPublisher(docs, home).build(tmp_path / "wiki")


def test_rejects_unsafe_navigation_slug(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    navigation_path = tmp_path / ".github" / "wiki" / "navigation.json"
    navigation = json.loads(navigation_path.read_text())
    navigation["pages"][0]["slug"] = "../escape"
    navigation_path.write_text(json.dumps(navigation))

    with pytest.raises(ValueError, match="Invalid Wiki navigation slug"):
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
    _write(docs / "reference-modules" / "broken.md", source)

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
    assert "<details><summary>View Mermaid source</summary>" in result
    assert "```text\nflowchart TD\n    A --> B\n```" in result
    assert "</details>" in result
    assert "```mermaid" not in result


def test_rejects_unclosed_mermaid_fence(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    source = "```mermaid\nflowchart TD\n"

    publisher = WikiPublisher(docs, home)
    with pytest.raises(ValueError, match="unclosed Mermaid fence"):
        publisher.rewrite(source, PurePosixPath("reference-modules/bflt.md"))


def test_rejects_missing_sequence_target(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    navigation_path = tmp_path / ".github" / "wiki" / "navigation.json"
    navigation = json.loads(navigation_path.read_text())
    navigation["sequences"][0]["steps"].append("workflows/missing.md")
    navigation_path.write_text(json.dumps(navigation))

    with pytest.raises(ValueError, match="Navigation sequence target not found"):
        WikiPublisher(docs, home)


def test_rejects_document_in_multiple_sequences(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    navigation_path = tmp_path / ".github" / "wiki" / "navigation.json"
    navigation = json.loads(navigation_path.read_text())
    navigation["sequences"].append(
        {"title": "Another path", "steps": ["overview.md", "guide-tool-selection.md"]}
    )
    navigation_path.write_text(json.dumps(navigation))

    with pytest.raises(ValueError, match="multiple navigation sequences"):
        WikiPublisher(docs, home)


def test_splits_and_orders_module_index(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    _write(docs / "reference-modules" / "alpha.md", "# Alpha Loader\n")
    _write(docs / "reference-modules" / "zeta.md", "# Zeta Loader\n")

    result = WikiPublisher(docs, home).build(tmp_path / "wiki")

    reference = (tmp_path / "wiki" / "Module-Reference.md").read_text()
    assert reference.index("[A](Module-Index-A)") < reference.index("[B](Module-Index-B)")
    assert reference.index("[B](Module-Index-B)") < reference.index("[Z](Module-Index-Z)")
    assert "[Alpha Loader](Reference-Modules-Alpha)" in (tmp_path / "wiki" / "Module-Index-A.md").read_text()
    assert "[Zeta Loader](Reference-Modules-Zeta)" in (tmp_path / "wiki" / "Module-Index-Z.md").read_text()
    assert "Alpha Loader" not in reference
    assert result.pages == 22


def test_requires_an_empty_output_directory(tmp_path: Path):
    docs, home = _fixture(tmp_path)
    _write(tmp_path / "wiki" / "existing.md")

    with pytest.raises(ValueError, match="not empty"):
        WikiPublisher(docs, home).build(tmp_path / "wiki")
