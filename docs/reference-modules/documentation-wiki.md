# Documentation Wiki Publishing

The Documentation Wiki turns Ablation's existing `docs/` library into a navigable GitHub Wiki. It gives readers a Home page, a persistent sidebar, and smaller topic indexes without creating a second set of documentation to maintain.

## Why this exists

A large documentation library can be technically complete and still difficult to explore. Ablation has hundreds of module references, workflows, anomaly records, translations, audits, and release documents. A directory listing shows filenames, but it does not provide a useful reading path.

The Wiki adds that reading path. It is presentation and navigation infrastructure, not an analyzer and not a new source of technical claims. The repository remains the authoritative source.

## What you need to do

Edit documentation normally under `docs/`, then commit and push it to `main`. No Wiki-specific markup or extra publication step is needed.

The `Documentation Wiki` workflow then:

1. Runs the publisher tests.
2. Converts and validates the complete documentation library.
3. Stops if a document link cannot be resolved.
4. Publishes the generated pages to `Ablation-Tool/ablation.wiki.git`.
5. Removes generated pages whose source documents were renamed or deleted.

Pull requests run validation only. Their contents do not reach the Wiki before merging. You can also select **Run workflow** on the Action named `Documentation Wiki` to republish the current `main` branch.

## What readers get

`Home.md` provides starting points for installation, concepts, tool selection, and the full document library. `_Sidebar.md` keeps those entry points and every documentation category available while reading.

Each category has its own alphabetical index. This divides the library into manageable groups such as Module Reference, Workflows, Known Anomalies, Integrations, Languages, and Release Updates. Readers can use these pages instead of scrolling through one list of hundreds of filenames.

The Wiki represents the latest `main` branch. For documentation tied to an older release, use the `docs/` directory in that release's source tree.

## How page names work

GitHub Wiki pages use a flat namespace, while Ablation's documentation uses directories. The publisher preserves the directory meaning in each page name:

```text
docs/getting-started.md
-> Getting-Started

docs/reference-modules/bflt.md
-> Reference-Modules-Bflt

docs/workflows/android-reverse-engineering.md
-> Workflows-Android-Reverse-Engineering
```

The two existing index files have explicit, distinct names: `docs/index.md` becomes `Documentation-Index`, and `docs/INDEX.md` becomes `Document-Library`. Duplicate generated names stop the build instead of silently replacing one document with another.

## How links and assets work

Relative Markdown document links become Wiki links, including their heading anchors. A link from a module reference to `../workflows/android-reverse-engineering.md` therefore remains inside the Wiki.

Links to source files become absolute links to the corresponding file on `main`. Relative images, including existing HTML `<img>` tags, use GitHub's raw asset URLs and must exist in the repository. External URLs and local heading anchors are left alone. Fenced code blocks and inline code spans are preserved, so an example that looks like a Markdown link is not rewritten as though it were real navigation.

Mermaid fences become prominent links to the rendered diagram in the canonical repository document, anchored to the current section. Their source remains visible in a plain-text code block. This avoids the blank Mermaid frame produced by the Wiki renderer without discarding documentation content or adding a rendering dependency. Other fenced code blocks and inline code spans are preserved.

The publisher handles ordinary inline and reference-style Markdown links. Documents with unusually complex multiline link syntax should use a simple inline destination or an explicit GitHub URL so the result remains easy to verify.

## Local validation

Run these commands from the repository root:

```bash
python3 -m pytest -q tests/test_wiki_publishing.py
python3 tools/publish_wiki.py --output /tmp/ablation-wiki-preview
```

The output directory must be new or empty. This prevents the builder from deleting unrelated files. The command reports the number of source documents, generated pages, and categories. Inspect the generated Markdown before publishing when changing navigation or link handling.

No GitHub token is needed for a local build. The publisher uses only the Python standard library.

## Publication safety

Publication happens only after all source documents build successfully. A failed test or unresolved document link leaves the previous Wiki in place. Workflow runs are serialized so two documentation pushes cannot overwrite each other's publication order.

The workflow's token permission is limited to repository contents. It clones the Wiki into a temporary directory and commits generated pages as Nicholas Michael Kloster using the Ablation contact address. No documentation code examples are executed.

## Wiki ownership and limitations

Treat the Wiki as generated output. Direct Wiki edits are replaced by the next synchronization. Make every documentation correction in `docs/` instead.

The first Wiki page must be created once through GitHub's web interface to initialize the Wiki repository. After that, the workflow owns `Home.md`, `_Sidebar.md`, and all generated pages.

Wiki navigation is deliberately grouped only by the existing top-level documentation directories. It does not infer a conceptual hierarchy between individual modules. Curated reading paths belong in documents such as `docs/index.md`, `docs/INDEX.md`, and the workflow guides, where they remain versioned with the project.
