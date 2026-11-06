<!--
  Ablation-Tool repository README template ("streamlined dropdown" version).
  Copy this file to <repo>/README.md and replace every <PLACEHOLDER>.

  Rules:
  - No branding banners, wordmark images, or shields. Text and tables only.
  - Every capability row links to implementation code and, where applicable, a doc page.
  - Keep it information dense: categories are collapsible <details> sections.
  - Plain language first. Define every product name and abbreviation before using it.
  - No em dashes. Short sentences. Separate tested behavior, limits, and remaining work.
  - Do not claim unimplemented features or unverified compliance.
-->

# <PROJECT NAME>

<One-sentence positioning statement: what it is, who it is for, what question it answers.>

<One short paragraph of plain language. Explain the primary product surface as if the reader has never seen the codebase. Define every named component (for example: "X is the native graphical workbench. It is a desktop application built with GTK3, the same Linux UI toolkit used by GNOME applications, not a web page.").>

**Current version:** <x.y.z>

**Primary question:** <the one question the project answers for its user>

---

## Capabilities

<!-- One <details> block per category. Keep the table columns:
     Capability (doc link) | Code (numbered source links) | Description (one sentence). -->

<details>
<summary><CATEGORY 1, e.g. Collection & Evidence></summary>

**<Category display name>**

<2-4 sentences explaining what this category does in plain language and how it fits the whole.>

| Capability | Code | Description |
|:---|:---|:---|
| [<Capability>](<docs/page.md>) | [1](<src/file.c>)&nbsp;[2](<src/file2.c>) | <One-sentence description of tested behavior.> |

</details>

<details>
<summary><CATEGORY 2></summary>

**<Category display name>**

<Plain-language explanation.>

| Capability | Code | Description |
|:---|:---|:---|
| [<Capability>](<docs/page.md>) | [1](<src/file.c>)&nbsp;[2](<src/file2.c>) | <One-sentence description.> |

</details>

<details>
<summary><CATEGORY 3, e.g. Workbench / UI></summary>

**<Category display name>**

<Plain-language explanation of the user-facing surface.>

- <Bullet when a table does not fit.>
- <Bullet.>

</details>

<details>
<summary><CATEGORY 4, e.g. Diagnostics></summary>

<Command or table content.>

</details>

## Setup & About

<details>
<summary>Quick Start</summary>

### Build and verify

```bash
<minimal tested commands>
```

### <First workflow>

```bash
<commands>
```

### <Second workflow>

```bash
<commands>
```

</details>

<details>
<summary>Verification Status</summary>

- <Test counts and suites actually run.>
- <Vectors, real-hardware, or end-to-end exercises actually performed.>
- <Third-party reviews, if any.>

Run the complete verification matrix:

```bash
<commands>
```

</details>

<details>
<summary>Limits & Safe Use</summary>

- <Honest limitation.>
- <Honest limitation.>

</details>

<details>
<summary>Documentation</summary>

- [Capability reference](docs/capabilities.md)
- [<Other guide>](docs/<page>.md)

</details>

<details>
<summary>Responsible Use & Contact</summary>

<Responsible use statement: authorized use only, preserved evidence, sensitive material handling.>

Report bugs through [GitHub Issues](https://github.com/Ablation-Tool/<repo>/issues).

</details>
