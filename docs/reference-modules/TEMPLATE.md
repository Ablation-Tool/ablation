# Module Name

One sentence describing what this module does and the problem it solves.

---

## Why this exists

Numbered list of gaps this module fills. Each item names the specific thing that was not possible before this module existed, why other approaches failed, and what Ablation now does instead.

---

## How it works

Technical explanation of the algorithm or approach. Include a mermaid pipeline diagram when the data flow has more than two stages. Cover the key design decisions that affect output quality.

---

## Class Name

Constructor signature and key methods with parameter descriptions.

```python
from ablation.analyzers.module_name import ClassName

obj = ClassName.from_context(ctx)
results = obj.run()
```

---

## Usage

Runnable code examples covering the main paths. Show the minimal call to get useful output, then show the extended call with options.

```python
# Minimal
results = ClassName.from_path('/path/to/target').run()

# With options
results = ClassName.from_context(ctx, custom_option=True).run()
for r in results:
    print(r)
```

---

## Example output

A real sample of what the module returns. Show a populated finding dict, a printed result, or annotated output: whichever is most representative.

```
[SEVERITY] FINDING_TYPE   function_name (0xVA)
  detail: explanation of what was found
  source: where the input came from
```

---

## False positives

What generates noise and how to eliminate it before manual review. Cover the 2-3 most common FP sources and the filter or check that rules each one out.

---

## Pipeline position

**Before this module:** what to run first and why.

**After this module:** what this feeds into.

---

## Reading findings

| Field | Content |
|:---|:---|
| `field_name` | What this field contains |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `va` | Virtual address of the finding in the binary |

---

## See also

- [Related Module](binary-lifter.md): example destination; replace it when using this template
- [Another Module](semantic-code-search.md): example destination; replace it when using this template
