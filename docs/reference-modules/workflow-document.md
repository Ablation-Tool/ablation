# WorkflowDocument

## Why this exists

1. `SESSION.md` is human-maintained flat markdown with no schema validation on stage
 outputs. A `finding_confirmation` missing `byte_proof` is not caught until FORGE
 runs on the RE module, at which point the finding may already be registered.

2. Stage routing is implicit in prose. There is no machine-checkable rule that
   `candidate_profile` must follow `semantic_sweep` or that `registration` requires
 a passing `forge_gate_passed` field. Session context carries this knowledge; the
 document does not.

3. Stage outputs are untyped. An integer virtual address stored as a string, a
 missing required field, or a candidates list containing non-dict items produces
 no error until a downstream tool tries to use the value.

`WorkflowDocument` addresses all three gaps. Each pipeline stage has a schema;
`advance()` validates the populated instance before committing and records a
timestamped transition. The document serialises to JSON and survives compaction.

---

## Module

```
ablation/analyzers/workflow_document.py
```

---

## Classes

### `Stage`

```python
@dataclass
class Stage:
    name: str
    schema: dict
    instance: dict
    routing: list[str]
    committed: bool
```

`schema` format: `{"required": [...], "properties": {k: {"type": typname}}}`.
`routing` holds names of stages to activate next; empty list means terminal.

### `StageTransition`

```python
@dataclass
class StageTransition:
    from_stage: str
    to_stage: str
    timestamp: str
    producer_id: str
```

`timestamp` is ISO-8601 UTC.

### `WorkflowDocument`

```python
class WorkflowDocument:
    stages: list[Stage]
    doc_id: str
    log: list[StageTransition]
```

---

## API

### `__init__()`

```python
WorkflowDocument(
    stages: list[Stage],
    doc_id: str = "",
)
```

Raises `ValueError` if `stages` is empty.

---

### `current()`

```python
def current(self) -> Stage
```

Returns the active (not yet committed) stage.

---

### `validate()`

```python
def validate(
    self,
    stage_name: str,
    instance: dict,
) -> list[str]
```

Validates `instance` against the named stage's schema without advancing. Returns
a list of error strings; an empty list means the instance is valid.

Checks:
- All keys in `schema["required"]` are present.
- Each key in `schema["properties"]` with a declared `"type"` matches the expected
 Python type. Supported type names: `str`, `int`, `float`, `bool`, `list`, `dict`.

---

### `advance()`

```python
def advance(
    self,
    instance: dict,
    producer_id: str = "",
) -> list[str]
```

Validates `instance`, commits the current stage, records a `StageTransition` for
each routing target, advances `current()` to the first routing target, and returns
the routing list.

Raises `ValueError` if the instance does not satisfy the current stage's schema.
Returns `[]` when the workflow reaches a terminal stage.

---

### `dirty_since_commit()`

```python
def dirty_since_commit(self) -> bool
```

Returns `True` if any committed stage's instance has been mutated since
`advance()` was called. Detects out-of-band writes to `stage.instance`.

---

### `report()`

```python
def report(self) -> str
```

Human-readable status table:

```
WorkflowDocument id='cisco/fmc_server'
  triage                   COMMITTED   fields=6
  semantic_sweep           CURRENT     fields=0
  candidate_profile        pending     fields=0
  taint_trace              pending     fields=0
  finding_confirmation     pending     fields=0
  registration             pending     fields=0
  transitions logged: 1
```

---

### `to_json()` and `from_json()`

```python
def to_json(self) -> str

@classmethod
def from_json(
    cls,
    s: str,
) -> WorkflowDocument
```

Full round-trip serialisation including committed snapshots and transition log.

---

### `for_re_session()`

```python
@classmethod
def for_re_session(
    cls,
    vendor: str,
    target: str,
) -> WorkflowDocument
```

Pre-built six-stage pipeline matching the ablation standard tool ordering.

| Stage | Required fields |
|-------|----------------|
| `triage` | `binary_hash`, `arch`, `bits`, `section_count`, `string_count`, `plt_count` |
| `semantic_sweep` | `query`, `candidates` |
| `candidate_profile` | `va`, `name`, `complexity`, `call_count`, `caller_count` |
| `taint_trace` | `source_va`, `sink_va`, `path_length`, `taint_regs` |
| `finding_confirmation` | `va`, `cwe`, `severity`, `title`, `description`, `byte_proof` |
| `registration` | `finding_id`, `forge_gate_passed` |

---

## Schema format

```python
schema = {
    "required": ["field_a", "field_b"],
    "properties": {
        "field_a": {"type": "str"},
        "field_b": {"type": "int"},
        "field_c": {"type": "list"},
    },
}
```

Type names: `str`, `int`, `float`, `bool`, `list`, `dict`.
No external dependency. `float` accepts both `int` and `float` values.
`field_c` above is optional; properties with no matching `required` entry are
only type-checked if present.

---

## Example: Cisco RE session

```python
from ablation.analyzers.workflow_document import WorkflowDocument
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build("/path/to/fmc_server")
vendor = "cisco"
target = "fmc_server"
doc = WorkflowDocument.for_re_session(
    vendor,
    target,
)

# build the triage instance from BinaryContext
summary = ctx.summary()
triage_instance = {
    "binary_hash": summary["sha256"],
    "arch": summary["arch"],
    "bits": summary["bits"],
    "section_count": summary["section_count"],
    "string_count": summary["string_count"],
    "plt_count": summary["plt_count"],
}

# validate before writing
errors = doc.validate(
    "triage",
    triage_instance,
)
if errors:
    raise ValueError(errors)

# advance: validates, commits, returns next stage names
next_stages = doc.advance(
    triage_instance,
    producer_id="session-42",
)
# ["semantic_sweep"]

# persist between sessions
from pathlib import Path
Path("re/cisco/fmc_server_workflow.json").write_text(doc.to_json())

# resume in a later session
doc2 = WorkflowDocument.from_json(
    Path("re/cisco/fmc_server_workflow.json").read_text()
)
print(doc2.report())
```

---

## Integration with StageCommitment

`WorkflowDocument` tracks what each stage contains and whether it is valid.
`StageCommitment` tracks who produced it and whether it has been tampered with.
Use them together:

```python
from ablation.analyzers.stage_commitment import StageCommitment

sc = StageCommitment(doc_id="cisco/fmc_server")
next_stages = doc.advance(
    triage_instance,
    producer_id="session-42",
)
sc.commit(
    "triage",
    triage_instance,
    producer="session-42",
)
```

See `stage-commitment.md` for the full API.

---

## How it works

Provides the session state, indexing, and utility functions that other Ablation modules depend on. The implementation details vary by class; see the class-level docstrings and the relevant workflow docs for specifics.

---

## Usage

```python
from ablation.analyzers.workflow_document import WorkflowDocument

results = WorkflowDocument.from_context(ctx).run()
for r in results:
    print(r)
```

---

## Example output

```
# Output varies by module. See Usage section for representative examples.
```

---

## False positives

Core infrastructure modules do not emit security findings directly. False positives in downstream scanners are addressed at the scanner level, not here.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` to build the analysis session.

**After this module:** Results feed directly into the analysis pipeline: `SemanticSearcher`, `TaintTracker`, or output modules depending on the task.

---

## Reading findings

| Field | Content |
|:---|:---|
| `result` | Module-specific output; see the class docstring for the exact type |

---

## See also

- [BinaryContext](binary-context.md) — session foundation for all analysis
- [SemanticSearch](semantic-search.md) — function candidate identification
- [FindingRegistry](registry.md) — persistent finding storage
