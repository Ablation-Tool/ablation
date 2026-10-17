# StageCommitment

## Why this exists

1. FORGE is a point-in-time gate. It does not persist a hash of what passed.
 When a finding is revised after confirmation there is no record of the original
 committed content, which session produced it, or whether the revision was
 reviewed by anyone.

2. Multi-session review has no tamper-evidence. If two agents work on the same
 target across sessions there is no machine-checkable way to detect whether a
 finding was altered between sessions without manually diffing SESSION.md files.

3. The connection between a confirmed finding and its originating workflow stage
 is not recorded. `FindingRegistry.register()` captures the finding; it does
 not record who produced it or whether a second agent reviewed and approved it.

`StageCommitment` addresses all three gaps using the No-Lock/Approving pattern.
The producer commits a content hash without freezing the instance. The reviewer
countersigns covering both the original hash and the final content. `verify()`
detects any mutation at any later point.

---

## Module

```
ablation/analyzers/stage_commitment.py
```

No external dependencies. Uses `hashlib.sha256` and `json` from the standard
library.

---

## The No-Lock/Approving Pattern

Derived from IBM XFDL signature filters.

```
Producer                       Reviewer
   |                              |
commit(instance)                  |
  content_hash = sha256(instance) |
   |                              |
   |       [reviewer reads and optionally revises]
   |                              |
   |                     approve(revised_instance)
   |                       approving_hash =
   |                         sha256(content_hash + sha256(revised))
   |                              |
verify(current_instance) ---------+
  current == content_hash                  -> ok
  current == revised_content_hash
    and approving_hash valid               -> ok (approved revision)
  anything else                            -> tampered
```

A `lock_mode="no-lock"` commitment does not freeze the instance. The reviewer
may revise it. But if anyone alters the instance after the approving hash is
recorded, `verify()` detects the mismatch. Both the original and final state are
bound to the chain.

---

## Classes

### `CommitmentRecord`

```python
@dataclass
class CommitmentRecord:
    stage_name: str
    producer: str
    content_hash: str
    timestamp: str
    lock_mode: str
    approver: str | None
    revised_content_hash: str | None
    approving_hash: str | None
```

`content_hash` is `sha256` of the canonicalised JSON of the committed instance.
`approving_hash` is `sha256` of `content_hash + revised_hash` where `revised_hash`
is empty string when no revision was made.

### `StageCommitment`

```python
class StageCommitment:
    doc_id: str
```

---

## API

### `__init__()`

```python
StageCommitment(doc_id: str = "")
```

`doc_id` should match the `WorkflowDocument.doc_id` for the same pipeline.

---

### `commit()`

```python
def commit(
    self,
    stage_name: str,
    instance: dict,
    producer: str,
    lock_mode: str = "no-lock",
) -> CommitmentRecord
```

Records a content hash for `stage_name`. Raises `ValueError` if `lock_mode`
is not `"no-lock"` or `"locked"`, or if `producer` is empty.

Calling `commit()` a second time for the same `stage_name` overwrites the prior
record. Use `approve()` for the review step rather than re-committing.

---

### `approve()`

```python
def approve(
    self,
    stage_name: str,
    approver: str,
    revised_instance: dict | None = None,
) -> CommitmentRecord
```

Countersigns the committed stage. `revised_instance=None` means the reviewer
accepts the original content unchanged. The approving hash still binds the
reviewer's identity to the committed content.

Raises `KeyError` if `stage_name` has no prior commitment.
Raises `ValueError` if `approver` is empty.

---

### `verify()`

```python
def verify(
    self,
    stage_name: str,
    current_instance: dict,
) -> tuple[bool, str]
```

Returns a two-element tuple. First element is `True` when the chain is intact,
`False` otherwise. Second element is a reason string.

| Reason string | Meaning |
|--------------|---------|
| `"ok"` | current instance matches the committed hash |
| `"ok (approved revision)"` | current matches revised hash and approving chain is valid |
| `"no commitment for stage '...'"` | `commit()` was never called |
| `"content mutated:..."` | instance changed after commit with no approved revision |
| `"approving hash mismatch"` | revised_content_hash matches but approving_hash is wrong |

---

### `audit_trail()`

```python
def audit_trail(self) -> str
```

Human-readable table of all commitments:

```
StageCommitment doc_id='cisco/fmc_server'
  stage                    producer       lock        approver       chain
  ------------------------------------------------------------------------
  triage                   session-42     no-lock     session-43     approved
  semantic_sweep           session-42     no-lock     -              pending
  finding_confirmation     session-42     locked      session-43     approved
```

---

### `to_json()` and `from_json()`

```python
def to_json(self) -> str

@classmethod
def from_json(
    cls,
    s: str,
) -> StageCommitment
```

Full round-trip serialisation of all `CommitmentRecord` entries.

---

## Example: two-agent review chain

```python
from ablation.analyzers.workflow_document import WorkflowDocument
from ablation.analyzers.stage_commitment import StageCommitment

vendor = "cisco"
target = "fmc_server"
doc = WorkflowDocument.for_re_session(
    vendor,
    target,
)
sc = StageCommitment(doc_id="cisco/fmc_server")

# Agent A (session-42): produce and commit triage
instance = {
    "binary_hash": "deadbeef",
    "arch": "arm64",
    "bits": 64,
    "section_count": 9,
    "string_count": 1400,
    "plt_count": 320,
}
doc.advance(
    instance,
    producer_id="session-42",
)
sc.commit(
    "triage",
    instance,
    producer="session-42",
    lock_mode="no-lock",
)

# Agent B (session-43): review and approve without revision
ok, reason = sc.verify(
    "triage",
    instance,
)
assert ok

sc.approve(
    "triage",
    approver="session-43",
)

ok, reason = sc.verify(
    "triage",
    instance,
)
assert ok  # reason == "ok"

# Tamper detection
instance["arch"] = "x86_64"
ok, reason = sc.verify(
    "triage",
    instance,
)
assert not ok  # "content mutated: original deadbeef... / current ..."

print(sc.audit_trail())
```

---

## Integration with FindingRegistry

```python
from ablation.analyzers.finding_registry import FindingRegistry
from ablation.analyzers.stage_commitment import StageCommitment

sc = StageCommitment(doc_id="cisco/fmc_server")
reg = FindingRegistry()

# after finding_confirmation stage is committed
confirmation = doc.stages[4].instance
sc.commit(
    "finding_confirmation",
    confirmation,
    producer="session-42",
    lock_mode="no-lock",
)

# after FORGE passes and finding is registered
fid = reg.register(
    vendor="cisco",
    product="fmc_server",
    title=confirmation["title"],
    description=confirmation["description"],
    cwe_class=confirmation["cwe"],
    severity=confirmation["severity"],
    func_addr=confirmation["va"],
)
reg_instance = {"finding_id": fid, "forge_gate_passed": True}
doc.advance(
    reg_instance,
    producer_id="session-42",
)
sc.commit(
    "registration",
    reg_instance,
    producer="session-42",
    lock_mode="locked",
)

# persist the full chain
from pathlib import Path
Path("re/cisco/fmc_server_commitments.json").write_text(sc.to_json())
```

See `workflow-document.md` for the `WorkflowDocument` API.

---

## How it works

Provides the session state, indexing, and utility functions that other Ablation modules depend on. The implementation details vary by class; see the class-level docstrings and the relevant workflow docs for specifics.

---

## Usage

```python
from ablation.analyzers.stage_commitment import StageCommitment

sc = StageCommitment(doc_id="arm64-target-2024")
rec = sc.commit(
    stage_name="triage",
    instance={"binary": "/path/to/target.elf", "n_funcs": 1200},
    producer="analyst",
    lock_mode="no-lock",
)
sc.approve(stage_name="triage", approver="lead")
print(sc.audit_trail())
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

## Reading output

`StageCommitment.audit_trail()` returns a formatted string of the full commitment chain. Access individual records via the `StageCommitment` object attributes. Each `CommitmentRecord` has:

| Attribute | Content |
|:---|:---|
| `stage_name` | Stage identifier (e.g., `'taint_analysis'`, `'path_solver'`) |
| `producer` | Producer identity string |
| `content_hash` | SHA-256 of the committed stage output |
| `timestamp` | ISO 8601 commitment time |
| `lock_mode` | `'soft'` (revisable by approver) or `'hard'` (immutable) |
| `approver` | Approver identity string, or `None` if not yet approved |
| `revised_content_hash` | SHA-256 of approved revision, or `None` |
| `approving_hash` | SHA-256 of the approval record itself, or `None` |

---

## See also

- [BinaryContext](binary-context.md) — session foundation for all analysis
- [SemanticSearch](semantic-search.md) — function candidate identification
- [FindingRegistry](registry.md) — persistent finding storage
