# Encoding DAG

**File:** `ablation/analyzers/encoding_dag.py`

The EncodingDAG is a bitfield-to-instruction encoding framework for fixed-width ISAs. It implements a three-layer model: raw bytes map to named bitfields, named bitfields map to semantic operations, and semantic operations link through dataflow edges into basic blocks.

---

**The problem it solves**

Every RE tool that supports multiple architectures handles ISA encoding the same way: one bespoke decoder per architecture. Each has its own bit mask arithmetic, its own field extraction, its own opcode dispatch. When you add a new ISA, you write all of that again from scratch. When a bug exists, such as a wrong field offset or endianness error, you fix it in one decoder and have no guarantee the same bug isn't silently present in six others.

Ablation had the same problem before the EncodingDAG. The docs note: "every ISA decoder embedded its own field extraction logic: bit masks, shifts, and width calculations repeated across each architecture." The PEFABIClobberScanner existed as a concrete casualty. The PPC32 `ori` instruction has its RA field at bits [20:16], not [25:21], and that error was invisible until it silently produced the wrong encoding. Without a structural layer, there was no way to catch it at encode time.

---

**The three-layer model**

Layer 1: Raw bytes as an integer. Any fixed-width instruction is packed as a 24-bit, 32-bit, or similar-width integer. The packing is identical to RGB color packing: `I = B0×65536 + B1×256 + B2`. This isn't aesthetic. It means the opcode, occupying the high bits or R channel, clusters visually and numerically. All ADD variants produce the same R value regardless of operands, so a range scan over the integer corpus finds all ADD instructions without a hash lookup.

Layer 2: Encoding DAG. A `Field` is a named bit range with an optional fixed value. A `Template` is a sequence of Fields for one instruction form. `Template.encode(values)` packs field values left to right; `Template.decode(I)` extracts them and raises `DecodingError` if any fixed field mismatches. This is the opcode dispatch mechanism. Each `Template` has a fixed opcode `Field`, and `ISASpec.decode()` tries Templates in order, skipping those whose fixed opcode field doesn't match. The PEFABIClobberScanner fix was: define `Field("RA", 5)` at bits [20:16] explicitly, and the wrong-offset bug becomes an `EncodingError` at encode time rather than silent bad output.

Layer 3: Semantic DAG. A `SemanticOp` names what an instruction does and carries typed operands: register names, immediates, and `MemRef` base/offset pairs. A `DataflowEdge` records explicit producer-consumer links between ops: "node n1 writes r0, node n3 reads r0." A `SemanticBlock` groups ops into a basic block and exposes `dag_nodes()` for topological traversal.

The key property: before the SemanticDAG, taint results were flat sink, source pairs. Confirming that a LOAD result flows into an ADD that feeds a STORE required re-deriving register liveness manually. `DataflowEdge` makes that chain explicit and walkable without re-analysis.

---

**What this enables that other tools don't have**

1. **ISA-agnostic analysis code.** Any tool that works on `SemanticBlock` + `DataflowEdge` works on every ISA that has an `ISASpec`. The PEFABIClobberScanner uses `dag_nodes()` to check whether r4/r5 are live at a PPC32 call site. The same traversal logic would work on any ISA. In Ghidra that would require ISA-specific p-code analysis; in IDA, architecture-specific scripting against the op type system.

2. **Verified round-trip encode/decode as a test surface.** `ISASpec.encode(op).to_bytes()` followed by `ISASpec.decode(bytes)` must reconstruct the original `SemanticOp`. This round-trip is a property test: if it fails, the `Template` has a field layout bug. No other RE tool has a structural layer between raw bytes and semantic meaning. They go directly from bytes to their own IR with no intermediate structural representation to round-trip.

3. **Visual instruction corpus clustering.** `EncodingNode.to_rgb_int()` is used as the key in `SAXIndex`. Instructions with the same opcode sort into a contiguous integer band, so finding "all instructions in function X that are LOAD variants" is a bounded range scan rather than a full disassembly pass. This is the mechanism that makes sweep-scale pattern matching over large binaries feasible at the speed Ablation advertises.

4. **Fixed-field mismatch catches layout bugs at write time.** When you define a new `Template`, wrong bit assignments raise `EncodingError` during the first `encode()` call, before the module touches a real binary. Every other tool's ISA decoders fail silently, producing wrong results on live binaries.

---

## Why this exists

Three things were not possible before in Ablation:

**1. No shared bit-extraction layer.** Every ISA decoder embedded its own field extraction logic: bit masks, shifts, and width calculations repeated across each architecture. Adding a new ISA meant writing those operations from scratch. `Field` and `Template` centralize this so each bit range is defined once and reused by every encoder, decoder, and disassembler that needs it.

**2. No reusable encode/decode round-trip.** Taint trackers and lifters needed to reconstruct instruction encodings to verify byte sequences. Without a shared model, every tool that touched raw bytes had its own ad-hoc packing and unpacking, and they disagreed on edge cases fixed-field mismatches, register numbering. `ISASpec.encode()` and `ISASpec.decode()` give every tool a single verified round-trip path.

**3. No semantic-layer dataflow graph.** Before `SemanticBlock`, taint results were flat lists of sink, source pairs with no explicit producer-consumer links. Confirming that a LOAD result flows into an ADD that feeds a STORE required manual tracing. `DataflowEdge` records those links explicitly so any tool can walk the DAG without re-deriving it.

---

## Three-layer architecture

```mermaid
flowchart TD
    A(["Raw bytes from binary"]):::input --> B["Layer 1 · Raw bytes / RGB-style integer\nThree bytes pack into a 24-bit integer:\n  I24 = (B0 × 65536) + (B1 × 256) + B2\n       = (R  × 256²) + (G  × 256¹) + (B × 256⁰)\nHelpers: rgb_to_bytes · bytes_to_rgb · rgb_int"]:::primary

    B:::primary --> C["ISASpec.decode()"]:::secondary

    C:::secondary --> D["Layer 2 · Encoding DAG\nField: named bit range with optional fixed value\n  Field('opcode', width=6, fixed=0b000001)\n  Field('rA',     width=4, fixed=None)  ← variable\n\nTemplate: MSB-first sequence of Fields for one insn form\n  Template('LOAD_mem', [opcode, mode, rA, rB, imm8])\n  .encode({'rA': 0, 'rB': 5, 'imm8': 4}) → I24\n  .decode(I24) → {'opcode': 1, 'mode': 2, 'rA': 0, ...}\n\nEncodingNode: instantiated Template (DAG root)\n  node.to_hex() / to_bytes() / to_rgb() / show_layout()"]:::tertiary

    D:::tertiary --> E["ISASpec.decode() + Binding"]:::tertiary

    E:::tertiary --> F["Layer 3 · Semantic DAG / IR\nSemanticOp: one operation with typed operands\n  SemanticOp('LOAD', {'dst': 'r0', 'base': 'r5', 'offset': 4})\n  operands: registers (str), immediates (int), MemRef(base, off)\n\nDataflowEdge: explicit producer-consumer link\n  DataflowEdge(producer_id='n1', consumer_id='n3', reg='r0')\n\nSemanticBlock: basic block of SemanticOps with edges\n  SemanticBlock('entry').add_op(...).add_edge(...)"]:::tertiary

    F:::tertiary --> G(["ISASpec: ties all three layers together\n.encode(SemanticOp) → EncodingNode\n.decode(bytes)      → (EncodingNode, SemanticOp)"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
```

---

## Quick start

```python
from ablation.analyzers.encoding_dag import ISA24, SemanticOp

# Encode a semantic op to bytes
op = SemanticOp("LOAD", {"dst": "r0", "base": "r5", "offset": 4}, node_id="n1")
node = ISA24.encode(op)
print(node.to_hex())        # 0x060504
print(node.to_rgb())        # (6, 5, 4)
print(node.to_rgb_int())    # 394500 = 6*65536 + 5*256 + 4

# Decode bytes back to semantic
enode, sop = ISA24.decode(bytes.fromhex("060504"))
print(sop)                  # LOAD  dst=r0, base=r5, offset=4

# ASCII bit layout
print(node.show_layout())
# Bit ranges:  [23:18]  [17:16]  [15:12]  [11:8]  [7:0]
# Fields:      opcode   mode     rA       rB      imm8
# Values:      000001   10       0000     0101    00000100
# Hex: 0x060504  I=394500
```

---

## Layer 1: Raw bytes and the I24 integer

Layer 1 is the byte representation layer. It normalizes any fixed-width instruction to an
integer so that `Field` and `Template` arithmetic operates on a single value rather than
a byte array.

For a 3-byte (24-bit) instruction, the integer is:

```
I24 = (byte[0] × 65536) + (byte[1] × 256) + byte[2]
    = (R × 256²)        + (G × 256¹)      + (B × 256⁰)
```

This is identical to the way a 24-bit RGB color is stored, so the integer is also called
the **RGB integer**. The mapping is deliberate: it means you can visualize an instruction
stream as a sequence of colors. Two instructions with the same opcode but different
operands produce visually distinct hues, which is useful when scanning for repeated
patterns across a disassembly.

The three Layer 1 helpers convert between representations:

| Helper | Input | Output |
|---|---|---|
| `rgb_to_bytesr, g, b` | Three integers (0-255) | `bytes` of length 3 |
| `bytes_to_rgb(b)` | `bytes` of length 3 | `r, g, b` tuple |
| `rgb_intr, g, b` | Three integers | Single `int` 0-16777215 |

For ISAs with instruction widths other than 24 bits, the packing extends naturally: a
32-bit ISA uses a 4-byte RGBA integer. The field arithmetic in Layer 2 is width-agnostic;
only the byte packing helpers in Layer 1 are width-specific.

---

## Layer 2: Encoding DAG

Layer 2 is the structural layer. It describes how bits are arranged inside an instruction
and how to pack or unpack them.

### Field

A `Field` represents one named bit range inside an instruction word.

```python
@dataclass(frozen=True)
class Field:
    name: str
    width: int           # number of bits this field occupies
    fixed: Optional[int] # None = variable operand; int = opcode discriminator
```

**Variable fields** with `fixed=None` carry operand values. During encode, the caller
supplies a value; during decode, the extracted bits are returned as-is.

**Fixed fields** with `fixed=<int>` are opcode discriminators. During encode, the fixed
value is packed unconditionally; the caller does not supply it. During decode, if the
extracted bits do not equal `fixed`, a `DecodingError` is raised. This is how Template
dispatch works: each Template has a fixed `opcode` field, and decode tries Templates
in order until one's fixed fields all match the raw integer.

The constraint `value < 2**width` is checked at encode time; a value that does not fit
raises `EncodingError`.

### Template

A Template is a named, MSB-first sequence of Fields representing one instruction form.
The Fields are listed from the most-significant bit to the least-significant bit; the
first Field occupies the top bits of the integer.

**How encoding works:**

`Template.encode(values)` iterates Fields from MSB to LSB. For each Field it takes
`values[name]` or `fixed` for fixed Fields, validates the width, then packs the value
into the running integer by shifting:

```
I = 0
for field in fields:          # MSB to LSB
    value = values[field.name] or field.fixed
    assert value < 2**field.width
    I = (I << field.width) | value
return I
```

**How decoding works:**

`Template.decode(I)` reverses the process. It shifts out bits from the MSB end and
assigns them to each field in order:

```
remaining_bits = total_width   # e.g. 24
for field in fields:
    remaining_bits -= field.width
    value = (I >> remaining_bits) & ((1 << field.width) - 1)
    if field.fixed is not None and value != field.fixed:
        raise DecodingError(...)
    result[field.name] = value
```

A fixed-field mismatch means this Template does not match the instruction; `ISASpec`
tries the next Template.

```python
from ablation.analyzers.encoding_dag import Template, Field

tmpl = Template("ADD_reg", [
    Field("opcode", 6, fixed=0b000100),   # bits [23:18]
    Field("mode",   2, fixed=0b11),        # bits [17:16]
    Field("rA",     4),                    # bits [15:12]
    Field("rB",     4),                    # bits [11:8]
    Field("imm8",   8, fixed=0),           # bits [7:0]
])

tmpl.encode({"rA": 0, "rB": 1})
# → 0x130100
# opcode=0b000100 (4), mode=0b11 (3), rA=0b0000 (0), rB=0b0001 (1), imm8=0

tmpl.decode(0x130100)
# → {"opcode": 4, "mode": 3, "rA": 0, "rB": 1, "imm8": 0}
```

**Template.show_layout()** prints an ASCII bit-field diagram:

```
Bit ranges:  [23:18]  [17:16]  [15:12]  [11:8]  [7:0]
Fields:      opcode   mode     rA       rB      imm8
Values:      000100   11       0000     0001    00000000
Hex: 0x130100  I=1245440
```

### EncodingNode

An `EncodingNode` is an instantiated `Template` and serves as the DAG root. It bundles
the Template with a concrete set of field values so that the same encoded instruction can
be inspected, serialized, or displayed in multiple formats without re-encoding.

```python
node = EncodingNode(tmpl, {"rA": 0, "rB": 1})
```

| Method | Returns | Description |
|---|---|---|
| `node.to_hex()` | `str` | Hex string, e.g. `"0x130100"` |
| `node.to_bytes()` | `bytes` | Raw byte sequence, e.g. `b'\x13\x01\x00'` |
| `node.to_rgb()` | `int, int, int` | RGB triple, e.g. R=19, G=1, B=0 |
| `node.to_rgb_int()` | `int` | Single integer, e.g. `1245440` |
| `node.all_fields()` | `dict` | All field values including fixed fields |
| `node.show_layout()` | `str` | ASCII bit-field diagram |
| `node.template` | `Template` | The backing Template |
| `node.values` | `dict` | The variable field values passed at construction |

`to_rgb_int()` is used as a corpus key in `SAXIndex` because it maps each unique
instruction encoding to a unique integer, making sorted search and clustering efficient.

---

## Layer 3: Semantic DAG

Layer 3 is the meaning layer. It names what an instruction does and records how the
result of one instruction flows into the operands of another.

### SemanticOp

A `SemanticOp` represents one instruction at the semantic level: an operation name, a
dictionary of typed operands, and an optional node ID that uniquely identifies this
instance in a `SemanticBlock`.

```python
@dataclass
class SemanticOp:
    op: str                 # operation name, e.g. "LOAD", "ADD", "STORE"
    operands: dict          # keys are role names; values are reg str, int, or MemRef
    node_id: str            # unique ID within a SemanticBlock, e.g. "n1"
    taint: bool = False     # True when this op is on a taint path
```

Operand value types:

| Type | Python type | Example |
|---|---|---|
| Register | `str` | `"r0"`, `"rdi"`, `"$a0"` |
| Immediate | `int` | `4`, `0x1000`, `-8` |
| Memory reference | `MemRefbase, offset` | `MemRef("r5", 4)` = `mem[r5 + 4]` |

```python
# Register operand
SemanticOp("MOV",   {"dst": "r0", "src": "r1"},             "n1")

# Immediate operand
SemanticOp("ADD",   {"dst": "r0", "src": "r1", "imm": 4},   "n2")

# Memory reference
SemanticOp("STORE", {"src": "r0", "addr": MemRef("r5", 12)}, "n3")
```

### DataflowEdge

A `DataflowEdge` is an explicit producer-consumer dependency between two `SemanticOp`
nodes. It records which register carries the value.

```python
@dataclass
class DataflowEdge:
    producer_id: str   # node_id of the op that writes the register
    consumer_id: str   # node_id of the op that reads it
    reg: str           # register name
```

Edges are what makes a `SemanticBlock` a DAG rather than just a list. Without edges,
you know which operations exist but not in what order their values depend on each other.
A taint tracker uses edges to propagate taint from source to sink without re-analysing
register liveness. A lifter uses them to produce correct SSA form.

### SemanticBlock

A `SemanticBlock` is a basic block: a named, ordered list of `SemanticOp` nodes plus a
set of `DataflowEdge` connections.

```python
from ablation.analyzers.encoding_dag import SemanticBlock, DataflowEdge, SemanticOp

blk = SemanticBlock("entry")
blk.add_op(SemanticOp("LOAD",  {"dst": "r0", "base": "r5", "offset": 4},  "n1"))
blk.add_op(SemanticOp("LOAD",  {"dst": "r1", "base": "r5", "offset": 8},  "n2"))
blk.add_op(SemanticOp("ADD",   {"dst": "r0", "src": "r1"},                "n3"))
blk.add_op(SemanticOp("STORE", {"src": "r0", "base": "r5", "offset": 12}, "n4"))

# n1 writes r0; n3 reads r0 → edge n1→n3
# n2 writes r1; n3 reads r1 → edge n2→n3
# n3 writes r0; n4 reads r0 → edge n3→n4
blk.add_edge(DataflowEdge("n1", "n3", "r0"))
blk.add_edge(DataflowEdge("n2", "n3", "r1"))
blk.add_edge(DataflowEdge("n3", "n4", "r0"))
```

**SemanticBlock API:**

| Method | Returns | Description |
|---|---|---|
| `blk.add_op(op)` | `self` | Append a `SemanticOp`; raises if `node_id` collides |
| `blk.add_edge(edge)` | `self` | Record a producer-consumer dependency |
| `blk.get_op(node_id)` | `SemanticOp` | Look up an op by ID; raises `KeyError` if absent |
| `blk.ops` | `list[SemanticOp]` | All ops in insertion order |
| `blk.edges` | `list[DataflowEdge]` | All edges |
| `blk.dag_nodes()` | generator | Topological traversal of ops following edge order |
| `blk.tainted_ops()` | `list[SemanticOp]` | Ops with `taint=True` |
| `blk.mark_taint(node_id)` | `None` | Set `taint=True` on one op |

**dag_nodes() and cycle detection:**

`dag_nodes()` yields ops in topological order: a producer is always yielded before all
its consumers. If the edge graph contains a cycle, it raises `ValueError("cycle
detected")`. Callers that build blocks from analyzed binaries should wrap the call in
`try/except ValueError` and fall back to insertion-order iteration via `blk.ops` when
a cycle is present. Cycles are rare in well-formed basic blocks but can appear when
taint edges are added manually.

```python
# Safe topological walk
try:
    for op in blk.dag_nodes():
        print(op.op, op.operands)
except ValueError:
    for op in blk.ops:       # insertion order fallback
        print(op.op, op.operands)
```

---

## ISASpec: Round-Trip Encode and Decode

`ISASpec` owns a template registry plus `Binding` objects that map semantic op names to
template names and semantic operand keys to template field names.

### Binding and FieldBinding

A `Binding` connects one semantic op name to one `Template`. It lists a `FieldBinding`
for each variable field, declaring which semantic operand key maps to which template
field and what type the operand is.

```python
@dataclass
class FieldBinding:
    field_name: str       # Template field name, e.g. "rA"
    operand_key: str      # SemanticOp operand key, e.g. "dst"
    operand_type: str     # "reg", "imm", or "memref"
```

When `operand_type="reg"`, `ISASpec.encode()` looks up the register name in
`reg_table` to get its integer encoding. When `operand_type="imm"`, the operand is
used directly as an integer. When `operand_type="memref"`, the `MemRef.base` is
looked up in `reg_table` and the `MemRef.offset` fills the immediate field.

```python
from ablation.analyzers.encoding_dag import ISASpec, Template, Field, Binding, FieldBinding

spec = ISASpec(
    name="my-isa",
    templates={
        "LOAD_mem": Template("LOAD_mem", [
            Field("opcode", 6, fixed=0b000001),
            Field("mode",   2, fixed=0b10),
            Field("rA",     4),
            Field("rB",     4),
            Field("imm8",   8),
        ]),
    },
    bindings=[
        Binding("LOAD", "LOAD_mem", [
            FieldBinding("rA",   "dst",    operand_type="reg"),
            FieldBinding("rB",   "base",   operand_type="reg"),
            FieldBinding("imm8", "offset", operand_type="imm"),
        ]),
    ],
    reg_table={"r0": 0, "r1": 1, "r2": 2, "r3": 3,
               "r4": 4, "r5": 5, "r6": 6, "r7": 7},
    opcode_field="opcode",
)
```

### How encode() works

`ISASpec.encode(sop)` finds the `Binding` whose op name matches `sop.op`, then:

1. Looks up the `Template` named in the binding.
2. Builds a `values` dict by iterating `FieldBinding` entries: resolves registers via
   `reg_table`, copies immediates as-is, splits `MemRef` into base register + offset.
3. Calls `Template.encode(values)` to get the integer.
4. Returns an `EncodingNodetemplate, values`.

### How decode() works

`ISASpec.decoderaw_bytes` converts bytes to an integer and tries each registered
`Template` in order:

1. Calls `Template.decode(I)` on the integer.
2. If all fixed fields match, decode succeeds; a `SemanticOp` is reconstructed by
 reversing the `FieldBinding` mappings (integers → register names via `reg_table`
 inversion, immediates passed through).
3. If any fixed field mismatches, a `DecodingError` is caught internally and the next
 Template is tried.
4. If no Template matches, `ISASpec.decode()` raises `DecodingError`.

The `opcode_field` parameter names the field used as the primary dispatch key. When
present, decode skips Templates whose `opcode_field` fixed value does not match the
extracted opcode bits, so the search is Otemplates_with_matching_opcode rather than
Oall_templates.

```python
node = spec.encode(SemanticOp("LOAD", {"dst": "r0", "base": "r5", "offset": 4}))
enode, sop = spec.decode(node.to_bytes())
# sop.op == "LOAD"
# sop.operands == {"dst": "r0", "base": "r5", "offset": 4}
```

---

## ISA-24 bundled example

`ISA24` is a pre-built `ISASpec` for a 24-bit toy ISA bundled with Ablation for testing
and examples:

```
  [ opcode(6) | mode(2) | rA(4) | rB(4) | imm8(8) ] = 24 bits
```

The 6-bit opcode gives 64 possible instruction forms. Mode distinguishes addressing
variants: `00` = PC-relative, `10` = register-indirect, `11` = register-register.

| Mnemonic | opcode (bin) | mode | Semantics |
|---|---|---|---|
| LOAD | 000001 | 10 | `rA = mem[rB + imm8]` |
| STORE | 000010 | 10 | `mem[rB + imm8] = rA` |
| ADD | 000100 | 11 | `rA += rB` |
| MUL | 001000 | 11 | `rA *= rB` |
| JMP | 010000 | 00 | `PC += imm8` (signed) |
| MOV | 010101 | 11 | `rA = rB` |

```python
from ablation.analyzers.encoding_dag import ISA24, SemanticOp

ops = [
    SemanticOp("LOAD",  {"dst": "r0", "base": "r5", "offset":  4}, "n1"),
    SemanticOp("LOAD",  {"dst": "r1", "base": "r5", "offset":  8}, "n2"),
    SemanticOp("ADD",   {"dst": "r0", "src":  "r1"},                "n3"),
    SemanticOp("STORE", {"src": "r0", "base": "r5", "offset": 12}, "n4"),
]
for op in ops:
    node = ISA24.encode(op)
    r, g, b = node.to_rgb()
    print(f"{op.node_id}: {op.op:6s}  {node.to_hex()}  I24={node.to_rgb_int():<10}  R={r} G={g} B={b}")

# n1: LOAD    0x060504  I24=394500      R=6  G=5  B=4
# n2: LOAD    0x061508  I24=398600      R=6  G=21 B=8
# n3: ADD     0x130100  I24=1245440     R=19 G=1  B=0
# n4: STORE   0x0A050C  I24=656652      R=10 G=5  B=12
```

The R channel carries most of the opcode information because the opcode occupies bits
[23:18]: LOAD and STORE share R=6 and R=10 respectively regardless of their operands,
while ADD and MUL produce much higher R values. This makes instruction class
distinguishable by color at a glance.

---

## Extending to a new ISA

```mermaid
flowchart LR
    A(["Define Field objects\nfor each bit range\nin the instruction encoding"]):::input --> B["Group into Template instances\none per instruction form"]:::primary
    B:::primary --> C["Write FieldBinding entries\nmapping semantic operand keys\nto template fields"]:::secondary
    C:::secondary --> D["Wrap in a Binding\n(op name + template name + field bindings)"]:::tertiary
    D:::tertiary --> E(["Build ISASpec\nwith template registry\nand binding list"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
```

**Step-by-step example: adding a RISC-V-style R-type instruction.**

R-type encodes three register fields: `rd` destination, `rs1`, `rs2`, with a 7-bit
opcode and a 3-bit `funct3` discriminator packed into a 32-bit word:

```
[ funct7(7) | rs2(5) | rs1(5) | funct3(3) | rd(5) | opcode(7) ] = 32 bits
```

```python
from ablation.analyzers.encoding_dag import Field, Template, Binding, FieldBinding, ISASpec

# 1. Define fields
f_funct7 = Field("funct7",  7, fixed=0b0000000)   # ADD: funct7=0
f_rs2    = Field("rs2",     5)
f_rs1    = Field("rs1",     5)
f_funct3 = Field("funct3",  3, fixed=0b000)        # ADD: funct3=0
f_rd     = Field("rd",      5)
f_opcode = Field("opcode",  7, fixed=0b0110011)    # R-type opcode

# 2. Group into a Template (MSB first)
add_tmpl = Template("ADD_rv32", [f_funct7, f_rs2, f_rs1, f_funct3, f_rd, f_opcode])

# 3. Write FieldBindings
add_binding = Binding("ADD", "ADD_rv32", [
    FieldBinding("rd",  "dst",  operand_type="reg"),
    FieldBinding("rs1", "src1", operand_type="reg"),
    FieldBinding("rs2", "src2", operand_type="reg"),
])

# 4. Build ISASpec
rv32_int = ISASpec(
    name="rv32i",
    templates={"ADD_rv32": add_tmpl},
    bindings=[add_binding],
    reg_table={"x0": 0, "x1": 1, "x2": 2, ..., "x31": 31},
    opcode_field="opcode",
)

# Encode: ADD x1, x2, x3
node = rv32_int.encode(SemanticOp("ADD", {"dst": "x1", "src1": "x2", "src2": "x3"}))
print(node.to_hex())     # 0x00310033
print(node.show_layout())
```

Variable-length ISAs such as x86 need hierarchical templates: one for the opcode byte,
one for ModRM, one for SIB, and so on. The EncodingDAG composition nodes are `Template`
references; the root template aggregates sub-templates by concatenating their encodings.

---

## Real-world usage: PEFABIClobberScanner

`PEFABIClobberScanner` uses the EncodingDAG to verify PPC32 PEF ABI register usage at
call sites for `OTStrCat`, `OTStrCopy`, and `OTMemcpy`. The scanner reconstructs each
call site's instruction stream as a `SemanticBlock` and adds `DataflowEdge` entries to
trace which registers are live at the call. The `dag_nodes()` traversal then confirms
whether the correct argument registers r4 and r5 hold caller-supplied values without
intermediate clobbers.

The EncodingDAG is used here because the PPC32 `ori` encoding has a subtle field
layout issue: the RA field is bits [20:16], not bits [25:21] as in the standard
D-form. Defining this as an explicit `Field("RA", 5)` in the PPC32 `Template` for `ori`
catches the layout error at encode time rather than silently producing the wrong
instruction encoding.

---

## Exceptions

| Exception | When raised |
|---|---|
| `EncodingError` | Field value too wide for its bit width; no `Binding` found for op name; register not in `reg_table` |
| `DecodingError` | No `Template` matches the integer all fixed-field checks fail; raw bytes have wrong length for the ISA width |

---

## How it works

`EncodingDAG` represents ISA instruction encodings as a three-layer DAG for fixed-width architectures. Layer 1: raw bytes / hex / RGB-integer B0, B1, B2. Layer 2: bitfield template: each node is a named field with width and position, extracted via mask-and-shift. Layer 3: semantic IR: field values mapped to symbolic operands registers, immediates, targets. The DAG structure allows the same bitfield template to be shared across opcodes that differ only in one field, reducing the encoding table size for dense ISAs.

---

## Usage

```python
from ablation.analyzers.encoding_dag import ISASpec, SemanticOp, SemanticBlock

# Round-trip: encode a semantic op to bytes, then decode back
op = SemanticOp("LOAD", {"dst": "r0", "base": "r5", "offset": 4}, node_id="n1")
node = ISA24.encode(op)        # ISA24 is a bundled 24-bit example ISASpec
print(node.to_hex())           # 0x060504
print(node.to_rgb())           # (6, 5, 4) — RGB packing matches ISA-24 layout

enode, sop = ISA24.decode(bytes.fromhex("060504"))
print(sop)                     # n1: LOAD dst=r0, base=r5, offset=4
print(node.show_layout())      # ASCII bit-field layout

# Build a semantic IR block with explicit dataflow edges
from ablation.analyzers.encoding_dag import DataflowEdge
block = SemanticBlock(label="entry")
block.add_op(SemanticOp("ADD",  {"dst": "r1", "a": "r0", "b": 4}, node_id="a"))
block.add_op(SemanticOp("LOAD", {"dst": "r2", "base": "r1"},      node_id="b"))
block.add_edge(DataflowEdge(producer_id="a", consumer_id="b", value_name="r1"))
for op in block.dag_nodes():   # topological order
    print(op)
```

---

## Example output

```
# SemanticOp.__str__() per node in the DAG:
0001: ADD  dst=r3, src1=r4, src2=r5
0002: LOAD  dst=r2, addr=[r3 + 0x8]
0003: STORE  addr=[r1 + 0x14], src=r2
0004: CALL  target=0x12500, args=(r0, r1, r2)

# MemRef.__str__():
[r3 + 0x10]
```

---

## False positives

**Fixed-width ISAs only.** `EncodingDAG` assumes all instructions are the same width set at construction time. It does not handle variable-length encodings like x86, nanoMIPS, or ARM Thumb2. Use `NanoMIPSDecoder` for nanoMIPS, Capstone for x86.

---

## Pipeline position

**Before this module:** Build the bitfield template table from the ISA reference for example IBM SPU ISA v1.2 for SPU, LoongArch ABI for LA64.

**After this module:** Use the decoded `SemanticOp` IR as input to architecture-specific taint trackers and CFG builders.

---

## Reading output

`ISASpec.encode(sop)` returns an `EncodingNode`:

| Attribute | Type | Content |
|:---|:---|:---|
| `template` | `Template` | The `Template` used for encoding bitfield layout |
| `field_values` | `Dict[str,int]` | `{field_name: int_value}` for all fields in the template |
| `to_bytes()` | method | Raw byte encoding big-endian |
| `to_hex()` | method | `'0xRRGGBB'`-style hex string |
| `to_rgb()` | method | `R, G, B` tuple ISA-24 maps to RGB exactly |
| `show_layout()` | method | ASCII bitfield breakdown for debugging |

`ISASpec.decode(data)` returns a two-element tuple of `EncodingNode` and `SemanticOp`: the raw node and the decoded semantic operation.

`SemanticBlock.dag_nodes()` yields `SemanticOp` instances in topological order.

---

## See also

- [BinaryContext](binary-context.md): session state and function/import index
- [TaintAnalysis](taint-analysis.md): dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md): behavioral candidate search on the binary
