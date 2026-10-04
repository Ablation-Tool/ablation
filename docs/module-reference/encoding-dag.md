# Encoding DAG

**File:** `ablation/analyzers/encoding_dag.py`

Generic bitfield-to-instruction encoding framework for fixed-width ISAs.
Implements the three-layer model described in the EDAG-24 design document:

```
Layer 1  Raw bytes / hex / RGB-integer
         (B0, B1, B2) ↔ 0xRRGGBB ↔ I24 = R*65536 + G*256 + B

Layer 2  Encoding DAG
         Named bitfields (Field) + positional composition (Template)
         EncodingNode = one instantiated template (the DAG root)

Layer 3  Semantic DAG / IR
         SemanticOp nodes with typed operands; DataflowEdge for
         producer/consumer links; SemanticBlock for basic blocks
```

Binding ties Layer 3 ↔ Layer 2. ISASpec owns a template registry plus
bindings, giving a single object for round-trip encode/decode.

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

## Layer 1 — Raw / RGB-style

Every instruction is 3 bytes `(B0, B1, B2)`. The RGB packing formula gives the
canonical 24-bit integer:

```
I24 = (B0 × 65536) + (B1 × 256) + B2
    = (R  × 256²)  + (G  × 256¹) + (B × 256⁰)
```

Convenience helpers:

```python
from ablation.analyzers.encoding_dag import rgb_to_bytes, bytes_to_rgb, rgb_int

rgb_to_bytes(6, 5, 4)          # b'\x06\x05\x04'
bytes_to_rgb(b'\x06\x05\x04')  # (6, 5, 4)
rgb_int(6, 5, 4)               # 394500
```

---

## Layer 2 — Encoding DAG

### Field

```python
@dataclass(frozen=True)
class Field:
    name: str
    width: int           # bits
    fixed: Optional[int] # None = variable; int = fixed value checked on decode
```

### Template

Named sequence of Fields, listed MSB-first, representing one instruction form.

```python
from ablation.analyzers.encoding_dag import Template, Field

tmpl = Template("ADD_reg", [
    Field("opcode", 6, fixed=0b000100),
    Field("mode",   2, fixed=0b11),
    Field("rA",     4),
    Field("rB",     4),
    Field("imm8",   8, fixed=0),
])

# Encode to integer
tmpl.encode({"rA": 0, "rB": 1})        # 0x130100

# Decode from integer
tmpl.decode(0x130100)
# {"opcode": 4, "mode": 3, "rA": 0, "rB": 1, "imm8": 0}
```

### EncodingNode

An instantiated Template: the DAG root.

```python
node = EncodingNode(tmpl, {"rA": 0, "rB": 1})
node.to_hex()        # "0x130100"
node.to_bytes()      # b'\x13\x01\x00'
node.to_rgb()        # (19, 1, 0)
node.to_rgb_int()    # 1245440 = 19*65536 + 1*256 + 0
node.all_fields()    # {"opcode": 4, "mode": 3, "rA": 0, "rB": 1, "imm8": 0}
node.show_layout()   # ASCII diagram
```

---

## Layer 3 — Semantic DAG / IR

### SemanticOp

```python
SemanticOp(
    op="LOAD",
    operands={"dst": "r0", "base": "r5", "offset": 4},
    node_id="n1",       # optional, used in show_layout and block edges
)
```

Operand values are typed:
- Registers: string names (`"r0"`, `"r5"`, `"rBP"`)
- Immediates: `int`
- Memory references: `MemRef(base="r5", offset=4)`

### SemanticBlock

Groups SemanticOps into a basic block with explicit dataflow edges:

```python
from ablation.analyzers.encoding_dag import SemanticBlock, DataflowEdge

blk = SemanticBlock("entry")
blk.add_op(SemanticOp("LOAD",  {"dst": "r0", "base": "r5", "offset": 4},  "n1"))
blk.add_op(SemanticOp("LOAD",  {"dst": "r1", "base": "r5", "offset": 8},  "n2"))
blk.add_op(SemanticOp("ADD",   {"dst": "r0", "src": "r1"},                "n3"))
blk.add_op(SemanticOp("STORE", {"src": "r0", "base": "r5", "offset": 12}, "n4"))

# Explicit dataflow edges (n1→n3: r0, n2→n3: r1, n3→n4: r0)
blk.add_edge(DataflowEdge("n1", "n3", "r0"))
blk.add_edge(DataflowEdge("n2", "n3", "r1"))
blk.add_edge(DataflowEdge("n3", "n4", "r0"))
```

---

## ISASpec — round-trip encode / decode

```python
from ablation.analyzers.encoding_dag import ISASpec, Template, Field, Binding, FieldBinding

spec = ISASpec(
    name="my-isa",
    templates={"LOAD_mem": Template(...)},
    bindings=[Binding("LOAD", "LOAD_mem", [
        FieldBinding("rA",   "dst",    operand_type="reg"),
        FieldBinding("rB",   "base",   operand_type="reg"),
        FieldBinding("imm8", "offset", operand_type="imm"),
    ])],
    reg_table={"r0": 0, "r1": 1, ..., "r15": 15},
    opcode_field="opcode",
)

node = spec.encode(SemanticOp("LOAD", {"dst": "r0", "base": "r5", "offset": 4}))
enode, sop = spec.decode(node.to_bytes())
```

---

## ISA-24 (bundled example)

Pre-built `ISASpec` for the 24-bit toy ISA:

```
[ opcode(6) | mode(2) | rA(4) | rB(4) | imm8(8) ] = 24 bits
```

| Mnemonic | opcode  | mode | Semantics |
|----------|---------|------|-----------|
| LOAD     | 000001  | 10   | `rA = mem[rB + imm8]` |
| STORE    | 000010  | 10   | `mem[rB + imm8] = rA` |
| ADD      | 000100  | 11   | `rA += rB` (two-operand) |
| MUL      | 001000  | 11   | `rA *= rB` |
| JMP      | 010000  | 00   | `PC += imm8` (signed) |
| MOV      | 010101  | 11   | `rA = rB` |

```python
from ablation.analyzers.encoding_dag import ISA24

# Encode the 4-instruction sequence from the design document
ops = [
    SemanticOp("LOAD",  {"dst": "r0", "base": "r5", "offset":  4}, "n1"),
    SemanticOp("LOAD",  {"dst": "r1", "base": "r5", "offset":  8}, "n2"),
    SemanticOp("ADD",   {"dst": "r0", "src":  "r1"},                "n3"),
    SemanticOp("STORE", {"src": "r0", "base": "r5", "offset": 12}, "n4"),
]
for op in ops:
    node = ISA24.encode(op)
    r, g, b = node.to_rgb()
    print(f"{op.node_id}: {op.op:6s}  {node.to_hex()}  "
          f"I24={node.to_rgb_int():<10}  R={r} G={g} B={b}")

# n1: LOAD    0x060504  I24=394500      R=6  G=5  B=4
# n2: LOAD    0x061508  I24=398600      R=6  G=21 B=8
# n3: ADD     0x130100  I24=1245440     R=19 G=1  B=0
# n4: STORE   0x0A050C  I24=656652      R=10 G=5  B=12

# Decode a raw hex string
enode, sop = ISA24.decode_hex("57AABC")
print(sop)   # MOV  dst=r10, src=r10
```

---

## Extending to a new ISA

1. Define `Field` objects for each bitfield in the instruction encoding.
2. Group them into `Template` instances, one per instruction form.
3. Write `FieldBinding` entries that map semantic operand keys to template fields.
4. Wrap in a `Binding` (op name + template name + field bindings).
5. Build an `ISASpec` with the template registry and binding list.

For variable-length ISAs (x86), build hierarchical templates: one for the
opcode byte, one for ModRM, one for SIB, etc. The Encoding DAG's composition
nodes are just Template references; the root template aggregates sub-templates
by concatenating their encodings.

---

## Exceptions

| Exception | When raised |
|-----------|-------------|
| `EncodingError` | Field value too wide; no binding for op; register not in table |
| `DecodingError` | No template matches the opcode; fixed-field mismatch |
