"""
encoding_dag.py — Generic Encoding DAG: bitfield templates and semantic IR for fixed-width ISAs.

Three-layer model:

    Layer 1  Raw bytes / hex / RGB-integer
             (B0, B1, B2) ↔ hex 0xRRGGBB ↔ I24 = R*65536 + G*256 + B

    Layer 2  Encoding DAG
             Named bitfields + positional composition inside a Template.
             An EncodingNode is one instantiated template (the DAG root).

    Layer 3  Semantic DAG / IR
             SemanticOp nodes with typed operands; DataflowEdge for producer/consumer links;
             SemanticBlock groups ops into a basic block.

Binding ties Layer 3 → Layer 2 (encode) and Layer 2 → Layer 3 (decode).
ISASpec owns a template registry plus bindings, giving a single object for round-trip work.

ISA-24 (bundled example):
    A 24-bit fixed-width toy ISA used in the design document.
    [ opcode(6) | mode(2) | rA(4) | rB(4) | imm8(8) ] = 24 bits
    Encoding identical to RGB packing: I24 = R*65536 + G*256 + B.

Usage::

    from ablation.analyzers.encoding_dag import ISA24, SemanticOp

    # Encode a semantic op to bytes
    op = SemanticOp("LOAD", {"dst": "r0", "base": "r5", "offset": 4}, node_id="n1")
    node = ISA24.encode(op)
    print(node.to_hex())   # 0x060504
    print(node.to_rgb())   # (6, 5, 4)

    # Decode bytes back to semantic
    enode, sop = ISA24.decode(bytes.fromhex("060504"))
    print(sop)             # n1: LOAD dst=r0, base=r5, offset=4

    # ASCII bit layout
    print(node.show_layout())
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple


# ── Exceptions ────────────────────────────────────────────────────────────────

class EncodingError(ValueError):
    """Raised when field values cannot be assembled into a valid encoding."""


class DecodingError(ValueError):
    """Raised when raw bytes do not match any known template."""


# ── Field ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Field:
    """A named bitfield with a fixed width (in bits) and an optional fixed value.

    Variable fields (fixed=None) are filled from SemanticOp operands at encode time.
    Fixed fields always carry the same value and are checked during decode.
    """
    name: str
    width: int
    fixed: Optional[int] = None

    def mask(self) -> int:
        return (1 << self.width) - 1

    def is_variable(self) -> bool:
        return self.fixed is None


# ── Template ──────────────────────────────────────────────────────────────────

@dataclass
class Template:
    """Ordered sequence of Fields describing one instruction encoding.

    Fields are listed MSB-first. ``layout: opcode | mode | rA | rB | imm8``
    corresponds to Fields in that order.

    The Template is the composition node in the Encoding DAG: leaf nodes are
    Field instances; the root concatenates them into a single integer.
    """
    name: str
    fields: List[Field]

    @property
    def total_bits(self) -> int:
        return sum(f.width for f in self.fields)

    @property
    def total_bytes(self) -> int:
        bits = self.total_bits
        if bits % 8:
            raise EncodingError(f"Template {self.name}: total_bits={bits} not byte-aligned")
        return bits // 8

    def _variable_names(self) -> List[str]:
        return [f.name for f in self.fields if f.is_variable()]

    def encode(self, values: Dict[str, int]) -> int:
        """Concatenate fields MSB-first into a single integer."""
        result = 0
        shift = self.total_bits
        for f in self.fields:
            shift -= f.width
            v = f.fixed if f.fixed is not None else values.get(f.name, 0)
            if v < 0 or v > f.mask():
                raise EncodingError(
                    f"{self.name}.{f.name}: value {v} out of range for {f.width}-bit field"
                )
            result |= (v & f.mask()) << shift
        return result

    def decode(self, raw: int) -> Dict[str, int]:
        """Extract all field values from a raw integer."""
        out: Dict[str, int] = {}
        shift = self.total_bits
        for f in self.fields:
            shift -= f.width
            v = (raw >> shift) & f.mask()
            out[f.name] = v
            if f.fixed is not None and v != f.fixed:
                raise DecodingError(
                    f"{self.name}.{f.name}: expected fixed value {f.fixed:#x}, got {v:#x}"
                )
        return out

    def to_bytes(self, values: Dict[str, int]) -> bytes:
        return self.encode(values).to_bytes(self.total_bytes, "big")

    def to_rgb(self, values: Dict[str, int]) -> Tuple[int, int, int]:
        """Return (R, G, B) byte triple. Requires total_bits == 24."""
        if self.total_bits != 24:
            raise EncodingError(f"to_rgb requires 24-bit template; got {self.total_bits}")
        b = self.to_bytes(values)
        return b[0], b[1], b[2]


# ── EncodingNode ──────────────────────────────────────────────────────────────

@dataclass
class EncodingNode:
    """An instantiated Template: the Encoding DAG root node for one instruction.

    Leaf nodes are the Template's Field instances with their concrete values.
    This node can be projected into bytes, hex, or an RGB-style integer.
    """
    template: Template
    field_values: Dict[str, int]  # variable field name -> value

    def to_int(self) -> int:
        return self.template.encode(self.field_values)

    def to_bytes(self) -> bytes:
        return self.template.to_bytes(self.field_values)

    def to_hex(self) -> str:
        return "0x" + self.to_bytes().hex().upper()

    def to_rgb(self) -> Tuple[int, int, int]:
        return self.template.to_rgb(self.field_values)

    def to_rgb_int(self) -> int:
        """I24 = R*65536 + G*256 + B — the RGB packing formula."""
        r, g, b = self.to_rgb()
        return (r * 65536) + (g * 256) + b

    def show_layout(self) -> str:
        """ASCII bit-range diagram with field labels and values."""
        lines: List[str] = []
        total = self.template.total_bits
        header_pos: List[str] = []
        label_row: List[str] = []
        value_row: List[str] = []

        shift = total
        for f in self.template.fields:
            shift -= f.width
            v = f.fixed if f.fixed is not None else self.field_values.get(f.name, 0)
            hi = shift + f.width - 1
            lo = shift
            header_pos.append(f"[{hi}:{lo}]".center(f.width * 2 + 1))
            label_row.append(f.name.center(f.width * 2 + 1))
            value_row.append(f"{v:0{f.width}b}".center(f.width * 2 + 1))

        sep = "  "
        lines.append("Bit ranges:  " + sep.join(header_pos))
        lines.append("Fields:      " + sep.join(label_row))
        lines.append("Values:      " + sep.join(value_row))
        lines.append(f"Hex: {self.to_hex()}  I={self.to_int()}")
        return "\n".join(lines)

    def all_fields(self) -> Dict[str, int]:
        """Return all field values including fixed fields."""
        out = {}
        shift = self.template.total_bits
        raw = self.to_int()
        for f in self.template.fields:
            shift -= f.width
            out[f.name] = (raw >> shift) & f.mask()
        return out


# ── Semantic layer ────────────────────────────────────────────────────────────

@dataclass
class MemRef:
    """Memory operand: base register + integer offset."""
    base: str
    offset: int = 0

    def __str__(self) -> str:
        if self.offset:
            return f"[{self.base} + {self.offset}]"
        return f"[{self.base}]"


@dataclass
class SemanticOp:
    """One operation in the Semantic DAG / IR.

    Operand values are typed:
        - Registers: string names ("r0", "x5", "a0")
        - Immediates: int
        - Memory references: MemRef

    Dataflow edges are implicit: if op A produces a value consumed by op B,
    B's operands will name the same register/temporary as A's destination.
    Explicit edges can be added to a SemanticBlock for analysis passes.
    """
    op: str
    operands: Dict[str, Any]
    node_id: Optional[str] = None

    def __str__(self) -> str:
        ops = ", ".join(f"{k}={v}" for k, v in self.operands.items())
        prefix = f"{self.node_id}: " if self.node_id else ""
        return f"{prefix}{self.op}  {ops}"


@dataclass(frozen=True)
class DataflowEdge:
    """Directed edge from producer node to consumer node in the Semantic DAG."""
    producer_id: str
    consumer_id: str
    value_name: str  # the register/temporary that flows across this edge


@dataclass
class SemanticBlock:
    """An ordered list of SemanticOps forming a basic block, plus explicit dataflow edges."""
    label: str
    ops: List[SemanticOp] = field(default_factory=list)
    edges: List[DataflowEdge] = field(default_factory=list)
    successors: List[str] = field(default_factory=list)  # labels of next blocks

    def add_op(self, op: SemanticOp) -> None:
        self.ops.append(op)

    def add_edge(self, edge: DataflowEdge) -> None:
        self.edges.append(edge)

    def dag_nodes(self) -> Iterator[SemanticOp]:
        """Yield ops in topological order derived from DataflowEdges.

        Nodes with no incoming edges are emitted first; each node is emitted
        only after all its producers have been emitted. Falls back to insertion
        order for ops not referenced by any edge (e.g. side-effect-only stores
        with no explicit dataflow consumers).

        Raises ValueError if the edge set contains a cycle.
        """
        if not self.edges:
            yield from self.ops
            return

        by_id: Dict[str, SemanticOp] = {op.node_id: op for op in self.ops if op.node_id}
        # count incoming edges per node
        in_degree: Dict[str, int] = {nid: 0 for nid in by_id}
        dependents: Dict[str, List[str]] = {nid: [] for nid in by_id}
        for e in self.edges:
            if e.consumer_id in in_degree:
                in_degree[e.consumer_id] += 1
            if e.producer_id in dependents:
                dependents[e.producer_id].append(e.consumer_id)

        # Kahn's algorithm — preserves relative insertion order for ties
        ready = [op for op in self.ops if op.node_id and in_degree[op.node_id] == 0]
        emitted: set = set()
        while ready:
            op = ready.pop(0)
            yield op
            emitted.add(op.node_id)
            for consumer_id in dependents.get(op.node_id, []):
                in_degree[consumer_id] -= 1
                if in_degree[consumer_id] == 0:
                    consumer_op = by_id.get(consumer_id)
                    if consumer_op:
                        ready.append(consumer_op)

        # emit any ops without node_id or not in the edge graph
        for op in self.ops:
            if op.node_id not in emitted:
                yield op

        if len(emitted) < len(by_id):
            raise ValueError(f"SemanticBlock '{self.label}': cycle detected in dataflow edges")


# ── FieldBinding and Binding ──────────────────────────────────────────────────

@dataclass(frozen=True)
class FieldBinding:
    """Maps one template field to a semantic operand or a constant.

    operand_key=None means use fixed_val (a compile-time constant in this encoding).
    operand_type="reg" means the operand is a register name; encode converts it
    to a register ID and decode converts back.
    operand_type="imm" means the operand is an integer value used directly.
    """
    field_name: str
    operand_key: Optional[str] = None
    fixed_val: int = 0
    operand_type: str = "imm"  # "reg" or "imm"


@dataclass
class Binding:
    """Connects one semantic operation form to an encoding template.

    field_bindings: list of FieldBinding — one per variable template field.
    """
    op: str
    template_name: str
    field_bindings: List[FieldBinding]

    def _reg_id(self, name: str, reg_table: Dict[str, int]) -> int:
        if name not in reg_table:
            raise EncodingError(f"Unknown register: {name!r}")
        return reg_table[name]

    def build_field_values(
        self, operands: Dict[str, Any], reg_table: Dict[str, int]
    ) -> Dict[str, int]:
        """Produce the template field_values dict from semantic operands."""
        out: Dict[str, int] = {}
        for fb in self.field_bindings:
            if fb.operand_key is None:
                out[fb.field_name] = fb.fixed_val
            elif fb.operand_type == "reg":
                out[fb.field_name] = self._reg_id(str(operands[fb.operand_key]), reg_table)
            else:
                out[fb.field_name] = int(operands[fb.operand_key])
        return out

    def build_operands(
        self, field_values: Dict[str, int], reg_names: Dict[int, str]
    ) -> Dict[str, Any]:
        """Produce semantic operands from decoded template field_values."""
        out: Dict[str, Any] = {}
        for fb in self.field_bindings:
            if fb.operand_key is None:
                continue
            v = field_values.get(fb.field_name, fb.fixed_val)
            if fb.operand_type == "reg":
                out[fb.operand_key] = reg_names.get(v, f"r{v}")
            else:
                out[fb.operand_key] = v
        return out


# ── ISASpec ───────────────────────────────────────────────────────────────────

@dataclass
class ISASpec:
    """Complete ISA definition: templates + bindings + register table.

    Provides encode (SemanticOp → EncodingNode → bytes) and
    decode (bytes → EncodingNode + SemanticOp) in a single object.

    opcode_field: the Field name used to dispatch decoding (default "opcode").
    """
    name: str
    templates: Dict[str, Template]
    bindings: List[Binding]
    reg_table: Dict[str, int]       # register name -> id  (e.g. {"r0": 0, "r5": 5})
    opcode_field: str = "opcode"

    def __post_init__(self) -> None:
        self._reg_names: Dict[int, str] = {v: k for k, v in self.reg_table.items()}
        # opcode dispatch: fixed value of opcode_field in each template -> template name
        self._opcode_dispatch: Dict[int, str] = {}
        for tname, tmpl in self.templates.items():
            for f in tmpl.fields:
                if f.name == self.opcode_field and f.fixed is not None:
                    self._opcode_dispatch[f.fixed] = tname

    # ── encode ───────────────────────────────────────────────────────────────

    def encode(self, op: SemanticOp) -> EncodingNode:
        """Encode a SemanticOp to an EncodingNode (which carries the raw bytes)."""
        binding = self._find_binding(op.op)
        tmpl = self.templates[binding.template_name]
        fv = binding.build_field_values(op.operands, self.reg_table)
        return EncodingNode(tmpl, fv)

    def encode_bytes(self, op: SemanticOp) -> bytes:
        return self.encode(op).to_bytes()

    # ── decode ───────────────────────────────────────────────────────────────

    def decode(self, data: bytes) -> Tuple[EncodingNode, SemanticOp]:
        """Decode bytes into (EncodingNode, SemanticOp)."""
        # Use first template to locate opcode field bit position
        raw = int.from_bytes(data, "big")
        opcode_val = self._extract_opcode(raw)
        tname = self._opcode_dispatch.get(opcode_val)
        if tname is None:
            raise DecodingError(f"No template for opcode {opcode_val:#x}")
        tmpl = self.templates[tname]
        field_vals = tmpl.decode(raw)
        enode = EncodingNode(tmpl, {k: v for k, v in field_vals.items()
                                    if tmpl.fields[self._field_idx(tmpl, k)].is_variable()})
        binding = self._find_binding_by_template(tname)
        operands = binding.build_operands(field_vals, self._reg_names)
        sop = SemanticOp(op=binding.op, operands=operands)
        return enode, sop

    def decode_hex(self, hex_str: str) -> Tuple[EncodingNode, SemanticOp]:
        """Decode a hex string like '060504' or '0x060504'."""
        clean = hex_str.replace("0x", "").replace(" ", "")
        return self.decode(bytes.fromhex(clean))

    # ── helpers ───────────────────────────────────────────────────────────────

    def _find_binding(self, op: str) -> Binding:
        for b in self.bindings:
            if b.op == op:
                return b
        raise EncodingError(f"No binding for op {op!r}")

    def _find_binding_by_template(self, tname: str) -> Binding:
        for b in self.bindings:
            if b.template_name == tname:
                return b
        raise DecodingError(f"No binding for template {tname!r}")

    def _extract_opcode(self, raw: int) -> int:
        """Extract the opcode field value from a raw instruction integer.

        Assumes all templates share the same opcode field position and width
        (true for fixed-layout ISAs like ISA-24). For ISAs with variable field
        positions, override this method or pre-decode using a dispatch template.
        """
        tmpl = next(iter(self.templates.values()))
        shift = tmpl.total_bits
        for f in tmpl.fields:
            shift -= f.width
            if f.name == self.opcode_field:
                return (raw >> shift) & f.mask()
        raise DecodingError(f"Opcode field {self.opcode_field!r} not found in templates")

    @staticmethod
    def _field_idx(tmpl: Template, name: str) -> int:
        for i, f in enumerate(tmpl.fields):
            if f.name == name:
                return i
        raise KeyError(name)


# ── ISA-24 ────────────────────────────────────────────────────────────────────
#
# 24-bit fixed-width toy ISA.
# Layout: [ opcode(6) | mode(2) | rA(4) | rB(4) | imm8(8) ] = 24 bits
#
# opcode encoding:
#   LOAD  = 0b000001  MEM: rA = mem[rB + imm8]
#   STORE = 0b000010  MEM: mem[rB + imm8] = rA
#   ADD   = 0b000100  REG: rA += rB  (two-operand)
#   MUL   = 0b001000  REG: rA *= rB
#   JMP   = 0b010000  BR:  PC += imm8 (signed)
#   MOV   = 0b010101  REG: rA = rB
#
# mode bits:
#   11 = REG  (register-register; imm8 ignored)
#   10 = MEM  (memory, base+offset)
#   01 = IMM  (register-immediate)
#   00 = BR   (PC-relative branch)
#
# Registers r0-r15; r5 = rBP (frame pointer), r6 = rSP (stack pointer).

def _isa24_templates() -> Dict[str, Template]:
    def _fields(opcode_val: int, mode_val: int) -> List[Field]:
        return [
            Field("opcode", 6, fixed=opcode_val),
            Field("mode",   2, fixed=mode_val),
            Field("rA",     4),
            Field("rB",     4),
            Field("imm8",   8),
        ]

    return {
        "LOAD_mem":  Template("LOAD_mem",  _fields(0b000001, 0b10)),
        "STORE_mem": Template("STORE_mem", _fields(0b000010, 0b10)),
        "ADD_reg":   Template("ADD_reg",   _fields(0b000100, 0b11)),
        "MUL_reg":   Template("MUL_reg",   _fields(0b001000, 0b11)),
        "JMP_br":    Template("JMP_br",    [
            Field("opcode", 6, fixed=0b010000),
            Field("mode",   2, fixed=0b00),
            Field("rA",     4, fixed=0),
            Field("rB",     4, fixed=0),
            Field("imm8",   8),
        ]),
        "MOV_reg":   Template("MOV_reg",   _fields(0b010101, 0b11)),
    }


def _isa24_bindings() -> List[Binding]:
    # LOAD: LOAD_mem  rA=dst(reg), rB=base(reg), imm8=offset(imm)
    load = Binding("LOAD", "LOAD_mem", [
        FieldBinding("rA",   "dst",    operand_type="reg"),
        FieldBinding("rB",   "base",   operand_type="reg"),
        FieldBinding("imm8", "offset", operand_type="imm"),
    ])
    # STORE: STORE_mem  rA=src(reg), rB=base(reg), imm8=offset(imm)
    store = Binding("STORE", "STORE_mem", [
        FieldBinding("rA",   "src",    operand_type="reg"),
        FieldBinding("rB",   "base",   operand_type="reg"),
        FieldBinding("imm8", "offset", operand_type="imm"),
    ])
    # ADD: ADD_reg  rA=dst_src1(reg), rB=src2(reg), imm8 fixed 0
    add = Binding("ADD", "ADD_reg", [
        FieldBinding("rA",   "dst",  operand_type="reg"),
        FieldBinding("rB",   "src",  operand_type="reg"),
        FieldBinding("imm8", None,   fixed_val=0),
    ])
    # MUL: MUL_reg  rA=dst(reg), rB=src(reg), imm8 fixed 0
    mul = Binding("MUL", "MUL_reg", [
        FieldBinding("rA",   "dst",  operand_type="reg"),
        FieldBinding("rB",   "src",  operand_type="reg"),
        FieldBinding("imm8", None,   fixed_val=0),
    ])
    # JMP: JMP_br  imm8=offset(imm)
    jmp = Binding("JMP", "JMP_br", [
        FieldBinding("imm8", "offset", operand_type="imm"),
    ])
    # MOV: MOV_reg  rA=dst(reg), rB=src(reg), imm8 fixed 0
    mov = Binding("MOV", "MOV_reg", [
        FieldBinding("rA",   "dst",  operand_type="reg"),
        FieldBinding("rB",   "src",  operand_type="reg"),
        FieldBinding("imm8", None,   fixed_val=0),
    ])
    return [load, store, add, mul, jmp, mov]


def _isa24_reg_table() -> Dict[str, int]:
    tbl = {f"r{i}": i for i in range(16)}
    tbl["rBP"] = 5
    tbl["rSP"] = 6
    return tbl


ISA24: ISASpec = ISASpec(
    name="ISA-24",
    templates=_isa24_templates(),
    bindings=_isa24_bindings(),
    reg_table=_isa24_reg_table(),
    opcode_field="opcode",
)
"""Pre-built ISASpec for the 24-bit toy ISA described in the design document."""


# ── Convenience ───────────────────────────────────────────────────────────────

def rgb_to_bytes(r: int, g: int, b: int) -> bytes:
    """Pack an RGB triple into 3 bytes (identical to a 24-bit instruction word)."""
    return bytes([r & 0xFF, g & 0xFF, b & 0xFF])


def bytes_to_rgb(data: bytes) -> Tuple[int, int, int]:
    """Unpack 3 bytes into an (R, G, B) triple."""
    if len(data) < 3:
        raise ValueError("Need at least 3 bytes")
    return data[0], data[1], data[2]


def rgb_int(r: int, g: int, b: int) -> int:
    """I24 = R*65536 + G*256 + B — the RGB packing formula."""
    return (r * 65536) + (g * 256) + b
