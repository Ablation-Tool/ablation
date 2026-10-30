import hashlib
import json
from dataclasses import dataclass

from .errors import FormatError, UnsupportedFormatError
from .io_utils import ensure_directory, write_bytes, write_text
from .savf import _text, _u16, _u32, _u64

OPCODE_NAMES = {0x1042: "CPYNV", 0x10B2: "CPYBLA"}
COMPONENT_FIELDS = (("instruction_stream", 0x70), ("odv", 0x74), ("oes", 0x78))


def _operand(value):
    if value == 0:
        return {"kind": "null", "raw": "0x0000"}
    kind = value >> 13
    if kind in (2, 3, 4, 6, 7):
        raise UnsupportedFormatError("compound OPM operands are not implemented")
    if value & 0x2000:
        immediate = value & 0x1FFF
        if value & 0x8000:
            immediate -= 0x2000
        return {"kind": "immediate", "raw": f"0x{value:04x}", "value": immediate}
    return {"kind": "odt_reference", "raw": f"0x{value:04x}", "index": value}


def decode_opm_instruction(data, offset=0):
    if offset < 0 or offset % 2 or offset + 6 > len(data):
        raise FormatError("OPM instruction is truncated or unaligned")
    opcode_entry = _u16(data, offset)
    if opcode_entry & 0x1000:
        if (opcode_entry >> 8) & 0x0F:
            raise UnsupportedFormatError("optional OPM instruction forms are not implemented")
        opcode = opcode_entry & 0x10FF
    else:
        opcode = opcode_entry
    if opcode not in OPCODE_NAMES:
        raise UnsupportedFormatError(f"unsupported OPM opcode 0x{opcode:04x}")
    operands = [_operand(_u16(data, offset + 2)), _operand(_u16(data, offset + 4))]
    return {
        "offset": offset,
        "encoding": data[offset:offset + 6].hex(),
        "length": 6,
        "opcode_entry": f"0x{opcode_entry:04x}",
        "opcode": f"0x{opcode:04x}",
        "mnemonic": OPCODE_NAMES[opcode],
        "operands": operands,
        "scope": "single verified instruction; ODT names and runtime behavior are not resolved",
    }


def _serialized_sections(data):
    sections = []
    offset = 0x200
    while offset < len(data):
        if len(sections) >= 16 or offset + 0x20 > len(data):
            raise FormatError("invalid serialized program section count or header")
        section_type = _u16(data, offset)
        units = _u16(data, offset + 2)
        length = units * 512
        if not units or offset + length > len(data):
            raise FormatError("serialized program section lies outside the item")
        sections.append({
            "index": len(sections),
            "offset": offset,
            "type_raw": f"0x{section_type:04x}",
            "declared_512_byte_units": units,
            "length": length,
            "end_inclusive": offset + length - 1,
        })
        offset += length
    return sections


def _component(data, template, template_end, name, field_offset):
    relative = _u32(data, template + field_offset)
    start = template + relative
    if relative < 0x100 or start + 4 > template_end:
        raise FormatError(f"OPM {name} offset lies outside the template")
    length = _u32(data, start)
    alignment = 2 if name == "instruction_stream" else 4 if name == "odv" else 1
    if length < 4 or length % alignment or start + length > template_end:
        raise FormatError(f"OPM {name} length lies outside the template")
    raw = data[start:start + length]
    return {
        "name": name,
        "offset_relative_to_template": relative,
        "start": start,
        "end_inclusive": start + length - 1,
        "length": length,
        "length_includes_prefix": True,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


@dataclass
class OpmProgramRecovery:
    source_name: str
    source_sha256: str
    object_header: object
    template_offset: int
    template_size: int
    template_pointer_raw: str
    sections: list[dict]
    components: list[dict]
    code_start: int
    code_end: int
    code_sha256: str

    def to_dict(self):
        return {
            "source": self.source_name,
            "sha256": self.source_sha256,
            "layout": "legacy OPM program template with length-prefixed MI components",
            "object_header": self.object_header.to_dict(),
            "opm_template": {
                "offset": self.template_offset,
                "declared_size": self.template_size,
                "pointer_raw": self.template_pointer_raw,
            },
            "serialized_section_count": len(self.sections),
            "serialized_sections": self.sections,
            "components": self.components,
            "code_region": {
                "start": self.code_start,
                "end_inclusive": self.code_end,
                "length": self.code_end - self.code_start + 1,
                "sha256": self.code_sha256,
                "boundary": "length-prefixed OPM MI instruction-stream component; two-byte entries follow the prefix",
            },
            "supported_opcodes": ["CPYBLA", "CPYNV"],
            "instruction_analysis": "single-instruction decoding with null, immediate, or simple ODT operands; no linear sweep",
        }

    def extract(self, data, output_directory):
        output = ensure_directory(output_directory)
        filenames = {"instruction_stream": "code.bin", "odv": "odv.bin", "oes": "oes.bin"}
        for component in self.components:
            write_bytes(output / filenames[component["name"]], data[component["start"]:component["end_inclusive"] + 1])
        write_text(output / "program.json", json.dumps(self.to_dict(), indent=2) + "\n")
        return output

    def decode_at(self, data, offset):
        first = self.code_start + 4
        if offset < first or offset > self.code_end - 1 or (offset - first) % 2:
            raise FormatError("OPM instruction offset lies outside the instruction stream or is unaligned")
        result = decode_opm_instruction(data, offset)
        if offset + result["length"] - 1 > self.code_end:
            raise FormatError("OPM instruction extends beyond the instruction stream")
        return result


def recover_opm_program(data, source_name, object_header):
    sections = _serialized_sections(data)
    expected_types = ("0x0181", "0x0581", "0x0281")
    if len(sections) != 3 or tuple(section["type_raw"] for section in sections) != expected_types:
        raise UnsupportedFormatError("unsupported OPM serialized-section layout")
    first, second, _ = sections
    if first["offset"] != object_header.segment_offset:
        raise FormatError("OPM first section does not match the object header")
    header = object_header.program_header_offset
    if header + 16 > first["end_inclusive"] + 1:
        raise FormatError("OPM program header is truncated")
    pointer = _u64(data, header + 8)
    if pointer >> 24 != object_header.segment_id + 1 or pointer & 0xFFFFFF != 0x20:
        raise UnsupportedFormatError("unsupported OPM template pointer")
    template = second["offset"] + 0x20
    second_end = second["end_inclusive"] + 1
    if template + 0x100 > second_end:
        raise FormatError("OPM template header is truncated")
    if _u16(data, template + 8) != 0x0201 or _text(data[template + 10:template + 40]) != object_header.name:
        raise FormatError("OPM template object identity does not match the object header")
    template_size = _u32(data, template)
    if template_size < 0x100 or template + template_size > second_end:
        raise FormatError("OPM template size lies outside its section")
    template_end = template + template_size
    components = [_component(data, template, template_end, name, offset) for name, offset in COMPONENT_FIELDS]
    for previous, following in zip(components, components[1:]):
        if previous["end_inclusive"] >= following["start"]:
            raise FormatError("OPM template components overlap")
    instruction = components[0]
    return OpmProgramRecovery(
        source_name, hashlib.sha256(data).hexdigest(), object_header, template,
        template_size, f"0x{pointer:016x}", sections, components,
        instruction["start"], instruction["end_inclusive"], instruction["sha256"],
    )
