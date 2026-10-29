"""Schema-driven validation and construction of Junos gencfg IPC messages."""
from __future__ import annotations

import json
from pathlib import Path


def load_schemas() -> dict:
    path = Path(__file__).parent.parent / "data" / "junos_gencfg.json"
    return json.loads(path.read_text())


def _field(data: bytes, definition: dict) -> int:
    offset = definition["offset"]
    width = 2 if definition["type"] == "u16" else 4
    if offset + width > len(data):
        return 0
    return int.from_bytes(data[offset:offset + width], "big")


def _put(data: bytearray, offset: int, width: int, value: int) -> None:
    data[offset:offset + width] = value.to_bytes(width, "big")


def serialize_vrf_group(
    group_id: int,
    vrf_ids: list[int] | tuple[int, ...] = (),
    operation: int = 2,
    lsys_id: int = 0,
) -> bytes:
    if operation not in (1, 2, 3):
        raise ValueError("VRF-group operation must be 1, 2, or 3")
    if not 0 <= group_id < 0x1000:
        raise ValueError("VRF-group ID must be between 0 and 4095")
    if not 0 <= lsys_id <= 0xFFFF:
        raise ValueError("Logical-system ID must fit in 16 bits")
    if any(not 0 <= vrf_id <= 0xFFFFFFFF for vrf_id in vrf_ids):
        raise ValueError("VRF IDs must fit in 32 bits")
    if len(vrf_ids) > (0xFFFFFFFF - 0x98) // 8:
        raise ValueError("VRF count overflows the declared blob length")
    blob = bytearray(0x98 + 8 * len(vrf_ids))
    _put(blob, 0, 4, len(blob))
    _put(blob, 0x84, 2, group_id)
    _put(blob, 0x88, 4, lsys_id)
    _put(blob, 0x8C, 4, len(vrf_ids))
    for index, vrf_id in enumerate(vrf_ids):
        offset = 0x98 + index * 8
        _put(blob, offset, 2, 2)
        _put(blob, offset + 2, 2, 8)
        _put(blob, offset + 4, 4, vrf_id)
    message = bytearray(0x11C)
    _put(message, 0, 2, 0x89)
    _put(message, 2, 2, 4)
    _put(message, 4, 4, operation)
    _put(message, 12, 4, len(blob))
    _put(message, 32, 2, 4)
    _put(message, 34, 2, group_id)
    return bytes(message + blob)


def _validate_vrf_blob(message: bytes, fields: dict[str, int], operation: int, schema: dict) -> tuple[list[dict], dict]:
    checks = []

    def check(name: str, expected: object, actual: object, valid: bool) -> None:
        checks.append({"name": name, "expected": expected, "actual": actual, "valid": valid})

    offset = schema["blob_offset"]
    present = len(message) > offset
    required = operation in schema["operations_requiring_blob"]
    check("blob_present", schema["operations_requiring_blob"] if required else "optional", present, present or not required)
    if not present:
        return checks, {"present": False, "required": required, "entries": []}

    blob = message[offset:]
    declared = _field(blob, {"offset": schema["declared_length_offset"], "type": "u32"})
    count = _field(blob, {"offset": schema["declared_vrf_count_offset"], "type": "u32"})
    entries_offset = schema["first_variable_entry_offset"]
    check("blob_length_minimum", f">={entries_offset}", declared, declared >= entries_offset)
    check("blob_available", declared, len(blob), declared == len(blob))
    check("key_length_matches_blob", declared, fields["key_length"], fields["key_length"] == declared)
    expected = entries_offset + schema["entry_length"] * count
    check("blob_length_arithmetic", "<=0xffffffff", expected, expected <= 0xFFFFFFFF)
    check("declared_blob_length", expected, declared, expected == declared and expected <= 0xFFFFFFFF)

    entries = []
    cursor = entries_offset
    limit = min(declared, len(blob))
    while cursor < limit:
        index = len(entries)
        remaining = limit - cursor
        header_valid = remaining >= 4
        check(f"entry_{index}_header", ">=4 bytes remaining", remaining, header_valid)
        if not header_valid:
            break
        entry_type = int.from_bytes(blob[cursor:cursor + 2], "big")
        length = int.from_bytes(blob[cursor + 2:cursor + 4], "big")
        entry = {"index": index, "offset": cursor, "type": entry_type, "length": length}
        check(f"entry_{index}_type", schema["entry_type"], entry_type, entry_type == schema["entry_type"])
        check(f"entry_{index}_length", schema["entry_length"], length, length == schema["entry_length"])
        check(f"entry_{index}_progress", ">0", length, length > 0)
        aligned = (length + schema["entry_alignment"] - 1) & ~(schema["entry_alignment"] - 1)
        bounds_valid = length <= remaining and aligned <= remaining
        check(f"entry_{index}_bounds", f"<={remaining} bytes remaining", aligned, bounds_valid)
        if entry_type == schema["entry_type"] and length >= 8 and remaining >= 8:
            entry["vrf_id"] = int.from_bytes(blob[cursor + 4:cursor + 8], "big")
        entries.append(entry)
        if aligned <= 0 or aligned > remaining:
            break
        cursor += aligned
    check("entry_cursor", declared, cursor, cursor == declared)
    check("vrf_count", count, len(entries), count == len(entries))
    return checks, {
        "present": True,
        "required": required,
        "declared_length": declared,
        "available_length": len(blob),
        "declared_vrf_count": count,
        "parsed_vrf_count": len(entries),
        "group_id": _field(blob, {"offset": schema["group_id_offset"], "type": "u16"}),
        "lsys_id": _field(blob, {"offset": schema["lsys_id_offset"], "type": "u32"}),
        "entries": entries,
    }


def validate_message(data: bytes, family: str = "vrf-group") -> dict[str, object]:
    schemas = load_schemas()
    if family not in schemas["families"]:
        raise ValueError(f"Unknown gencfg family: {family}")
    schema = schemas["families"][family]
    definitions = schema["fields"]
    fields = {name: _field(data, definition) for name, definition in definitions.items()}
    major = fields["major_type"]
    variant = schema["variants"].get(str(major))
    checks = []

    def check(name: str, expected: object, actual: object, valid: bool) -> None:
        checks.append({"name": name, "expected": expected, "actual": actual, "valid": valid})

    check("major_type", sorted(int(value) for value in schema["variants"]), major, variant is not None)
    check("minor_type_header", schema["minor_type"], fields["minor_type"], fields["minor_type"] == schema["minor_type"])
    check("minor_type", schema["minor_type"], fields["minor_type_check"], fields["minor_type_check"] == schema["minor_type"])
    operation = fields["operation"]
    check(
        "operation",
        f"{schema['operation']['minimum']}..{schema['operation']['maximum']}",
        operation,
        schema["operation"]["minimum"] <= operation <= schema["operation"]["maximum"],
    )
    if variant is not None:
        check("key_length", f">={variant['key_length_minimum']}", fields["key_length"], fields["key_length"] >= variant["key_length_minimum"])
        check("message_size", f">={variant['message_size_minimum']}", len(data), len(data) >= variant["message_size_minimum"])
    blob = {"present": False, "required": False, "entries": []}
    if major == schema.get("blob_major_type") and "blob_offset" in schema:
        blob_checks, blob = _validate_vrf_blob(data, fields, operation, schema)
        checks.extend(blob_checks)
    return {
        "family": family,
        "variant": major,
        "valid": all(item["valid"] for item in checks),
        "fields": fields,
        "checks": checks,
        "blob_offset": schema.get("blob_offset"),
        "blob": blob,
    }
