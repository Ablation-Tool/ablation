import hashlib
import struct
from pathlib import Path

from .errors import FormatError
from .image import LoadImage, Symbol, TextChunk
from .relocation import parse_rld


ESD_TYPES = {
    0x0: "SD", 0x1: "LR", 0x2: "ER", 0x3: "LR", 0x4: "PC", 0x5: "CM",
    0x6: "PR", 0x7: "NULL", 0xA: "WX", 0xD: "SD_QUAD", 0xE: "PC_QUAD", 0xF: "CM_QUAD",
}


def u16(data, offset):
    return struct.unpack_from(">H", data, offset)[0]


def u24(data, offset):
    return int.from_bytes(data[offset:offset + 3], "big")


def u32(data, offset):
    return struct.unpack_from(">I", data, offset)[0]


def _program_object_symbols(data, records):
    signature = "IEWBXLF ".encode("cp500")
    symbols = []
    inventory = []
    binary_inventory = []
    errors = []
    for record in records:
        start = record["file_offset"]
        end = start + record["length"]
        cursor = start
        while cursor < end:
            cursor = data.find(signature, cursor, end)
            if cursor < 0:
                break
            if cursor + 24 > end:
                errors.append({"file_offset": cursor, "error": "truncated IEWBXLF header"})
                break
            kind = data[cursor + 16:cursor + 20].decode("cp500", errors="replace").strip()
            if kind == "NAME":
                count = u32(data, cursor + 20)
                pointers_end = cursor + 24 + count * 4
                if pointers_end > end:
                    errors.append({"file_offset": cursor, "error": "IEWBXLF NAME pointers exceed record"})
                else:
                    for index in range(count):
                        pointer = u32(data, cursor + 24 + index * 4)
                        if pointer + 4 > len(data):
                            errors.append({"file_offset": pointer, "error": "IEWBXLF name pointer outside input"})
                            continue
                        attributes = data[pointer]
                        length = u16(data, pointer + 1)
                        name_end = pointer + 3 + length
                        if not length or name_end > len(data):
                            errors.append({"file_offset": pointer, "error": "invalid IEWBXLF name length"})
                            continue
                        raw_name = data[pointer + 3:name_end]
                        name = raw_name.decode("cp500", errors="replace")
                        if not name.isprintable():
                            binary_inventory.append({
                                "name_hex": raw_name.hex(), "name_file_offset": pointer + 3,
                                "attributes": attributes, "address": None,
                            })
                            continue
                        symbols.append(Symbol(name, -1, "NAME", None, None, attributes, "IEWBXLF"))
                        inventory.append({
                            "name": name, "name_file_offset": pointer + 3,
                            "attributes": attributes, "address": None,
                        })
            cursor += 8
    return symbols, {
        "program_object_names": inventory,
        "program_object_binary_names": binary_inventory,
        "program_object_name_errors": errors,
    }


def _program_object(data, source_name):
    if len(data) < 0x78 or data[:8] != "IEWPLMH ".encode("cp500"):
        raise FormatError("not an IEWPLMH program object")
    header_length = u32(data, 8)
    module_size = u32(data, 0x10)
    record_count = u32(data, 0x14)
    if header_length != 0x78 or module_size != len(data):
        raise FormatError("inconsistent LMH header")
    if 0x18 + record_count * 12 > len(data):
        raise FormatError("LMH record table exceeds input")
    records = []
    for index in range(record_count):
        offset = 0x18 + index * 12
        record_id, file_offset, length = struct.unpack_from(">III", data, offset)
        if file_offset + length > len(data):
            raise FormatError("LMH record outside input")
        records.append({
            "index": record_id >> 16, "flags": record_id & 0xFFFF,
            "file_offset": file_offset, "length": length,
            "signature": data[file_offset:file_offset + 8].decode("cp500", errors="replace"),
        })
    segment_signature = "IEWPSEGM".encode("cp500")
    segment_offset = data.find(segment_signature)
    if segment_offset >= 0:
        if segment_offset + 0x40 > len(data):
            raise FormatError("truncated IEWPSEGM")
        text_length = u32(data, segment_offset + 0x14)
        text_file_offset = u32(data, segment_offset + 0x18)
        text_rva = u32(data, segment_offset + 0x1C)
        entry_rva = u32(data, segment_offset + 0x24)
        segment_words = [f"{u32(data, segment_offset + offset):08x}" for offset in range(0, 0x40, 4)]
    else:
        text_record = next((record for record in records if record["index"] == 7), None)
        if text_record is None:
            raise FormatError("program object has neither IEWPSEGM nor LMH text record")
        text_file_offset = text_record["file_offset"]
        text_length = text_record["length"]
        text_rva = 0
        entry_rva = None
        segment_words = None
    if text_file_offset + text_length > len(data):
        raise FormatError("program-object text exceeds input")
    chunks = [TextChunk(text_rva, text_file_offset, text_length)]
    symbols, name_metadata = _program_object_symbols(data, records)
    metadata = {
        "module_size": module_size, "segment_record_file_offset": segment_offset,
        "text_file_offset": text_file_offset, "text_rva": text_rva,
        "segment_words": segment_words, **name_metadata,
    }
    return LoadImage(source_name, hashlib.sha256(data).hexdigest(), "IEWPLMH", data[text_file_offset:text_file_offset + text_length], symbols, chunks, entry_rva, records, metadata)


def _cesd(data):
    records = []
    symbols = []
    offset = 0
    while offset < len(data) and data[offset] == 0x20:
        if offset + 8 > len(data):
            raise FormatError("truncated CESD header")
        first_id = u16(data, offset + 4)
        length = u16(data, offset + 6)
        if length % 16 or offset + 8 + length > len(data):
            raise FormatError("invalid CESD record length")
        records.append({"file_offset": offset, "first_esdid": first_id, "flags": data[offset + 1], "length": length})
        for index in range(length // 16):
            entry_offset = offset + 8 + index * 16
            type_code = data[entry_offset + 8]
            kind = ESD_TYPES.get(type_code & 0x0F, f"UNKNOWN_{type_code & 0x0F:x}")
            symbols.append(Symbol(
                data[entry_offset:entry_offset + 8].decode("cp500", errors="replace").rstrip(),
                u24(data, entry_offset + 9), kind, u24(data, entry_offset + 13),
                first_id + index, data[entry_offset + 12], "CESD",
            ))
        offset += 8 + length
    if not records:
        raise FormatError("load module has no CESD")
    return offset, records, symbols


def _idrs(data, offset):
    result = []
    while offset < len(data) and data[offset] == 0x80:
        if offset + 3 > len(data):
            raise FormatError("truncated IDR")
        length = data[offset + 1] + 1
        if length < 7 or offset + length > len(data):
            raise FormatError("invalid IDR length")
        subtype = data[offset + 2]
        payload = data[offset + 3:offset + length]
        result.append({
            "file_offset": offset, "length": length, "raw_subtype": subtype,
            "subtype": subtype & 0x0F, "last": bool(subtype & 0x90),
            "data_hex": payload.hex(), "data_cp500": payload.decode("cp500", errors="replace"),
        })
        offset += length
        if subtype & 0x90:
            break
    if not result or not result[-1]["last"]:
        raise FormatError("unterminated IDR sequence")
    return offset, result


def _pds_load_module(data, source_name):
    offset, cesd_records, symbols = _cesd(data)
    offset, idrs = _idrs(data, offset)
    records = []
    chunks = []
    eom = False
    while offset < len(data):
        if offset + 16 > len(data):
            raise FormatError("truncated control/RLD header")
        record_offset = offset
        record_id = data[offset]
        record_type = record_id & 3
        if record_type not in (1, 2, 3) or record_id & 0xF0:
            raise FormatError(f"unsupported record ID {record_id:#x} at {offset:#x}")
        control_length = u16(data, offset + 4)
        rld_length = u16(data, offset + 6)
        rld_offset = offset + 16
        control_offset = rld_offset + rld_length
        record_end = control_offset + control_length
        if record_end > len(data):
            raise FormatError("truncated control/RLD data")
        if control_length % 4:
            raise FormatError("unaligned control data")
        control_items = [
            {"esdid": u16(data, item), "length": u16(data, item + 2)}
            for item in range(control_offset, rld_offset, 4)
        ]
        text_length = u16(data, offset + 14) if record_type in (1, 3) else 0
        text_address = u24(data, offset + 9) if record_type in (1, 3) else None
        if record_end + text_length > len(data):
            raise FormatError("truncated TEXT")
        record = {
            "index": len(records), "file_offset": record_offset, "record_id": record_id,
            "record_type": record_type, "following_count": data[offset + 3],
            "control_length": control_length, "rld_length": rld_length,
            "rld_file_offset": rld_offset, "ccw_hex": data[offset + 8:offset + 16].hex(),
            "control_items": control_items, "text_address": text_address,
            "text_file_offset": record_end if text_length else None, "text_length": text_length,
            "end_of_segment": bool(record_id & 4), "end_of_module": bool(record_id & 8),
        }
        records.append(record)
        if text_length:
            chunks.append(TextChunk(text_address, record_end, text_length))
        offset = record_end + text_length
        eom = eom or bool(record_id & 8)
    if offset != len(data) or not eom:
        raise FormatError("PDS load module did not end exactly at EOM")
    image_size = max((chunk.address + chunk.length for chunk in chunks), default=0)
    image = bytearray(image_size)
    covered = bytearray(image_size)
    for chunk in chunks:
        payload = data[chunk.file_offset:chunk.file_offset + chunk.length]
        for index, value in enumerate(payload):
            position = chunk.address + index
            if covered[position] and image[position] != value:
                raise FormatError("conflicting overlapping TEXT")
            image[position] = value
            covered[position] = 1
    relocations = []
    rld_state = {}
    for record in records:
        if not record["rld_length"]:
            continue
        start = record["rld_file_offset"]
        raw_rld = data[start:start + record["rld_length"]]
        entries = parse_rld(raw_rld, symbols, record["index"], start, rld_state)
        for entry in entries:
            if entry.rva + entry.length > image_size:
                raise FormatError(f"RLD address outside load image at {entry.rva:#x}")
        relocations.extend(entry.to_dict() for entry in entries)
    ceestart = next((symbol for symbol in symbols if symbol.name == "CEESTART" and symbol.kind.startswith("SD")), None)
    metadata = {
        "cesd_records": cesd_records, "idrs": idrs,
        "text_covered_bytes": sum(covered), "text_gap_bytes": image_size - sum(covered),
        "ceestart": ceestart.__dict__ if ceestart else None,
        "relocation_count": len(relocations), "relocations": relocations,
    }
    return LoadImage(source_name, hashlib.sha256(data).hexdigest(), "PDS_LOAD_MODULE", bytes(image), symbols, chunks, None, records, metadata)


def parse_load_image(data, source_name="<memory>"):
    if data[:8] == "IEWPLMH ".encode("cp500"):
        return _program_object(data, source_name)
    if data and data[0] == 0x20:
        return _pds_load_module(data, source_name)
    raise FormatError("unsupported z/OS executable format")


def read_load_image(path):
    path = Path(path)
    return parse_load_image(path.read_bytes(), str(path))
