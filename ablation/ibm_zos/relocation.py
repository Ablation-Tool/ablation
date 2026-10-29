from dataclasses import dataclass

from .errors import FormatError


@dataclass
class Relocation:
    rva: int
    length: int
    kind: str
    negative: bool
    r_esdid: int
    p_esdid: int
    record_index: int
    repeated: bool
    file_offset: int
    target_name: str | None
    resident_name: str | None
    target_address: int | None
    resolved: bool

    def to_dict(self):
        return self.__dict__.copy()


def parse_rld(data, symbols=(), record_index=0, file_offset=0, state=None):
    symbols_by_id = {symbol.symbol_id: symbol for symbol in symbols}
    result = []
    offset = 0
    state = {} if state is None else state
    r_esdid = state.get("r_esdid")
    p_esdid = state.get("p_esdid")
    repeat = state.get("repeat", False)
    while offset < len(data):
        entry_offset = offset
        repeated = repeat
        if repeated:
            if offset + 4 > len(data):
                raise FormatError("truncated repeated RLD entry")
        else:
            if offset + 8 > len(data):
                raise FormatError("truncated full RLD entry")
            r_esdid = int.from_bytes(data[offset:offset + 2], "big")
            p_esdid = int.from_bytes(data[offset + 2:offset + 4], "big")
            offset += 4
        flags = data[offset]
        rva = int.from_bytes(data[offset + 1:offset + 4], "big")
        offset += 4
        target = symbols_by_id.get(r_esdid)
        resident = symbols_by_id.get(p_esdid)
        relative_immediate = (flags & 0x38) in (0x38, 0x3C)
        unresolved = relative_immediate or bool(flags & 0x80)
        resolved = target is not None and target.kind not in ("ER", "WX") and not unresolved
        result.append(Relocation(
            rva=rva,
            length=((flags >> 2) & 3) + 1 + (4 if flags & 0x40 else 0),
            kind="RI" if relative_immediate else "U" if flags & 0x80 else "V" if flags & 0x10 else "A",
            negative=bool(flags & 2),
            r_esdid=r_esdid,
            p_esdid=p_esdid,
            record_index=record_index,
            repeated=repeated,
            file_offset=file_offset + entry_offset,
            target_name=target.name if target else None,
            resident_name=resident.name if resident else None,
            target_address=target.address if resolved else None,
            resolved=resolved,
        ))
        repeat = bool(flags & 1)
    state.update({"r_esdid": r_esdid, "p_esdid": p_esdid, "repeat": repeat})
    return result


def image_relocations(image):
    return [Relocation(**item) for item in image.metadata.get("relocations", [])]


def relocate_image(image, base_address=0):
    if not isinstance(base_address, int) or isinstance(base_address, bool) or base_address < 0:
        raise ValueError("relocation base must be a nonnegative integer")
    relocations = image_relocations(image)
    relocated = bytearray(image.text)
    entries = []
    for relocation in relocations:
        item = relocation.to_dict()
        item["base_address"] = base_address
        end = relocation.rva + relocation.length
        if relocation.rva < 0 or end > len(relocated):
            raise FormatError(f"RLD address outside load image at {relocation.rva:#x}")
        original = int.from_bytes(relocated[relocation.rva:end], "big")
        item["original_value"] = original
        if not relocation.resolved:
            item["status"] = "unresolved"
            item["relocated_value"] = original
            entries.append(item)
            continue
        delta = -base_address if relocation.negative else base_address
        signed_original = int.from_bytes(relocated[relocation.rva:end], "big", signed=True)
        value = signed_original + delta
        bits = relocation.length * 8
        if not -(1 << (bits - 1)) <= value < 1 << bits:
            raise FormatError(f"RLD value overflows {relocation.length}-byte adcon at {relocation.rva:#x}")
        encoded = value & ((1 << bits) - 1)
        relocated[relocation.rva:end] = encoded.to_bytes(relocation.length, "big")
        item["relocated_value"] = encoded
        item["status"] = "unchanged" if base_address == 0 else "applied"
        entries.append(item)
    report = {
        "base_address": base_address,
        "relocation_count": len(entries),
        "applied_count": sum(item["status"] == "applied" for item in entries),
        "unchanged_count": sum(item["status"] == "unchanged" for item in entries),
        "unresolved_count": sum(item["status"] == "unresolved" for item in entries),
        "entries": entries,
    }
    return bytes(relocated), report
