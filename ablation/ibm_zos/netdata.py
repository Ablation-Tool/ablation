import hashlib
import json
import os
import re
import struct
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from .errors import FormatError, SafetyError, UnsupportedFormatError
from .io_utils import ensure_directory, remove_for_symlink, write_bytes, write_text


TEXT_UNITS = {
    0x0001: ("INMDDNAM", "character"), 0x0002: ("INMDSNAM", "character"),
    0x0003: ("INMMEMBR", "character"), 0x000B: ("INMSECND", "decimal"),
    0x000C: ("INMDIR", "decimal"), 0x0022: ("INMEXPDT", "character"),
    0x0028: ("INMTERM", "character"), 0x0030: ("INMBLKSZ", "decimal"),
    0x003C: ("INMDSORG", "hex"), 0x0042: ("INMLRECL", "decimal"),
    0x0049: ("INMRECFM", "hex"), 0x1001: ("INMTNODE", "character"),
    0x1002: ("INMTUID", "character"), 0x1011: ("INMFNODE", "character"),
    0x1012: ("INMFUID", "character"), 0x1020: ("INMLREF", "character"),
    0x1021: ("INMLCHG", "character"), 0x1022: ("INMCREAT", "character"),
    0x1023: ("INMFVERS", "character"), 0x1024: ("INMFTIME", "character"),
    0x1025: ("INMTTIME", "character"), 0x1026: ("INMFACK", "character"),
    0x1027: ("INMERRCD", "character"), 0x1028: ("INMUTILN", "character"),
    0x1029: ("INMUSERP", "character"), 0x102A: ("INMRECCT", "character"),
    0x102C: ("INMSIZE", "decimal"), 0x102F: ("INMNUMF", "decimal"),
    0x8012: ("INMTYPE", "hex"),
}
SAFE_NAME = re.compile(r"^[A-Za-z0-9@#$_.-]+$")


def u16(data, offset=0):
    return struct.unpack_from(">H", data, offset)[0]


def u32(data, offset=0):
    return struct.unpack_from(">I", data, offset)[0]


def dsorg(value):
    names = ((0x8000, "ISAM"), (0x4000, "PS"), (0x2000, "DA"), (0x1000, "BTAM"), (0x0200, "PO"))
    result = next((name for bit, name in names if value & bit), "?")
    return result + ("U" if value & 1 else "")


def recfm(value):
    if not value:
        raise FormatError("empty RECFM")
    flag = value[0]
    kind = {0x40: "V", 0x80: "F", 0xC0: "U"}.get(flag & 0xC0, "?")
    return kind + ("B" if flag & 0x10 else "") + ("A" if flag & 4 else "") + ("M" if flag & 2 else "") + ("S" if flag & 8 else "")


def parse_text_units(data, encoding="cp1140"):
    units = OrderedDict()
    raw = []
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data):
            raise FormatError("truncated text-unit header")
        key, count = struct.unpack_from(">HH", data, offset)
        offset += 4
        values = []
        for index in range(count):
            if offset + 2 > len(data):
                raise FormatError("truncated text-unit value")
            length = u16(data, offset)
            offset += 2
            if offset + length > len(data):
                raise FormatError("text-unit value exceeds control record")
            item = data[offset:offset + length]
            offset += length
            kind = TEXT_UNITS.get(key, (f"UNKNOWN_{key:04X}", "hex"))[1]
            if kind == "character":
                value = item.decode(encoding)
            elif kind == "decimal":
                value = int.from_bytes(item, "big")
            else:
                value = item.hex()
            values.append(value)
            raw.append({"key": key, "index": index, "length": length, "hex": item.hex()})
        name = TEXT_UNITS.get(key, (f"UNKNOWN_{key:04X}", "hex"))[0]
        if key == 0x0002:
            units[name] = ".".join(values)
        elif key in (0x003C, 0x0049) and values:
            units[name] = int(values[-1], 16)
        elif len(values) == 1:
            units[name] = values[0]
        else:
            units[name] = values
    if offset != len(data):
        raise FormatError("text-unit parser did not consume its input")
    return units, raw


@dataclass
class ControlRecord:
    kind: str
    number: int
    units: dict
    raw_units: list


@dataclass
class Member:
    name: str
    ttr: int
    is_alias: bool
    parameters: bytes
    notes: int
    data: bytes | None = None
    target: str | None = None

    @property
    def suffix(self):
        return ".bin"


@dataclass
class Dataset:
    name: str
    number: int
    utility: str
    organization: str
    record_format: str
    logical_record_length: int
    container_type: str
    metadata: dict
    records: list[bytes] = field(repr=False)
    members: OrderedDict[str, Member] = field(default_factory=OrderedDict)

    @property
    def is_partitioned(self):
        return bool(self.members)

    def member_bytes(self, name):
        member = self.members[name]
        if member.is_alias:
            return self.members[member.target].data
        return member.data

    def to_dict(self, include_hashes=True):
        result = {
            "name": self.name, "number": self.number, "utility": self.utility,
            "organization": self.organization, "record_format": self.record_format,
            "logical_record_length": self.logical_record_length,
            "container_type": self.container_type, "metadata": self.metadata,
            "members": [],
        }
        for member in self.members.values():
            item = {
                "name": member.name, "ttr": member.ttr, "alias": member.is_alias,
                "target": member.target, "parameters_hex": member.parameters.hex(),
                "notes": member.notes,
            }
            payload = self.member_bytes(member.name)
            if include_hashes and payload is not None:
                item["size"] = len(payload)
                item["sha256"] = hashlib.sha256(payload).hexdigest()
            result["members"].append(item)
        return result


@dataclass
class NetdataFile:
    source_name: str
    source_sha256: str
    header: dict
    controls: list[ControlRecord]
    datasets: OrderedDict[str, Dataset]
    messages: list[bytes]
    terminated: bool

    def to_dict(self):
        return {
            "format": "IBM NETDATA", "source": self.source_name,
            "sha256": self.source_sha256, "header": self.header,
            "controls": [
                {"kind": c.kind, "number": c.number, "units": c.units, "raw_units": c.raw_units}
                for c in self.controls
            ],
            "datasets": [dataset.to_dict() for dataset in self.datasets.values()],
            "messages_hex": [message.hex() for message in self.messages],
            "terminated": self.terminated,
        }


def _parse_copyr1(record):
    if len(record) < 56:
        raise FormatError("short COPYR1")
    if int.from_bytes(record[1:4], "big") == 0xCA6D0F:
        offset = 0
    elif len(record) >= 64 and int.from_bytes(record[9:12], "big") == 0xCA6D0F:
        offset = 8
    else:
        raise FormatError("COPYR1 eyecatcher not found")
    body = record[offset:]
    return {
        "container_type": "PDSE" if body[0] & 1 else "PDS",
        "dsorg": dsorg(u16(body, 4)), "block_length": u16(body, 6),
        "lrecl": u16(body, 8), "recfm": recfm(body[10:12]),
        "key_length": body[11], "option_code": body[12], "sms_flags": body[13],
        "transport_block_size": u16(body, 14), "header_records": u16(body, 36),
    }


def _parse_directory_record(record, members):
    if len(record) < 22:
        raise FormatError("short PDS directory block")
    length = u16(record, 20) - 2
    if length < 0 or 22 + length > len(record):
        raise FormatError("PDS directory entries exceed block")
    entries = record[22:22 + length]
    offset = 0
    complete = False
    while offset < len(entries):
        if entries[offset:offset + 8] == b"\xff" * 8:
            complete = True
            break
        if offset + 12 > len(entries):
            raise FormatError("truncated PDS directory entry")
        name = entries[offset:offset + 8].decode("cp1140").rstrip()
        if not name or not SAFE_NAME.fullmatch(name):
            raise SafetyError("unsafe PDS member name")
        ttr = int.from_bytes(entries[offset + 8:offset + 11], "big")
        flags = entries[offset + 11]
        parameter_length = (flags & 0x1F) * 2
        end = offset + 12 + parameter_length
        if end > len(entries):
            raise FormatError("PDS directory parameters exceed entry area")
        if name in members:
            raise FormatError(f"duplicate PDS member {name}")
        members[name] = Member(name, ttr, bool(flags & 0x80), entries[offset + 12:end], (flags & 0x60) >> 5)
        offset = end
    return complete


def _decode_variable_records(data):
    if len(data) < 4:
        raise FormatError("short variable-record block")
    block_length = u16(data, 0)
    if block_length < 4 or block_length > len(data):
        raise FormatError("invalid variable-block descriptor")
    result = bytearray()
    offset = 4
    while offset < block_length:
        if offset + 4 > block_length:
            raise FormatError("truncated variable-record descriptor")
        length = u16(data, offset)
        if length < 4 or offset + length > block_length:
            raise FormatError("invalid variable-record length")
        result.extend(data[offset + 4:offset + length])
        offset += length
    return bytes(result)


def _extract_members(records, copyr1, members):
    primary_ttrs = sorted((member.ttr, name) for name, member in members.items() if not member.is_alias)
    if not primary_ttrs:
        raise FormatError("PDS has no primary members")
    stream = b"".join(records)
    payloads = OrderedDict((name, bytearray()) for _, name in primary_ttrs)
    current = 0
    finalized = set()
    offset = 0
    previous_ttr = None
    closed = False
    while offset < len(stream):
        if offset + 12 > len(stream):
            raise FormatError("truncated IEBCOPY member sub-block")
        member_ttr = int.from_bytes(stream[offset + 6:offset + 9], "big")
        length = u16(stream, offset + 10)
        end = offset + 12 + length
        if end > len(stream):
            raise FormatError("IEBCOPY member sub-block exceeds input")
        if copyr1["container_type"] == "PDSE" and closed:
            while member_ttr == previous_ttr:
                offset = end
                if offset + 12 > len(stream):
                    break
                member_ttr = int.from_bytes(stream[offset + 6:offset + 9], "big")
                length = u16(stream, offset + 10)
                end = offset + 12 + length
                if end > len(stream):
                    raise FormatError("PDSE continuation exceeds input")
            closed = False
            if offset >= len(stream):
                break
        if member_ttr == 0 and length == 0:
            offset = end
            continue
        if current >= len(primary_ttrs):
            raise FormatError("more member payloads than primary directory entries")
        name = primary_ttrs[current][1]
        if length == 0:
            if name in finalized:
                raise FormatError(f"duplicate end-of-member for {name}")
            finalized.add(name)
            current += 1
            closed = copyr1["container_type"] == "PDSE"
            previous_ttr = member_ttr
        else:
            payload = stream[offset + 12:end]
            if copyr1["recfm"].startswith("V"):
                payload = _decode_variable_records(payload)
            payloads[name].extend(payload)
        offset = end
    if current < len(primary_ttrs) and current == len(primary_ttrs) - 1 and primary_ttrs[current][1] not in finalized:
        finalized.add(primary_ttrs[current][1])
        current += 1
    if current != len(primary_ttrs):
        raise FormatError("not all PDS primary members were reconstructed")
    for name, payload in payloads.items():
        members[name].data = bytes(payload)
    for member in members.values():
        if member.is_alias:
            targets = [name for ttr, name in primary_ttrs if ttr == member.ttr]
            if len(targets) != 1:
                raise FormatError(f"alias {member.name} has no unique primary target")
            member.target = targets[0]


def _dataset_from_candidate(candidate, descriptors, records):
    number = candidate["numfile"]
    descriptor = descriptors.get(number, {})
    utility = descriptor.get("INMUTILN", candidate["units"].get("INMUTILN", ""))
    if utility == "AMSCIPHR" or candidate["units"].get("INMUTILN") == "AMSCIPHR":
        raise UnsupportedFormatError("AMSCIPHR encrypted NETDATA is unsupported")
    name = descriptor.get("INMDSNAM", candidate["units"].get("INMDSNAM"))
    if not name:
        raise FormatError(f"dataset {number} has no name")
    if not SAFE_NAME.fullmatch(name):
        raise SafetyError("unsafe dataset name")
    organization_value = descriptor.get("INMDSORG", candidate["units"].get("INMDSORG", 0))
    record_format_value = descriptor.get("INMRECFM", candidate["units"].get("INMRECFM", 0))
    lrecl = descriptor.get("INMLRECL", candidate["units"].get("INMLRECL", 0))
    dataset = Dataset(
        name, number, utility, dsorg(organization_value), recfm(record_format_value.to_bytes(2, "big")),
        lrecl, "PS", {"descriptor": descriptor, "transport": candidate["units"]}, records,
    )
    if utility == "IEBCOPY":
        if len(records) < 3:
            raise FormatError("IEBCOPY stream is too short")
        copyr1 = _parse_copyr1(records[0])
        dataset.container_type = copyr1["container_type"]
        dataset.record_format = copyr1["recfm"]
        dataset.logical_record_length = copyr1["lrecl"]
        dataset.metadata["copyr1"] = copyr1
        dataset.metadata["copyr2_sha256"] = hashlib.sha256(records[1]).hexdigest()
        index = 2
        complete = False
        directory = bytearray()
        consumed = 0
        while index < len(records) and not complete:
            directory.extend(records[index])
            index += 1
            while consumed + 276 <= len(directory) and not complete:
                complete = _parse_directory_record(directory[consumed:consumed + 276], dataset.members)
                consumed += 276
        if not complete:
            raise FormatError("unterminated PDS directory")
        member_records = [bytes(directory[consumed:]), *records[index:]]
        _extract_members(member_records, copyr1, dataset.members)
    else:
        dataset.members["DATA"] = Member("DATA", 0, False, b"", 0, b"".join(records))
    return dataset


def parse_netdata(data, source_name="<memory>"):
    if len(data) < 10 or data[2:8].decode("cp1140", errors="replace") != "INMR01":
        raise FormatError("not a NETDATA file beginning with INMR01")
    controls = []
    candidates = []
    descriptors = {}
    streams = OrderedDict()
    current_stream = None
    buffer = bytearray()
    control_buffer = bytearray()
    terminated = False
    offset = 0
    while offset < len(data):
        length = data[offset]
        if length < 2 or offset + length > len(data):
            raise FormatError(f"invalid NETDATA segment at {offset:#x}")
        flag = data[offset + 1]
        payload = data[offset + 2:offset + length]
        if flag & 0x20:
            control_buffer.extend(payload)
            if flag & 0x40:
                kind = control_buffer[:6].decode("cp1140", errors="replace")
                body = bytes(control_buffer[6:])
                if kind == "INMR06":
                    terminated = True
                    control_buffer.clear()
                    offset += length
                    break
                if kind == "INMR02":
                    if len(body) < 4:
                        raise FormatError("short INMR02")
                    number = u32(body, 0)
                    units, raw = parse_text_units(body[4:])
                    record = ControlRecord(kind, len([c for c in controls if c.kind == kind]) + 1, units, raw)
                    units["numfile"] = number
                    if units.get("INMUTILN") == "IEBCOPY":
                        descriptors[number] = units
                    else:
                        candidates.append({"numfile": number, "units": units})
                else:
                    units, raw = parse_text_units(body)
                    record = ControlRecord(kind, len([c for c in controls if c.kind == kind]) + 1, units, raw)
                controls.append(record)
                if kind == "INMR03":
                    if not candidates:
                        raise FormatError("INMR03 has no transport INMR02")
                    current_stream = len(streams)
                    streams[current_stream] = []
                control_buffer.clear()
        else:
            if current_stream is None:
                raise FormatError("data segment precedes INMR03")
            buffer.extend(payload)
            if flag & 0x40:
                streams[current_stream].append(bytes(buffer))
                buffer.clear()
        offset += length
    if buffer or control_buffer:
        raise FormatError("unterminated NETDATA segment sequence")
    if not terminated:
        raise FormatError("NETDATA has no INMR06")
    if len(streams) != len(candidates):
        raise FormatError("transport/data stream count mismatch")
    datasets = OrderedDict()
    messages = []
    for index, records in streams.items():
        candidate = candidates[index]
        if "INMTERM" in candidate["units"]:
            messages.append(b"".join(records))
            continue
        dataset = _dataset_from_candidate(candidate, descriptors, records)
        if dataset.name in datasets:
            raise FormatError(f"duplicate dataset {dataset.name}")
        datasets[dataset.name] = dataset
    header = next((c.units for c in controls if c.kind == "INMR01"), None)
    if header is None:
        raise FormatError("NETDATA has no INMR01")
    return NetdataFile(source_name, hashlib.sha256(data).hexdigest(), header, controls, datasets, messages, terminated)


def read_netdata(path):
    path = Path(path)
    return parse_netdata(path.read_bytes(), str(path))


def extract_dataset(netdata, dataset_name, output_directory, overwrite=False):
    if dataset_name not in netdata.datasets:
        raise KeyError(dataset_name)
    dataset = netdata.datasets[dataset_name]
    root = ensure_directory(Path(output_directory) / dataset.name)
    for member in dataset.members.values():
        if member.is_alias:
            continue
        path = root / f"{member.name}{member.suffix}"
        write_bytes(path, member.data, overwrite)
    for member in dataset.members.values():
        if not member.is_alias:
            continue
        path = root / f"{member.name}{member.suffix}"
        remove_for_symlink(path, overwrite)
        os.symlink(f"{member.target}{member.suffix}", path)
        if not path.resolve().is_file():
            raise SafetyError(f"unresolved alias {member.name}")
    metadata = root / "dataset.json"
    write_text(metadata, json.dumps(dataset.to_dict(), indent=2) + "\n", overwrite)
    return root
