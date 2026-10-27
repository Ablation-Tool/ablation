"""Filesystem, ELF, and function-level cross-version diffs."""
from __future__ import annotations

import hashlib
import json
import re
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile


@dataclass(frozen=True)
class FileRecord:
    path: str
    kind: str
    size: int
    sha256: str
    mode: str
    elf: bool
    link_target: str = ""


@dataclass(frozen=True)
class FileChange:
    path: str
    status: str
    old_size: int
    new_size: int
    delta: int
    elf: bool


@dataclass(frozen=True)
class FunctionRecord:
    name: str
    va: int
    size: int
    signature: str
    instructions: tuple[str, ...]


def build_manifest(root: str | Path) -> dict[str, FileRecord]:
    base = Path(root)
    records: dict[str, FileRecord] = {}
    for path in base.rglob("*"):
        relative = path.relative_to(base).as_posix()
        if path.is_symlink():
            records[relative] = FileRecord(relative, "symlink", 0, "", "", False, str(path.readlink()))
            continue
        if not path.is_file():
            continue
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            magic = stream.read(4)
            digest.update(magic)
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        records[relative] = FileRecord(
            path=relative,
            kind="file",
            size=path.stat().st_size,
            sha256=digest.hexdigest(),
            mode=oct(stat.S_IMODE(path.stat().st_mode)),
            elf=magic == b"\x7fELF",
        )
    return records


def manifest_json(records: dict[str, FileRecord]) -> str:
    return json.dumps({path: asdict(record) for path, record in sorted(records.items())}, indent=2)


def diff_manifests(
    old: dict[str, FileRecord],
    new: dict[str, FileRecord],
) -> dict[str, object]:
    changes: list[FileChange] = []
    for path in sorted(old.keys() | new.keys()):
        before = old.get(path)
        after = new.get(path)
        status = "added" if before is None else "removed" if after is None else "changed" if before != after else "unchanged"
        if status == "unchanged":
            continue
        old_size = before.size if before else 0
        new_size = after.size if after else 0
        changes.append(FileChange(
            path=path,
            status=status,
            old_size=old_size,
            new_size=new_size,
            delta=new_size - old_size,
            elf=bool((before and before.elf) or (after and after.elf)),
        ))
    summary = {
        "added": sum(change.status == "added" for change in changes),
        "removed": sum(change.status == "removed" for change in changes),
        "changed": sum(change.status == "changed" for change in changes),
        "unchanged": len(old.keys() & new.keys()) - sum(change.status == "changed" for change in changes),
        "changed_elf": sum(change.elf for change in changes),
    }
    return {
        "summary": summary,
        "changes": [asdict(change) for change in changes],
        "ranked": [
            asdict(change)
            for change in sorted(changes, key=lambda item: (abs(item.delta), item.path), reverse=True)
            if change.elf
        ],
    }


_RELEASE_PATTERNS = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\s+UTC)?\b"),
    re.compile(r"\b\d+\.\d+[A-Z]+\d*[A-Z0-9]*-D\d+(?:\.\d+)?\b", re.IGNORECASE),
    re.compile(r"\b\d+\.\d+R\d+(?:-S\d+)?(?:\.\d+)?\b", re.IGNORECASE),
    re.compile(r"(?:/volume/build|/opt/build|/build|/home/[^\s]+)/[^\s]*"),
    re.compile(r"\b[0-9a-f]{32,40}\b", re.IGNORECASE),
]


def normalize_string(value: str) -> str:
    for pattern in _RELEASE_PATTERNS:
        value = pattern.sub("<release>", value)
    return value


def normalized_strings(path: str | Path, minimum: int = 5) -> set[str]:
    data = Path(path).read_bytes()
    values = set()
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data):
        values.add(normalize_string(match.group(0).decode("ascii")))
    return values


def elf_summary(path: str | Path) -> dict[str, object]:
    with open(path, "rb") as stream:
        elf = ELFFile(stream)
        imports = set()
        exports = set()
        for section in elf.iter_sections():
            if section.header.sh_type not in ("SHT_DYNSYM", "SHT_SYMTAB"):
                continue
            for symbol in section.iter_symbols():
                if not symbol.name:
                    continue
                if symbol.entry.st_shndx == "SHN_UNDEF":
                    imports.add(symbol.name)
                elif symbol.entry.st_value:
                    exports.add(symbol.name)
        text = elf.get_section_by_name(".text")
        return {
            "architecture": elf.get_machine_arch(),
            "bits": elf.elfclass,
            "little_endian": elf.little_endian,
            "flags": elf.header.e_flags,
            "text_size": text.header.sh_size if text else 0,
            "imports": sorted(imports),
            "exports": sorted(exports),
        }


def compare_elf(old: str | Path, new: str | Path) -> dict[str, object]:
    before = elf_summary(old)
    after = elf_summary(new)
    old_strings = normalized_strings(old)
    new_strings = normalized_strings(new)
    return {
        "old": before,
        "new": after,
        "added_imports": sorted(set(after["imports"]) - set(before["imports"])),
        "removed_imports": sorted(set(before["imports"]) - set(after["imports"])),
        "added_strings": sorted(new_strings - old_strings),
        "removed_strings": sorted(old_strings - new_strings),
    }


def _normalize_operand(value: str) -> str:
    value = re.sub(r"0x[0-9a-fA-F]+", "<addr>", value)
    value = re.sub(r"(?<![A-Za-z_])-?\d+(?![A-Za-z_])", "<imm>", value)
    return re.sub(r"\s+", " ", value).strip()


def normalize_instruction(mnemonic: str, operands: str = "") -> str:
    return f"{mnemonic.lower()} {_normalize_operand(operands)}".strip()


def _capstone_for(arch: str, little_endian: bool):
    endian = capstone.CS_MODE_LITTLE_ENDIAN if little_endian else capstone.CS_MODE_BIG_ENDIAN
    if arch == "mips32":
        return capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | endian)
    if arch == "mips64":
        return capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 | endian)
    if arch == "x86_32":
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    if arch == "x86_64":
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    if arch == "arm32":
        return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | endian)
    if arch == "arm64":
        return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM | endian)
    if arch in ("ppc32", "ppc64"):
        mode = capstone.CS_MODE_32 if arch == "ppc32" else capstone.CS_MODE_64
        return capstone.Cs(capstone.CS_ARCH_PPC, mode | endian)
    raise ValueError(f"Function diff does not support {arch}")


def function_records(path: str | Path, max_function_size: int = 4096) -> dict[str, FunctionRecord]:
    from ablation.analyzers.binary_context import BinaryContext

    context = BinaryContext.build(str(path))
    data = Path(path).read_bytes()
    with open(path, "rb") as stream:
        elf = ELFFile(stream)
        decoder = _capstone_for(context.arch, elf.little_endian)
        text = elf.get_section_by_name(".text")
        if text is None:
            return {}
        text_va = text.header.sh_addr
        text_offset = text.header.sh_offset
        text_size = text.header.sh_size
    starts = sorted({va for va in context.func_starts if text_va <= va < text_va + text_size})
    names = {va: name for name, va in context.exports.items()}
    records = {}
    for index, va in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else text_va + text_size
        size = min(max(end - va, 0), max_function_size)
        if size == 0:
            continue
        offset = text_offset + va - text_va
        instructions = tuple(
            normalize_instruction(insn.mnemonic, insn.op_str)
            for insn in decoder.disasm(data[offset:offset + size], va)
        )
        signature = hashlib.sha256("\n".join(instructions).encode()).hexdigest()
        name = names.get(va, f"sub_{va:x}")
        records[name] = FunctionRecord(name, va, size, signature, instructions)
    return records


def match_functions(
    old: dict[str, FunctionRecord],
    new: dict[str, FunctionRecord],
) -> dict[str, object]:
    matched_names = old.keys() & new.keys()
    old_remaining = {name: record for name, record in old.items() if name not in matched_names}
    new_remaining = {name: record for name, record in new.items() if name not in matched_names}
    changed = []
    unchanged = []
    for name in sorted(matched_names):
        entry = {"name": name, "old_va": hex(old[name].va), "new_va": hex(new[name].va)}
        if old[name].signature == new[name].signature:
            unchanged.append(entry)
        else:
            changed.append(entry)
    new_by_signature = {record.signature: record for record in new_remaining.values()}
    for name, before in list(old_remaining.items()):
        after = new_by_signature.get(before.signature)
        if after is not None:
            unchanged.append({"name": name, "matched_name": after.name, "old_va": hex(before.va), "new_va": hex(after.va)})
            new_remaining.pop(after.name, None)
            old_remaining.pop(name, None)
    return {
        "summary": {
            "changed": len(changed),
            "unchanged": len(unchanged),
            "added": len(new_remaining),
            "removed": len(old_remaining),
        },
        "changed": changed,
        "unchanged": unchanged,
        "added": [record.name for record in new_remaining.values()],
        "removed": [record.name for record in old_remaining.values()],
    }


def diff_elf_functions(old: str | Path, new: str | Path) -> dict[str, object]:
    return match_functions(function_records(old), function_records(new))
