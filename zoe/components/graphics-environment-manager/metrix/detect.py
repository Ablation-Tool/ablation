from dataclasses import dataclass
from pathlib import Path
import struct


ELF_MACHINES = {
    0x02: "sparc", 0x03: "x86", 0x08: "mips", 0x14: "ppc32",
    0x15: "ppc64", 0x16: "s390", 0x28: "arm32", 0x2A: "superh",
    0x32: "ia64", 0x3E: "x86_64", 0xB7: "aarch64", 0xF3: "riscv",
    0xFC: "loongarch64",
}
PE_MACHINES = {
    0x014C: "x86", 0x01C0: "arm32", 0x01C4: "arm32",
    0x0200: "ia64", 0x8664: "x86_64", 0xAA64: "aarch64",
}
SOURCE_SUFFIXES = {
    ".c": "c-source", ".h": "c-header", ".cc": "cpp-source", ".cpp": "cpp-source",
    ".cxx": "cpp-source", ".hpp": "cpp-header", ".py": "python-source",
    ".sh": "shell-source", ".pl": "perl-source", ".rb": "ruby-source",
    ".js": "javascript-source", ".ts": "typescript-source", ".java": "java-source",
    ".s": "assembly-source", ".asm": "assembly-source", ".f": "fortran-source",
    ".f90": "fortran-source", ".json": "json", ".jsonl": "json-lines",
    ".yaml": "yaml", ".yml": "yaml", ".xml": "xml", ".md": "markdown",
    ".html": "html", ".htm": "html", ".txt": "plain-text", ".csv": "csv",
    ".tsv": "tsv",
}


@dataclass(frozen=True)
class Detection:
    format: str
    architecture: str
    endianness: str
    artifact_class: str
    method: str
    evidence: str


def result(format_name, architecture="unknown", endianness="unknown", artifact_class="data", method="magic", evidence=""):
    return Detection(format_name, architecture, endianness, artifact_class, method, evidence)


def _u16(data, offset, byteorder):
    return int.from_bytes(data[offset:offset + 2], byteorder)


def _u32(data, offset, byteorder):
    return int.from_bytes(data[offset:offset + 4], byteorder)


def _elf(sample):
    ident = sample[:16]
    if ident[4] not in (1, 2) or ident[5] not in (1, 2):
        return result("elf", evidence="invalid ELF class or data encoding")
    byteorder = "little" if ident[5] == 1 else "big"
    endianness = byteorder
    machine = _u16(sample, 18, byteorder)
    elf_type = _u16(sample, 16, byteorder)
    architecture = ELF_MACHINES.get(machine, f"machine-0x{machine:04x}")
    if machine == 0x08:
        architecture = "mips32" if ident[4] == 1 else "mips64"
    elif machine == 0x02:
        architecture = "sparc32" if ident[4] == 1 else "sparc64"
    elif machine == 0x16:
        architecture = "s390" if ident[4] == 1 else "s390x"
    elif machine == 0xF3:
        architecture = "riscv32" if ident[4] == 1 else "riscv64"
    artifact_class = "executable" if elf_type == 2 else "library" if elf_type in (1, 3) else "data"
    return result(
        "elf", architecture, endianness, artifact_class,
        evidence=f"ELF{32 if ident[4] == 1 else 64}; type={elf_type}; machine=0x{machine:04x}",
    )


def _pe(sample):
    if len(sample) < 0x40:
        return result("mz-executable", artifact_class="executable", evidence="truncated MZ header")
    pe_offset = _u32(sample, 0x3C, "little")
    if pe_offset + 24 > len(sample) or sample[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        return result("mz-executable", artifact_class="executable", evidence=f"MZ header; PE signature not present in bounded sample at 0x{pe_offset:x}")
    machine = _u16(sample, pe_offset + 4, "little")
    characteristics = _u16(sample, pe_offset + 22, "little")
    architecture = PE_MACHINES.get(machine, f"machine-0x{machine:04x}")
    artifact_class = "library" if characteristics & 0x2000 else "executable"
    return result("pe", architecture, "little", artifact_class, evidence=f"PE signature at 0x{pe_offset:x}; machine=0x{machine:04x}")


def _mach_o(sample):
    magic = sample[:4]
    layouts = {
        b"\xfe\xed\xfa\xce": ("little", 32), b"\xce\xfa\xed\xfe": ("big", 32),
        b"\xfe\xed\xfa\xcf": ("little", 64), b"\xcf\xfa\xed\xfe": ("big", 64),
    }
    if magic in layouts:
        byteorder, bits = layouts[magic]
        cpu = _u32(sample, 4, byteorder)
        base = cpu & 0x00FFFFFF
        abi64 = bool(cpu & 0x01000000)
        names = {7: "x86_64" if abi64 else "x86", 12: "aarch64" if abi64 else "arm32", 18: "ppc64" if abi64 else "ppc32"}
        architecture = names.get(base, f"cpu-0x{cpu:08x}")
        file_type = _u32(sample, 12, byteorder)
        artifact_class = "library" if file_type in (1, 6, 7, 8, 9) else "executable"
        return result("mach-o", architecture, byteorder, artifact_class, evidence=f"Mach-O {bits}-bit; cpu=0x{cpu:08x}; file_type={file_type}")
    if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        byteorder = "big" if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") else "little"
        count = _u32(sample, 4, byteorder)
        if 0 < count <= 32:
            return result("mach-o-universal", "multi-architecture", byteorder, "executable", evidence=f"universal binary; architecture_count={count}")


def _savf(sample, size):
    if size < 528 or size % 528:
        return None
    count32 = _u32(sample, 8, "big") if len(sample) >= 12 else 0
    count64 = int.from_bytes(sample[0x38:0x40], "big") if len(sample) >= 0x40 else 0
    count = size // 528
    if (count32 and count32 != count) or (count64 and count64 != count) or (not count32 and not count64):
        return None
    logical = _u32(sample, 0x34, "big") or 512
    physical = (logical // 512) * 528 + logical % 512
    if logical < 512 or logical % 512 or physical + 4 > len(sample):
        return None
    if sample[physical:physical + 4] != b"\xff\xff\xff\xff":
        return None
    return result("ibm-savf", endianness="big", artifact_class="archive", method="magic+structure", evidence=f"528-byte records; count={count}; first_item_logical=0x{logical:x}")


def _text(sample, name):
    if sample.startswith(b"\xef\xbb\xbf"):
        raw = sample[3:]
        encoding = "utf-8-sig"
    elif sample.startswith(b"\xff\xfe") or sample.startswith(b"\xfe\xff"):
        raw = sample[2:]
        encoding = "utf-16-le" if sample.startswith(b"\xff\xfe") else "utf-16-be"
    else:
        raw = sample
        encoding = "utf-8"
    if not raw or (encoding == "utf-8" and b"\x00" in raw):
        return None
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError:
        return None
    printable = sum(character.isprintable() or character in "\r\n\t" for character in text)
    if printable / len(text) < 0.90:
        return None
    suffix = Path(name).suffix.lower()
    format_name = SOURCE_SUFFIXES.get(suffix, "plain-text")
    artifact_class = "source" if format_name not in {"plain-text", "markdown", "csv", "tsv"} else "document"
    return result(format_name, endianness="not-applicable", artifact_class=artifact_class, method="text+extension" if suffix else "text", evidence=f"{encoding}; printable_ratio={printable / len(text):.3f}; suffix={suffix or 'none'}")


def detect(sample, size, name):
    sample = bytes(sample)
    if not sample and size == 0:
        return result("empty", endianness="not-applicable", artifact_class="data", method="size", evidence="zero-byte file")
    if sample.startswith(b"\x7fELF") and len(sample) >= 20:
        return _elf(sample)
    if sample.startswith(b"MZ"):
        return _pe(sample)
    mach_o = _mach_o(sample)
    if mach_o:
        return mach_o
    if sample.startswith(b"\xca\xfe\xba\xbe") and len(sample) >= 8:
        major = _u16(sample, 6, "big")
        if 45 <= major <= 100:
            return result("java-class", "jvm", "big", "library", evidence=f"class major_version={major}")
    if sample.startswith(b"\x00asm"):
        return result("webassembly", "wasm", "little", "executable", evidence="WebAssembly binary magic")
    if sample.startswith(b"\x01\xdf"):
        return result("xcoff32", "ppc32", "big", "executable", evidence="XCOFF32 magic 0x01df")
    if sample.startswith(b"\x01\xf7"):
        return result("xcoff64", "ppc64", "big", "executable", evidence="XCOFF64 magic 0x01f7")
    qzrdpack = "QZRDPACK".encode("cp500")
    if sample.startswith(qzrdpack):
        return result("ibm-qzrdpack", endianness="big", artifact_class="archive", evidence="EBCDIC QZRDPACK header")
    if sample.startswith("IEWPLMH ".encode("cp500")):
        return result("ibm-iewplmh", "s390", "big", "executable", evidence="EBCDIC IEWPLMH program-object header")
    if len(sample) >= 8 and sample[1] == 0xE0 and sample[2:8] == "INMR01".encode("cp1140"):
        return result("ibm-netdata", endianness="big", artifact_class="archive", evidence="EBCDIC INMR01 segmented control record")
    savf = _savf(sample, size)
    if savf:
        return savf
    if sample.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        is_jar = Path(name).suffix.lower() == ".jar"
        return result("java-archive" if is_jar else "zip", endianness="not-applicable", artifact_class="archive", method="magic+extension" if is_jar else "magic", evidence="ZIP local/header record" + ("; .jar suffix" if is_jar else ""))
    if sample.startswith(b"\x1f\x8b"):
        return result("gzip", endianness="not-applicable", artifact_class="archive", evidence="gzip magic")
    if sample.startswith(b"BZh"):
        return result("bzip2", endianness="not-applicable", artifact_class="archive", evidence="bzip2 magic")
    if sample.startswith(b"\xfd7zXZ\x00"):
        return result("xz", endianness="not-applicable", artifact_class="archive", evidence="XZ stream magic")
    if sample.startswith(b"7z\xbc\xaf\x27\x1c"):
        return result("7zip", endianness="not-applicable", artifact_class="archive", evidence="7-Zip signature")
    if sample.startswith((b"\x1f\x8d", b"\x1f\x9d")):
        return result("compress", endianness="not-applicable", artifact_class="archive", evidence="Unix compress magic")
    if sample.startswith(b"\x28\xb5\x2f\xfd"):
        return result("zstd", endianness="not-applicable", artifact_class="archive", evidence="Zstandard frame magic")
    if sample.startswith(b"\xed\xab\xee\xdb"):
        return result("rpm", endianness="big", artifact_class="archive", evidence="RPM lead magic")
    if sample.startswith(b"!<arch>\n"):
        is_deb = Path(name).suffix.lower() == ".deb"
        return result("debian-package" if is_deb else "ar-archive", endianness="not-applicable", artifact_class="archive", method="magic+extension" if is_deb else "magic", evidence="Unix ar magic" + ("; .deb suffix" if is_deb else ""))
    if len(sample) >= 262 and sample[257:262] == b"ustar":
        return result("tar", endianness="not-applicable", artifact_class="archive", evidence="ustar header")
    if any(sample[offset:offset + 5] == b"CD001" for offset in (0x8001, 0x8801, 0x9001) if offset + 5 <= len(sample)):
        return result("iso9660", endianness="not-applicable", artifact_class="image", evidence="ISO 9660 CD001 descriptor")
    if sample.startswith(b"%PDF-"):
        return result("pdf", endianness="not-applicable", artifact_class="document", evidence="PDF header")
    if sample.startswith(b"\x89PNG\r\n\x1a\n"):
        return result("png", endianness="big", artifact_class="image", evidence="PNG signature")
    if sample.startswith(b"\xff\xd8\xff"):
        return result("jpeg", endianness="not-applicable", artifact_class="image", evidence="JPEG signature")
    if sample.startswith((b"GIF87a", b"GIF89a")):
        return result("gif", endianness="little", artifact_class="image", evidence="GIF header")
    if sample.startswith(b"SQLite format 3\x00"):
        return result("sqlite", endianness="big", artifact_class="data", evidence="SQLite database header")
    text = _text(sample, name)
    if text:
        return text
    suffix = Path(name).suffix.lower()
    return result("unknown", artifact_class="data", method="insufficient-evidence", evidence=f"header_hex={sample[:16].hex()}; suffix={suffix or 'none'}")
