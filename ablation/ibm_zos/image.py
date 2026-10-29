import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .io_utils import ensure_directory, write_bytes, write_text


@dataclass
class Symbol:
    name: str
    address: int
    kind: str
    length: int | None = None
    symbol_id: int | None = None
    attributes: int | None = None
    source: str = "container"


@dataclass
class TextChunk:
    address: int
    file_offset: int
    length: int


@dataclass
class LoadImage:
    source_name: str
    source_sha256: str
    format: str
    text: bytes
    symbols: list[Symbol]
    chunks: list[TextChunk]
    entry_rva: int | None
    records: list[dict]
    metadata: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "source": self.source_name, "sha256": self.source_sha256,
            "format": self.format, "architecture": "S/390 big-endian",
            "text_size": len(self.text), "text_sha256": hashlib.sha256(self.text).hexdigest(),
            "entry_rva": self.entry_rva,
            "chunks": [chunk.__dict__ for chunk in self.chunks],
            "symbol_count": len(self.symbols), "records": self.records,
            "metadata": self.metadata,
        }

    def write(self, output_directory):
        output = ensure_directory(output_directory)
        write_bytes(output / "text.bin", self.text)
        write_text(output / "image.json", json.dumps(self.to_dict(), indent=2) + "\n")
        symbols = [symbol.__dict__ for symbol in self.symbols]
        write_text(output / "symbols.json", json.dumps(symbols, indent=2) + "\n")
        strings = ebcdic_strings(self.text)
        write_text(output / "strings.json", json.dumps(strings, indent=2, ensure_ascii=False) + "\n")
        write_text(output / "strings.txt", "".join(
            f'{item["address"]:08x} {item["value"]}\n' for item in strings
        ))
        return output


def ebcdic_strings(data, minimum=4):
    decoded = data.decode("cp500", errors="replace")
    result = []
    for match in re.finditer(r"[\x20-\x7e]{4,}", decoded):
        value = match.group()
        if len(value) >= minimum and sum(character.isalnum() for character in value) >= 3:
            result.append({"address": match.start(), "value": value})
    return result
