import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .errors import FormatError
from .functions import Recovery
from .io_utils import ensure_directory, write_text


@dataclass
class ImportStatement:
    kind: str
    dll: str
    symbol: str
    start_record: int
    end_record: int
    demangled: str | None = None
    demangle_status: str = "unparsed"

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class SideDeck:
    source_name: str
    source_sha256: str
    statements: list[ImportStatement]

    def to_dict(self, include_statements=True):
        result = {
            "source": self.source_name, "sha256": self.source_sha256,
            "format": "FB80 EBCDIC binder definition side-deck",
            "import_count": len(self.statements),
            "kind_counts": dict(Counter(item.kind for item in self.statements)),
            "dll_counts": dict(Counter(item.dll for item in self.statements)),
            "demangle_counts": dict(Counter(item.demangle_status for item in self.statements)),
            "unique_symbol_count": len({item.symbol for item in self.statements}),
        }
        if include_statements:
            result["imports"] = [item.to_dict() for item in self.statements]
        return result

    def write(self, output_prefix):
        output = Path(output_prefix)
        ensure_directory(output.parent)
        write_text(output.with_suffix(".json"), json.dumps(self.to_dict(), indent=2) + "\n")
        write_text(output.with_suffix(".txt"), "".join(
            f"{item.kind:4s} {item.dll:8s} {item.symbol} ; {item.demangled or item.demangle_status}\n"
            for item in self.statements
        ))
        return output


def _parse_import_start(line, record_number):
    match = re.match(r"^\s*IMPORT\s+(CODE|DATA)\s+'([^']+)'\s+(\S.*)$", line)
    style = "space"
    if match is None:
        match = re.match(r"^\s*IMPORT\s+(CODE|DATA),\s*'([^']+)',\s*'(.*)$", line)
        style = "comma"
    if match is None:
        return None
    return match.group(1), match.group(2), match.group(3), style


def parse_side_deck(data, source_name="<memory>", demangle=True):
    if not data or len(data) % 80:
        raise FormatError("side-deck is not a nonempty FB80 sequence")
    statements = []
    current = None
    for record_number, offset in enumerate(range(0, len(data), 80), 1):
        line = data[offset:offset + 80].decode("cp1140").rstrip()
        start = _parse_import_start(line, record_number)
        if start is not None:
            if current is not None:
                raise FormatError(f"unterminated import at record {current['start_record']}")
            kind, dll, fragment, style = start
            current = {"kind": kind, "dll": dll, "fragment": fragment, "style": style, "start_record": record_number}
        elif line.strip():
            if current is None:
                raise FormatError(f"unexpected nonblank record {record_number}")
            current["fragment"] += line.strip()
        else:
            if current is not None:
                raise FormatError(f"blank record inside import at {record_number}")
        if current is None:
            continue
        fragment = current["fragment"]
        complete = fragment.endswith("'") if current["style"] == "comma" else not fragment.endswith("*")
        if not complete:
            if not fragment.endswith("*"):
                raise FormatError(f"continuation marker missing at record {record_number}")
            current["fragment"] = fragment[:-1]
            continue
        if current["style"] == "comma":
            if not fragment.endswith("'"):
                raise FormatError(f"unterminated quoted import at {record_number}")
            symbol = fragment[:-1]
        else:
            symbol = fragment
        if not symbol:
            raise FormatError(f"empty symbol at record {record_number}")
        statements.append(ImportStatement(current["kind"], current["dll"], symbol, current["start_record"], record_number))
        current = None
    if current is not None:
        raise FormatError(f"unterminated import at record {current['start_record']}")
    if not statements:
        raise FormatError("side-deck has no imports")
    if demangle:
        for statement in statements:
            statement.demangled, statement.demangle_status = demangle_ibm_cpp(statement.symbol)
    return SideDeck(source_name, hashlib.sha256(data).hexdigest(), statements)


def read_side_deck(path):
    path = Path(path)
    return parse_side_deck(path.read_bytes(), str(path))


OPERATORS = {
    "__aad": "operator+=", "__ad": "operator+", "__asu": "operator-=", "__su": "operator-",
    "__amu": "operator*=", "__mu": "operator*", "__adv": "operator/=", "__dv": "operator/",
    "__as": "operator=", "__als": "operator<<", "__ars": "operator>>",
}
BASIC_TYPES = {
    "v": "void", "b": "bool", "c": "char", "s": "short", "i": "int", "l": "long",
    "f": "float", "d": "double", "w": "wchar_t", "x": "long long",
}


def _identifier(text, offset):
    match = re.match(r"(\d+)", text[offset:])
    if match is None:
        raise ValueError("length-prefixed identifier expected")
    length = int(match.group(1))
    start = offset + len(match.group(1))
    end = start + length
    if length == 0 or end > len(text):
        raise ValueError("identifier exceeds input")
    name = text[start:end]
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ValueError("unsupported identifier")
    return name, end


def _qualified_name(text, offset=0):
    names = []
    if text.startswith("Q", offset):
        match = re.match(r"Q(\d+)_", text[offset:])
        if match is None:
            raise ValueError("nested-name count expected")
        offset += len(match.group(0))
        count = int(match.group(1))
        for _ in range(count):
            name, offset = _identifier(text, offset)
            names.append(name)
    else:
        name, offset = _identifier(text, offset)
        names.append(name)
    return "::".join(names), offset


def _type(text, offset):
    const = False
    unsigned = False
    pointer = False
    reference = False
    while offset < len(text):
        qualifier = text[offset]
        if qualifier == "C":
            const = True
        elif qualifier == "U":
            unsigned = True
        elif qualifier == "P":
            pointer = True
        elif qualifier == "R":
            reference = True
        else:
            break
        offset += 1
    if offset < len(text) and text[offset] in BASIC_TYPES:
        name = BASIC_TYPES[text[offset]]
        offset += 1
    elif offset < len(text) and (text[offset].isdigit() or text.startswith("Q", offset)):
        name, offset = _qualified_name(text, offset)
    else:
        raise ValueError("unsupported type")
    prefix = "unsigned " if unsigned else ""
    const_prefix = "const " if const else ""
    suffix = ("*" if pointer else "") + ("&" if reference else "")
    return f"{prefix}{const_prefix}{name}{suffix}", offset


def _arguments(text, offset):
    arguments = []
    if offset < len(text) and text[offset] == "v" and offset + 1 == len(text):
        return arguments, offset + 1
    while offset < len(text):
        argument, offset = _type(text, offset)
        arguments.append(argument)
    return arguments, offset


def _method_or_global(operator, text):
    class_name = None
    const_method = False
    offset = 0
    if text and text[0] != "F":
        class_name, offset = _qualified_name(text, offset)
        if offset < len(text) and text[offset] == "C" and offset + 1 < len(text) and text[offset + 1] == "F":
            const_method = True
            offset += 1
    if offset >= len(text) or text[offset] != "F":
        raise ValueError("function marker expected")
    arguments, offset = _arguments(text, offset + 1)
    if offset != len(text):
        raise ValueError("trailing function encoding")
    prefix = f"{class_name}::" if class_name else ""
    suffix = " const" if const_method else ""
    return f"{prefix}{operator}({', '.join(arguments)}){suffix}"


def demangle_ibm_cpp(symbol):
    try:
        if symbol.startswith("__vft"):
            return None, "virtual_table"
        for prefix, operator in OPERATORS.items():
            marker = prefix + "__"
            if symbol.startswith(marker):
                return _method_or_global(operator, symbol[len(marker):]), "demangled"
        if symbol.startswith("__ct__"):
            class_name, offset = _qualified_name(symbol, 6)
            if offset >= len(symbol) or symbol[offset] != "F":
                raise ValueError("constructor marker expected")
            arguments, offset = _arguments(symbol, offset + 1)
            if offset != len(symbol):
                raise ValueError("trailing constructor encoding")
            return f"{class_name}::{class_name.split('::')[-1]}({', '.join(arguments)})", "demangled"
        if symbol.startswith("__dt__"):
            class_name, offset = _qualified_name(symbol, 6)
            arguments, offset = _arguments(symbol, offset + 1)
            if offset != len(symbol) or arguments:
                raise ValueError("unsupported destructor")
            return f"{class_name}::~{class_name.split('::')[-1]}()", "demangled"
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)__(.+)$", symbol)
        if match:
            name, remainder = match.groups()
            class_name, offset = _qualified_name(remainder, 0)
            if offset < len(remainder) and remainder[offset] == "F":
                arguments, offset = _arguments(remainder, offset + 1)
                if offset == len(remainder):
                    return f"{class_name}::{name}({', '.join(arguments)})", "demangled"
        return None, "unparsed"
    except (ValueError, IndexError):
        return None, "unparsed"


def normalize_name(name):
    return re.sub(r"\s+", "", name) if name else ""


def correlate_functions(recovery, decks):
    symbols = {}
    for deck in decks:
        for statement in deck.statements:
            for name in {statement.symbol, statement.demangled}:
                normalized = normalize_name(name)
                if normalized:
                    symbols.setdefault(normalized, []).append((deck, statement))
    matches = []
    for function in recovery.functions:
        normalized = normalize_name(function.name)
        if not normalized or normalized not in symbols:
            continue
        for deck, statement in symbols[normalized]:
            matches.append({
                "entry_rva": function.entry_rva, "code_rva": function.code_rva,
                "function_name": function.name, "dll": statement.dll,
                "side_deck": deck.source_name, "symbol": statement.symbol,
                "demangled": statement.demangled, "kind": statement.kind,
                "match": "normalized_name",
            })
    return {"match_count": len(matches), "matches": matches}


def compare_inventories(left, right):
    left_symbols = {item.symbol for item in left.statements}
    right_symbols = {item.symbol for item in right.statements}
    union = left_symbols | right_symbols
    return {
        "left": left.source_name, "right": right.source_name,
        "left_count": len(left_symbols), "right_count": len(right_symbols),
        "intersection_count": len(left_symbols & right_symbols),
        "left_only_count": len(left_symbols - right_symbols),
        "right_only_count": len(right_symbols - left_symbols),
        "jaccard": len(left_symbols & right_symbols) / len(union) if union else 1.0,
    }
