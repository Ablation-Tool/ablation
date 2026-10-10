"""CAN DBC database parser.

Parses the Vector/PEAK DBC format used by virtually all automotive CAN analysis
tools (CANdb++, SavvyCAN, Wireshark, BUSMASTER, cantools). Extracts message
definitions, signal layouts, value tables, and comments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── compiled patterns ─────────────────────────────────────────────────────────

# BO_ 790 DME_316: 8 DME
_RE_BO = re.compile(
    r'^BO_\s+(\d+)\s+(\w+)\s*:\s*(\d+)\s+(\S+)'
)

#  SG_ EngineSpeed : 24|16@1+ (0.125,0) [0|8031.875] "rpm" Vector__XXX
_RE_SG = re.compile(
    r'^\s*SG_\s+(\w+)\s*(?:[Mm]\d*)?\s*:\s*'
    r'(\d+)\|(\d+)@([01])([+\-])\s+'
    r'\(([^,]+),([^)]+)\)\s+'
    r'\[([^|]*)\|([^\]]*)\]\s+'
    r'"([^"]*)"\s*(.*)'
)

# CM_ SG_ 168 EngineTorque "comment text";
# CM_ BO_ 790 "comment text";
# No ^ anchor — used with finditer() which scans the whole string.
# re.DOTALL lets "." match newlines so multi-line comment strings are captured.
_RE_CM_SG = re.compile(
    r'CM_\s+SG_\s+(\d+)\s+(\w+)\s+"(.*?)"\s*;', re.DOTALL
)
_RE_CM_BO = re.compile(
    r'CM_\s+BO_\s+(\d+)\s+"(.*?)"\s*;', re.DOTALL
)

# VAL_ 790 Status_DSC 1 "OK" 0 "DSC_ERROR";
_RE_VAL = re.compile(
    r'VAL_\s+(\d+)\s+(\w+)\s+(.*?)\s*;', re.DOTALL
)
_RE_VAL_PAIR = re.compile(r'(\d+)\s+"([^"]*)"')

# F = floating-point number token (factor, offset, min, max)
_RE_FLOAT = re.compile(r'[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?')


# ── data types ────────────────────────────────────────────────────────────────

@dataclass
class CANSignal:
    """One signal within a CAN message."""
    name: str
    start_bit: int
    length: int              # bits
    little_endian: bool      # True = Intel/little-endian byte order
    is_signed: bool
    factor: float
    offset: float
    min_val: float
    max_val: float
    unit: str
    receivers: list[str]
    comment: str = ""
    value_table: dict[int, str] = field(default_factory=dict)

    def decode(self, raw_int: int) -> float:
        """Return the physical value for a raw integer: raw * factor + offset."""
        return raw_int * self.factor + self.offset


@dataclass
class CANMessage:
    """One CAN message with all its signals."""
    msg_id: int              # canonical CAN ID (11-bit or 29-bit, bit 31 stripped)
    name: str
    dlc: int                 # data length code in bytes
    sender: str
    is_extended: bool        # True = 29-bit extended frame
    signals: list[CANSignal]
    comment: str = ""

    @property
    def raw_id(self) -> int:
        """DBC raw ID (bit 31 set for extended frames)."""
        return self.msg_id | 0x80000000 if self.is_extended else self.msg_id

    def signal(self, name: str) -> Optional[CANSignal]:
        """Return the named signal, or None."""
        for s in self.signals:
            if s.name == name:
                return s
        return None


# ── parser ────────────────────────────────────────────────────────────────────

class CanDbcParser:
    """
    Parse a CAN DBC database file.

    Extracts message definitions, signal layouts, value tables, and comments.
    Handles both standard 11-bit frames and extended 29-bit frames (J1939).
    """

    def __init__(self) -> None:
        self._messages: dict[int, CANMessage] = {}  # canonical_id -> message

    # ── constructors ─────────────────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: str | Path) -> "CanDbcParser":
        """
        Parse a DBC file.

        Raises FileNotFoundError when the path does not exist.
        Malformed signal lines are silently skipped.
        """
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        parser = cls()
        parser._parse(text)
        return parser

    @classmethod
    def from_string(cls, text: str) -> "CanDbcParser":
        """Parse DBC text directly."""
        parser = cls()
        parser._parse(text)
        return parser

    # ── public API ───────────────────────────────────────────────────────────

    def messages(self) -> list[CANMessage]:
        """Return all messages, sorted by CAN ID."""
        return sorted(self._messages.values(), key=lambda m: m.msg_id)

    def message(self, can_id: int) -> Optional[CANMessage]:
        """Return the message for a CAN ID, or None."""
        return self._messages.get(can_id)

    def find_signals(self, pattern: str) -> list[tuple[CANMessage, CANSignal]]:
        """
        Return all (message, signal) pairs where the signal name matches pattern.

        Pattern is a case-insensitive substring match.
        """
        pat = pattern.lower()
        result: list[tuple[CANMessage, CANSignal]] = []
        for msg in self._messages.values():
            for sig in msg.signals:
                if pat in sig.name.lower():
                    result.append((msg, sig))
        return sorted(result, key=lambda t: (t[0].msg_id, t[1].name))

    def extended_messages(self) -> list[CANMessage]:
        """Return only 29-bit extended frame messages."""
        return [m for m in self.messages() if m.is_extended]

    def standard_messages(self) -> list[CANMessage]:
        """Return only 11-bit standard frame messages."""
        return [m for m in self.messages() if not m.is_extended]

    def signal_count(self) -> int:
        """Return total number of signals across all messages."""
        return sum(len(m.signals) for m in self._messages.values())

    def summary(self) -> str:
        """Return a short text summary of the loaded database."""
        n_msg = len(self._messages)
        n_sig = self.signal_count()
        n_ext = sum(1 for m in self._messages.values() if m.is_extended)
        n_std = n_msg - n_ext
        n_val = sum(
            1 for m in self._messages.values()
            for s in m.signals if s.value_table
        )
        return (
            f"CAN DBC database\n"
            f"  messages : {n_msg} total ({n_std} standard  {n_ext} extended)\n"
            f"  signals  : {n_sig}\n"
            f"  val_tables: {n_val}"
        )

    # ── private: parsing ─────────────────────────────────────────────────────

    def _parse(self, text: str) -> None:
        lines = text.splitlines()
        current_msg: Optional[CANMessage] = None

        for line in lines:
            # Message definition
            m = _RE_BO.match(line)
            if m:
                raw_id = int(m.group(1))
                is_ext = bool(raw_id & 0x80000000)
                can_id = raw_id & 0x1FFFFFFF if is_ext else raw_id
                current_msg = CANMessage(
                    msg_id=can_id,
                    name=m.group(2),
                    dlc=int(m.group(3)),
                    sender=m.group(4),
                    is_extended=is_ext,
                    signals=[],
                )
                self._messages[can_id] = current_msg
                continue

            # Signal definition (must follow a BO_ line)
            s = _RE_SG.match(line)
            if s and current_msg is not None:
                sig = self._parse_signal(s)
                if sig is not None:
                    current_msg.signals.append(sig)
                continue

            # Blank line clears current message context
            if not line.strip():
                current_msg = None

        # Second pass: comments and value tables
        self._parse_comments(text)
        self._parse_value_tables(text)

    @staticmethod
    def _parse_signal(m: re.Match) -> Optional[CANSignal]:
        try:
            name = m.group(1)
            start_bit = int(m.group(2))
            length = int(m.group(3))
            little_endian = m.group(4) == "1"
            is_signed = m.group(5) == "-"
            factor_s = m.group(6).strip()
            offset_s = m.group(7).strip()
            min_s = m.group(8).strip()
            max_s = m.group(9).strip()
            unit = m.group(10)
            recv_str = m.group(11).strip()
            receivers = [r for r in recv_str.split(",") if r.strip()]
            factor = float(factor_s) if factor_s else 1.0
            offset = float(offset_s) if offset_s else 0.0
            min_val = float(min_s) if min_s else 0.0
            max_val = float(max_s) if max_s else 0.0
        except (ValueError, IndexError):
            return None
        return CANSignal(
            name=name,
            start_bit=start_bit,
            length=length,
            little_endian=little_endian,
            is_signed=is_signed,
            factor=factor,
            offset=offset,
            min_val=min_val,
            max_val=max_val,
            unit=unit,
            receivers=receivers,
        )

    def _parse_comments(self, text: str) -> None:
        # Signal comments
        for m in _RE_CM_SG.finditer(text):
            raw_id = int(m.group(1))
            sig_name = m.group(2)
            comment = m.group(3).strip()
            is_ext = bool(raw_id & 0x80000000)
            can_id = raw_id & 0x1FFFFFFF if is_ext else raw_id
            msg = self._messages.get(can_id)
            if msg is None:
                continue
            sig = msg.signal(sig_name)
            if sig is not None:
                sig.comment = comment
        # Message comments
        for m in _RE_CM_BO.finditer(text):
            raw_id = int(m.group(1))
            comment = m.group(2).strip()
            is_ext = bool(raw_id & 0x80000000)
            can_id = raw_id & 0x1FFFFFFF if is_ext else raw_id
            msg = self._messages.get(can_id)
            if msg is not None:
                msg.comment = comment

    def _parse_value_tables(self, text: str) -> None:
        for m in _RE_VAL.finditer(text):
            raw_id = int(m.group(1))
            sig_name = m.group(2)
            val_str = m.group(3)
            is_ext = bool(raw_id & 0x80000000)
            can_id = raw_id & 0x1FFFFFFF if is_ext else raw_id
            msg = self._messages.get(can_id)
            if msg is None:
                continue
            sig = msg.signal(sig_name)
            if sig is None:
                continue
            for pair in _VAL_RE_PAIR.finditer(val_str):
                try:
                    sig.value_table[int(pair.group(1))] = pair.group(2)
                except ValueError:
                    pass


# Module-level alias for _RE_VAL_PAIR used inside _parse_value_tables
_VAL_RE_PAIR = _RE_VAL_PAIR
