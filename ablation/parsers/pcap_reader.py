"""
parsers/pcap_reader.py — libpcap file reader

Parses classic libpcap (.pcap) files (global header + per-packet records).
No external dependencies. Handles both byte orders (native and swapped magic).

Typical use:
    packets = PCAPReader.read('/path/to/capture.pcap')
    for pkt in packets:
        frame = EthernetFrame.from_bytes(pkt.data)
        if frame.ethertype == 0x8765:
            process_hsio(frame.payload)
"""

from __future__ import annotations
import struct
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional


# ── libpcap global header constants ──────────────────────────────────────────
# Magic bytes identify the file endianness.
# 0xa1b2c3d4 = native byte order
# 0xd4c3b2a1 = swapped byte order (file written on opposite-endian machine)

_PCAP_MAGIC_NATIVE  = 0xa1b2c3d4
_PCAP_MAGIC_SWAPPED = 0xd4c3b2a1

# Global header: magic(4) + version_major(2) + version_minor(2) +
#                thiszone(4) + sigfigs(4) + snaplen(4) + network(4) = 24 bytes
_PCAP_GLOBAL_HEADER_SIZE = 24

# Per-packet record header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4) = 16 bytes
_PCAP_RECORD_HEADER_SIZE = 16

# Ethernet header: dst_mac(6) + src_mac(6) + ethertype(2) = 14 bytes
_ETH_HEADER_SIZE = 14


@dataclass
class PCAPGlobalHeader:
    magic:         int    # 0xa1b2c3d4 or 0xd4c3b2a1
    version_major: int
    version_minor: int
    thiszone:      int    # GMT offset in seconds (usually 0)
    sigfigs:       int    # accuracy of timestamps (usually 0)
    snaplen:       int    # max bytes captured per packet
    network:       int    # link-layer type (1 = Ethernet)
    byte_swapped:  bool   # True if file was written in opposite byte order


@dataclass
class PCAPPacket:
    """One captured packet from a libpcap file."""
    index:    int     # 0-based packet index in file
    ts:       float   # timestamp in seconds (ts_sec + ts_usec/1e6)
    ts_sec:   int
    ts_usec:  int
    incl_len: int     # number of bytes stored in file
    orig_len: int     # original length on wire (may be > incl_len if truncated)
    data:     bytes   # raw captured bytes (len == incl_len)


@dataclass
class EthernetFrame:
    """Parsed Ethernet II frame."""
    dst_mac:   str    # "xx:xx:xx:xx:xx:xx"
    src_mac:   str    # "xx:xx:xx:xx:xx:xx"
    ethertype: int    # 16-bit EtherType
    payload:   bytes  # bytes after the 14-byte Ethernet header


class PCAPError(Exception):
    """Raised for malformed or unsupported PCAP files."""


class PCAPReader:
    """Read a classic libpcap (.pcap) file and return all captured packets."""

    @classmethod
    def read(cls, path: str | Path) -> List[PCAPPacket]:
        """Parse a .pcap file and return a list of PCAPPacket objects."""
        data = Path(path).read_bytes()
        header, endian = cls._parse_global_header(data)
        packets = cls._parse_records(data, endian)
        return packets

    @classmethod
    def read_with_header(cls, path: str | Path):
        """Return (PCAPGlobalHeader, List[PCAPPacket])."""
        data = Path(path).read_bytes()
        header, endian = cls._parse_global_header(data)
        packets = cls._parse_records(data, endian)
        return header, packets

    # ── internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_global_header(data: bytes):
        if len(data) < _PCAP_GLOBAL_HEADER_SIZE:
            raise PCAPError(f"File too short for PCAP global header: {len(data)} bytes")

        magic = struct.unpack_from('<I', data, 0)[0]
        if magic == _PCAP_MAGIC_NATIVE:
            endian = '<'
            swapped = False
        elif magic == _PCAP_MAGIC_SWAPPED:
            endian = '>'
            swapped = True
        else:
            raise PCAPError(f"Not a libpcap file (magic={magic:#010x})")

        vmaj, vmin, tz, sigfigs, snaplen, network = struct.unpack_from(
            f'{endian}HHIIII', data, 4
        )
        hdr = PCAPGlobalHeader(
            magic=magic,
            version_major=vmaj,
            version_minor=vmin,
            thiszone=tz,
            sigfigs=sigfigs,
            snaplen=snaplen,
            network=network,
            byte_swapped=swapped,
        )
        return hdr, endian

    @staticmethod
    def _parse_records(data: bytes, endian: str) -> List[PCAPPacket]:
        packets: List[PCAPPacket] = []
        offset = _PCAP_GLOBAL_HEADER_SIZE
        idx = 0
        total = len(data)

        while offset < total:
            if offset + _PCAP_RECORD_HEADER_SIZE > total:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(
                f'{endian}IIII', data, offset
            )
            offset += _PCAP_RECORD_HEADER_SIZE

            if offset + incl_len > total:
                break

            pkt_data = data[offset:offset + incl_len]
            offset += incl_len

            packets.append(PCAPPacket(
                index=idx,
                ts=ts_sec + ts_usec / 1_000_000.0,
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                incl_len=incl_len,
                orig_len=orig_len,
                data=pkt_data,
            ))
            idx += 1

        return packets


class EthernetFrame:
    """Parse an Ethernet II frame from raw bytes."""

    def __init__(self, dst_mac: str, src_mac: str, ethertype: int, payload: bytes):
        self.dst_mac   = dst_mac
        self.src_mac   = src_mac
        self.ethertype = ethertype
        self.payload   = payload

    @classmethod
    def from_bytes(cls, data: bytes) -> 'EthernetFrame':
        if len(data) < _ETH_HEADER_SIZE:
            raise PCAPError(f"Frame too short for Ethernet header: {len(data)} bytes")
        dst = ':'.join(f'{b:02x}' for b in data[0:6])
        src = ':'.join(f'{b:02x}' for b in data[6:12])
        ethertype = struct.unpack_from('>H', data, 12)[0]
        payload = data[_ETH_HEADER_SIZE:]
        return cls(dst_mac=dst, src_mac=src, ethertype=ethertype, payload=payload)

    def __repr__(self) -> str:
        return (
            f"EthernetFrame(src={self.src_mac}, dst={self.dst_mac}, "
            f"ethertype={self.ethertype:#06x}, payload_len={len(self.payload)})"
        )


def summarize(path: str | Path) -> str:
    """Return a one-line human-readable summary of a PCAP file."""
    hdr, pkts = PCAPReader.read_with_header(path)
    if not pkts:
        return f"{Path(path).name}: 0 packets"
    dur = pkts[-1].ts - pkts[0].ts
    start = datetime.utcfromtimestamp(pkts[0].ts_sec).strftime('%Y-%m-%d %H:%M:%S UTC')
    return (
        f"{Path(path).name}: {len(pkts)} packets, "
        f"linktype={hdr.network}, "
        f"start={start}, "
        f"duration={dur*1000:.1f}ms"
    )
