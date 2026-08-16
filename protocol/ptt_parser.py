#!/usr/bin/env python3
"""
ptt_parser.py — HiJoy PTT Wire Protocol Parser

Parses captured PTT signaling packets from pcap/raw captures.
Validates against inferred structure from static analysis.

Protocol structure (inferred):
  struct PTTSignalingMessage {
      uint8_t  command_class;      // 3 = normal, others unknown
      uint8_t  message_length;     // 18 = normal, varies?
      uint8_t  version_or_type;    // 2 = normal
      uint8_t  error_code;         // 6 = status, 0 = success?
      uint8_t  payload[14];        // Remaining data
  };

Usage:
  # Parse from pcap
  python3 ptt_parser.py --pcap capture.pcap --port 5000

  # Parse from raw binary
  python3 ptt_parser.py --binary message.bin

  # Live capture
  python3 ptt_parser.py --live eth0 --port 5000

Author: NuClide Research
Date: 2026-08-16
"""

import argparse
import struct
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional
import socket


@dataclass
class PTTMessage:
    """Parsed PTT signaling message"""
    command_class: int
    message_length: int
    version_or_type: int
    error_code: int
    payload: bytes

    # Metadata
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    timestamp: Optional[float] = None

    def __str__(self):
        lines = []
        lines.append("PTT Signaling Message:")
        lines.append(f"  Command Class:   0x{self.command_class:02x} ({self.command_class})")
        lines.append(f"  Message Length:  0x{self.message_length:02x} ({self.message_length})")
        lines.append(f"  Version/Type:    0x{self.version_or_type:02x} ({self.version_or_type})")
        lines.append(f"  Error Code:      0x{self.error_code:02x} ({self.error_code})")
        lines.append(f"  Payload ({len(self.payload)} bytes):")
        lines.append(self._hexdump(self.payload))

        if self.source_ip:
            lines.append(f"  Source:      {self.source_ip}:{self.source_port}")
            lines.append(f"  Destination: {self.dest_ip}:{self.dest_port}")

        return '\n'.join(lines)

    def _hexdump(self, data: bytes, indent: int = 4) -> str:
        """Format bytes as hexdump"""
        lines = []
        for i in range(0, len(data), 16):
            hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
            lines.append(f"{' '*indent}{i:04x}: {hex_part:<48} |{ascii_part}|")
        return '\n'.join(lines)

    def is_valid(self) -> tuple[bool, str]:
        """Validate message against known patterns"""
        issues = []

        # Check known good values
        if self.command_class not in [3]:  # Only 3 is known
            issues.append(f"Unknown command_class: {self.command_class}")

        if self.message_length != 18:  # Expected length
            issues.append(f"Non-standard length: {self.message_length}")

        if self.version_or_type not in [2]:  # Only 2 is known
            issues.append(f"Unknown version: {self.version_or_type}")

        if self.error_code not in [0, 6]:  # 0 = success?, 6 = known status
            issues.append(f"Unknown error code: {self.error_code}")

        if len(self.payload) != 14:
            issues.append(f"Payload size mismatch: expected 14, got {len(self.payload)}")

        if not issues:
            return True, "Valid"
        else:
            return False, "; ".join(issues)


class PTTParser:
    """Parse PTT protocol messages"""

    MIN_MESSAGE_SIZE = 4  # Header only
    EXPECTED_SIZE = 18    # Full message

    @staticmethod
    def parse(data: bytes, **kwargs) -> Optional[PTTMessage]:
        """Parse a PTT message from raw bytes"""
        if len(data) < PTTParser.MIN_MESSAGE_SIZE:
            return None

        try:
            # Parse header
            command_class, message_length, version_or_type, error_code = struct.unpack('BBBB', data[:4])

            # Parse payload (remaining bytes)
            payload = data[4:] if len(data) > 4 else b''

            # Pad or truncate to expected 14 bytes
            if len(payload) < 14:
                payload = payload.ljust(14, b'\x00')
            else:
                payload = payload[:14]

            return PTTMessage(
                command_class=command_class,
                message_length=message_length,
                version_or_type=version_or_type,
                error_code=error_code,
                payload=payload,
                **kwargs
            )
        except Exception as e:
            print(f"[!] Parse error: {e}")
            return None

    @staticmethod
    def parse_pcap(pcap_path: Path, port: int = 5000) -> List[PTTMessage]:
        """Parse PTT messages from pcap file"""
        messages = []

        try:
            import dpkt
        except ImportError:
            print("[!] dpkt not installed. Install with: pip install dpkt")
            return messages

        try:
            with open(pcap_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)

                for timestamp, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if not isinstance(eth.data, dpkt.ip.IP):
                            continue

                        ip = eth.data
                        if not isinstance(ip.data, dpkt.udp.UDP):
                            continue

                        udp = ip.data
                        if udp.dport != port and udp.sport != port:
                            continue

                        # Parse PTT message
                        msg = PTTParser.parse(
                            udp.data,
                            source_ip=socket.inet_ntoa(ip.src),
                            dest_ip=socket.inet_ntoa(ip.dst),
                            source_port=udp.sport,
                            dest_port=udp.dport,
                            timestamp=timestamp
                        )

                        if msg:
                            messages.append(msg)

                    except Exception as e:
                        continue

        except FileNotFoundError:
            print(f"[!] File not found: {pcap_path}")
        except Exception as e:
            print(f"[!] PCAP parse error: {e}")

        return messages

    @staticmethod
    def parse_binary(binary_path: Path) -> Optional[PTTMessage]:
        """Parse PTT message from binary file"""
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
                return PTTParser.parse(data)
        except Exception as e:
            print(f"[!] Error reading {binary_path}: {e}")
            return None


def live_capture(interface: str, port: int = 5000):
    """Live capture PTT packets (requires root)"""
    try:
        import scapy.all as scapy
    except ImportError:
        print("[!] scapy not installed. Install with: pip install scapy")
        return

    print(f"[*] Starting live capture on {interface}, port {port}")
    print("[*] Press Ctrl+C to stop\n")

    def packet_handler(packet):
        if packet.haslayer(scapy.UDP):
            udp = packet[scapy.UDP]
            if udp.dport == port or udp.sport == port:
                msg = PTTParser.parse(
                    bytes(udp.payload),
                    source_ip=packet[scapy.IP].src if packet.haslayer(scapy.IP) else None,
                    dest_ip=packet[scapy.IP].dst if packet.haslayer(scapy.IP) else None,
                    source_port=udp.sport,
                    dest_port=udp.dport,
                )

                if msg:
                    print("="*80)
                    print(msg)
                    valid, reason = msg.is_valid()
                    if valid:
                        print("  ✓ VALID")
                    else:
                        print(f"  ✗ ISSUES: {reason}")
                    print()

    scapy.sniff(iface=interface, filter=f"udp port {port}", prn=packet_handler)


def main():
    parser = argparse.ArgumentParser(description='HiJoy PTT Protocol Parser')
    parser.add_argument('--pcap', type=Path, help='Parse from pcap file')
    parser.add_argument('--binary', type=Path, help='Parse from binary file')
    parser.add_argument('--live', type=str, help='Live capture on interface (requires root)')
    parser.add_argument('--port', type=int, default=5000, help='PTT port (default: 5000)')
    parser.add_argument('--validate', action='store_true', help='Validate messages against known patterns')

    args = parser.parse_args()

    if args.pcap:
        print(f"[*] Parsing pcap: {args.pcap}")
        messages = PTTParser.parse_pcap(args.pcap, args.port)

        print(f"\n[+] Found {len(messages)} PTT messages\n")
        print("="*80)

        for i, msg in enumerate(messages):
            print(f"\nMessage {i+1}/{len(messages)}:")
            print(msg)

            if args.validate:
                valid, reason = msg.is_valid()
                if valid:
                    print("  ✓ VALID")
                else:
                    print(f"  ✗ ISSUES: {reason}")
            print()

    elif args.binary:
        print(f"[*] Parsing binary: {args.binary}")
        msg = PTTParser.parse_binary(args.binary)

        if msg:
            print("\n" + "="*80)
            print(msg)

            if args.validate:
                valid, reason = msg.is_valid()
                if valid:
                    print("  ✓ VALID")
                else:
                    print(f"  ✗ ISSUES: {reason}")
            print()
        else:
            print("[!] Failed to parse message")

    elif args.live:
        live_capture(args.live, args.port)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
