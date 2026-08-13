#!/usr/bin/env python3
"""
Network Analysis Module
Synthesized from: Linux System Programming, Hacking: The Art of Exploitation,
Violent Python (O'Connor) — ch2 port scan/brute force, ch4 PCAP/DNS traffic analysis
Black Hat Python 2nd ed — ch2 TCP/UDP/netcat primitives, ch3 raw sockets + ICMP scanner,
ch5 web dir brute force + form auth brute force

Enumerate network connections, listening ports, firewall rules.
PCAP forensics: credential extraction, DNS query enumeration, HTTP request logging.
ICMP host discovery, web directory enumeration.
"""

import subprocess
import socket
import struct
import re
import base64
import os
import json
import ssl
import platform as _platform
import threading
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_IS_MACOS = _platform.system() == 'Darwin'
_IS_LINUX = _platform.system() == 'Linux'

class NetworkAnalyzer:
    """Analyze network configuration and connections"""
    
    def __init__(self):
        self.connections = []
        self.listening = []
        self.firewall_rules = []
        self.interfaces = []
    
    def enumerate_all(self):
        """Run all network enumeration"""
        self.get_interfaces()
        self.get_connections()
        self.get_listening_ports()
        self.get_firewall_rules()
        
        return {
            'interfaces': self.interfaces,
            'connections': self.connections,
            'listening': self.listening,
            'firewall': self.firewall_rules
        }
    
    def get_interfaces(self):
        """Enumerate network interfaces"""
        if _IS_MACOS:
            return self._get_interfaces_macos()
        # Linux: read from /proc/net/dev
        try:
            with open('/proc/net/dev') as f:
                lines = f.readlines()[2:]
                for line in lines:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        iface = parts[0].strip()
                        try:
                            result = subprocess.run(
                                ['ip', 'addr', 'show', iface],
                                capture_output=True, text=True, timeout=1
                            )
                            ip_addr = None
                            for l in result.stdout.split('\n'):
                                if 'inet ' in l:
                                    ip_addr = l.split()[1].split('/')[0]
                                    break
                            self.interfaces.append({'name': iface, 'ip': ip_addr})
                        except:
                            self.interfaces.append({'name': iface})
        except:
            pass
        return self.interfaces

    def _get_interfaces_macos(self):
        try:
            result = subprocess.run(
                ['ifconfig', '-a'], capture_output=True, text=True, timeout=3
            )
            current = None
            for line in result.stdout.split('\n'):
                if line and not line[0].isspace():
                    current = line.split(':')[0]
                elif current and 'inet ' in line:
                    parts = line.split()
                    ip = parts[1] if len(parts) >= 2 else None
                    self.interfaces.append({'name': current, 'ip': ip})
                    current = None
        except:
            pass
        return self.interfaces
    
    def get_connections(self):
        """Get active network connections"""
        if _IS_MACOS:
            return self._get_connections_macos()
        self.connections = []
        for proto_file, proto in [('/proc/net/tcp', 'tcp'), ('/proc/net/tcp6', 'tcp6')]:
            try:
                with open(proto_file) as f:
                    lines = f.readlines()[1:]
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 10:
                            local = parts[1]
                            remote = parts[2]
                            state = int(parts[3], 16)
                            uid = int(parts[7])
                            local_ip, local_port = self._parse_addr(local, proto == 'tcp6')
                            remote_ip, remote_port = self._parse_addr(remote, proto == 'tcp6')
                            states = {
                                0x01: 'ESTABLISHED', 0x02: 'SYN_SENT', 0x03: 'SYN_RECV',
                                0x04: 'FIN_WAIT1', 0x05: 'FIN_WAIT2', 0x06: 'TIME_WAIT',
                                0x07: 'CLOSE', 0x08: 'CLOSE_WAIT', 0x09: 'LAST_ACK',
                                0x0A: 'LISTEN', 0x0B: 'CLOSING'
                            }
                            conn = {
                                'protocol': proto,
                                'local_ip': local_ip, 'local_port': local_port,
                                'remote_ip': remote_ip, 'remote_port': remote_port,
                                'state': states.get(state, f'UNKNOWN({state})'),
                                'uid': uid
                            }
                            if state == 0x0A:
                                self.listening.append(conn)
                            else:
                                self.connections.append(conn)
            except:
                pass
        return self.connections

    def _get_connections_macos(self):
        self.connections = []
        try:
            result = subprocess.run(
                ['lsof', '-i', '-n', '-P'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) < 9:
                    continue
                state = parts[-1] if parts[-1].startswith('(') else ''
                state = state.strip('()')
                addr_part = parts[8] if len(parts) > 8 else ''
                if '->' in addr_part:
                    local_str, remote_str = addr_part.split('->', 1)
                else:
                    local_str, remote_str = addr_part, '*:*'
                def _split(s):
                    if ':' in s:
                        idx = s.rfind(':')
                        return s[:idx], s[idx+1:]
                    return s, '0'
                local_ip, local_port = _split(local_str)
                remote_ip, remote_port = _split(remote_str)
                try:
                    local_port = int(local_port)
                except:
                    local_port = 0
                try:
                    remote_port = int(remote_port)
                except:
                    remote_port = 0
                conn = {
                    'protocol': parts[7].lower() if len(parts) > 7 else 'tcp',
                    'local_ip': local_ip, 'local_port': local_port,
                    'remote_ip': remote_ip, 'remote_port': remote_port,
                    'state': state, 'uid': 0
                }
                if state == 'LISTEN':
                    self.listening.append(conn)
                else:
                    self.connections.append(conn)
        except:
            pass
        return self.connections

    def get_listening_ports(self):
        """Get listening ports (already populated by get_connections)"""
        return self.listening
    
    def get_firewall_rules(self):
        """Get firewall rules (iptables)"""
        try:
            result = subprocess.run(
                ['iptables', '-L', '-n', '-v'],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0:
                self.firewall_rules.append({
                    'type': 'iptables',
                    'output': result.stdout
                })
        except:
            pass
        
        # Check if firewalld is running
        try:
            result = subprocess.run(
                ['firewall-cmd', '--list-all'],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0:
                self.firewall_rules.append({
                    'type': 'firewalld',
                    'output': result.stdout
                })
        except:
            pass
        
        return self.firewall_rules
    
    def _parse_addr(self, addr_str, ipv6=False):
        """Parse address from /proc/net format"""
        ip_hex, port_hex = addr_str.split(':')
        port = int(port_hex, 16)
        
        if ipv6:
            # IPv6 address
            ip_bytes = bytes.fromhex(ip_hex)
            # Convert to readable format (simplified)
            ip = ':'.join([f'{b:02x}' for b in ip_bytes])
        else:
            # IPv4 address (little endian)
            ip_int = int(ip_hex, 16)
            ip = socket.inet_ntoa(struct.pack('<I', ip_int))
        
        return ip, port
    
    def report(self):
        """Generate human-readable report"""
        lines = []
        lines.append("="*60)
        lines.append("NETWORK ANALYSIS")
        lines.append("="*60)
        
        lines.append(f"\nInterfaces: {len(self.interfaces)}")
        for iface in self.interfaces:
            ip = iface.get('ip', 'N/A')
            lines.append(f"  {iface['name']}: {ip}")
        
        lines.append(f"\nListening Ports: {len(self.listening)}")
        for conn in sorted(self.listening, key=lambda x: x['local_port'])[:20]:
            lines.append(f"  {conn['protocol']} {conn['local_ip']}:{conn['local_port']} (UID {conn['uid']})")
        
        lines.append(f"\nActive Connections: {len(self.connections)}")
        for conn in self.connections[:20]:
            lines.append(f"  {conn['protocol']} {conn['local_ip']}:{conn['local_port']} -> "
                        f"{conn['remote_ip']}:{conn['remote_port']} ({conn['state']}) UID {conn['uid']}")
        
        if self.firewall_rules:
            lines.append(f"\nFirewall: {len(self.firewall_rules)} rulesets found")
        
        return "\n".join(lines)

if __name__ == '__main__':
    analyzer = NetworkAnalyzer()
    analyzer.enumerate_all()
    print(analyzer.report())


class PCAPAnalyzer:
    """Parse PCAP files for credential extraction and protocol analysis.
    Uses pure Python (struct) — no scapy/dpkt dependency.
    Patterns sourced from: Violent Python ch2 (FTP/SSH brute force via ftplib/pxssh),
    ch4 (dpkt Ethernet/IP/TCP/HTTP layer iteration, DNS fast-flux/domain-flux detection).
    """

    PCAP_MAGIC = 0xA1B2C3D4        # big-endian
    PCAP_MAGIC_NS = 0xA1B23C4D     # big-endian nanosecond variant
    PCAP_MAGIC_LE = 0xD4C3B2A1     # little-endian
    PCAP_MAGIC_LE_NS = 0x4D3CB2A1  # little-endian nanosecond variant
    LINKTYPE_ETHERNET = 1
    LINKTYPE_RAW = 101

    _ETH_HDR = 14
    _IP_MIN = 20
    _TCP_MIN = 20
    _UDP_HDR = 8
    _DNS_HDR = 12

    _DNS_QTYPES = {
        1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
        15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY'
    }
    _HTTP_METHODS = {b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH'}

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.packets = []       # list of (ts_sec, ts_usec, raw_bytes)
        self.credentials = []
        self.dns_queries = []
        self.http_requests = []
        self._endian = '>'
        self._linktype = self.LINKTYPE_ETHERNET

    def parse(self) -> bool:
        """Read PCAP file, parse all packet records into self.packets.

        Global header layout: magic(4)+version_major(2)+version_minor(2)+
        thiszone(4)+sigfigs(4)+snaplen(4)+network(4) = 24 bytes.
        Record header layout: ts_sec(4)+ts_usec(4)+incl_len(4)+orig_len(4) = 16 bytes.
        Endianness determined from magic number.
        Returns True on success.
        """
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read()
        except OSError:
            return False

        if len(data) < 24:
            return False

        magic = struct.unpack('>I', data[:4])[0]
        if magic in (self.PCAP_MAGIC, self.PCAP_MAGIC_NS):
            self._endian = '>'
        elif magic in (self.PCAP_MAGIC_LE, self.PCAP_MAGIC_LE_NS):
            self._endian = '<'
        else:
            return False

        e = self._endian
        _magic, _vmaj, _vmin, _tz, _sf, _snap, network = struct.unpack(
            e + 'IHHiIII', data[:24]
        )
        self._linktype = network

        offset = 24
        while offset + 16 <= len(data):
            ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(
                e + 'IIII', data[offset:offset + 16]
            )
            offset += 16
            if offset + incl_len > len(data):
                break
            self.packets.append((ts_sec, ts_usec, data[offset:offset + incl_len]))
            offset += incl_len

        return len(self.packets) > 0

    # ------------------------------------------------------------------
    # Internal protocol parsers
    # ------------------------------------------------------------------

    def _eth_to_ip(self, pkt: bytes):
        """Strip link layer, return IPv4 payload bytes or None."""
        if self._linktype == self.LINKTYPE_ETHERNET:
            if len(pkt) < self._ETH_HDR:
                return None
            ethertype = struct.unpack('>H', pkt[12:14])[0]
            if ethertype == 0x0800:
                return pkt[self._ETH_HDR:]
            if ethertype == 0x8100 and len(pkt) >= 18:   # 802.1Q VLAN
                ethertype2 = struct.unpack('>H', pkt[16:18])[0]
                if ethertype2 == 0x0800:
                    return pkt[18:]
            return None
        if self._linktype == self.LINKTYPE_RAW:
            return pkt
        return None

    def _parse_ipv4(self, buf: bytes):
        """Parse IPv4 header. Returns (src, dst, proto, payload) or None."""
        if len(buf) < self._IP_MIN:
            return None
        ihl = (buf[0] & 0x0F) * 4
        if ihl < self._IP_MIN or len(buf) < ihl:
            return None
        proto = buf[9]
        src = socket.inet_ntoa(buf[12:16])
        dst = socket.inet_ntoa(buf[16:20])
        return src, dst, proto, buf[ihl:]

    def _parse_tcp(self, buf: bytes):
        """Parse TCP header. Returns (sport, dport, payload) or None."""
        if len(buf) < self._TCP_MIN:
            return None
        sport, dport = struct.unpack('>HH', buf[0:4])
        data_off = (buf[12] >> 4) * 4
        if data_off < self._TCP_MIN or len(buf) < data_off:
            return None
        return sport, dport, buf[data_off:]

    def _parse_udp(self, buf: bytes):
        """Parse UDP header. Returns (sport, dport, payload) or None."""
        if len(buf) < self._UDP_HDR:
            return None
        sport, dport = struct.unpack('>HH', buf[0:4])
        return sport, dport, buf[self._UDP_HDR:]

    def _decode_dns_name(self, data: bytes, offset: int):
        """Decode DNS label-encoded QNAME. Returns (name_str, next_offset).

        Handles pointer compression (0xC0 prefix). Caps iterations to prevent
        infinite loops on malformed data.
        """
        labels = []
        visited = set()
        pos = offset
        end = -1
        budget = 128
        while pos < len(data) and budget > 0:
            budget -= 1
            if pos in visited:
                break
            visited.add(pos)
            length = data[pos]
            if length == 0:
                if end == -1:
                    end = pos + 1
                break
            if (length & 0xC0) == 0xC0:   # pointer
                if pos + 1 >= len(data):
                    break
                ptr = ((length & 0x3F) << 8) | data[pos + 1]
                if end == -1:
                    end = pos + 2
                pos = ptr
            else:
                pos += 1
                if pos + length > len(data):
                    break
                labels.append(data[pos:pos + length].decode('ascii', errors='replace'))
                pos += length
        return '.'.join(labels), (end if end != -1 else pos + 1)

    # ------------------------------------------------------------------
    # Extractors
    # ------------------------------------------------------------------

    def extract_credentials(self) -> list:
        """Scan TCP payloads for cleartext credentials.

        Protocols covered:
          - FTP port 21: USER/PASS command sequence (ftplib pattern from Violent Python ch2)
          - Telnet port 23: 'login:' / 'Password:' prompts
          - HTTP Basic Auth ports 80/8080: Authorization: Basic <base64>

        Returns list of {'proto': str, 'src': str, 'dst': str, 'cred': str}.
        """
        self.credentials = []
        ftp_state = {}  # stream_key -> {'user': str, 'pass': str}

        for _ts_sec, _ts_usec, pkt_data in self.packets:
            ip_buf = self._eth_to_ip(pkt_data)
            if ip_buf is None:
                continue
            parsed = self._parse_ipv4(ip_buf)
            if parsed is None:
                continue
            src, dst, proto, ip_payload = parsed
            if proto != 6:   # TCP only
                continue
            tcp = self._parse_tcp(ip_payload)
            if tcp is None:
                continue
            sport, dport, payload = tcp
            if not payload:
                continue

            try:
                text = payload.decode('utf-8', errors='replace')
            except Exception:
                continue

            # FTP USER/PASS sequence — port 21
            # Pattern: ftplib.FTP.login(user, pass) issues "USER x\r\nPASS y\r\n"
            if dport == 21 or sport == 21:
                stream_key = f'{src}:{sport}->{dst}:{dport}'
                if stream_key not in ftp_state:
                    ftp_state[stream_key] = {}
                m_user = re.search(r'^USER\s+(\S+)', text, re.IGNORECASE | re.MULTILINE)
                m_pass = re.search(r'^PASS\s+(\S+)', text, re.IGNORECASE | re.MULTILINE)
                if m_user:
                    ftp_state[stream_key]['user'] = m_user.group(1).strip()
                if m_pass:
                    ftp_state[stream_key]['pass'] = m_pass.group(1).strip()
                state = ftp_state[stream_key]
                if 'user' in state and 'pass' in state:
                    self.credentials.append({
                        'proto': 'FTP',
                        'src': src,
                        'dst': dst,
                        'cred': state['user'] + ':' + state['pass']
                    })
                    ftp_state[stream_key] = {}

            # Telnet login prompt — port 23
            # Pattern: interactive prompt sequences 'login:' / 'Password:'
            if dport == 23 or sport == 23:
                m_login = re.search(r'login:\s*(\S+)', text, re.IGNORECASE)
                m_pass = re.search(r'[Pp]assword:\s*(\S+)', text)
                if m_login:
                    self.credentials.append({
                        'proto': 'Telnet',
                        'src': src,
                        'dst': dst,
                        'cred': 'user=' + m_login.group(1).strip()
                    })
                if m_pass:
                    self.credentials.append({
                        'proto': 'Telnet',
                        'src': src,
                        'dst': dst,
                        'cred': 'pass=' + m_pass.group(1).strip()
                    })

            # HTTP Basic Auth — common HTTP ports
            # Pattern: dpkt HTTP layer inspection (Violent Python ch4), header Authorization: Basic
            if dport in (80, 8080, 8000, 3000):
                m_auth = re.search(
                    r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)',
                    text, re.IGNORECASE
                )
                if m_auth:
                    try:
                        decoded = base64.b64decode(m_auth.group(1)).decode('utf-8', errors='replace')
                    except Exception:
                        decoded = m_auth.group(1)
                    self.credentials.append({
                        'proto': 'HTTP-Basic',
                        'src': src,
                        'dst': dst,
                        'cred': decoded
                    })

        return self.credentials

    def extract_dns(self) -> list:
        """Extract DNS queries from UDP port 53 packets.

        Parses DNS header (txid, flags, qdcount) and question section
        (QNAME label encoding, QTYPE, QCLASS).
        Also captures NXDOMAIN responses (rcode=3) — domain-flux indicator
        per Violent Python ch4 Conficker/domain-flux analysis pattern.

        Returns list of {'query': str, 'type': str, 'src': str, 'rcode': int, 'qr': str}.
        """
        self.dns_queries = []

        for _ts_sec, _ts_usec, pkt_data in self.packets:
            ip_buf = self._eth_to_ip(pkt_data)
            if ip_buf is None:
                continue
            parsed = self._parse_ipv4(ip_buf)
            if parsed is None:
                continue
            src, dst, proto, ip_payload = parsed
            if proto != 17:   # UDP
                continue
            udp = self._parse_udp(ip_payload)
            if udp is None:
                continue
            sport, dport, payload = udp
            if dport != 53 and sport != 53:
                continue
            if len(payload) < self._DNS_HDR:
                continue

            try:
                # DNS header: txid(2)+flags(2)+qdcount(2)+ancount(2)+nscount(2)+arcount(2)
                _txid, flags, qdcount = struct.unpack('>HHH', payload[0:6])
                qr_bit = (flags >> 15) & 1   # 0=query, 1=response
                rcode = flags & 0x0F

                if qdcount == 0:
                    continue

                offset = self._DNS_HDR
                for _ in range(min(qdcount, 4)):
                    if offset >= len(payload):
                        break
                    name, offset = self._decode_dns_name(payload, offset)
                    if offset + 4 > len(payload):
                        break
                    qtype, _qclass = struct.unpack('>HH', payload[offset:offset + 4])
                    offset += 4
                    type_str = self._DNS_QTYPES.get(qtype, str(qtype))

                    # Capture queries and NXDOMAIN responses (rcode=3 = domain-flux signal)
                    if qr_bit == 0 or rcode == 3:
                        self.dns_queries.append({
                            'query': name,
                            'type': type_str,
                            'src': src,
                            'rcode': rcode,
                            'qr': 'query' if qr_bit == 0 else 'response'
                        })
            except Exception:
                continue

        return self.dns_queries

    def extract_http(self) -> list:
        """Extract HTTP request lines and selected headers.

        Inspects TCP port 80/8080/8000/3000 payloads for HTTP/1.x request pattern.
        Captures: method, path, Host, User-Agent, Cookie (truncated to 128 chars).
        Pattern from Violent Python ch4: dpkt.http.Request layer on TCP payload
        to find GETs for LOIC download and HIVEMIND IRC commands.

        Returns list of {'method', 'host', 'path', 'src', 'dst',
                          'user_agent', 'cookie'} dicts.
        """
        self.http_requests = []

        for _ts_sec, _ts_usec, pkt_data in self.packets:
            ip_buf = self._eth_to_ip(pkt_data)
            if ip_buf is None:
                continue
            parsed = self._parse_ipv4(ip_buf)
            if parsed is None:
                continue
            src, dst, proto, ip_payload = parsed
            if proto != 6:   # TCP
                continue
            tcp = self._parse_tcp(ip_payload)
            if tcp is None:
                continue
            sport, dport, payload = tcp
            if dport not in (80, 8080, 8000, 3000) or not payload:
                continue

            try:
                eol = payload.find(b'\r\n')
                if eol == -1:
                    continue
                first_line = payload[:eol]
                parts = first_line.split(b' ', 2)
                if len(parts) < 3 or parts[0] not in self._HTTP_METHODS:
                    continue
                if not parts[2].startswith(b'HTTP/'):
                    continue

                method = parts[0].decode('ascii', errors='replace')
                path = parts[1].decode('ascii', errors='replace')

                host = ''
                user_agent = ''
                cookie = ''
                headers_buf = payload[eol + 2:]
                for line in headers_buf.split(b'\r\n'):
                    if not line:
                        break
                    if b':' not in line:
                        continue
                    hname, _, hval = line.partition(b':')
                    hn = hname.strip().lower()
                    hv = hval.strip().decode('utf-8', errors='replace')
                    if hn == b'host':
                        host = hv
                    elif hn == b'user-agent':
                        user_agent = hv
                    elif hn == b'cookie':
                        cookie = hv[:128]

                self.http_requests.append({
                    'method': method,
                    'host': host,
                    'path': path,
                    'src': src,
                    'dst': dst,
                    'user_agent': user_agent,
                    'cookie': cookie
                })
            except Exception:
                continue

        return self.http_requests

    def run_all(self) -> dict:
        """Parse file and run all extractors. Returns summary dict."""
        if not self.parse():
            return {'error': 'parse failed', 'filepath': self.filepath, 'packet_count': 0}
        self.extract_credentials()
        self.extract_dns()
        self.extract_http()
        return {
            'filepath': self.filepath,
            'packet_count': len(self.packets),
            'credentials': self.credentials,
            'dns_queries': self.dns_queries,
            'http_requests': self.http_requests,
        }


def analyze_pcap(filepath: str) -> dict:
    """Parse a PCAP file and return extracted network intelligence.

    Pure stdlib (struct, re, socket, base64) — no scapy/dpkt.
    Covers: FTP/Telnet/HTTP-Basic credential extraction,
            DNS query enumeration + NXDOMAIN (domain-flux) detection,
            HTTP request logging (method, host, path, headers).

    Pattern source: Violent Python ch2 (ftplib FTP brute force credential flow,
    pxssh SSH brute force) + ch4 (dpkt Ethernet/IP/TCP/HTTP layer iteration,
    DNS fast-flux/domain-flux DNSRR/DNSQR parsing).

    Returns dict: filepath, packet_count, credentials, dns_queries, http_requests.
    """
    return PCAPAnalyzer(filepath).run_all()


# ---------------------------------------------------------------------------
# ICMPScanner
# Pattern source: Black Hat Python 2nd ed ch3 — raw socket sniffer, IPPROTO_ICMP,
# struct-based ICMP echo request craft, checksum fold, recvfrom with timeout.
# Scanner pattern: send echo request per host, parse type byte in reply.
# ---------------------------------------------------------------------------

class ICMPScanner:
    """ICMP echo-based host discovery over a subnet.

    Requires CAP_NET_RAW or root. Uses SOCK_RAW + IPPROTO_ICMP: kernel prepends
    the IP header on send but strips it on receive (Linux), so the ICMP reply
    arrives at offset 0 of recvfrom data — no need to skip a 20-byte IP header.

    BHP ch3 pattern: craft type=8 code=0 ICMP echo, compute ones-complement
    checksum, sendto, recvfrom 1 s timeout, check reply[0] == 0 (echo reply).
    """

    _ICMP_ECHO_REQUEST = 8
    _ICMP_ECHO_REPLY   = 0
    _RECV_BUF          = 1024

    def _checksum(self, data: bytes) -> int:
        """RFC 1071 ones-complement checksum."""
        s = 0
        n = len(data)
        for i in range(0, n - 1, 2):
            s += (data[i] << 8) + data[i + 1]
        if n % 2:
            s += data[-1] << 8
        # fold carry
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return (~s) & 0xFFFF

    def _build_packet(self) -> bytes:
        """Craft 8-byte ICMP echo request (type=8, code=0, id=pid&0xFFFF, seq=1)."""
        pid = os.getpid() & 0xFFFF
        # checksum field set to 0 for calculation
        header = struct.pack('>BBHHH', self._ICMP_ECHO_REQUEST, 0, 0, pid, 1)
        csum = self._checksum(header)
        return struct.pack('>BBHHH', self._ICMP_ECHO_REQUEST, 0, csum, pid, 1)

    def _probe(self, ip: str) -> dict:
        """Send one ICMP echo request to ip; return result dict."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError:
            return {'error': 'requires_root'}
        try:
            sock.settimeout(1.0)
            pkt = self._build_packet()
            sock.sendto(pkt, (ip, 0))
            try:
                data, _ = sock.recvfrom(self._RECV_BUF)
                # Linux IPPROTO_ICMP: kernel strips IP header; reply starts at offset 0.
                # If the kernel includes the IP header (some configs), offset 20 holds type.
                # Check offset 0 first (standard); fall back to offset 20 if needed.
                reply_type = data[0] if data else -1
                if reply_type == self._ICMP_ECHO_REPLY:
                    return {'host': ip, 'alive': True}
                # fallback: IP header present (20 bytes)
                if len(data) >= 21 and data[20] == self._ICMP_ECHO_REPLY:
                    return {'host': ip, 'alive': True}
            except socket.timeout:
                pass
            return {'host': ip, 'alive': False}
        finally:
            sock.close()

    def _subnet_hosts(self, subnet: str):
        """Yield all host IP strings for a CIDR subnet, e.g. '192.168.1.0/24'."""
        if '/' in subnet:
            base, prefix = subnet.split('/', 1)
            prefix = int(prefix)
        else:
            base = subnet
            prefix = 32
        base_int = struct.unpack('>I', socket.inet_aton(base))[0]
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        network = base_int & mask
        broadcast = network | (~mask & 0xFFFFFFFF)
        # skip network and broadcast addresses
        for host_int in range(network + 1, broadcast):
            yield socket.inet_ntoa(struct.pack('>I', host_int))

    def scan(self, subnet: str) -> list:
        """Ping-sweep a subnet in parallel. Returns list of result dicts.

        Each result is {'host': str, 'alive': bool} or {'error': 'requires_root'}.
        On PermissionError the list contains a single error dict.

        Pattern: BHP ch3 host-discovery scanner — ThreadPoolExecutor fan-out,
        one raw ICMP socket per worker, results collected via as_completed.
        """
        hosts = list(self._subnet_hosts(subnet))
        if not hosts:
            return []

        results = []
        # test permission with a single probe before spinning up the pool
        test = self._probe(hosts[0])
        if 'error' in test:
            return [{'error': 'requires_root'}]

        results.append(test)
        remaining = hosts[1:]

        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = {pool.submit(self._probe, ip): ip for ip in remaining}
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception:
                    pass

        return results


# ---------------------------------------------------------------------------
# WebDirBrute
# Pattern source: Black Hat Python 2nd ed ch5 — URL brute force with threading,
# urllib for no-redirect requests, 200/301/302/403 discrimination, form-auth POST.
# ---------------------------------------------------------------------------

_BUILTIN_WORDLIST = [
    'admin', 'api', 'backup', 'config', 'dashboard', 'db', 'debug', 'env',
    'etc', 'login', 'manager', 'phpmyadmin', 'robots.txt', '.env', '.git/config',
    'api/v1', 'api/v2', 'swagger.json', 'openapi.json', 'graphql', 'metrics',
    'health', 'status', 'actuator', 'actuator/env', 'actuator/mappings',
    'upload', 'uploads', 'files', 'wp-admin',
]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Raise HTTPError instead of following redirects, preserving the status code."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


class WebDirBrute:
    """Web directory/path brute-forcer using stdlib urllib.

    Pattern source: BHP ch5 — threaded URL list iteration, urllib no-redirect
    handler, 200/301/302 detection, severity classification.

    Does not follow redirects: 301/302 are captured as MEDIUM (path exists,
    server redirects). 403 captured as LOW (path exists but forbidden).
    """

    _SEVERITY = {200: 'HIGH', 301: 'MEDIUM', 302: 'MEDIUM', 403: 'LOW'}

    def __init__(self, target_url: str, wordlist=None, threads: int = 10, timeout: int = 5):
        self.target_url = target_url.rstrip('/')
        self.wordlist = wordlist if wordlist is not None else list(_BUILTIN_WORDLIST)
        self.threads = threads
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirectHandler)

    def _probe(self, path: str) -> dict | None:
        """Fetch target_url/path. Returns result dict or None on connection error."""
        url = f'{self.target_url}/{path}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                status = resp.status
                length = len(resp.read())
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                length = len(exc.read())
            except Exception:
                length = 0
        except urllib.error.URLError:
            return None
        except Exception:
            return None

        severity = self._SEVERITY.get(status)
        if severity is None:
            return None  # 404, 5xx — not interesting

        return {
            'path': path,
            'status': status,
            'length': length,
            'severity': severity,
        }

    def scan(self) -> list:
        """Brute-force all paths in wordlist using a thread pool.

        Returns list of {'path', 'status', 'length', 'severity'} dicts,
        one per path that returned 200/301/302/403.

        Pattern: BHP ch5 threaded URL brute-force — each thread probes one path,
        results collected; 404 and connection errors silently discarded.
        """
        found = []
        lock = threading.Lock()

        def worker(path):
            result = self._probe(path)
            if result:
                with lock:
                    found.append(result)

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            list(pool.map(worker, self.wordlist))

        found.sort(key=lambda r: (
            {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}.get(r['severity'], 9),
            r['path']
        ))
        return found


# ---------------------------------------------------------------------------
# run_network_analysis
# ---------------------------------------------------------------------------

def run_network_analysis(target: str) -> dict:
    """Run ICMP sweep and/or web dir brute against target.

    If target looks like a URL (starts with http:// or https://), runs WebDirBrute.
    Otherwise, treats target as a subnet (e.g. '10.0.0.0/24') and runs ICMPScanner.
    If target is a bare IP with no prefix, wraps as /32 (single host ping).

    Returns dict with keys:
      'target'     : str
      'icmp'       : list of ICMPScanner results (empty if URL target)
      'web'        : list of WebDirBrute results (empty if subnet target)
      'findings'   : list of {'severity', 'title', 'detail', 'host'} dicts
    """
    is_url = target.startswith('http://') or target.startswith('https://')
    icmp_results = []
    web_results = []
    findings = []

    if not is_url:
        # ICMP host discovery
        subnet = target if '/' in target else target + '/32'
        icmp_results = ICMPScanner().scan(subnet)
        for r in icmp_results:
            if r.get('alive'):
                findings.append({
                    'severity': 'INFO',
                    'title': 'Host alive (ICMP echo reply)',
                    'detail': f'Host {r["host"]} responded to ICMP echo request',
                    'host': r['host'],
                })
            elif 'error' in r:
                findings.append({
                    'severity': 'INFO',
                    'title': 'ICMP scan requires root',
                    'detail': 'Raw socket creation denied; re-run with elevated privileges',
                    'host': target,
                })
                break

    if is_url:
        # Web directory brute force
        web_results = WebDirBrute(target).scan()
        # derive host from URL for finding records
        try:
            from urllib.parse import urlparse
            host = urlparse(target).netloc
        except Exception:
            host = target

        for r in web_results:
            findings.append({
                'severity': r['severity'],
                'title': f'Web path exposed: /{r["path"]} ({r["status"]})',
                'detail': (
                    f'HTTP {r["status"]} at {target}/{r["path"]} '
                    f'(response length {r["length"]} bytes)'
                ),
                'host': host,
            })

    return {
        'target': target,
        'icmp': icmp_results,
        'web': web_results,
        'findings': findings,
    }


# ---------------------------------------------------------------------------
# probe_nats_server
# ---------------------------------------------------------------------------

def probe_nats_server(host, port=4222, timeout=5.0) -> list:
    """Probe a NATS server for authentication and TLS misconfigurations.

    Synthesized from: Event-Driven Architecture in Golang (Packt) ch6 —
    NATS JetStream connection model, INFO banner fields (auth_required,
    tls_required), and pub-sub protocol primitives (PUB/SUB/+OK/-ERR).

    Protocol flow:
      1. TCP connect -> server immediately sends INFO JSON banner.
      2. PUB <subject> <bytes>\\r\\n<payload>\\r\\n — no CONNECT needed on
         open servers; server responds +OK or -ERR 'Authorization Violation'.
      3. SUB <subject> <sid>\\r\\n — same gating pattern.

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings = []
    info = {}

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)

        # Read INFO banner — server sends it immediately on connect
        banner = b""
        try:
            while b"\r\n" not in banner:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                banner += chunk
        except (socket.timeout, OSError):
            pass

        banner_str = banner.decode("utf-8", errors="replace")

        # Parse INFO JSON (format: "INFO {...}\r\n")
        if banner_str.startswith("INFO "):
            try:
                json_part = banner_str[5:].split("\r\n")[0]
                info = json.loads(json_part)
            except Exception:
                pass

        if not info:
            # Could not parse banner — port open but not NATS
            sock.close()
            return findings

        # auth_required=false (or absent) means any client can connect
        if not info.get("auth_required", False):
            findings.append({
                "severity": "CRITICAL",
                "title": "NATS_NO_AUTH",
                "detail": (
                    "NATS INFO banner reports auth_required=false — "
                    "any client can connect without credentials"
                ),
                "host": host,
                "port": port,
            })

        # tls_required=false means plaintext connections are accepted
        if not info.get("tls_required", False):
            findings.append({
                "severity": "MEDIUM",
                "title": "NATS_TLS_NOT_REQUIRED",
                "detail": (
                    "NATS INFO banner reports tls_required=false — "
                    "clients may connect without TLS encryption"
                ),
                "host": host,
                "port": port,
            })

        # Attempt unauthenticated PUB (no CONNECT frame sent)
        try:
            sock.sendall(b"PUB _probe.test 5\r\nhello\r\n")
            pub_resp = b""
            try:
                pub_resp = sock.recv(64)
            except (socket.timeout, OSError):
                pass
            if pub_resp.startswith(b"+OK"):
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NATS_UNAUTHORIZED_PUBLISH",
                    "detail": (
                        "NATS accepted PUB command without authentication "
                        "(+OK returned) — any client can publish to any subject"
                    ),
                    "host": host,
                    "port": port,
                })

            # Attempt unauthenticated SUB
            sock.sendall(b"SUB _probe.test 1\r\n")
            sub_resp = b""
            try:
                sub_resp = sock.recv(64)
            except (socket.timeout, OSError):
                pass
            if sub_resp.startswith(b"+OK"):
                findings.append({
                    "severity": "HIGH",
                    "title": "NATS_UNAUTHORIZED_SUBSCRIBE",
                    "detail": (
                        "NATS accepted SUB command without authentication "
                        "(+OK returned) — any client can subscribe to any subject"
                    ),
                    "host": host,
                    "port": port,
                })
        except OSError:
            pass

        try:
            sock.close()
        except OSError:
            pass

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return findings


# ---------------------------------------------------------------------------
# probe_rabbitmq_management
# ---------------------------------------------------------------------------

def probe_rabbitmq_management(host, port=15672, timeout=5.0) -> list:
    """Probe RabbitMQ management HTTP API for default credentials and unauth access.

    Synthesized from: Event-Driven Architecture in Golang (Packt) ch6 —
    RabbitMQ as a drop-in JetStream alternative; management API surface
    (queues, connections, vhosts) and default guest:guest credential risk
    in out-of-the-box deployments.

    Checks performed:
      GET /api/overview  Basic auth guest:guest -> 200 = default creds active
      GET /api/queues    unauthenticated         -> 200 = queue list exposed
      GET /api/connections unauthenticated       -> 200 = connection metadata exposed
      GET /api/vhosts    unauthenticated         -> 200 = vhost list exposed

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings = []
    base_url = f"http://{host}:{port}"

    def _get(path, auth=None):
        """GET request; returns (status_code, body) or (None, None) on conn error."""
        url = f"{base_url}{path}"
        headers = {"User-Agent": "Mozilla/5.0"}
        if auth:
            creds = base64.b64encode(
                f"{auth[0]}:{auth[1]}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {creds}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except Exception:
            return None, None

    # 1. Default credentials guest:guest via /api/overview
    status, _ = _get("/api/overview", auth=("guest", "guest"))
    if status == 200:
        findings.append({
            "severity": "CRITICAL",
            "title": "RABBITMQ_DEFAULT_CREDENTIALS",
            "detail": (
                "RabbitMQ management API /api/overview is accessible with "
                "default credentials guest:guest — broker is fully compromised"
            ),
            "host": host,
            "port": port,
        })

    # 2. Unauthenticated queue enumeration
    status, _ = _get("/api/queues")
    if status == 200:
        findings.append({
            "severity": "CRITICAL",
            "title": "RABBITMQ_QUEUES_UNAUTH",
            "detail": (
                "RabbitMQ /api/queues returned HTTP 200 without authentication — "
                "queue topology and message counts are publicly readable"
            ),
            "host": host,
            "port": port,
        })

    # 3. Unauthenticated connection metadata
    status, _ = _get("/api/connections")
    if status == 200:
        findings.append({
            "severity": "HIGH",
            "title": "RABBITMQ_CONNECTIONS_UNAUTH",
            "detail": (
                "RabbitMQ /api/connections returned HTTP 200 without authentication — "
                "active client connection metadata (IPs, TLS state, user) is exposed"
            ),
            "host": host,
            "port": port,
        })

    # 4. Unauthenticated vhost enumeration
    status, _ = _get("/api/vhosts")
    if status == 200:
        findings.append({
            "severity": "HIGH",
            "title": "RABBITMQ_VHOSTS_READABLE",
            "detail": (
                "RabbitMQ /api/vhosts returned HTTP 200 without authentication — "
                "virtual host list is publicly enumerable"
            ),
            "host": host,
            "port": port,
        })

    return findings


# ---------------------------------------------------------------------------
# probe_rabbitmq_amqp
# ---------------------------------------------------------------------------

def probe_rabbitmq_amqp(host, port=5672, timeout=5.0) -> list:
    """Probe RabbitMQ AMQP 0-9-1 port for open access and default credentials.

    Synthesized from: Event-Driven Architecture in Golang (Packt) ch6 —
    AMQP broker wire protocol handshake (Connection.Start / Connection.StartOk /
    Connection.Tune), delivery guarantees, and the operational risk of default
    guest credentials in unencrypted AMQP deployments.

    Protocol flow (AMQP 0-9-1):
      Client -> b"AMQP\\x00\\x00\\x09\\x01"  (protocol header)
      Server -> Connection.Start frame (class=10, method=10)
      Client -> Connection.StartOk  (class=10, method=11, PLAIN guest:guest)
      Server -> Connection.Tune (class=10, method=30) if credentials accepted

    Frame format: type(1B) + channel(2B BE) + size(4B BE) + payload + 0xCE

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings = []
    AMQP_HEADER = b"AMQP\x00\x00\x09\x01"
    FRAME_END = 0xCE

    def _recv_frame(sock):
        """Read one AMQP frame. Returns (frame_type, channel, payload) or None."""
        try:
            hdr = b""
            while len(hdr) < 7:
                chunk = sock.recv(7 - len(hdr))
                if not chunk:
                    return None
                hdr += chunk
            frame_type, channel, size = struct.unpack(">BHI", hdr)
            payload = b""
            while len(payload) < size:
                chunk = sock.recv(size - len(payload))
                if not chunk:
                    return None
                payload += chunk
            sock.recv(1)  # frame-end byte 0xCE
            return frame_type, channel, payload
        except (socket.timeout, OSError):
            return None

    def _build_start_ok():
        """Build Connection.StartOk frame with PLAIN guest:guest credentials."""
        # PLAIN response: NUL + username + NUL + password
        response = b"\x00guest\x00guest"
        mechanism = b"PLAIN"
        locale = b"en_US"
        # Payload layout (AMQP 0-9-1 spec):
        #   class-id (2B) + method-id (2B)
        #   client-properties: empty table (4B length = 0)
        #   mechanism: shortstr (1B len + bytes)
        #   response: longstr (4B len + bytes)
        #   locale: shortstr (1B len + bytes)
        payload = (
            struct.pack(">HH", 10, 11)
            + struct.pack(">I", 0)
            + struct.pack(">B", len(mechanism)) + mechanism
            + struct.pack(">I", len(response)) + response
            + struct.pack(">B", len(locale)) + locale
        )
        return (
            struct.pack(">BHI", 1, 0, len(payload))
            + payload
            + bytes([FRAME_END])
        )

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(AMQP_HEADER)

        frame = _recv_frame(sock)
        if frame is not None:
            frame_type, channel, payload = frame
            # Method frame (type=1) with Connection.Start (class=10, method=10)
            if frame_type == 1 and len(payload) >= 4:
                class_id, method_id = struct.unpack(">HH", payload[:4])

                if class_id == 10 and method_id == 10:
                    findings.append({
                        "severity": "HIGH",
                        "title": "AMQP_PORT_OPEN",
                        "detail": (
                            "AMQP 0-9-1 port responding with Connection.Start — "
                            "broker is accepting client connections"
                        ),
                        "host": host,
                        "port": port,
                    })

                    # Plaintext on non-TLS AMQP port
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "AMQP_PLAINTEXT_CREDENTIALS",
                        "detail": (
                            f"AMQP broker on port {port} does not wrap connections "
                            "in TLS — credentials transmitted in plaintext during "
                            "Connection.StartOk handshake"
                        ),
                        "host": host,
                        "port": port,
                    })

                    # Try Connection.StartOk with guest:guest
                    try:
                        sock.sendall(_build_start_ok())
                        tune = _recv_frame(sock)
                        if tune is not None:
                            t_type, _, t_payload = tune
                            if t_type == 1 and len(t_payload) >= 4:
                                t_class, t_method = struct.unpack(
                                    ">HH", t_payload[:4]
                                )
                                if t_class == 10 and t_method == 30:
                                    findings.append({
                                        "severity": "CRITICAL",
                                        "title": "AMQP_GUEST_AUTH_ACCEPTED",
                                        "detail": (
                                            "RabbitMQ AMQP accepted guest:guest "
                                            "credentials — Connection.Tune returned "
                                            "after StartOk; broker is fully accessible"
                                        ),
                                        "host": host,
                                        "port": port,
                                    })
                    except OSError:
                        pass

        try:
            sock.close()
        except OSError:
            pass

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return findings


# ---------------------------------------------------------------------------
# detect_event_injection_surface
# ---------------------------------------------------------------------------

def detect_event_injection_surface(host, port=443, timeout=5.0) -> list:
    """Probe an HTTP/HTTPS API for unauthenticated event injection surfaces.

    Synthesized from: Event-Driven Architecture in Golang (Packt) ch4-ch9 —
    integration event publication endpoints, event sourcing history APIs,
    subscription registration patterns, webhook delivery surfaces, and the
    dual-write / transactional outbox architecture that exposes internal
    event streams via management APIs.

    Checks performed:
      POST /events or /api/events  {"type":"system.admin","data":{}}
        -> 200/201 = unauthenticated event injection accepted
      GET  /api/events?after=0&limit=10000
        -> 200 = full event history publicly readable
      GET  /api/subscriptions
        -> 200 = subscription list enumerable without auth
      POST /api/webhooks  {"url":"http://169.254.169.254/...","events":["*"]}
        -> 200/201 = unauthenticated webhook registration (SSRF pivot)

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings = []
    scheme = "https" if port == 443 else "http"
    base_url = f"{scheme}://{host}:{port}"

    # Non-verifying SSL context for broad reachability on self-signed certs
    if scheme == "https":
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        _opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx)
        )
    else:
        _opener = urllib.request.build_opener()

    def _request(method, path, body=None):
        """HTTP request; returns (status, body_bytes) or (None, None) on error."""
        url = f"{base_url}{path}"
        data = None
        headers = {"User-Agent": "Mozilla/5.0"}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(data))
        req = urllib.request.Request(
            url, data=data, headers=headers, method=method
        )
        try:
            with _opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except Exception:
            return None, None

    # 1. Unauthenticated event injection via POST /events or /api/events
    event_payload = {"type": "system.admin", "data": {}}
    injected = False
    for path in ("/events", "/api/events"):
        status, _ = _request("POST", path, body=event_payload)
        if status in (200, 201):
            findings.append({
                "severity": "CRITICAL",
                "title": "EVENT_INJECTION_UNAUTH",
                "detail": (
                    f"POST {path} accepted unauthenticated event injection "
                    f"(HTTP {status}) with type=system.admin — arbitrary event "
                    "types can be submitted without credentials"
                ),
                "host": host,
                "port": port,
            })
            injected = True
            break

    # 2. Unauthenticated event log enumeration
    status, _ = _request("GET", "/api/events?after=0&limit=10000")
    if status == 200:
        findings.append({
            "severity": "HIGH",
            "title": "EVENT_LOG_ENUMERABLE",
            "detail": (
                "GET /api/events?after=0&limit=10000 returned HTTP 200 without "
                "authentication — full event history is publicly readable"
            ),
            "host": host,
            "port": port,
        })

    # 3. Unauthenticated subscription list exposure
    status, _ = _request("GET", "/api/subscriptions")
    if status == 200:
        findings.append({
            "severity": "HIGH",
            "title": "SUBSCRIPTION_LIST_UNAUTH",
            "detail": (
                "GET /api/subscriptions returned HTTP 200 without authentication — "
                "active event subscription topology is publicly enumerable"
            ),
            "host": host,
            "port": port,
        })

    # 4. Unauthenticated webhook registration -> SSRF pivot
    webhook_payload = {
        "url": "http://169.254.169.254/latest/meta-data/",
        "events": ["*"],
    }
    status, _ = _request("POST", "/api/webhooks", body=webhook_payload)
    if status in (200, 201):
        findings.append({
            "severity": "CRITICAL",
            "title": "WEBHOOK_REGISTRATION_UNAUTH",
            "detail": (
                f"POST /api/webhooks returned HTTP {status} without authentication — "
                "unauthenticated webhook registration enables SSRF pivot to internal "
                "services (IMDSv1 tested: 169.254.169.254)"
            ),
            "host": host,
            "port": port,
        })


def probe_agent_registry(host, port=443, timeout=5.0) -> list:
    """Probe an HTTP/HTTPS endpoint for unauthenticated A2A agent registry exposure.

    Synthesized from: Design Multi-Agent AI Systems Using MCP and A2A (Packt, Sayfan,
    2026) — Agent Card publication (/.well-known/agent.json), A2A JSON-RPC 2.0 task
    dispatch (message/send), agent registry enumeration endpoints, and multi-agent
    topology disclosure via unprotected /registry and /agents surfaces. The A2A
    protocol specifies that an Agent Card MUST be served at /.well-known/agent.json
    and describes the agent's name, capabilities, supported protocols, and
    authentication requirements. Unauthenticated exposure maps the entire agent mesh.

    Checks performed:
      GET  /.well-known/agent.json
        -> JSON with "name" + "capabilities" keys = HIGH AGENT_CARD_EXPOSED
      GET  /registry  or  /agents
        -> agent list in response body = CRITICAL AGENT_REGISTRY_UNAUTH
      GET  /api/v1/agents
        -> agents[] array present = CRITICAL AGENT_LIST_UNAUTH
      POST /a2a/v1/message/send  or  /api/tasks/send
           {"jsonrpc":"2.0","method":"message/send","id":1,
            "params":{"message":{"role":"user","parts":[{"text":"ping"}]}}}
        -> task/message response accepted = CRITICAL A2A_TASK_DISPATCH_UNAUTH

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings = []
    scheme = "https" if port == 443 else "http"
    base_url = f"{scheme}://{host}:{port}"

    if scheme == "https":
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        _opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx)
        )
    else:
        _opener = urllib.request.build_opener()

    def _request(method, path, body=None):
        url = f"{base_url}{path}"
        data = None
        headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(data))
        req = urllib.request.Request(
            url, data=data, headers=headers, method=method
        )
        try:
            with _opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except Exception:
            return None, None

    # 1. A2A Agent Card — /.well-known/agent.json
    status, body = _request("GET", "/.well-known/agent.json")
    if status == 200 and body:
        try:
            card = json.loads(body)
            if isinstance(card, dict) and "name" in card and "capabilities" in card:
                findings.append({
                    "severity": "HIGH",
                    "title": "AGENT_CARD_EXPOSED",
                    "detail": (
                        "GET /.well-known/agent.json returned a valid A2A Agent Card "
                        f"(name={card.get('name')!r}) without authentication — agent "
                        "capabilities, supported protocols, and authentication "
                        "requirements are publicly enumerable"
                    ),
                    "host": host,
                    "port": port,
                })
        except (ValueError, TypeError):
            pass

    # 2. Agent registry / topology enumeration
    for path in ("/registry", "/agents"):
        status, body = _request("GET", path)
        if status == 200 and body:
            try:
                data = json.loads(body)
                is_list = isinstance(data, list) and len(data) > 0
                is_dict_with_agents = (
                    isinstance(data, dict)
                    and any(k in data for k in ("agents", "registry", "items", "results"))
                )
                if is_list or is_dict_with_agents:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "AGENT_REGISTRY_UNAUTH",
                        "detail": (
                            f"GET {path} returned HTTP 200 without authentication — "
                            "multi-agent mesh topology is publicly enumerable, exposing "
                            "agent identities, endpoint addresses, and capability sets"
                        ),
                        "host": host,
                        "port": port,
                    })
                    break
            except (ValueError, TypeError):
                pass

    # 3. Versioned agent list API
    status, body = _request("GET", "/api/v1/agents")
    if status == 200 and body:
        try:
            data = json.loads(body)
            agents_present = (
                (isinstance(data, dict) and "agents" in data and isinstance(data["agents"], list))
                or (isinstance(data, list) and len(data) > 0)
            )
            if agents_present:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "AGENT_LIST_UNAUTH",
                    "detail": (
                        "GET /api/v1/agents returned HTTP 200 without authentication — "
                        "complete agent inventory accessible without credentials"
                    ),
                    "host": host,
                    "port": port,
                })
        except (ValueError, TypeError):
            pass

    # 4. A2A JSON-RPC 2.0 task dispatch — unauthenticated message/send
    task_payload = {
        "jsonrpc": "2.0",
        "method": "message/send",
        "id": 1,
        "params": {
            "message": {
                "role": "user",
                "parts": [{"text": "ping"}],
            }
        },
    }
    for path in ("/a2a/v1/message/send", "/api/tasks/send"):
        status, body = _request("POST", path, body=task_payload)
        if status in (200, 201, 202) and body:
            try:
                data = json.loads(body)
                is_task_response = isinstance(data, dict) and (
                    "result" in data
                    or "task" in data
                    or "taskId" in data
                    or "id" in data
                    or "status" in data
                )
                if is_task_response:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "A2A_TASK_DISPATCH_UNAUTH",
                        "detail": (
                            f"POST {path} accepted unauthenticated A2A message/send "
                            f"(HTTP {status}) — tasks can be dispatched to any registered "
                            "agent without credentials, enabling arbitrary agent invocation "
                            "across the multi-agent mesh"
                        ),
                        "host": host,
                        "port": port,
                    })
                    break
            except (ValueError, TypeError):
                pass

    return findings


def probe_tool_registry(host, port=443, timeout=5.0) -> list:
    """Probe an HTTP/HTTPS endpoint for unauthenticated tool registry and execution exposure.

    Synthesized from: Design Multi-Agent AI Systems Using MCP and A2A (Packt, Sayfan,
    2026) — MCP tool definition schemas, agent capability inventories, tool-call
    dispatch surfaces, and workflow definition APIs. The MCP and A2A protocols
    specify that agents publish tool definitions (name, description, inputSchema)
    to allow orchestrators to discover and invoke capabilities. Unauthenticated
    access exposes the full capability inventory and — on misconfigured deployments —
    enables direct tool execution without agent mediation or auth checks.

    Checks performed:
      GET  /tools  or  /api/tools
        -> tool list in response = CRITICAL TOOL_REGISTRY_UNAUTH
      GET  /api/v1/tool-definitions
        -> JSON schema array = CRITICAL TOOL_SCHEMAS_UNAUTH
      POST /api/tools/execute  or  /tool-call
           {"tool":"bash","input":{"cmd":"id"}}
        -> output present in response = CRITICAL TOOL_EXEC_UNAUTH
      GET  /api/v1/workflows
        -> workflow definitions array = HIGH WORKFLOW_DEFINITIONS_UNAUTH

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings = []
    scheme = "https" if port == 443 else "http"
    base_url = f"{scheme}://{host}:{port}"

    if scheme == "https":
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        _opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx)
        )
    else:
        _opener = urllib.request.build_opener()

    def _request(method, path, body=None):
        url = f"{base_url}{path}"
        data = None
        headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(data))
        req = urllib.request.Request(
            url, data=data, headers=headers, method=method
        )
        try:
            with _opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except Exception:
            return None, None

    # 1. Tool registry enumeration
    for path in ("/tools", "/api/tools"):
        status, body = _request("GET", path)
        if status == 200 and body:
            try:
                data = json.loads(body)
                is_tool_list = isinstance(data, list) and len(data) > 0
                is_tool_dict = (
                    isinstance(data, dict)
                    and any(k in data for k in ("tools", "items", "results", "capabilities"))
                )
                if is_tool_list or is_tool_dict:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "TOOL_REGISTRY_UNAUTH",
                        "detail": (
                            f"GET {path} returned HTTP 200 without authentication — "
                            "agent capability inventory (tool names, descriptions, and "
                            "input schemas) is publicly enumerable, exposing the full "
                            "attack surface of the agent's tool ecosystem"
                        ),
                        "host": host,
                        "port": port,
                    })
                    break
            except (ValueError, TypeError):
                pass

    # 2. MCP tool definition schema exposure
    status, body = _request("GET", "/api/v1/tool-definitions")
    if status == 200 and body:
        try:
            data = json.loads(body)
            has_schemas = (
                (isinstance(data, list) and len(data) > 0)
                or (isinstance(data, dict) and any(
                    k in data for k in ("definitions", "tools", "schemas")
                ))
            )
            if has_schemas:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "TOOL_SCHEMAS_UNAUTH",
                    "detail": (
                        "GET /api/v1/tool-definitions returned HTTP 200 without "
                        "authentication — full MCP tool schemas (inputSchema, "
                        "outputSchema, parameter constraints) are publicly readable, "
                        "enabling precise payload construction for tool exploitation"
                    ),
                    "host": host,
                    "port": port,
                })
        except (ValueError, TypeError):
            pass

    # 3. Direct tool execution — arbitrary command execution probe
    exec_payload = {"tool": "bash", "input": {"cmd": "id"}}
    exec_paths = ("/api/tools/execute", "/tool-call")
    for path in exec_paths:
        status, body = _request("POST", path, body=exec_payload)
        if status in (200, 201) and body:
            try:
                data = json.loads(body)
                has_output = isinstance(data, dict) and any(
                    k in data for k in ("output", "result", "stdout", "content", "text")
                )
                if has_output:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "TOOL_EXEC_UNAUTH",
                        "detail": (
                            f"POST {path} accepted unauthenticated tool execution "
                            f"(HTTP {status}) with tool=bash input cmd=id — arbitrary "
                            "tool invocation is possible without credentials, enabling "
                            "full agent capability abuse including code execution"
                        ),
                        "host": host,
                        "port": port,
                    })
                    break
            except (ValueError, TypeError):
                pass

    # 4. Workflow definition enumeration
    status, body = _request("GET", "/api/v1/workflows")
    if status == 200 and body:
        try:
            data = json.loads(body)
            has_workflows = (
                (isinstance(data, list) and len(data) > 0)
                or (isinstance(data, dict) and any(
                    k in data for k in ("workflows", "items", "definitions", "results")
                ))
            )
            if has_workflows:
                findings.append({
                    "severity": "HIGH",
                    "title": "WORKFLOW_DEFINITIONS_UNAUTH",
                    "detail": (
                        "GET /api/v1/workflows returned HTTP 200 without authentication — "
                        "agent automation workflow definitions are publicly readable, "
                        "exposing orchestration logic, trigger conditions, and inter-agent "
                        "task routing that an attacker can map and manipulate"
                    ),
                    "host": host,
                    "port": port,
                })
        except (ValueError, TypeError):
            pass

    return findings


def probe_event_store(host: str, port: int = 2113, timeout: float = 10.0) -> list:
    """Probe EventStoreDB for unauthenticated HTTP/gRPC exposure and open stream access.

    Synthesized from: Event-Driven Architecture in Golang (Packt) ch5 —
    event sourcing append-only stream model, aggregate event streams, and the
    $all system stream; ch2 — event store strong-consistency requirements and
    optimistic concurrency control; ch9 — transactional messaging and the dual-write
    problem that event stores are designed to solve.

    EventStoreDB exposes two ports:
      2113 — HTTP AtomPub API (streams, events, subscriptions, projections)
      1113 — gRPC API (EventStore.Client)

    The /streams endpoint lists all user-created streams (aggregate histories).
    The /streams/$all system stream contains every event across all streams —
    full application history readable with a single unauthenticated GET.

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings = []

    def _tcp_open(check_port: int) -> bool:
        """Return True if TCP connect to check_port succeeds within timeout."""
        try:
            sock = socket.create_connection((host, check_port), timeout=timeout)
            sock.close()
            return True
        except (socket.timeout, OSError, ConnectionRefusedError):
            return False

    def _get(path: str):
        """GET http://host:2113<path>; return (status, body_bytes) or (None, None)."""
        url = f"http://{host}:2113{path}"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0",
                "ES-LongPoll": "0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except Exception:
            return None, None

    # 1. TCP connect port 2113 — EventStoreDB HTTP API
    if _tcp_open(2113):
        findings.append({
            "severity": "HIGH",
            "title": "EVENTSTORE_HTTP_OPEN",
            "detail": (
                f"TCP connect to {host}:2113 succeeded — EventStoreDB HTTP AtomPub API "
                "port is reachable; this port exposes stream management, event reads, "
                "persistent subscriptions, and projection management endpoints that "
                "require authentication in secured deployments"
            ),
            "host": host,
            "port": 2113,
        })

    # 2. TCP connect port 1113 — EventStoreDB gRPC API
    if _tcp_open(1113):
        findings.append({
            "severity": "HIGH",
            "title": "EVENTSTORE_GRPC_OPEN",
            "detail": (
                f"TCP connect to {host}:1113 succeeded — EventStoreDB gRPC API port "
                "is reachable; the gRPC interface (EventStore.Client) provides full "
                "stream read/write and subscription access and is subject to the same "
                "authentication controls as the HTTP API"
            ),
            "host": host,
            "port": 1113,
        })

    # 3. GET /streams — unauthenticated stream enumeration
    status, body = _get("/streams")
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "EVENTSTORE_STREAMS_UNAUTH",
            "detail": (
                f"GET http://{host}:2113/streams returned HTTP 200 without "
                "authentication — the full list of event streams (aggregate histories) "
                "is publicly enumerable; each stream name reveals an aggregate type and "
                "ID (e.g. 'order-7f3a', 'payment-c12b') that can be individually read "
                "to reconstruct complete business event histories"
            ),
            "host": host,
            "port": 2113,
        })

    # 4. GET /streams/$all — unauthenticated system stream read
    status, body = _get("/streams/%24all")
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "EVENTSTORE_ALL_STREAM_UNAUTH",
            "detail": (
                f"GET http://{host}:2113/streams/$all returned HTTP 200 without "
                "authentication — the $all system stream contains every event written "
                "across all aggregate streams; unauthenticated read access exposes the "
                "complete event-sourced history of the application including domain "
                "events, state transitions, and any PII embedded in event payloads"
            ),
            "host": host,
            "port": 2113,
        })

    return findings


def probe_kafka_schema_registry(host: str, port: int = 8081, timeout: float = 10.0) -> list:
    """Probe Confluent Schema Registry for unauthenticated schema and config exposure.

    Synthesized from: Event-Driven Architecture in Golang (Packt) ch9 —
    transactional messaging outbox pattern and the role of schema contracts in
    guaranteeing event-carried state transfer consistency; ch8 — saga choreography
    and the command/reply message schemas that drive distributed transaction
    coordination; ch6 — NATS JetStream and RabbitMQ as schema-governed message brokers
    where schema registry exposure reveals the full inter-service contract surface.

    Confluent Schema Registry REST API (default :8081):
      GET /subjects              — list all registered subject names (one per topic)
      GET /schemas/ids/1         — fetch schema by numeric ID (IDs are sequential)
      GET /config                — global compatibility level (BACKWARD/FORWARD/FULL/NONE)

    Subject names follow '<topic>-key' / '<topic>-value' conventions; names containing
    PII-adjacent terms (user, customer, payment, health, medical) indicate topics that
    likely carry sensitive data and warrant elevated severity.

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings = []
    base_url = f"http://{host}:{port}"
    PII_TERMS = ("user", "customer", "payment", "health", "medical")

    def _get(path: str):
        """GET base_url+path; return (status, body_bytes) or (None, None)."""
        url = f"{base_url}{path}"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.schemaregistry.v1+json, application/json",
                "User-Agent": "Mozilla/5.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except Exception:
            return None, None

    # 1. GET /subjects — schema registry subject enumeration
    status, body = _get("/subjects")
    if status == 200 and body:
        try:
            subjects = json.loads(body)
        except (ValueError, TypeError):
            subjects = []

        if isinstance(subjects, list):
            findings.append({
                "severity": "CRITICAL",
                "title": "KAFKA_SCHEMA_REGISTRY_UNAUTH",
                "detail": (
                    f"GET {base_url}/subjects returned HTTP 200 without authentication "
                    f"— {len(subjects)} subject(s) enumerated; subject list reveals the "
                    "complete Kafka topic schema contract surface including producer/consumer "
                    "bindings; subjects: "
                    + (", ".join(subjects[:10]) + (" ..." if len(subjects) > 10 else "")
                       if subjects else "(empty)")
                ),
                "host": host,
                "port": port,
            })

            # PII subject name scan
            for name in subjects:
                name_lower = name.lower()
                for term in PII_TERMS:
                    if term in name_lower:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "KAFKA_SENSITIVE_SCHEMA",
                            "detail": (
                                f"Schema Registry subject '{name}' matches PII indicator "
                                f"'{term}' — this topic likely carries sensitive data "
                                "(personal identifiers, financial records, or health "
                                "information); schema is readable without authentication"
                            ),
                            "host": host,
                            "port": port,
                        })
                        break  # one finding per subject, first matching term wins

    # 2. GET /schemas/ids/1 — first schema content read
    status, body = _get("/schemas/ids/1")
    if status == 200 and body:
        findings.append({
            "severity": "HIGH",
            "title": "KAFKA_SCHEMA_CONTENT_EXPOSED",
            "detail": (
                f"GET {base_url}/schemas/ids/1 returned HTTP 200 without authentication "
                "— message schema content is readable; schema definitions expose field "
                "names, types, and default values that reveal data models and enable "
                "precise payload construction for topic injection or consumer spoofing"
            ),
            "host": host,
            "port": port,
        })

    # 3. GET /config — global compatibility config
    status, body = _get("/config")
    if status == 200 and body:
        compat_level = ""
        try:
            cfg = json.loads(body)
            compat_level = cfg.get("compatibilityLevel", "")
        except (ValueError, TypeError):
            pass
        findings.append({
            "severity": "MEDIUM",
            "title": "KAFKA_SCHEMA_CONFIG_EXPOSED",
            "detail": (
                f"GET {base_url}/config returned HTTP 200 without authentication — "
                "global schema compatibility configuration is publicly readable"
                + (f" (compatibilityLevel={compat_level})" if compat_level else "")
                + "; compatibility level NONE indicates schema evolution is ungoverned, "
                "increasing the risk of silent consumer breakage on schema change"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_otel_collector(host: str, port: int = 4317, timeout: float = 10.0) -> list:
    """Probe an OpenTelemetry Collector for unauthenticated OTLP receivers and debug interfaces.

    OpenTelemetry Collector exposes OTLP gRPC on 4317, OTLP HTTP on 4318, and an optional
    zpages debug extension on 55679.  All three are unauthenticated by default in the
    reference collector configuration from the go-for-devops / otel-collector-contrib demo.
    An open gRPC receiver allows arbitrary span injection; an open HTTP /v1/traces endpoint
    accepts POST from any origin; zpages /debug/tracez surfaces active in-flight spans and
    their attributes including request parameters, user IDs, and session tokens embedded
    by instrumentation libraries.
    """
    import socket
    import urllib.request
    import urllib.error

    findings = []

    def _tcp_open(h: str, p: int) -> bool:
        try:
            with socket.create_connection((h, p), timeout=timeout):
                return True
        except OSError:
            return False

    def _get(url: str):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read(4096)
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except OSError:
            return None, b""

    # 1. TCP port 4317 -- OTLP gRPC receiver
    if _tcp_open(host, 4317):
        findings.append({
            "severity": "HIGH",
            "title": "OTEL_GRPC_COLLECTOR_OPEN",
            "detail": (
                f"TCP connect to {host}:4317 succeeded -- OpenTelemetry OTLP gRPC receiver "
                "is reachable without network-level restriction; the OTel Collector gRPC "
                "endpoint accepts span and metric export from any client, enabling arbitrary "
                "trace injection that can pollute observability backends and mask malicious "
                "activity within legitimate-looking telemetry pipelines"
            ),
            "host": host,
            "port": 4317,
        })

    # 2. TCP port 4318 -- OTLP HTTP receiver
    if _tcp_open(host, 4318):
        findings.append({
            "severity": "HIGH",
            "title": "OTEL_HTTP_COLLECTOR_OPEN",
            "detail": (
                f"TCP connect to {host}:4318 succeeded -- OpenTelemetry OTLP HTTP receiver "
                "is reachable; port 4318 is the HTTP/Protobuf endpoint that accepts "
                "/v1/traces, /v1/metrics, and /v1/logs POST requests without authentication "
                "in the default collector configuration; open access allows span and log "
                "injection and cross-origin telemetry collection from browser agents"
            ),
            "host": host,
            "port": 4318,
        })

    # 3. GET http://host:4318/v1/traces -- trace ingestion endpoint probe
    status, body = _get(f"http://{host}:4318/v1/traces")
    if status is not None and status in (200, 400, 405, 415):
        # 400/405/415 confirm the endpoint exists and is responding; 200 = active receiver
        findings.append({
            "severity": "CRITICAL",
            "title": "OTEL_TRACES_ENDPOINT_UNAUTH",
            "detail": (
                f"GET http://{host}:4318/v1/traces returned HTTP {status} -- the OTLP HTTP "
                "trace ingestion endpoint is responding without authentication; this endpoint "
                "is the canonical receiver for application span data; unauthenticated access "
                "permits injection of fabricated spans into any trace ID, enabling timeline "
                "manipulation in Jaeger/Tempo/Zipkin backends and masking of attacker lateral "
                "movement within distributed traces of production services"
            ),
            "host": host,
            "port": 4318,
        })

    # 4. GET http://host:55679/debug/tracez -- zpages debug interface
    status, body = _get(f"http://{host}:55679/debug/tracez")
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "OTEL_ZPAGES_EXPOSED",
            "detail": (
                f"GET http://{host}:55679/debug/tracez returned HTTP 200 -- the OpenTelemetry "
                "Collector zpages debug extension is publicly accessible; zpages surfaces "
                "active in-flight spans and their full attribute sets, which instrumentation "
                "libraries populate with HTTP request headers, URL parameters, user session "
                "tokens, and RPC method arguments; this constitutes an unauthenticated "
                "live telemetry dump of production traffic attributes and service topology"
            ),
            "host": host,
            "port": 55679,
        })

    return findings


def probe_vector_aggregator(host: str, port: int = 8686, timeout: float = 10.0) -> list:
    """Probe a Vector log aggregator for unauthenticated management API and metrics exposure.

    Vector (vector.dev) exposes a GraphQL management API on port 8686 by default and a
    Prometheus-compatible metrics endpoint on 9598.  The GraphQL API is unauthenticated
    in default deployments and exposes full pipeline topology -- component IDs, source types,
    transform configurations, and sink destinations -- which reveals the complete log
    collection and forwarding architecture of the target environment.
    """
    import urllib.request
    import urllib.error
    import json as _json

    findings = []

    def _get(url: str, data: bytes = None, extra_headers: dict = None):
        try:
            headers = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}
            if extra_headers:
                headers.update(extra_headers)
            req = urllib.request.Request(url, data=data, headers=headers,
                                         method="POST" if data else "GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read(8192)
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except OSError:
            return None, b""

    # 1. GET http://host:8686/health -- Vector API health endpoint
    status, body = _get(f"http://{host}:8686/health")
    if status == 200:
        findings.append({
            "severity": "HIGH",
            "title": "VECTOR_API_OPEN",
            "detail": (
                f"GET http://{host}:8686/health returned HTTP 200 -- Vector log aggregator "
                "management API is accessible without authentication; the Vector API on "
                "port 8686 provides full read/write control over the log pipeline including "
                "component reload, topology inspection, and in some versions dynamic "
                "configuration mutation; unauthenticated access exposes log routing "
                "infrastructure to redirection, silencing, or sink substitution attacks"
            ),
            "host": host,
            "port": 8686,
        })

    # 2. GET http://host:8686/graphql -- Vector GraphQL management API presence check
    status, body = _get(f"http://{host}:8686/graphql")
    if status in (200, 400, 405):
        findings.append({
            "severity": "CRITICAL",
            "title": "VECTOR_GRAPHQL_UNAUTH",
            "detail": (
                f"GET http://{host}:8686/graphql returned HTTP {status} -- Vector GraphQL "
                "management interface is responding without authentication; the GraphQL API "
                "exposes introspection and operational queries over log pipeline topology, "
                "component health, event throughput rates, and error states; it additionally "
                "supports mutations in some Vector versions, allowing pipeline reconfiguration "
                "without credentials"
            ),
            "host": host,
            "port": 8686,
        })

    # 3. GET http://host:9598/metrics -- Vector Prometheus metrics endpoint
    status, body = _get(f"http://{host}:9598/metrics")
    if status == 200 and body:
        findings.append({
            "severity": "MEDIUM",
            "title": "VECTOR_METRICS_EXPOSED",
            "detail": (
                f"GET http://{host}:9598/metrics returned HTTP 200 -- Vector Prometheus "
                "metrics endpoint is publicly accessible; exposed metrics include per-component "
                "event ingestion rates, drop rates, buffer utilization, and sink delivery "
                "statistics that reveal log pipeline throughput, volume by source, and "
                "infrastructure topology without requiring any credentials"
            ),
            "host": host,
            "port": 9598,
        })

    # 4. POST http://host:8686/graphql with component list query
    gql_payload = _json.dumps(
        {"query": "{components{list{id componentType}}}"}
    ).encode()
    status, body = _get(f"http://{host}:8686/graphql", data=gql_payload)
    if status == 200 and body:
        detail_suffix = ""
        try:
            parsed = _json.loads(body)
            components = (
                parsed.get("data", {})
                      .get("components", {})
                      .get("list", [])
            )
            if components:
                ids = [c.get("id", "") for c in components[:10]]
                detail_suffix = (
                    f"; {len(components)} component(s) enumerated -- "
                    + ", ".join(ids[:5])
                    + (" ..." if len(ids) > 5 else "")
                )
        except (ValueError, TypeError):
            pass
        findings.append({
            "severity": "CRITICAL",
            "title": "VECTOR_COMPONENT_LIST",
            "detail": (
                f"POST http://{host}:8686/graphql with component-list query returned HTTP 200 "
                "-- full log pipeline component topology is readable without authentication"
                + detail_suffix
                + "; component IDs and types expose data source categories (Kubernetes logs, "
                "syslog, application stdout, S3 sinks), transform logic, and forwarding "
                "destinations, providing an attacker a complete map of the log infrastructure "
                "and enabling targeted blind-spot engineering by suppressing specific sources"
            ),
            "host": host,
            "port": 8686,
        })

    return findings


def probe_redis_exposure(host: str, port: int = 6379, timeout: float = 5.0) -> list:
    """Probe a Redis instance for unauthenticated access and dangerous command availability.

    Redis ships with no authentication enabled by default.  The PING/INFO/CONFIG/DEBUG
    command sequence is the standard verification ladder: PING confirms unauthenticated
    command execution; INFO server leaks version (CVE correlation surface); CONFIG GET
    confirms the server is fully manageable without credentials; DEBUG SLEEP 0 confirms
    the DEBUG command family is enabled, which provides a path to RCE via
    DEBUG RELOAD / DEBUG LOADMODULE on older builds and CONFIG SET dir + SAVE on any
    version with an exposed writable filesystem.
    """
    import socket

    findings: list = []

    def _redis_cmd(sock: socket.socket, cmd: str) -> bytes:
        """Send a raw Redis inline command and read the response (up to 4096 bytes)."""
        try:
            sock.sendall(cmd.encode())
            return sock.recv(4096)
        except OSError:
            return b""

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return findings

    try:
        # 1. PING — confirm unauthenticated command execution
        resp = _redis_cmd(sock, "PING\r\n")
        if b"+PONG" in resp:
            findings.append({
                "severity": "CRITICAL",
                "title": "REDIS_UNAUTH",
                "detail": (
                    f"TCP {host}:{port} -- PING returned +PONG without authentication; "
                    "Redis is accepting commands from unauthenticated clients; "
                    "no requirepass or ACL default user restriction is in effect; "
                    "full key-space is readable and writable by any network peer"
                ),
                "host": host,
                "port": port,
            })

        # 2. INFO server — extract version string
        resp = _redis_cmd(sock, "INFO server\r\n")
        if resp and resp[:1] == b"$":
            version = ""
            for line in resp.split(b"\r\n"):
                if line.startswith(b"redis_version:"):
                    version = line.split(b":", 1)[1].decode(errors="replace").strip()
                    break
            detail_suffix = f": version {version}" if version else ""
            findings.append({
                "severity": "CRITICAL",
                "title": "REDIS_INFO_UNAUTH",
                "detail": (
                    f"INFO server on {host}:{port} returned Redis server metadata "
                    f"without authentication{detail_suffix}; exposed fields include "
                    "redis_version, tcp_port, config_file path, executable path, "
                    "uptime, memory allocator, and OS build string; version disclosure "
                    "narrows CVE applicability and the config_file path enables targeted "
                    "CONFIG SET / CONFIG REWRITE attacks"
                ),
                "host": host,
                "port": port,
            })

        # 3. CONFIG GET bind — confirm full configuration readability
        resp = _redis_cmd(sock, "CONFIG GET bind\r\n")
        # A successful CONFIG GET returns a multi-bulk reply: *2\r\n$4\r\nbind\r\n...
        if resp and resp[:1] == b"*":
            findings.append({
                "severity": "HIGH",
                "title": "REDIS_CONFIG_READABLE",
                "detail": (
                    f"CONFIG GET bind on {host}:{port} returned a multi-bulk response "
                    "without authentication; the CONFIG GET command family exposes the full "
                    "running configuration including bind addresses, save intervals, dir "
                    "(data directory), and dbfilename; CONFIG SET paired with CONFIG REWRITE "
                    "allows persistent configuration modification; dir + dbfilename enable "
                    "the classic RDB-file cron-job write-to-authorized_keys privilege "
                    "escalation path on Linux hosts"
                ),
                "host": host,
                "port": port,
            })

        # 4. DEBUG SLEEP 0 — confirm DEBUG command family availability (RCE surface)
        resp = _redis_cmd(sock, "DEBUG SLEEP 0\r\n")
        if b"+OK" in resp:
            findings.append({
                "severity": "HIGH",
                "title": "REDIS_DEBUG_ENABLED",
                "detail": (
                    f"DEBUG SLEEP 0 on {host}:{port} returned +OK without authentication; "
                    "the DEBUG command family is enabled and accessible; DEBUG RELOAD forces "
                    "an in-memory RDB reload that can corrupt datasets; DEBUG LOADMODULE on "
                    "Redis < 7.0 loads arbitrary shared objects from the server filesystem "
                    "(RCE); combined with CONFIG SET dir the full DEBUG surface constitutes "
                    "a reliable unauthenticated code execution primitive on unpatched builds"
                ),
                "host": host,
                "port": port,
            })
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return findings


def probe_consul_service_mesh(host: str, port: int = 8500, timeout: float = 10.0) -> list:
    """Probe a Consul agent for unauthenticated service registry and KV store access.

    HashiCorp Consul ships with ACLs disabled by default (acl.enabled = false).
    Without ACLs the HTTP API at port 8500 exposes the complete service catalog,
    KV store, and ACL token list to any network peer.  The status/leader endpoint
    confirms cluster membership; catalog/services enumerates every registered service
    name and tag; kv/?keys walks the full KV namespace (Vault unseal keys, TLS certs,
    and application secrets are commonly stored here); acl/tokens returns all ACL
    tokens including the master token when ACLs are enabled but misconfigured.
    """
    import urllib.request
    import urllib.error
    import json

    findings: list = []

    def _get(path: str):
        url = f"http://{host}:{port}{path}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(65536)
                return resp.status, body
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except OSError:
            return None, b""

    # 1. GET /v1/status/leader — cluster leadership disclosure
    status, body = _get("/v1/status/leader")
    if status == 200 and body:
        leader = body.decode(errors="replace").strip().strip('"')
        detail_suffix = f": leader address {leader}" if leader else ""
        findings.append({
            "severity": "HIGH",
            "title": "CONSUL_STATUS_UNAUTH",
            "detail": (
                f"GET http://{host}:{port}/v1/status/leader returned HTTP 200 without "
                f"authentication{detail_suffix}; Consul cluster leadership is publicly "
                "enumerable; the leader IP:port identifies the Raft leader node, which "
                "is the write target for all catalog and KV mutations; combined with "
                "an open catalog API this enables precise targeting of cluster-state "
                "modification requests to a confirmed active leader"
            ),
            "host": host,
            "port": port,
        })

    # 2. GET /v1/catalog/services — full service registry enumeration
    status, body = _get("/v1/catalog/services")
    if status == 200 and body:
        service_names: list = []
        try:
            parsed = json.loads(body)
            service_names = list(parsed.keys()) if isinstance(parsed, dict) else []
        except (ValueError, TypeError):
            pass
        count = len(service_names)
        sample = ", ".join(service_names[:10]) + (" ..." if count > 10 else "")
        findings.append({
            "severity": "CRITICAL",
            "title": "CONSUL_SERVICES_UNAUTH",
            "detail": (
                f"GET http://{host}:{port}/v1/catalog/services returned HTTP 200 -- "
                f"service registry is fully exposed without authentication; "
                f"{count} service(s) enumerated"
                + (f": {sample}" if sample else "")
                + "; the catalog response maps every service name to its tags, "
                "enabling an attacker to enumerate the complete microservice topology, "
                "identify internal service names for DNS poisoning or sidecar injection, "
                "and determine which services lack health checks (deregistration target)"
            ),
            "host": host,
            "port": port,
        })

    # 3. GET /v1/kv/?keys — KV store key enumeration
    status, body = _get("/v1/kv/?keys")
    if status == 200 and body:
        keys: list = []
        try:
            keys = json.loads(body)
            if not isinstance(keys, list):
                keys = []
        except (ValueError, TypeError):
            pass
        count = len(keys)
        sample = ", ".join(keys[:5]) + (" ..." if count > 5 else "")
        findings.append({
            "severity": "CRITICAL",
            "title": "CONSUL_KV_KEYS_UNAUTH",
            "detail": (
                f"GET http://{host}:{port}/v1/kv/?keys returned HTTP 200 -- "
                f"key-value store key namespace is enumerable without authentication; "
                f"{count} key path(s) listed"
                + (f": {sample}" if sample else "")
                + "; Consul KV is a common storage location for Vault unseal keys, "
                "TLS certificate PEM blobs, database connection strings, API tokens, "
                "and dynamic application configuration; key enumeration precedes "
                "targeted GET /v1/kv/<key>?raw reads to extract the stored secrets"
            ),
            "host": host,
            "port": port,
        })

    # 4. GET /v1/acl/tokens — ACL token list (available when ACLs enabled + misconfigured)
    status, body = _get("/v1/acl/tokens")
    if status == 200 and body:
        tokens: list = []
        try:
            tokens = json.loads(body)
            if not isinstance(tokens, list):
                tokens = []
        except (ValueError, TypeError):
            pass
        count = len(tokens)
        findings.append({
            "severity": "CRITICAL",
            "title": "CONSUL_ACL_TOKENS_UNAUTH",
            "detail": (
                f"GET http://{host}:{port}/v1/acl/tokens returned HTTP 200 -- "
                f"ACL token list is accessible without authentication; {count} token(s) "
                "returned; token objects include SecretID (the bearer credential), "
                "Description, Policies, and Roles fields; a disclosed SecretID can be "
                "used directly in X-Consul-Token headers to impersonate any policy level "
                "up to and including the master management token, granting full "
                "read/write access to the catalog, KV store, intentions, and agent APIs"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_graphql_introspection(host: str, port: int = 4000, timeout: float = 10.0) -> list:
    """Probe GraphQL endpoints for unauthenticated access and introspection exposure.

    Checks /graphql and common alternate paths for:
    - Unauthenticated endpoint access ({__typename} probe)
    - Full schema enumerable via introspection (__schema query)
    - Sensitive type names in schema (user, auth, token, password, admin, credit, payment)
    """
    findings: list = []
    base_url = f"http://{host}:{port}"
    paths = ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]

    _SENSITIVE_PATTERNS = ("user", "auth", "token", "password", "admin", "credit", "payment")

    typename_query = json.dumps({"query": "{__typename}"}).encode()
    introspection_query = json.dumps(
        {"query": "{ __schema { types { name fields { name } } } }"}
    ).encode()

    post_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    for path in paths:
        url = base_url + path

        # 1. Endpoint probe — {__typename}
        try:
            req = urllib.request.Request(
                url,
                data=typename_query,
                headers=post_headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                raw = resp.read(65536)
        except urllib.error.HTTPError as exc:
            status = exc.code
            raw = b""
        except Exception:
            continue

        if status != 200:
            continue

        try:
            body = json.loads(raw)
        except (ValueError, TypeError):
            body = {}

        # Valid GraphQL response has "data" key (even if value is null/dict)
        if "data" not in body and "errors" not in body:
            continue

        findings.append({
            "severity": "HIGH",
            "title": "GRAPHQL_ENDPOINT_UNAUTH",
            "detail": (
                f"POST {url} with {{__typename}} probe returned HTTP 200 -- "
                "GraphQL API is accessible without authentication; "
                "unauthenticated callers can issue arbitrary queries; "
                "path: " + path
            ),
            "host": host,
            "port": port,
        })

        # 2. Full introspection query
        try:
            req2 = urllib.request.Request(
                url,
                data=introspection_query,
                headers=post_headers,
                method="POST",
            )
            with urllib.request.urlopen(req2, timeout=timeout) as resp2:
                status2 = resp2.status
                raw2 = resp2.read(524288)
        except urllib.error.HTTPError as exc:
            status2 = exc.code
            raw2 = b""
        except Exception:
            status2 = 0
            raw2 = b""

        if status2 == 200:
            try:
                body2 = json.loads(raw2)
            except (ValueError, TypeError):
                body2 = {}

            schema_data = (
                body2.get("data", {}) or {}
            ).get("__schema", {}) or {}
            types = schema_data.get("types", []) or []

            if types:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "GRAPHQL_INTROSPECTION_UNAUTH",
                    "detail": (
                        f"POST {url} with full __schema introspection query returned HTTP 200 "
                        f"with {len(types)} type(s) -- full schema is enumerable without "
                        "authentication; attackers can map every query, mutation, and field "
                        "to reconstruct the complete API surface; path: " + path
                    ),
                    "host": host,
                    "port": port,
                })

                # 3. Sensitive type name scan
                for t in types:
                    name = (t.get("name") or "").lower()
                    if not name or name.startswith("__"):
                        continue
                    for pattern in _SENSITIVE_PATTERNS:
                        if pattern in name:
                            findings.append({
                                "severity": "CRITICAL",
                                "title": "GRAPHQL_SENSITIVE_TYPE",
                                "detail": (
                                    f"{t.get('name', name)} type suggests sensitive data in schema -- "
                                    f"matched pattern '{pattern}'; type is enumerable via unauthenticated "
                                    "introspection; fields within this type may expose credentials, "
                                    "PII, payment data, or privilege-escalation mutations; path: " + path
                                ),
                                "host": host,
                                "port": port,
                            })
                            break  # one finding per type

    return findings


def probe_grpc_server_reflection(host: str, port: int = 50051, timeout: float = 10.0) -> list:
    """Probe a gRPC port for open access, HTTP/2 handshake, and server reflection.

    Detection chain:
    - TCP connect: port reachable
    - HTTP/2 client preface + SETTINGS frame: server speaks HTTP/2
    - gRPC ServerReflection/ServerReflectionInfo request: reflection enabled
    """
    findings: list = []

    # 1. TCP connect
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (OSError, socket.timeout):
        return findings

    findings.append({
        "severity": "HIGH",
        "title": "GRPC_PORT_OPEN",
        "detail": (
            f"TCP connect to {host}:{port} succeeded -- "
            "gRPC server port is network-accessible; "
            "unauthenticated callers may invoke service methods if no auth interceptor is configured"
        ),
        "host": host,
        "port": port,
    })

    # 2. HTTP/2 client preface + SETTINGS frame
    # RFC 7540 §3.5: client preface = PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n + empty SETTINGS (type=0x4)
    CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    SETTINGS_FRAME = (
        b"\x00\x00\x00"      # length = 0
        b"\x04"              # type = SETTINGS
        b"\x00"              # flags = 0
        b"\x00\x00\x00\x00" # stream_id = 0
    )

    try:
        sock.sendall(CLIENT_PREFACE + SETTINGS_FRAME)
        sock.settimeout(timeout)
        response = b""
        for _ in range(8):
            chunk = sock.recv(256)
            if not chunk:
                break
            response += chunk
            if len(response) >= 9:
                break
    except (OSError, socket.timeout):
        sock.close()
        return findings

    # HTTP/2 SETTINGS frame from server: type byte at offset 3 == 0x04
    http2_confirmed = len(response) >= 9 and response[3:4] == b"\x04"

    if not http2_confirmed:
        sock.close()
        return findings

    findings.append({
        "severity": "HIGH",
        "title": "GRPC_HTTP2_HANDSHAKE",
        "detail": (
            f"TCP {host}:{port} responded to HTTP/2 client preface with a SETTINGS frame -- "
            "server speaks HTTP/2; consistent with gRPC transport layer; "
            "further service enumeration via reflection is feasible"
        ),
        "host": host,
        "port": port,
    })

    # 3. gRPC server reflection request
    # ServerReflection/ServerReflectionInfo unary over HTTP/2
    # Path: /grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo
    # Protobuf encode: ServerReflectionRequest { list_services: "" }
    # Field 4 (list_services) = string "": tag = (4 << 3 | 2) = 0x22, length = 0
    proto_payload = b"\x22\x00"  # field 4, wire type 2, length 0

    # gRPC frame: compression-flag (0x00) + message-length (4 bytes BE) + payload
    grpc_message = b"\x00" + struct.pack(">I", len(proto_payload)) + proto_payload

    path_bytes = b"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"

    def _hpack_literal(name: bytes, value: bytes) -> bytes:
        """Encode a never-indexed literal header field (no Huffman)."""
        return (
            b"\x00"
            + bytes([len(name)]) + name
            + bytes([len(value)]) + value
        )

    header_block = (
        b"\x82"  # :method: POST (indexed, table entry 3)
        b"\x86"  # :scheme: http (indexed, table entry 7)
        + _hpack_literal(b":path", path_bytes)
        + _hpack_literal(b":authority", f"{host}:{port}".encode())
        + _hpack_literal(b"content-type", b"application/grpc")
        + _hpack_literal(b"te", b"trailers")
    )

    stream_id = 1  # first client stream

    def _h2_frame(ftype: int, flags: int, sid: int, payload: bytes) -> bytes:
        length = len(payload)
        return (
            bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
            + bytes([ftype, flags])
            + struct.pack(">I", sid & 0x7FFFFFFF)
            + payload
        )

    # HEADERS frame (type=0x1), END_HEADERS flag=0x4
    headers_frame = _h2_frame(0x1, 0x4, stream_id, header_block)
    # DATA frame (type=0x0), END_STREAM flag=0x1
    data_frame = _h2_frame(0x0, 0x1, stream_id, grpc_message)

    try:
        sock.sendall(headers_frame + data_frame)
        sock.settimeout(timeout)
        resp2 = b""
        for _ in range(16):
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp2 += chunk
            if len(resp2) >= 64:
                break
    except (OSError, socket.timeout):
        sock.close()
        return findings
    finally:
        try:
            sock.close()
        except OSError:
            pass

    # Scan for HTTP/2 DATA frame (type 0x0) on stream 1 with non-empty gRPC payload
    reflection_confirmed = False
    if resp2:
        i = 0
        while i + 9 <= len(resp2):
            f_len = (resp2[i] << 16) | (resp2[i + 1] << 8) | resp2[i + 2]
            f_type = resp2[i + 3]
            f_sid = struct.unpack(">I", resp2[i + 5:i + 9])[0] & 0x7FFFFFFF
            payload_start = i + 9
            payload_end = payload_start + f_len
            if f_type == 0x0 and f_sid == stream_id and f_len > 5:
                grpc_payload = resp2[payload_start:payload_end]
                if len(grpc_payload) >= 5 and grpc_payload[0:1] == b"\x00":
                    grpc_msg_len = struct.unpack(">I", grpc_payload[1:5])[0]
                    if grpc_msg_len > 0:
                        reflection_confirmed = True
                        break
            i += 9 + f_len
            if i >= len(resp2):
                break

    if reflection_confirmed:
        findings.append({
            "severity": "CRITICAL",
            "title": "GRPC_REFLECTION_UNAUTH",
            "detail": (
                f"gRPC server at {host}:{port} responded to a ServerReflection/ServerReflectionInfo "
                "request without authentication -- server reflection is enabled; "
                "all service names, method signatures, and protobuf message schemas are enumerable "
                "by unauthenticated callers; attackers can reconstruct the complete RPC surface, "
                "identify sensitive methods (auth, admin, billing), and craft targeted RPC calls; "
                "disable reflection in production via grpc.EnableReflection=false or equivalent"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_vsphere_vcenter(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe VMware vSphere vCenter for exposed management interfaces and unauthenticated REST APIs."""
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    probes = [
        (
            f"https://{host}:{port}/ui/",
            ["vsphere", "vmware", "vcenter", "vsphere-client"],
            "HIGH",
            "VSPHERE_WEB_CLIENT_EXPOSED",
            "VMware vSphere web client accessible",
        ),
        (
            f"https://{host}:{port}/sdk",
            ["vmware", "soapenv", "moref", "vsphere", "vim."],
            "HIGH",
            "VSPHERE_SDK_EXPOSED",
            "VMware vSphere SOAP SDK endpoint accessible",
        ),
        (
            f"https://{host}:{port}/rest/vcenter/host",
            ['"value"', '"host_name"', '"connection_state"', '"power_state"'],
            "CRITICAL",
            "VCENTER_REST_HOSTS_UNAUTH",
            "vCenter host list accessible via REST API without authentication",
        ),
        (
            f"https://{host}:{port}/rest/vcenter/vm",
            ['"value"', '"name"', '"power_state"', '"memory_size_MiB"'],
            "CRITICAL",
            "VCENTER_REST_VMS_UNAUTH",
            "vCenter VM inventory accessible without authentication",
        ),
    ]

    for url, markers, severity, title, summary in probes:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json, text/html, */*",
                },
            )
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                if resp.status not in (200, 206):
                    continue
                body = resp.read(8192).decode("utf-8", errors="replace").lower()
                if any(m.lower() in body for m in markers):
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": summary,
                        "host": host,
                        "port": port,
                    })
        except Exception:
            pass

    return findings


def probe_kong_gateway_admin(host: str, port: int = 8001, timeout: float = 10.0) -> list:
    findings = []

    probes = [
        (
            f"http://{host}:{port}/",
            ['"version"', '"hostname"', '"node_id"', '"plugins"', '"lua_version"'],
            "CRITICAL",
            "KONG_ADMIN_UNAUTH",
            "Kong API Gateway admin interface accessible without authentication",
            port,
        ),
        (
            f"http://{host}:{port}/services",
            ['"data"', '"next"', '"total"', '"protocol"', '"host"', '"port"'],
            "CRITICAL",
            "KONG_SERVICES_UNAUTH",
            "Kong upstream services enumerable (backend API URLs exposed)",
            port,
        ),
        (
            f"http://{host}:{port}/routes",
            ['"data"', '"next"', '"paths"', '"methods"', '"service"'],
            "CRITICAL",
            "KONG_ROUTES_UNAUTH",
            "Kong routing rules enumerable (API path mapping exposed)",
            port,
        ),
        (
            f"http://{host}:{port}/consumers",
            ['"data"', '"next"', '"username"', '"custom_id"'],
            "HIGH",
            "KONG_CONSUMERS_UNAUTH",
            "Kong API consumer list accessible (credentials and ACLs)",
            port,
        ),
        (
            f"http://{host}:8002/",
            ['"kong"', "kong manager", "konnect", "<title>", "application/json"],
            "HIGH",
            "KONG_MANAGER_UNAUTH",
            "Kong manager dashboard accessible",
            8002,
        ),
    ]

    for url, markers, severity, title, summary, probe_port in probes:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json, text/html, */*",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status not in (200, 206):
                    continue
                body = resp.read(8192).decode("utf-8", errors="replace")
                body_lower = body.lower()
                if any(m.lower() in body_lower for m in markers):
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": summary,
                        "host": host,
                        "port": probe_port,
                    })
        except Exception:
            pass

    return findings


def probe_traefik_dashboard(host: str, port: int = 8080, timeout: float = 10.0) -> list:
    findings = []

    probes = [
        (
            f"http://{host}:{port}/api/version",
            ['"version"', '"codeName"', '"startDate"'],
            "HIGH",
            "TRAEFIK_API_EXPOSED",
            "Traefik reverse proxy API accessible",
        ),
        (
            f"http://{host}:{port}/api/rawdata",
            ['"routers"', '"middlewares"', '"services"', '"rule"', '"entryPoints"'],
            "CRITICAL",
            "TRAEFIK_RAWDATA_UNAUTH",
            "complete Traefik routing configuration exposed (backend services, TLS settings)",
        ),
        (
            f"http://{host}:{port}/api/http/routers",
            ['"rule"', '"service"', '"entryPoints"', '"status"'],
            "CRITICAL",
            "TRAEFIK_ROUTERS_UNAUTH",
            "Traefik HTTP router definitions accessible",
        ),
        (
            f"http://{host}:{port}/dashboard/",
            ["traefik", "<title>", "dashboard", "routers", "services"],
            "HIGH",
            "TRAEFIK_DASHBOARD_UNAUTH",
            "Traefik web dashboard accessible",
        ),
    ]

    for url, markers, severity, title, summary in probes:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json, text/html, */*",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status not in (200, 206):
                    continue
                body = resp.read(8192).decode("utf-8", errors="replace")
                body_lower = body.lower()
                if any(m.lower() in body_lower for m in markers):
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": summary,
                        "host": host,
                        "port": port,
                    })
        except Exception:
            pass

    return findings

def probe_rancher_management(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe Rancher Kubernetes management API for unauthenticated cluster, user, and settings exposure."""
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    probes = [
        (
            f"https://{host}:{port}/v3",
            ['"apiVersion"', '"links"', '"type"', "rancher"],
            "HIGH",
            "RANCHER_API_EXPOSED",
            "Rancher Kubernetes management API accessible",
        ),
        (
            f"https://{host}:{port}/v3/clusters",
            ['"data"', '"type":"collection"', '"resourceType":"cluster"', '"id"'],
            "CRITICAL",
            "RANCHER_CLUSTERS_UNAUTH",
            "Rancher managed cluster inventory accessible without authentication",
        ),
        (
            f"https://{host}:{port}/v3/users",
            ['"data"', '"resourceType":"user"', '"username"', '"principalIds"'],
            "CRITICAL",
            "RANCHER_USERS_UNAUTH",
            "Rancher user accounts enumerable without authentication",
        ),
        (
            f"https://{host}:{port}/v3/settings",
            ['"data"', '"resourceType":"setting"', '"value"', "bootstrapPassword", "server-url"],
            "CRITICAL",
            "RANCHER_SETTINGS_UNAUTH",
            "Rancher global settings exposed (may contain bootstrap credentials)",
        ),
    ]

    for url, markers, severity, title, summary in probes:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json, */*",
                },
            )
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                if resp.status not in (200, 206):
                    continue
                body = resp.read(8192).decode("utf-8", errors="replace")
                body_lower = body.lower()
                if any(m.lower() in body_lower for m in markers):
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": summary,
                        "host": host,
                        "port": port,
                    })
        except Exception:
            pass

    return findings


def probe_linkerd_control_plane(host: str, port: int = 8085, timeout: float = 10.0) -> list:
    """Probe Linkerd service mesh control plane for unauthenticated API exposure."""
    findings = []

    probes = [
        (
            f"http://{host}:{port}/api/version",
            ['"version"', '"buildDate"', '"goVersion"', "linkerd"],
            "HIGH",
            "LINKERD_API_EXPOSED",
            "Linkerd service mesh API accessible without authentication",
            port,
        ),
        (
            f"http://{host}:{port}/api/services",
            ['"services"', '"namespace"', '"name"', '"type"'],
            "CRITICAL",
            "LINKERD_SERVICES_UNAUTH",
            "Linkerd proxied service list accessible (complete service topology)",
            port,
        ),
        (
            f"http://{host}:8086/",
            ['"linkerd"', "viz", "namespace", "dashboard"],
            "HIGH",
            "LINKERD_VIZ_EXPOSED",
            "Linkerd visualization dashboard accessible",
            8086,
        ),
        (
            f"http://{host}:9996/metrics",
            ["linkerd_", "process_", "go_gc_", "# HELP", "# TYPE"],
            "HIGH",
            "LINKERD_METRICS_UNAUTH",
            "Linkerd control plane Prometheus metrics exposed",
            9996,
        ),
    ]

    for url, markers, severity, title, detail, probe_port in probes:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json, */*",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status not in (200, 206):
                    continue
                body = resp.read(8192).decode("utf-8", errors="replace")
                body_lower = body.lower()
                if any(m.lower() in body_lower for m in markers):
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": detail,
                        "host": host,
                        "port": probe_port,
                    })
        except Exception:
            pass

    return findings


def probe_cni_network_config(host: str, port: int = 9099, timeout: float = 10.0) -> list:
    """Probe Calico CNI Felix agent API and local CNI config files for network exposure."""
    findings = []

    remote_probes = [
        (
            f"http://{host}:{port}/api/v1/status",
            ['"state"', '"status"', '"version"', "felix", "calico"],
            "HIGH",
            "CALICO_FELIX_UNAUTH",
            "Calico CNI Felix agent API accessible",
        ),
        (
            f"http://{host}:{port}/api/v1/workloads",
            ['"workloads"', '"ipAddr"', '"mac"', '"endpoint"', '"ipNetworks"'],
            "CRITICAL",
            "CALICO_WORKLOADS_UNAUTH",
            "Calico workload endpoint list accessible (pod IPs and network policy)",
        ),
    ]

    for url, markers, severity, title, detail in remote_probes:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json, */*",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status not in (200, 206):
                    continue
                body = resp.read(8192).decode("utf-8", errors="replace")
                body_lower = body.lower()
                if any(m.lower() in body_lower for m in markers):
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": detail,
                        "host": host,
                        "port": port,
                    })
        except Exception:
            pass

    cni_dir = "/etc/cni/net.d/"
    if os.path.exists(cni_dir):
        findings.append({
            "severity": "HIGH",
            "title": "CNI_CONFIG_DIR_READABLE",
            "detail": "/etc/cni/net.d/ accessible (network configuration exposure)",
            "host": host,
            "port": 0,
        })

        try:
            conf_files = [
                f for f in os.listdir(cni_dir)
                if f.endswith(".conf") or f.endswith(".conflist")
            ]
            for fname in conf_files:
                fpath = os.path.join(cni_dir, fname)
                try:
                    with open(fpath, "r", errors="replace") as fh:
                        content = fh.read(4096).lower()
                    if any(kw in content for kw in ('"subnet"', '"ipam"', '"ranges"', '"gateway"')):
                        findings.append({
                            "severity": "MEDIUM",
                            "title": "CNI_SUBNET_CONFIG",
                            "detail": f"CNI subnet configuration readable (internal network addressing) — {fname}",
                            "host": host,
                            "port": 0,
                        })
                        break
                except Exception:
                    pass
        except Exception:
            pass

    return findings


def analyze_http_request_anomalies(host, port=80, timeout=10.0) -> list:
    """Detect HTTP request/response anomalies indicative of C2 or malicious infrastructure.

    Synthesized from Malware Data Science ch3 (dynamic behavioral analysis) and ch4
    (malware network analysis): Shannon entropy of HTTP response bodies flags encrypted
    C2 channels; junk-padding detection surfaces fixed-length message framing; repeated
    identical response sizes across three polls indicate templated beaconing; timing
    variance below 100 ms stdev reveals machine-driven cadence; per-character entropy
    on the leftmost hostname label identifies DGA-generated domains; three-pass DNS
    resolution exposes fast-flux A-record rotation; User-Agent discrimination reveals
    infrastructure that actively filters automated clients.
    """
    import math as _math
    import statistics as _statistics
    import time as _time

    findings = []
    base_url = f"http://{host}:{port}/"
    hostname_part = host.split(":")[0]

    # --- DGA hostname entropy ---
    def _char_entropy(s):
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((v / n) * _math.log2(v / n) for v in freq.values())

    domain_label = hostname_part.split(".")[0]
    if len(domain_label) >= 6:
        h_entropy = _char_entropy(domain_label)
        if h_entropy > 3.5:
            findings.append({
                "severity": "HIGH",
                "title": "DGA_HOSTNAME_PATTERN",
                "detail": (
                    f"Hostname label '{domain_label}' per-character entropy {h_entropy:.2f} bits "
                    f"(>3.5 threshold) — consistent with Domain Generation Algorithm output"
                ),
                "host": host,
                "port": port,
            })

    # --- Fast-flux DNS: resolve 3 times, detect IP variance ---
    try:
        ips = set()
        for _ in range(3):
            try:
                result = socket.getaddrinfo(hostname_part, None, socket.AF_INET, socket.SOCK_STREAM)
                for r in result:
                    ips.add(r[4][0])
            except Exception:
                pass
        if len(ips) > 1:
            findings.append({
                "severity": "HIGH",
                "title": "FAST_FLUX_DNS",
                "detail": (
                    f"DNS resolution returned {len(ips)} distinct IPs across 3 lookups: "
                    f"{', '.join(sorted(ips))} — fast-flux rotates A records to evade blocklists"
                ),
                "host": host,
                "port": port,
            })
    except Exception:
        pass

    # --- Fetch helpers ---
    browser_ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    curl_ua = "curl/7.68.0"

    def _fetch(ua, url=base_url):
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": ua, "Accept": "*/*", "Connection": "close"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(8192), resp.status
        except Exception:
            return None, None

    body_browser, _status_browser = _fetch(browser_ua)
    body_curl, _status_curl = _fetch(curl_ua)

    # Shannon entropy of response body
    if body_browser and len(body_browser) >= 64:
        freq = {}
        for b in body_browser:
            freq[b] = freq.get(b, 0) + 1
        n = len(body_browser)
        entropy = -sum((v / n) * _math.log2(v / n) for v in freq.values())
        if entropy > 7.5:
            findings.append({
                "severity": "HIGH",
                "title": "HIGH_ENTROPY_HTTP_RESPONSE",
                "detail": (
                    f"HTTP response body entropy {entropy:.2f} bits/byte (threshold 7.5) — "
                    f"characteristic of encrypted or compressed C2 channel payload"
                ),
                "host": host,
                "port": port,
            })

    # Junk padding: large run of identical bytes
    if body_browser and len(body_browser) >= 512:
        max_run = 0
        cur_byte = -1
        cur_run = 0
        for b in body_browser:
            if b == cur_byte:
                cur_run += 1
            else:
                cur_byte = b
                cur_run = 1
            if cur_run > max_run:
                max_run = cur_run
        if max_run >= 512:
            findings.append({
                "severity": "HIGH",
                "title": "HTTP_JUNK_PADDING_DETECTED",
                "detail": (
                    f"HTTP response contains run of {max_run} identical bytes — "
                    f"consistent with C2 channel padding responses to a fixed message length"
                ),
                "host": host,
                "port": port,
            })

    # UA-discriminating server
    if body_browser is not None and body_curl is not None:
        size_diff = abs(len(body_browser) - len(body_curl))
        if size_diff > 200 and len(body_browser) > 50 and len(body_curl) > 50:
            findings.append({
                "severity": "MEDIUM",
                "title": "UA_DISCRIMINATING_SERVER",
                "detail": (
                    f"Browser UA response {len(body_browser)} bytes vs curl UA {len(body_curl)} bytes "
                    f"(delta {size_diff}) — server actively discriminates automated clients"
                ),
                "host": host,
                "port": port,
            })

    # Beaconing: 3 polls — size consistency + timing variance
    try:
        sizes = []
        timings = []
        for _ in range(3):
            t0 = _time.monotonic()
            b, _ = _fetch(browser_ua)
            elapsed_s = _time.monotonic() - t0
            if b is not None:
                sizes.append(len(b))
                timings.append(elapsed_s)

        if len(sizes) == 3 and max(sizes) == min(sizes):
            findings.append({
                "severity": "MEDIUM",
                "title": "CONSISTENT_RESPONSE_SIZE_BEACON",
                "detail": (
                    f"All 3 HTTP polls returned identical size ({sizes[0]} bytes) — "
                    f"zero size variance consistent with templated C2 polling responses"
                ),
                "host": host,
                "port": port,
            })

        if len(timings) == 3:
            try:
                stdev_ms = _statistics.stdev(timings) * 1000
                if stdev_ms < 100:
                    findings.append({
                        "severity": "HIGH",
                        "title": "HTTP_BEACONING_PATTERN",
                        "detail": (
                            f"HTTP response timing std-dev {stdev_ms:.1f} ms across 3 polls "
                            f"(<100 ms threshold) — uniform cadence consistent with automated C2 beaconing"
                        ),
                        "host": host,
                        "port": port,
                    })
            except Exception:
                pass
    except Exception:
        pass

    return findings


def probe_decentralized_c2_infrastructure(host, port=80, timeout=10.0) -> list:
    """Detect decentralized/resilient C2 infrastructure patterns.

    Synthesized from Malware Data Science ch3 (dynamic behavioral analysis — network
    traffic monitoring) and ch4 (malware network analysis — shared C2 infrastructure
    attribution): BitTorrent DHT abuse for P2P command distribution, RAT/IRC port
    signatures, Tor SOCKS/control/relay ports, I2P and Freenet anonymization channels,
    domain fronting via mismatched Host headers, and automated-client fingerprinting
    used by evasive reverse-proxy beacons.
    """
    findings = []
    hostname = host.split(":")[0]

    def _tcp_connect(h, p, to=timeout):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            s.connect((h, p))
            s.close()
            return True
        except Exception:
            return False

    def _tcp_recv(h, p, send_bytes=None, recv_len=16, to=timeout):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            s.connect((h, p))
            if send_bytes:
                s.sendall(send_bytes)
            data = s.recv(recv_len)
            s.close()
            return data
        except Exception:
            return None

    def _udp_recv(h, p, send_bytes, recv_len=64, to=3.0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(to)
            s.sendto(send_bytes, (h, p))
            data, _ = s.recvfrom(recv_len)
            s.close()
            return data
        except Exception:
            return None

    # --- BitTorrent DHT ports 6881-6889 ---
    dht_ping = b'd1:ad2:id20:\x00' + b'\x01' * 19 + b'e1:q4:ping1:t2:aa1:y1:qe'
    for dht_port in range(6881, 6890):
        resp = _udp_recv(hostname, dht_port, dht_ping)
        if resp and len(resp) >= 4:
            findings.append({
                "severity": "HIGH",
                "title": "P2P_DHT_PORT_OPEN",
                "detail": (
                    f"BitTorrent DHT response on UDP/{dht_port} — "
                    f"DHT ports (6881-6889) abused by P2P C2 frameworks to distribute "
                    f"commands through torrent swarms"
                ),
                "host": host,
                "port": dht_port,
            })
            break

    # Port 51413: Transmission BitTorrent client
    if _tcp_connect(hostname, 51413, to=min(timeout, 3.0)):
        findings.append({
            "severity": "HIGH",
            "title": "BITTORRENT_CLIENT_PORT",
            "detail": (
                "TCP/51413 open (Transmission default port) — "
                "externally reachable BitTorrent client provides P2P channel for C2 or lateral movement"
            ),
            "host": host,
            "port": 51413,
        })

    # Common RAT/IRC C2 ports
    rat_ports = {
        4444: "Metasploit/Meterpreter default listener",
        4445: "Common secondary RAT listener",
        6667: "IRC — standard botnet C2 channel",
    }
    for rat_port, rat_desc in rat_ports.items():
        if _tcp_connect(hostname, rat_port, to=min(timeout, 3.0)):
            findings.append({
                "severity": "HIGH",
                "title": "COMMON_RAT_PORT_OPEN",
                "detail": (
                    f"TCP/{rat_port} open — {rat_desc}; "
                    f"high-signal C2 indicator on non-dedicated infrastructure"
                ),
                "host": host,
                "port": rat_port,
            })

    # --- Tor ---
    # Port 9050: SOCKS5 proxy
    socks5_greeting = bytes([0x05, 0x01, 0x00])
    socks_resp = _tcp_recv(hostname, 9050, send_bytes=socks5_greeting, recv_len=2, to=min(timeout, 3.0))
    if socks_resp and len(socks_resp) >= 2 and socks_resp[0] == 0x05 and socks_resp[1] == 0x00:
        findings.append({
            "severity": "CRITICAL",
            "title": "TOR_SOCKS_PROXY_EXPOSED",
            "detail": (
                "Port 9050 SOCKS5 handshake succeeded (0x05 0x00) — "
                "Tor SOCKS proxy accessible; provides anonymized routing for C2 and exfiltration traffic"
            ),
            "host": host,
            "port": 9050,
        })

    # Port 9051: Tor control port
    if _tcp_connect(hostname, 9051, to=min(timeout, 3.0)):
        findings.append({
            "severity": "CRITICAL",
            "title": "TOR_CONTROL_PORT_EXPOSED",
            "detail": (
                "TCP/9051 open — Tor control port; unauthenticated access permits circuit "
                "manipulation and full anonymization layer control"
            ),
            "host": host,
            "port": 9051,
        })

    # Port 9001: Tor relay ORPort — TLS handshake
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((hostname, 9001), timeout=min(timeout, 3.0))
        try:
            tls_sock = ctx.wrap_socket(raw, server_hostname=hostname)
            tls_sock.close()
            findings.append({
                "severity": "HIGH",
                "title": "TOR_RELAY_PORT",
                "detail": (
                    "TLS handshake completed on TCP/9001 — Tor ORPort active; "
                    "host may function as a Tor relay or exit node used as C2 relay"
                ),
                "host": host,
                "port": 9001,
            })
        except ssl.SSLError:
            raw.close()
    except Exception:
        pass

    # --- I2P ---
    for i2p_port in (7654, 4444):
        if _tcp_connect(hostname, i2p_port, to=min(timeout, 3.0)):
            findings.append({
                "severity": "HIGH",
                "title": "I2P_PORT_OPEN",
                "detail": (
                    f"TCP/{i2p_port} open — I2P anonymization network port; "
                    f"provides resilient C2 channels resistant to IP-based blocking"
                ),
                "host": host,
                "port": i2p_port,
            })

    # --- Freenet ---
    if _tcp_connect(hostname, 8888, to=min(timeout, 3.0)):
        findings.append({
            "severity": "HIGH",
            "title": "FREENET_PORT_OPEN",
            "detail": (
                "TCP/8888 open — Freenet default port; "
                "decentralized darknet used by advanced malware for C2 content distribution"
            ),
            "host": host,
            "port": 8888,
        })

    # --- Domain fronting: HTTPS with mismatched Host header ---
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((hostname, 443), timeout=timeout)
        try:
            tls_sock = ctx.wrap_socket(raw, server_hostname=hostname)
            front_host = "www.google.com"
            req_bytes = (
                f"GET / HTTP/1.1\r\nHost: {front_host}\r\n"
                f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            ).encode()
            tls_sock.sendall(req_bytes)
            resp_raw = b""
            try:
                while len(resp_raw) < 16384:
                    chunk = tls_sock.recv(4096)
                    if not chunk:
                        break
                    resp_raw += chunk
            except Exception:
                pass
            tls_sock.close()
            resp_text = resp_raw.decode("utf-8", errors="replace").lower()
            if "200 ok" in resp_text and "google" not in hostname.lower():
                findings.append({
                    "severity": "HIGH",
                    "title": "DOMAIN_FRONTING_INDICATOR",
                    "detail": (
                        f"HTTPS request with Host: {front_host} returned 200 OK from {host}:443 — "
                        f"domain fronting allows C2 traffic to masquerade behind CDN infrastructure"
                    ),
                    "host": host,
                    "port": 443,
                })
        except Exception:
            pass
    except Exception:
        pass

    # --- Automated client fingerprinting ---
    try:
        bot_ua = "python-requests/2.28.0"
        browser_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        target_url = f"http://{host}:{port}/"

        def _http_get(ua):
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": ua, "Accept": "*/*", "Connection": "close"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read(4096), r.status

        bot_body, bot_status = _http_get(bot_ua)
        norm_body, norm_status = _http_get(browser_ua)
        if bot_status != norm_status or abs(len(bot_body) - len(norm_body)) > 100:
            findings.append({
                "severity": "MEDIUM",
                "title": "AUTOMATED_CLIENT_FINGERPRINTING",
                "detail": (
                    f"'python-requests' UA: status={bot_status}, size={len(bot_body)} vs "
                    f"browser UA: status={norm_status}, size={len(norm_body)} — "
                    f"active bot-detection signals evasive C2 beacon or reverse-proxy infrastructure"
                ),
                "host": host,
                "port": port,
            })
    except Exception:
        pass

    return findings


def probe_cisco_sdwan_vmanage_exposure(host, port=8443, timeout=10.0) -> list:
    """Detect exposed Cisco SD-WAN vManage controller and unauthenticated REST API surfaces.

    Synthesized from Cisco Cloud Infrastructure (9780137690442) ch1 (Cisco Data Center
    Orchestration — Nexus Dashboard / APIC management plane exposure patterns) and ch3
    (Cisco Cloud ACI — Cloud APIC API surface, policy controller REST endpoints, and
    multi-site orchestrator authentication deficiencies): vManage is the SD-WAN policy
    and management controller that exposes a REST API on TCP/8443 — analogous to APIC/NDO
    in the ACI world. Unauthenticated access to /dataservice/* endpoints (device inventory,
    templates, certificates) is structurally equivalent to Cloud APIC policy-read exposure
    and carries the same blast radius: full network topology enumeration, credential
    extraction from device templates, and PKI trust compromise via the CA endpoint.
    CVE-2021-1479 (heap overflow via unauthenticated /dataservice/disasterrecovery download)
    and CVE-2023-20214 (unauthenticated REST API session establishment) are the canonical
    exploitation paths for internet-exposed vManage instances.
    """
    findings = []
    hostname = host.split(":")[0]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _https_get(path, extra_headers=None, body=None, method="GET"):
        try:
            url = f"https://{hostname}:{port}{path}"
            headers = {
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json, text/html, */*",
                "Connection": "close",
            }
            if extra_headers:
                headers.update(extra_headers)
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                status = resp.status
                raw = resp.read(32768)
                text = raw.decode("utf-8", errors="replace")
                return status, text
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception:
            return None, ""

    # Portal fingerprint: vManage web UI
    status, body = _https_get("/")
    if status in (200, 302, 301):
        body_lower = body.lower()
        if any(m in body_lower for m in ("cisco vmanage", "sd-wan", "vmanage", "sdwan")):
            findings.append({
                "severity": "MEDIUM",
                "title": "VMANAGE_PORTAL_FINGERPRINT",
                "detail": (
                    f"Cisco vManage web portal fingerprinted at https://{hostname}:{port}/ "
                    f"(HTTP {status}) — SD-WAN management controller exposed to network"
                ),
                "host": host,
                "port": port,
            })

    # Default credential check via j_security_check form auth
    cred_pairs = [
        ("admin", "admin"),
        ("admin", "Cisco12345"),
        ("admin", "VmanageAdmin"),
    ]
    for username, password in cred_pairs:
        post_body = f"j_username={username}&j_password={password}".encode()
        status, body = _https_get(
            "/j_security_check",
            extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=post_body,
            method="POST",
        )
        body_lower = body.lower()
        # Successful login: no "invalid" or "error" in response, or redirect to dashboard
        if status in (200, 302) and not any(
            m in body_lower for m in ("invalid", "incorrect", "failed", "error", "j_security_check")
        ):
            findings.append({
                "severity": "CRITICAL",
                "title": "VMANAGE_DEFAULT_CREDS",
                "detail": (
                    f"Cisco vManage authenticated with default credentials {username}:{password} "
                    f"via /j_security_check (HTTP {status}) — full SD-WAN management access"
                ),
                "host": host,
                "port": port,
            })
            break

    # Unauthenticated REST API endpoints
    rest_probes = [
        (
            "/dataservice/system/device/vedges",
            ["vedgelist", "deviceid", "uuid", "system-ip", "vEdge"],
            "CRITICAL",
            "VMANAGE_VEDGE_LIST_UNAUTH",
            "vEdge router list readable without authentication — full SD-WAN edge inventory exposed",
        ),
        (
            "/dataservice/device",
            ["data", "deviceid", "host-name", "system-ip", "reachability"],
            "CRITICAL",
            "VMANAGE_DEVICES_UNAUTH",
            "All SD-WAN devices readable without authentication — network topology fully enumerable",
        ),
        (
            "/dataservice/template/device",
            ["data", "templatename", "templateid", "devicetype"],
            "HIGH",
            "VMANAGE_TEMPLATES_UNAUTH",
            "Device templates readable without authentication — may contain pre-shared keys and credentials",
        ),
        (
            "/dataservice/certificate/rootcertificate",
            ["certificate", "-----begin", "rootcert", "pem"],
            "HIGH",
            "VMANAGE_CA_CERT_EXPOSED",
            "vManage CA root certificate readable without authentication — PKI trust anchor exposed",
        ),
        (
            "/dataservice/statistics/approute/fields",
            ["data", "fields", "query"],
            "CRITICAL",
            "VMANAGE_CVE_2023_20214",
            (
                "CVE-2023-20214: Unauthenticated REST API session established — "
                "unauthenticated read access to statistics/approute/fields endpoint confirmed"
            ),
        ),
        (
            "/dataservice/disasterrecovery/download",
            ["backup", "tar", "gzip", "\x1f\x8b", "disaster"],
            "CRITICAL",
            "VMANAGE_CVE_2021_1479",
            (
                "CVE-2021-1479: Unauthenticated disaster-recovery download endpoint reachable — "
                "heap buffer overflow vector; confirm version < 20.6.1 for exploitability"
            ),
        ),
    ]

    for path, markers, severity, title, detail in rest_probes:
        status, body = _https_get(
            path,
            extra_headers={"Accept": "application/json"},
        )
        if status == 200:
            body_lower = body.lower()
            if any(m.lower() in body_lower for m in markers):
                findings.append({
                    "severity": severity,
                    "title": title,
                    "detail": detail,
                    "host": host,
                    "port": port,
                })
                # Check templates for embedded credentials
                if title == "VMANAGE_TEMPLATES_UNAUTH" and any(
                    k in body_lower for k in ("password", "secret", "psk", "passphrase", "key")
                ):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "VMANAGE_TEMPLATE_CREDS",
                        "detail": (
                            "Device template response contains credential keywords "
                            "(password/secret/psk/passphrase/key) — "
                            "pre-shared keys or admin credentials may be readable in plaintext"
                        ),
                        "host": host,
                        "port": port,
                    })

    # vBond orchestrator port 12346 (UDP)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(min(timeout, 3.0))
        # vBond DTLS probe — send zero-length datagram, check for any response
        s.sendto(b"\x00" * 8, (hostname, 12346))
        try:
            data, _ = s.recvfrom(256)
            if data:
                findings.append({
                    "severity": "HIGH",
                    "title": "VBOND_ORCHESTRATOR_PORT",
                    "detail": (
                        f"vBond orchestrator UDP/12346 responsive on {hostname} — "
                        f"SD-WAN control-plane orchestration port exposed; "
                        f"vBond brokers vSmart/vManage connections for all vEdge devices"
                    ),
                    "host": host,
                    "port": 12346,
                })
        except socket.timeout:
            # Port reachable but no response is ambiguous; TCP fallback
            pass
        s.close()
    except Exception:
        pass

    # TCP fallback for vBond 12346
    try:
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(min(timeout, 3.0))
        result = s2.connect_ex((hostname, 12346))
        s2.close()
        if result == 0:
            findings.append({
                "severity": "HIGH",
                "title": "VBOND_ORCHESTRATOR_PORT",
                "detail": (
                    f"vBond orchestrator TCP/12346 open on {hostname} — "
                    f"SD-WAN control-plane orchestration port exposed"
                ),
                "host": host,
                "port": 12346,
            })
    except Exception:
        pass

    return findings


def probe_cisco_meraki_api_exposure(host, port=443, timeout=10.0) -> list:
    """Detect Cisco Meraki dashboard API exposure and local management page disclosure.

    Synthesized from Cisco Cloud Infrastructure (9780137690442) ch8 (Cisco Cloud Security —
    Cloudlock, Umbrella, Duo, Secure Cloud Analytics): Meraki is Cisco's cloud-managed
    networking platform. Its dashboard API uses a single API key (X-Cisco-Meraki-API-Key)
    that, when exposed in configuration files or environment variables, grants full
    read/write access to all networks under an organization — structurally equivalent to
    Cloudlock OAuth token exposure described in the CASB chapter. The local status page
    (port 80) exposes SSID, VLAN, uplink IPs, and client counts without authentication,
    matching the Cisco Cloud Security chapter's "shadow IT" visibility gap: network
    configuration data leaked from devices that IT assumes are cloud-managed and therefore
    safe. MX appliance web UI default credentials (admin:admin) represent the same
    credential hygiene failure Duo Security is positioned to address — MFA bypass via
    still-default device credentials.
    """
    findings = []
    hostname = host.split(":")[0]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _https_get(path, extra_headers=None, p=None):
        _port = p if p is not None else port
        try:
            url = f"https://{hostname}:{_port}{path}"
            headers = {
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json, text/html, */*",
                "Connection": "close",
            }
            if extra_headers:
                headers.update(extra_headers)
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                return resp.status, resp.read(16384).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(4096).decode("utf-8", errors="replace") if e.fp else ""
        except Exception:
            return None, ""

    def _http_get(path, extra_headers=None, p=80):
        try:
            url = f"http://{hostname}:{p}{path}"
            headers = {
                "User-Agent": "Mozilla/5.0",
                "Accept": "text/html, application/json, */*",
                "Connection": "close",
            }
            if extra_headers:
                headers.update(extra_headers)
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read(16384).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(4096).decode("utf-8", errors="replace") if e.fp else ""
        except Exception:
            return None, ""

    # Meraki dashboard API: /api/v1/organizations — no auth
    status, body = _https_get("/api/v1/organizations")
    if status == 200:
        body_lower = body.lower()
        if any(m in body_lower for m in ('"id"', '"name"', '"url"', "meraki")):
            findings.append({
                "severity": "HIGH",
                "title": "MERAKI_API_ENDPOINT_REACHABLE",
                "detail": (
                    f"Meraki dashboard API /api/v1/organizations returned HTTP 200 without "
                    f"valid API key — organization list may be accessible; confirm response "
                    f"is not an error stub"
                ),
                "host": host,
                "port": port,
            })

    # Meraki API key probe in common config paths
    config_paths = [
        "/.env",
        "/config.json",
        "/api-config.json",
        "/settings.json",
        "/config/meraki.json",
    ]
    api_key_patterns = [
        "meraki_api_key",
        "x-cisco-meraki-api-key",
        "meraki-api-key",
        "merakiapikey",
        "meraki_key",
    ]
    for cfg_path in config_paths:
        status, body = _https_get(cfg_path)
        if status == 200 and body:
            body_lower = body.lower()
            if any(pat in body_lower for pat in api_key_patterns):
                findings.append({
                    "severity": "CRITICAL",
                    "title": "MERAKI_API_KEY_IN_CONFIG",
                    "detail": (
                        f"Meraki API key pattern found in {cfg_path} (HTTP {status}) — "
                        f"X-Cisco-Meraki-API-Key grants full dashboard read/write access "
                        f"to all managed networks and devices under the organization"
                    ),
                    "host": host,
                    "port": port,
                })

    # Check HTTPS response bodies for disclosed API key header name (instructs clients)
    status, body = _https_get("/api/v1/organizations", extra_headers={"X-Cisco-Meraki-API-Key": "test"})
    if status in (200, 400, 401) and body:
        body_lower = body.lower()
        if "x-cisco-meraki-api-key" in body_lower and status == 200:
            findings.append({
                "severity": "CRITICAL",
                "title": "MERAKI_KEY_DISCLOSED",
                "detail": (
                    "Meraki API key header (X-Cisco-Meraki-API-Key) referenced in 200 response body — "
                    "possible API key value or authentication bypass in response content"
                ),
                "host": host,
                "port": port,
            })

    # Meraki local status page (port 80)
    status, body = _http_get("/local-status", p=80)
    if status == 200 and body:
        body_lower = body.lower()
        if any(m in body_lower for m in ("meraki", "ssid", "vlan", "uplink", "wan")):
            findings.append({
                "severity": "HIGH",
                "title": "MERAKI_LOCAL_STATUS_EXPOSED",
                "detail": (
                    f"Meraki local status page accessible at http://{hostname}:80/local-status "
                    f"(HTTP 200) — device-level status page reachable without authentication"
                ),
                "host": host,
                "port": 80,
            })
            # Check for specific network config details
            if any(m in body_lower for m in ("ssid", "vlan", "client", "uplink ip", "wan ip")):
                findings.append({
                    "severity": "HIGH",
                    "title": "MERAKI_STATUS_PAGE_UNAUTH",
                    "detail": (
                        "Meraki status page discloses network configuration without authentication: "
                        "SSID names, VLAN assignments, client counts, and uplink IP addresses "
                        "readable — enables targeted network reconnaissance"
                    ),
                    "host": host,
                    "port": 80,
                })

    # Meraki clickthrough / splash portal
    status, body = _https_get("/click")
    if status == 200 and body:
        body_lower = body.lower()
        if any(m in body_lower for m in ("meraki", "splash", "captive", "network access", "accept")):
            findings.append({
                "severity": "HIGH",
                "title": "MERAKI_SPLASH_PAGE_EXPOSED",
                "detail": (
                    f"Meraki clickthrough splash portal at https://{hostname}:{port}/click "
                    f"(HTTP 200) — captive portal endpoint accessible; may disclose org and "
                    f"network name in page content"
                ),
                "host": host,
                "port": port,
            })

    # Meraki MX appliance web UI (login page)
    for mx_path in ("/login/login", "/login"):
        status, body = _https_get(mx_path)
        if status in (200, 302) and body:
            body_lower = body.lower()
            if any(m in body_lower for m in ("meraki", "cisco", "mx", "security appliance", "login")):
                findings.append({
                    "severity": "HIGH",
                    "title": "MERAKI_MX_WEBUI",
                    "detail": (
                        f"Cisco Meraki MX appliance web UI fingerprinted at {mx_path} "
                        f"(HTTP {status}) — local management interface accessible"
                    ),
                    "host": host,
                    "port": port,
                })

                # Default credentials: admin:admin
                try:
                    post_body = b"username=admin&password=admin"
                    post_req = urllib.request.Request(
                        f"https://{hostname}:{port}{mx_path}",
                        data=post_body,
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Connection": "close",
                        },
                        method="POST",
                    )
                    with urllib.request.urlopen(post_req, context=ctx, timeout=timeout) as pr:
                        p_status = pr.status
                        p_body = pr.read(8192).decode("utf-8", errors="replace").lower()
                    if p_status in (200, 302) and not any(
                        e in p_body for e in ("invalid", "incorrect", "failed", "error")
                    ):
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "MERAKI_DEFAULT_CREDS",
                            "detail": (
                                f"Cisco Meraki MX web UI accepted default credentials admin:admin "
                                f"at {mx_path} (HTTP {p_status}) — full appliance management access"
                            ),
                            "host": host,
                            "port": port,
                        })
                except Exception:
                    pass
                break

    # Meraki MS switch management port 7351 (TCP)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(min(timeout, 3.0))
        result = s.connect_ex((hostname, 7351))
        s.close()
        if result == 0:
            findings.append({
                "severity": "HIGH",
                "title": "MERAKI_SWITCH_MGMT_PORT",
                "detail": (
                    f"Meraki MS switch management port TCP/7351 open on {hostname} — "
                    f"Meraki cloud management channel port exposed; "
                    f"used for switch-to-cloud keepalives and configuration push"
                ),
                "host": host,
                "port": 7351,
            })
    except Exception:
        pass

    return findings
