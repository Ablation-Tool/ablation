#!/usr/bin/env python3
"""
Network Analysis Module
Synthesized from: Linux System Programming, Hacking: The Art of Exploitation

Enumerate network connections, listening ports, firewall rules.
"""

import subprocess
import socket
import struct
import platform as _platform
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
