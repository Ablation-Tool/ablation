"""
cisco_config_re.py — Cisco IOS/NX-OS/ASA running-config reverse engineering tool.
Stdlib only. Extracts credentials, weak configurations, topology, and attack surface.
"""

import re
import json
import sys
from typing import Optional


# ---------------------------------------------------------------------------
# Cisco Type-7 Vigenere XOR key
# ---------------------------------------------------------------------------
_TYPE7_KEY = [
    0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e,
    0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44,
]

# Severity ordering for sorting
_SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}


def _sev_sort_key(item: dict) -> int:
    return _SEV_ORDER.get(item.get('severity', 'INFO'), 99)


class CiscoConfigRE:
    """Reverse engineers Cisco running/startup configs for credentials, topology, and weakness."""

    def __init__(self, config_text: str):
        self.text = config_text
        self.lines = config_text.splitlines()
        self.platform: Optional[str] = None  # 'ios', 'nxos', 'asa', 'ios-xr', 'unknown'
        self.hostname: Optional[str] = None
        self.version: Optional[str] = None
        # Run platform detection immediately so other methods can rely on it
        self.platform = self.detect_platform()
        self._extract_basics()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_basics(self):
        """Pull hostname and version from config."""
        for line in self.lines:
            m = re.match(r'^hostname\s+(\S+)', line, re.IGNORECASE)
            if m and not self.hostname:
                self.hostname = m.group(1)
            m = re.match(r'^(?:Cisco\s+)?(?:IOS|NX-OS|ASA)\s+(?:Software\s+)?[Vv]ersion\s+(\S+)', line)
            if m and not self.version:
                self.version = m.group(1)
            # NX-OS version line format
            m = re.match(r'^\s*version\s+(\S+)', line, re.IGNORECASE)
            if m and not self.version:
                self.version = m.group(1)

    def _first_lines(self, n: int = 10) -> str:
        return '\n'.join(self.lines[:n]).lower()

    # ------------------------------------------------------------------
    # Platform detection
    # ------------------------------------------------------------------

    def detect_platform(self) -> str:
        """
        Detect Cisco platform from config preamble.
        Returns: 'asa', 'nxos', 'ios-xr', 'ios', or 'unknown'
        """
        head = self._first_lines(15)
        if any(tok in head for tok in ('asa version', 'pixos', 'adaptive security appliance')):
            return 'asa'
        if any(tok in head for tok in ('nx-os', 'nexus', 'nxos')):
            return 'nxos'
        if 'ios xr' in head or 'iosxr' in head:
            return 'ios-xr'
        # IOS / IOS-XE
        if any(tok in head for tok in ('ios software', 'ios-xe', 'ios version', 'cisco ios')):
            return 'ios'
        # Fallback: presence of canonical IOS constructs
        full_lower = self.text[:2000].lower()
        if 'service timestamps' in full_lower or 'no service pad' in full_lower:
            return 'ios'
        return 'unknown'

    # ------------------------------------------------------------------
    # Type-7 decoder
    # ------------------------------------------------------------------

    def decode_type7(self, encrypted: str) -> str:
        """
        Decode Cisco type-7 password (reversible Vigenere XOR).
        Format: <seed(2 digits)><hex_pairs>
        Returns decoded plaintext, or empty string on error.
        """
        encrypted = encrypted.strip()
        if len(encrypted) < 2:
            return ''
        try:
            seed = int(encrypted[:2])
            hex_pairs = encrypted[2:]
            if len(hex_pairs) % 2 != 0:
                return ''
            result = []
            for i in range(0, len(hex_pairs), 2):
                byte_val = int(hex_pairs[i:i + 2], 16)
                key_idx = (i // 2 + seed) % 22
                result.append(chr(byte_val ^ _TYPE7_KEY[key_idx]))
            return ''.join(result)
        except (ValueError, IndexError):
            return ''

    # ------------------------------------------------------------------
    # Credential extraction
    # ------------------------------------------------------------------

    def extract_credentials(self) -> list:
        """
        Returns list of dicts:
        {severity, type, username, secret_type, value, line_num, context, decoded}
        """
        creds = []

        # Patterns: (regex, handler_name)
        # We iterate all lines with context.
        for idx, line in enumerate(self.lines):
            stripped = line.strip()
            lineno = idx + 1

            # ---- enable secret [0|5|7|8|9] <hash> ----
            m = re.match(
                r'^enable\s+secret\s+(?:level\s+\d+\s+)?(\d+)\s+(\S+)', stripped, re.IGNORECASE
            )
            if m:
                stype = int(m.group(1))
                val = m.group(2)
                decoded, sev = self._eval_secret(stype, val)
                creds.append({
                    'severity': sev,
                    'type': 'enable_secret',
                    'username': None,
                    'secret_type': f'type{stype}',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': decoded,
                })
                continue

            m = re.match(r'^enable\s+secret\s+(\S+)$', stripped, re.IGNORECASE)
            if m:
                # no type prefix — assume type 5
                val = m.group(1)
                creds.append({
                    'severity': 'HIGH',
                    'type': 'enable_secret',
                    'username': None,
                    'secret_type': 'type5',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': None,
                })
                continue

            # ---- enable password [0|7] <value> ----
            m = re.match(r'^enable\s+password\s+(\d+)\s+(\S+)', stripped, re.IGNORECASE)
            if m:
                stype = int(m.group(1))
                val = m.group(2)
                decoded = self.decode_type7(val) if stype == 7 else None
                sev = 'CRITICAL' if stype == 7 else ('HIGH' if stype == 0 else 'HIGH')
                creds.append({
                    'severity': sev,
                    'type': 'enable_password',
                    'username': None,
                    'secret_type': f'type{stype}',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': decoded,
                })
                continue

            m = re.match(r'^enable\s+password\s+(\S+)$', stripped, re.IGNORECASE)
            if m:
                val = m.group(1)
                creds.append({
                    'severity': 'CRITICAL',
                    'type': 'enable_password',
                    'username': None,
                    'secret_type': 'plaintext',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': val,
                })
                continue

            # ---- username <name> [privilege <N>] secret [type] <hash> ----
            m = re.match(
                r'^username\s+(\S+)\s+(?:privilege\s+(\d+)\s+)?secret\s+(\d+)\s+(\S+)',
                stripped, re.IGNORECASE
            )
            if m:
                uname = m.group(1)
                priv = int(m.group(2)) if m.group(2) else 1
                stype = int(m.group(3))
                val = m.group(4)
                decoded, sev = self._eval_secret(stype, val)
                if priv >= 15 and stype == 7:
                    sev = 'CRITICAL'
                creds.append({
                    'severity': sev,
                    'type': 'username_secret',
                    'username': uname,
                    'privilege': priv,
                    'secret_type': f'type{stype}',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': decoded,
                })
                continue

            m = re.match(
                r'^username\s+(\S+)\s+(?:privilege\s+(\d+)\s+)?secret\s+(\S+)',
                stripped, re.IGNORECASE
            )
            if m:
                uname = m.group(1)
                priv = int(m.group(2)) if m.group(2) else 1
                val = m.group(3)
                creds.append({
                    'severity': 'HIGH',
                    'type': 'username_secret',
                    'username': uname,
                    'privilege': priv,
                    'secret_type': 'type5',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': None,
                })
                continue

            # ---- username <name> password [type] <value> ----
            m = re.match(
                r'^username\s+(\S+)\s+(?:privilege\s+(\d+)\s+)?password\s+(\d+)\s+(\S+)',
                stripped, re.IGNORECASE
            )
            if m:
                uname = m.group(1)
                priv = int(m.group(2)) if m.group(2) else 1
                stype = int(m.group(3))
                val = m.group(4)
                decoded = self.decode_type7(val) if stype == 7 else (val if stype == 0 else None)
                sev = 'CRITICAL' if (stype == 7 and priv >= 15) else ('HIGH' if stype in (0, 7) else 'MEDIUM')
                creds.append({
                    'severity': sev,
                    'type': 'username_password',
                    'username': uname,
                    'privilege': priv,
                    'secret_type': f'type{stype}',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': decoded,
                })
                continue

            m = re.match(
                r'^username\s+(\S+)\s+(?:privilege\s+(\d+)\s+)?password\s+(\S+)',
                stripped, re.IGNORECASE
            )
            if m:
                uname = m.group(1)
                priv = int(m.group(2)) if m.group(2) else 1
                val = m.group(3)
                creds.append({
                    'severity': 'CRITICAL',
                    'type': 'username_password',
                    'username': uname,
                    'privilege': priv,
                    'secret_type': 'plaintext',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': val,
                })
                continue

            # ---- SNMP community ----
            m = re.match(
                r'^snmp-server\s+community\s+(\S+)(?:\s+(RO|RW))?',
                stripped, re.IGNORECASE
            )
            if m:
                community = m.group(1)
                access = (m.group(2) or 'RO').upper()
                is_default = community.lower() in ('public', 'private', 'cisco', 'admin')
                sev = 'CRITICAL' if is_default else ('HIGH' if access == 'RW' else 'MEDIUM')
                creds.append({
                    'severity': sev,
                    'type': 'snmp_community',
                    'username': None,
                    'secret_type': 'plaintext',
                    'value': community,
                    'access': access,
                    'default_string': is_default,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': community,
                })
                continue

            # ---- SNMP v3 user ----
            m = re.match(
                r'^snmp-server\s+user\s+(\S+)\s+(\S+)(?:\s+v3)?'
                r'(?:\s+auth\s+(\S+)\s+(\S+))?(?:\s+priv\s+(\S+)\s+(\S+))?',
                stripped, re.IGNORECASE
            )
            if m and 'snmp-server user' in stripped.lower():
                uname = m.group(1)
                group = m.group(2)
                auth_algo = m.group(3)
                auth_pass = m.group(4)
                priv_algo = m.group(5)
                priv_pass = m.group(6)
                entry = {
                    'severity': 'HIGH' if auth_pass else 'MEDIUM',
                    'type': 'snmp_v3_user',
                    'username': uname,
                    'group': group,
                    'secret_type': 'snmp_v3',
                    'value': auth_pass or '(no auth)',
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': auth_pass,
                }
                if priv_pass:
                    entry['priv_password'] = priv_pass
                creds.append(entry)
                continue

            # ---- TACACS key ----
            m = re.match(r'^tacacs(?:-server)?\s+key\s+(\d+)?\s*(\S+)', stripped, re.IGNORECASE)
            if m and 'tacacs' in stripped.lower() and 'key' in stripped.lower():
                stype_str = m.group(1)
                val = m.group(2)
                stype = int(stype_str) if stype_str else 0
                decoded = self.decode_type7(val) if stype == 7 else (val if stype == 0 else None)
                creds.append({
                    'severity': 'HIGH',
                    'type': 'tacacs_key',
                    'username': None,
                    'secret_type': f'type{stype}',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': decoded,
                })
                continue

            # ---- RADIUS key ----
            m = re.match(r'^radius(?:-server)?\s+key\s+(\d+)?\s*(\S+)', stripped, re.IGNORECASE)
            if m and 'radius' in stripped.lower() and 'key' in stripped.lower():
                stype_str = m.group(1)
                val = m.group(2)
                stype = int(stype_str) if stype_str else 0
                decoded = self.decode_type7(val) if stype == 7 else (val if stype == 0 else None)
                creds.append({
                    'severity': 'HIGH',
                    'type': 'radius_key',
                    'username': None,
                    'secret_type': f'type{stype}',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': decoded,
                })
                continue

            # ---- AAA server key ----
            m = re.match(r'^aaa-server\s+\S+\s+.*\s+key\s+(\S+)', stripped, re.IGNORECASE)
            if m:
                val = m.group(1)
                creds.append({
                    'severity': 'HIGH',
                    'type': 'aaa_server_key',
                    'username': None,
                    'secret_type': 'plaintext',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': val,
                })
                continue

            # ---- IPSec PSK (ISAKMP) ----
            m = re.match(
                r'^crypto\s+isakmp\s+key\s+(\S+)\s+address\s+(\S+)',
                stripped, re.IGNORECASE
            )
            if m:
                key = m.group(1)
                addr = m.group(2)
                creds.append({
                    'severity': 'HIGH',
                    'type': 'ipsec_psk',
                    'username': None,
                    'secret_type': 'plaintext',
                    'value': key,
                    'peer': addr,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': key,
                })
                continue

            # ---- IKEv2 pre-shared-key ----
            m = re.match(r'^\s*pre-shared-key\s+(?:local\s+|remote\s+)?(\S+)', stripped, re.IGNORECASE)
            if m:
                val = m.group(1)
                creds.append({
                    'severity': 'HIGH',
                    'type': 'ikev2_psk',
                    'username': None,
                    'secret_type': 'plaintext',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': val,
                })
                continue

            # ---- BGP MD5 password ----
            m = re.match(r'^\s*neighbor\s+(\S+)\s+password\s+(\d+)?\s*(\S+)', stripped, re.IGNORECASE)
            if m and 'neighbor' in stripped.lower() and 'password' in stripped.lower():
                peer = m.group(1)
                stype_str = m.group(2)
                val = m.group(3)
                stype = int(stype_str) if stype_str else 0
                decoded = self.decode_type7(val) if stype == 7 else (val if stype == 0 else None)
                creds.append({
                    'severity': 'MEDIUM',
                    'type': 'bgp_md5',
                    'username': None,
                    'peer': peer,
                    'secret_type': f'type{stype}',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': decoded,
                })
                continue

            # ---- OSPF message-digest-key ----
            m = re.match(
                r'^\s*ip\s+ospf\s+message-digest-key\s+\d+\s+md5\s+(\S+)',
                stripped, re.IGNORECASE
            )
            if m:
                val = m.group(1)
                creds.append({
                    'severity': 'MEDIUM',
                    'type': 'ospf_md5_key',
                    'username': None,
                    'secret_type': 'md5_key',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': val,
                })
                continue

            # ---- NTP authentication key ----
            m = re.match(
                r'^ntp\s+authentication-key\s+\d+\s+md5\s+(\S+)',
                stripped, re.IGNORECASE
            )
            if m:
                val = m.group(1)
                creds.append({
                    'severity': 'LOW',
                    'type': 'ntp_auth_key',
                    'username': None,
                    'secret_type': 'md5_key',
                    'value': val,
                    'line_num': lineno,
                    'context': stripped,
                    'decoded': val,
                })
                continue

        return sorted(creds, key=_sev_sort_key)

    def _eval_secret(self, stype: int, val: str):
        """Return (decoded_or_None, severity) for a secret type."""
        if stype == 0:
            return val, 'CRITICAL'  # plaintext
        if stype == 7:
            decoded = self.decode_type7(val)
            return decoded, 'CRITICAL'  # reversible
        if stype == 5:
            return None, 'HIGH'   # MD5 crypt — crackable offline
        if stype == 8:
            return None, 'MEDIUM'  # PBKDF2-SHA256
        if stype == 9:
            return None, 'MEDIUM'  # scrypt
        return None, 'HIGH'

    # ------------------------------------------------------------------
    # Weakness detection
    # ------------------------------------------------------------------

    def find_weak_config(self) -> list:
        """
        Returns list of {severity, title, detail, line_num, remediation}
        """
        weaknesses = []
        text_lower = self.text.lower()

        def _add(sev, title, detail, lineno, remediation):
            weaknesses.append({
                'severity': sev,
                'title': title,
                'detail': detail,
                'line_num': lineno,
                'remediation': remediation,
            })

        # Track which lines contain specific patterns
        def _find_line(pattern: str, flags=re.IGNORECASE) -> Optional[int]:
            for i, ln in enumerate(self.lines, 1):
                if re.search(pattern, ln, flags):
                    return i
            return None

        def _line_exists(pattern: str, flags=re.IGNORECASE) -> bool:
            return _find_line(pattern, flags) is not None

        # ---- no service password-encryption ----
        if _line_exists(r'no\s+service\s+password-encryption'):
            ln = _find_line(r'no\s+service\s+password-encryption')
            _add('CRITICAL', 'No Password Encryption',
                 'service password-encryption is disabled; all type-0 passwords visible in plaintext.',
                 ln, 'Add: service password-encryption')

        # ---- service password-encryption present but type-7 still weak ----
        elif _line_exists(r'service\s+password-encryption') and _line_exists(r'\s7\s+\S'):
            ln = _find_line(r'service\s+password-encryption')
            _add('HIGH', 'Type-7 Passwords in Use',
                 'service password-encryption only produces type-7 (Vigenere XOR), which is trivially reversible.',
                 ln, 'Replace type-7 passwords with type-9 (scrypt): username X secret 9 ...')

        # ---- no aaa new-model ----
        if not _line_exists(r'aaa\s+new-model'):
            _add('HIGH', 'No AAA New-Model',
                 'aaa new-model not found; centralized authentication framework disabled.',
                 None, 'Add: aaa new-model; configure TACACS+/RADIUS for centralized auth.')

        # ---- SNMP default community strings ----
        for default_str in ('public', 'private', 'cisco', 'admin'):
            pat = rf'snmp-server\s+community\s+{default_str}\b'
            if _line_exists(pat):
                ln = _find_line(pat)
                _add('CRITICAL', f'Default SNMP Community: {default_str}',
                     f'snmp-server community {default_str} — well-known string, trivial enumeration.',
                     ln, f'Remove; replace with randomized string and restrict with ACL.')

        # ---- SNMP community RW ----
        for i, ln in enumerate(self.lines, 1):
            m = re.search(r'snmp-server\s+community\s+(\S+)\s+RW', ln, re.IGNORECASE)
            if m:
                comm = m.group(1)
                if comm.lower() not in ('public', 'private', 'cisco', 'admin'):
                    _add('HIGH', 'SNMP Read-Write Community',
                         f'Community "{comm}" granted RW access — full device write via SNMP.',
                         i, 'Change to RO or remove; consider SNMPv3 authPriv.')

        # ---- telnet enabled on VTY ----
        in_vty = False
        vty_start = None
        for i, ln in enumerate(self.lines, 1):
            if re.match(r'\s*line\s+vty\s+\d+', ln, re.IGNORECASE):
                in_vty = True
                vty_start = i
            elif re.match(r'\s*line\s+', ln, re.IGNORECASE) and in_vty:
                in_vty = False
            if in_vty:
                if re.search(r'transport\s+input\s+(all|telnet)', ln, re.IGNORECASE):
                    _add('HIGH', 'Telnet Enabled on VTY',
                         f'VTY line (line ~{vty_start}) allows telnet; credentials sent in cleartext.',
                         i, 'Change to: transport input ssh')
                    break

        # ---- NX-OS feature telnet ----
        if self.platform == 'nxos' and _line_exists(r'feature\s+telnet'):
            ln = _find_line(r'feature\s+telnet')
            _add('HIGH', 'NX-OS Telnet Feature Enabled',
                 'feature telnet is active on NX-OS; unencrypted management access.',
                 ln, 'no feature telnet')

        # ---- SSH version 1 / no SSH v2 ----
        if _line_exists(r'ip\s+ssh\s+version\s+1') or (
            not _line_exists(r'ip\s+ssh\s+version\s+2') and _line_exists(r'ip\s+ssh')
        ):
            ln = _find_line(r'ip\s+ssh\s+version') or _find_line(r'ip\s+ssh')
            _add('MEDIUM', 'SSH Version 1 or Unspecified',
                 'SSH v1 is vulnerable to protocol-level attacks; v2 not explicitly enforced.',
                 ln, 'Add: ip ssh version 2')

        # ---- HTTP server (not HTTPS) ----
        if _line_exists(r'ip\s+http\s+server') and not _line_exists(r'no\s+ip\s+http\s+server'):
            ln = _find_line(r'ip\s+http\s+server')
            _add('HIGH', 'HTTP Management Server Enabled',
                 'ip http server enables unencrypted web management (not HTTPS).',
                 ln, 'no ip http server; enable ip http secure-server instead.')

        # ---- NX-OS ip http server ----
        if self.platform == 'nxos' and _line_exists(r'ip\s+http\s+server\s+enable'):
            ln = _find_line(r'ip\s+http\s+server\s+enable')
            _add('HIGH', 'NX-OS HTTP Management Enabled',
                 'HTTP management interface exposed (not HTTPS).',
                 ln, 'Disable HTTP; configure HTTPS with: ip http secure-server')

        # ---- exec-timeout 0 0 or no exec-timeout ----
        for i, ln in enumerate(self.lines, 1):
            if re.search(r'exec-timeout\s+0\s+0', ln, re.IGNORECASE):
                _add('MEDIUM', 'No Session Timeout',
                     'exec-timeout 0 0 disables idle session timeout — abandoned console/VTY sessions stay open.',
                     i, 'Set: exec-timeout 10 0 (10 minutes)')
                break

        if not _line_exists(r'exec-timeout'):
            _add('MEDIUM', 'No Exec-Timeout Configured',
                 'exec-timeout not found in config; idle sessions may not time out.',
                 None, 'Add exec-timeout under all line configurations.')

        # ---- config-register 0x2142 ----
        if _line_exists(r'config-register\s+0x2142'):
            ln = _find_line(r'config-register\s+0x2142')
            _add('CRITICAL', 'ROMMON Bypass Active (confreg 0x2142)',
                 'config-register 0x2142 instructs IOS to skip NVRAM on boot — password recovery mode; anyone with physical/console access can reload with no startup-config.',
                 ln, 'Set: config-register 0x2102 after confirming passwords are properly set.')

        # ---- logging: buffered but no host ----
        if _line_exists(r'logging\s+buffered') and not _line_exists(r'logging\s+host|logging\s+\d+\.\d+\.\d+\.\d+'):
            ln = _find_line(r'logging\s+buffered')
            _add('LOW', 'Logs Not Forwarded to SIEM',
                 'logging buffered configured but no logging host; syslog stays local only.',
                 ln, 'Add: logging host <siem_ip>')

        # ---- NTP without authentication ----
        if _line_exists(r'ntp\s+server') and not _line_exists(r'ntp\s+authenticate'):
            ln = _find_line(r'ntp\s+server')
            _add('MEDIUM', 'NTP Not Authenticated',
                 'ntp server configured without ntp authenticate; susceptible to NTP spoofing.',
                 ln, 'Add: ntp authenticate; ntp authentication-key <N> md5 <key>; ntp trusted-key <N>')

        # ---- enable password without enable secret (weaker hash) ----
        has_enable_secret = _line_exists(r'^enable\s+secret')
        has_enable_password = _line_exists(r'^enable\s+password')
        if has_enable_password and not has_enable_secret:
            ln = _find_line(r'^enable\s+password')
            _add('HIGH', 'enable password Without enable secret',
                 'enable password uses DES/type-7; enable secret uses MD5/scrypt and supersedes it.',
                 ln, 'Replace with: enable secret 9 <scrypt_hash>')

        # ---- username priv 15 + type-7 ----
        for i, ln in enumerate(self.lines, 1):
            m = re.match(
                r'^username\s+(\S+)\s+privilege\s+(\d+)\s+(?:password|secret)\s+7\s+(\S+)',
                ln.strip(), re.IGNORECASE
            )
            if m and int(m.group(2)) >= 15:
                _add('CRITICAL', f'Priv-15 User with Reversible Password: {m.group(1)}',
                     f'Username {m.group(1)} has privilege 15 and a type-7 (reversible) password.',
                     i, 'Upgrade to type-9 secret: username {m.group(1)} privilege 15 secret 9 <hash>')

        return sorted(weaknesses, key=_sev_sort_key)

    # ------------------------------------------------------------------
    # Topology mapping
    # ------------------------------------------------------------------

    def map_network_topology(self) -> dict:
        """
        Extract hostname, version, platform, interfaces, routing, VRFs, VLANs, ACLs, management.
        """
        topology = {
            'hostname': self.hostname,
            'version': self.version,
            'platform': self.platform,
            'interfaces': [],
            'routing': {
                'protocols': [],
                'bgp_peers': [],
                'ospf_areas': [],
                'eigrp_as': [],
                'static_routes': [],
            },
            'vrfs': [],
            'vlans': [],
            'acls': [],
            'management': {
                'tacacs_servers': [],
                'radius_servers': [],
                'ntp_servers': [],
                'syslog_servers': [],
                'snmp_hosts': [],
            },
        }

        # State machine for block parsing
        current_iface = None
        current_vrf = None
        current_acl = None
        in_router_block = None

        for idx, raw_line in enumerate(self.lines):
            ln = raw_line.strip()

            # ---- Interfaces ----
            m = re.match(r'^interface\s+(\S+)', ln, re.IGNORECASE)
            if m:
                if current_iface:
                    topology['interfaces'].append(current_iface)
                current_iface = {
                    'name': m.group(1),
                    'ip': None,
                    'mask': None,
                    'vlan': None,
                    'description': None,
                    'shutdown': False,
                    'ipv6': [],
                }
                current_vrf = None
                current_acl = None
                in_router_block = None
                continue

            if current_iface:
                if re.match(r'^\S', ln) and not ln.startswith('!') and not ln.startswith('#'):
                    # New top-level block
                    topology['interfaces'].append(current_iface)
                    current_iface = None
                else:
                    m = re.match(r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', ln, re.IGNORECASE)
                    if m:
                        current_iface['ip'] = m.group(1)
                        current_iface['mask'] = m.group(2)
                    m = re.match(r'description\s+(.*)', ln, re.IGNORECASE)
                    if m:
                        current_iface['description'] = m.group(1).strip()
                    if re.match(r'shutdown$', ln, re.IGNORECASE):
                        current_iface['shutdown'] = True
                    m = re.match(r'encapsulation\s+dot1q\s+(\d+)', ln, re.IGNORECASE)
                    if m:
                        current_iface['vlan'] = int(m.group(1))
                    m = re.match(r'switchport\s+access\s+vlan\s+(\d+)', ln, re.IGNORECASE)
                    if m:
                        current_iface['vlan'] = int(m.group(1))
                    m = re.match(r'ipv6\s+address\s+(\S+)', ln, re.IGNORECASE)
                    if m:
                        current_iface['ipv6'].append(m.group(1))

            # ---- VRFs ----
            m = re.match(r'^(?:ip\s+)?vrf\s+(?:definition\s+)?(\S+)', ln, re.IGNORECASE)
            if m:
                vrf_name = m.group(1)
                current_vrf = {'name': vrf_name, 'rd': None, 'route_targets': []}
                topology['vrfs'].append(current_vrf)
                continue
            if current_vrf:
                m = re.match(r'rd\s+(\S+)', ln, re.IGNORECASE)
                if m:
                    current_vrf['rd'] = m.group(1)
                m = re.match(r'route-target\s+(import|export)\s+(\S+)', ln, re.IGNORECASE)
                if m:
                    current_vrf['route_targets'].append({'direction': m.group(1), 'value': m.group(2)})

            # ---- VLANs ----
            m = re.match(r'^vlan\s+(\d+)$', ln, re.IGNORECASE)
            if m:
                vlan_id = int(m.group(1))
                if not any(v['id'] == vlan_id for v in topology['vlans']):
                    topology['vlans'].append({'id': vlan_id, 'name': None})
            m = re.match(r'^\s*name\s+(\S+)', ln, re.IGNORECASE)
            if m and topology['vlans']:
                topology['vlans'][-1]['name'] = m.group(1)

            # ---- ACLs ----
            m = re.match(r'^(?:ip\s+)?access-list\s+(standard|extended)\s+(\S+)', ln, re.IGNORECASE)
            if m:
                current_acl = {'name': m.group(2), 'type': m.group(1).lower(), 'entries_count': 0}
                topology['acls'].append(current_acl)
                continue
            m = re.match(r'^access-list\s+(\d+)\s+(\S+)', ln, re.IGNORECASE)
            if m:
                acl_num = m.group(1)
                acl_type = 'standard' if int(acl_num) <= 99 or 1300 <= int(acl_num) <= 1999 else 'extended'
                existing = next((a for a in topology['acls'] if a['name'] == acl_num), None)
                if existing:
                    existing['entries_count'] += 1
                else:
                    topology['acls'].append({'name': acl_num, 'type': acl_type, 'entries_count': 1})
                continue
            if current_acl and re.match(r'^\s+(permit|deny)', ln, re.IGNORECASE):
                current_acl['entries_count'] += 1

            # ---- Routing protocols ----
            m = re.match(r'^router\s+(\S+)(?:\s+(\S+))?', ln, re.IGNORECASE)
            if m:
                proto = m.group(1).lower()
                param = m.group(2)
                in_router_block = proto
                if proto not in topology['routing']['protocols']:
                    topology['routing']['protocols'].append(proto)
                if proto == 'bgp':
                    pass  # ASN is the param
                if proto == 'eigrp' and param:
                    topology['routing']['eigrp_as'].append(param)

            if in_router_block == 'bgp':
                m = re.match(r'^\s*neighbor\s+(\S+)\s+remote-as\s+(\d+)', ln, re.IGNORECASE)
                if m:
                    topology['routing']['bgp_peers'].append({'ip': m.group(1), 'remote_as': m.group(2)})

            if in_router_block == 'ospf':
                m = re.match(r'^\s*area\s+(\S+)', ln, re.IGNORECASE)
                if m and m.group(1) not in topology['routing']['ospf_areas']:
                    topology['routing']['ospf_areas'].append(m.group(1))

            # Static routes
            m = re.match(r'^ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)', ln, re.IGNORECASE)
            if m:
                topology['routing']['static_routes'].append({
                    'prefix': m.group(1),
                    'mask': m.group(2),
                    'nexthop': m.group(3),
                })

            # ---- Management ----
            m = re.match(r'^tacacs(?:-server)?\s+(?:host\s+|server\s+ip\s+)?(\d+\.\d+\.\d+\.\d+)', ln, re.IGNORECASE)
            if m:
                ip = m.group(1)
                if ip not in topology['management']['tacacs_servers']:
                    topology['management']['tacacs_servers'].append(ip)

            m = re.match(r'^radius(?:-server)?\s+(?:host\s+)?(\d+\.\d+\.\d+\.\d+)', ln, re.IGNORECASE)
            if m:
                ip = m.group(1)
                if ip not in topology['management']['radius_servers']:
                    topology['management']['radius_servers'].append(ip)

            m = re.match(r'^ntp\s+server\s+(?:vrf\s+\S+\s+)?(\S+)', ln, re.IGNORECASE)
            if m:
                srv = m.group(1)
                if srv not in topology['management']['ntp_servers']:
                    topology['management']['ntp_servers'].append(srv)

            m = re.match(r'^logging\s+(?:host\s+)?(\d+\.\d+\.\d+\.\d+)', ln, re.IGNORECASE)
            if m:
                ip = m.group(1)
                if ip not in topology['management']['syslog_servers']:
                    topology['management']['syslog_servers'].append(ip)

            m = re.match(r'^snmp-server\s+host\s+(\S+)', ln, re.IGNORECASE)
            if m:
                host = m.group(1)
                if host not in topology['management']['snmp_hosts']:
                    topology['management']['snmp_hosts'].append(host)

        # flush final interface
        if current_iface:
            topology['interfaces'].append(current_iface)

        return topology

    # ------------------------------------------------------------------
    # Attack surface
    # ------------------------------------------------------------------

    def find_attack_surface(self) -> list:
        """
        Returns externally-facing services and their configs:
        VTY lines, console, management interfaces, ACLs with wide-open permits.
        """
        surfaces = []

        in_line = False
        line_type = None
        line_start = None
        line_cfg = {}

        def _flush_line():
            if line_type and line_cfg:
                surfaces.append({
                    'type': 'line_' + line_type,
                    'line_num': line_start,
                    **line_cfg,
                })

        for i, raw_line in enumerate(self.lines, 1):
            ln = raw_line.strip()

            m = re.match(r'^line\s+(vty\s+\d+(?:\s+\d+)?|con\s+0|aux\s+0|tty\s+\d+)', ln, re.IGNORECASE)
            if m:
                _flush_line()
                line_type = m.group(1).split()[0].lower()  # vty, con, aux, tty
                line_start = i
                line_cfg = {
                    'raw': m.group(1),
                    'transport': 'all',  # default before override
                    'acl': None,
                    'exec_timeout': None,
                    'login': None,
                    'privilege': None,
                    'open': True,
                }
                in_line = True
                continue

            if in_line:
                if re.match(r'^\S', ln) and not ln.startswith('!'):
                    _flush_line()
                    in_line = False
                    line_type = None
                    line_cfg = {}
                else:
                    m = re.match(r'transport\s+input\s+(.*)', ln, re.IGNORECASE)
                    if m:
                        line_cfg['transport'] = m.group(1).strip()
                    m = re.match(r'access-class\s+(\S+)\s+(in|out)', ln, re.IGNORECASE)
                    if m:
                        line_cfg['acl'] = m.group(1)
                        line_cfg['open'] = False  # has ACL
                    m = re.match(r'exec-timeout\s+(\d+)\s+(\d+)', ln, re.IGNORECASE)
                    if m:
                        line_cfg['exec_timeout'] = f"{m.group(1)}m{m.group(2)}s"
                    m = re.match(r'login\s*(local|authentication\s+\S+)?', ln, re.IGNORECASE)
                    if m:
                        line_cfg['login'] = m.group(1) or 'default'
                    m = re.match(r'privilege\s+level\s+(\d+)', ln, re.IGNORECASE)
                    if m:
                        line_cfg['privilege'] = int(m.group(1))

        _flush_line()

        # Check ACLs that permit any source on mgmt-relevant ports
        for i, ln in enumerate(self.lines, 1):
            m = re.search(r'permit\s+(?:ip|tcp|udp)\s+any\s+any', ln, re.IGNORECASE)
            if m:
                surfaces.append({
                    'type': 'acl_any_permit',
                    'line_num': i,
                    'detail': ln.strip(),
                    'risk': 'HIGH — wildcard permit in ACL',
                })

        # HTTP/HTTPS management
        for i, ln in enumerate(self.lines, 1):
            if re.search(r'^ip\s+http\s+server\b', ln.strip(), re.IGNORECASE):
                surfaces.append({
                    'type': 'http_management',
                    'line_num': i,
                    'protocol': 'HTTP',
                    'port': 80,
                    'detail': ln.strip(),
                })
            if re.search(r'^ip\s+http\s+secure-server\b', ln.strip(), re.IGNORECASE):
                surfaces.append({
                    'type': 'http_management',
                    'line_num': i,
                    'protocol': 'HTTPS',
                    'port': 443,
                    'detail': ln.strip(),
                })

        # REST API / RESTCONF
        for i, ln in enumerate(self.lines, 1):
            if re.search(r'restconf', ln, re.IGNORECASE):
                surfaces.append({
                    'type': 'restconf',
                    'line_num': i,
                    'detail': ln.strip(),
                })
                break

        # NETCONF
        for i, ln in enumerate(self.lines, 1):
            if re.search(r'netconf', ln, re.IGNORECASE):
                surfaces.append({
                    'type': 'netconf',
                    'line_num': i,
                    'detail': ln.strip(),
                })
                break

        return surfaces

    # ------------------------------------------------------------------
    # Top-level analyze / report
    # ------------------------------------------------------------------

    def analyze(self) -> dict:
        return {
            'hostname': self.hostname,
            'version': self.version,
            'platform': self.platform,
            'credentials': self.extract_credentials(),
            'weaknesses': self.find_weak_config(),
            'topology': self.map_network_topology(),
            'attack_surface': self.find_attack_surface(),
        }

    def report(self) -> str:
        result = self.analyze()
        lines = [
            f"=== Cisco Config RE — {self.hostname or 'unknown'} [{self.platform}] ===",
            f"Version: {self.version or 'unknown'}",
            "",
            f"CREDENTIALS ({len(result['credentials'])}):",
        ]
        for c in result['credentials']:
            decoded = f" => DECODED: {c.get('decoded')}" if c.get('decoded') else ''
            lines.append(
                f"  [{c['severity']}] {c['type']} "
                f"user={c.get('username') or '-'} "
                f"type={c.get('secret_type','?')} "
                f"val={c.get('value','')[:40]}{decoded}"
            )
        lines.append("")
        lines.append(f"WEAKNESSES ({len(result['weaknesses'])}):")
        for w in result['weaknesses']:
            lines.append(f"  [{w['severity']}] {w['title']}")
            lines.append(f"           {w['detail']}")
            lines.append(f"           FIX: {w['remediation']}")
        lines.append("")
        lines.append(f"ATTACK SURFACE ({len(result['attack_surface'])}):")
        for s in result['attack_surface']:
            lines.append(f"  type={s['type']} line={s.get('line_num')} {s.get('detail','')[:80]}")
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Top-level function
# ---------------------------------------------------------------------------

def analyze_config(config_text_or_path: str) -> dict:
    """Top-level: accepts text string or file path. Returns unified findings."""
    import os
    if os.path.exists(config_text_or_path) and not config_text_or_path.startswith('\n'):
        try:
            with open(config_text_or_path, 'r', errors='replace') as fh:
                text = fh.read()
        except OSError:
            text = config_text_or_path
    else:
        text = config_text_or_path
    engine = CiscoConfigRE(text)
    return engine.analyze()


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    src = sys.argv[1] if len(sys.argv) > 1 else None
    if not src:
        print("Usage: cisco_config_re.py <config_file_or_->")
        sys.exit(1)
    if src == '-':
        text = sys.stdin.read()
    else:
        text = open(src, errors='replace').read()
    result = analyze_config(text)
    for c in result.get('credentials', []):
        t7 = f" => DECODED: {c.get('decoded')}" if c.get('decoded') else ''
        print(f"[{c['severity']}] {c['type']}: {str(c.get('value','?'))[:60]}{t7}")
    for w in result.get('weaknesses', []):
        print(f"[{w['severity']}] {w['title']}: {w['detail'][:100]}")
    print(json.dumps(result, indent=2, default=str))
