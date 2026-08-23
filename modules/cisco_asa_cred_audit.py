"""
cisco_asa_cred_audit.py — Cisco ASA credential and config auditor.

Two modes:
  CiscoASAConfigAudit  — offline: parse a running-config for weak/default secrets
  CiscoASALiveCredCheck — online:  probe live ASA management interfaces with default creds

Authorized assessment use only.
"""

import re
import socket
import ssl
import threading
from typing import Optional

# ── Type 7 XOR key (Cisco standard, 16-byte cycle) ───────────────────────────
_TYPE7_XLAT = [
    0x64, 0x73, 0x66, 0x64, 0x3B, 0x6B, 0x66, 0x38,
    0x38, 0x6C, 0x6B, 0x38, 0x53, 0x6B, 0x66, 0x38,
]

# ── Known default/weak values ─────────────────────────────────────────────────
_WEAK = {
    "cisco", "admin", "password", "default", "secret", "radius", "tacacs",
    "snmp", "public", "private", "community", "key", "token", "jwt",
    "vpn", "1234", "12345", "123456", "1111", "test", "guest",
}

# Known Type 7 encodings for default passwords (seed-0 and seed-8 variants)
# Generated from: encode('cisco',8)=085B05185B3C, encode('cisco',0)=00071A150754
# encode('admin',8)=08590806513D, encode('admin',0)=0005170B0D55
# encode('password',8)=08480D184B2404145C
_DEFAULT_TYPE7 = {
    "085B05185B3C", "00071A150754",   # cisco
    "08590806513D", "0005170B0D55",   # admin
    "08480D184B2404145C",             # password
}

# Known Type 5 (MD5) default hashes
_DEFAULT_TYPE5 = {"$1$k9K1j6rE$2KFQnbNIdI.2KYOU"}


def cisco_type7_decode(enc: str) -> str:
    """Decode a Cisco Type 7 obfuscated password string."""
    try:
        seed = int(enc[:2])
        enc = enc[2:]
        result = []
        for i in range(0, len(enc), 2):
            b = int(enc[i:i+2], 16)
            result.append(chr(b ^ _TYPE7_XLAT[(seed + i // 2) % 16]))
        return "".join(result)
    except Exception as e:
        return f"<decode error: {e}>"


def _is_weak(val: str) -> bool:
    return val.lower() in _WEAK or len(val) < 8


# ─────────────────────────────────────────────────────────────────────────────
class CiscoASAConfigAudit:
    """
    Offline audit of a Cisco ASA running-config for weak/default secrets,
    decodable Type 7 passwords, and credential exposure.

    Usage:
        with open("asa_running_config.txt") as f:
            audit = CiscoASAConfigAudit(f.read())
        for finding in audit.run():
            print(finding)
    """

    NAME = 'cisco_asa_config_audit'
    DESCRIPTION = 'Cisco ASA running-config offline credential audit'

    def __init__(self, config_text: str):
        self.config = config_text
        self._findings: list[dict] = []

    def _finding(self, fid: str, sev: str, title: str, detail: str,
                 evidence: dict | None = None):
        self._findings.append({
            'id':       fid,
            'severity': sev,
            'title':    title,
            'detail':   detail,
            'evidence': evidence or {},
        })

    def run(self) -> list[dict]:
        self._check_type7()
        self._check_enable_secret()
        self._check_radius()
        self._check_tacacs()
        self._check_snmp()
        self._check_vpn_psk()
        self._check_snmpv3()
        self._check_private_key()
        self._check_saml()
        self._check_webvpn()
        self._check_ike_psk()
        return self._findings

    def _check_type7(self):
        matches = re.findall(r'password 7 (\S+)', self.config)
        for enc in matches:
            decoded = cisco_type7_decode(enc)
            sev = 'CRITICAL' if enc in _DEFAULT_TYPE7 else ('HIGH' if _is_weak(decoded) else 'MEDIUM')
            self._finding('ASA_TYPE7', sev,
                f'Type 7 password: decoded = "{decoded}"',
                'Type 7 is reversible XOR obfuscation, not encryption. '
                'Any party with the config can recover the plaintext immediately.',
                {'encoded': enc, 'decoded': decoded})

    def _check_enable_secret(self):
        for t, h in re.findall(r'enable secret (\d) (\S+)', self.config):
            if t == '5':
                sev = 'CRITICAL' if h in _DEFAULT_TYPE5 else 'INFO'
                self._finding('ASA_ENABLE_SECRET_5', sev,
                    f'Enable secret Type 5 (MD5-crypt): {"DEFAULT HASH" if sev == "CRITICAL" else "custom"}',
                    'MD5-crypt ($1$) is crackable with hashcat/john. '
                    'If default hash found, plaintext = "cisco".',
                    {'hash': h, 'type': t})
            elif t == '7':
                decoded = cisco_type7_decode(h)
                self._finding('ASA_ENABLE_SECRET_7', 'CRITICAL',
                    f'Enable secret stored as Type 7 — reversible! decoded = "{decoded}"',
                    'Enable secret should never be Type 7; use enable secret (Type 5/8/9).',
                    {'encoded': h, 'decoded': decoded})
            elif t in ('8', '9'):
                self._finding('ASA_ENABLE_SECRET_89', 'INFO',
                    f'Enable secret Type {t} (PBKDF2/scrypt) — not directly crackable',
                    'Type 8 = PBKDF2-SHA256, Type 9 = scrypt. Strong if password is strong.',
                    {'hash': h[:24] + '...', 'type': t})

    def _check_radius(self):
        # ASA config: aaa-server <name> (<iface>) host <ip> key <secret>
        #   or: radius-server host <ip> key <secret>
        patterns = [
            r'aaa-server [^\n]+ key (\S+)',
            r'radius-server host [^\n]+ key (\S+)',
        ]
        found = []
        for pat in patterns:
            found.extend(re.findall(pat, self.config))

        for secret in found:
            if secret.startswith('*'):
                self._finding('ASA_RADIUS_SECRET_MASKED', 'INFO',
                    'RADIUS shared secret is masked in config output',
                    'Run "more system:running-config" or check ISE for plaintext value.',
                    {})
                continue
            sev = 'CRITICAL' if _is_weak(secret) else 'MEDIUM'
            self._finding('ASA_RADIUS_SECRET', sev,
                f'RADIUS shared secret: "{secret}" — {"WEAK" if sev == "CRITICAL" else "found"}',
                'RADIUS shared secret is the sole integrity anchor for Access-Accept packets. '
                'A known secret allows forging responses → F1/F2 exploit chain is unlocked.',
                {'secret': secret, 'weak': _is_weak(secret)})

    def _check_tacacs(self):
        matches = re.findall(r'tacacs-server key (\S+)', self.config)
        for key in matches:
            sev = 'HIGH' if _is_weak(key) else 'INFO'
            self._finding('ASA_TACACS_KEY', sev,
                f'TACACS+ key: "{key}"',
                'TACACS+ body is MD5-encrypted with this key. Weak key = known-plaintext attack possible.',
                {'key': key, 'weak': _is_weak(key)})

    def _check_snmp(self):
        communities = re.findall(r'snmp-server community (\S+)', self.config)
        for comm in communities:
            sev = 'CRITICAL' if comm.lower() in ('public', 'private') else \
                  ('HIGH' if _is_weak(comm) else 'INFO')
            self._finding('ASA_SNMP_COMMUNITY', sev,
                f'SNMP community string: "{comm}"',
                'Default/weak SNMP community gives read (or write) access to MIB including '
                'interface table, routing table, and config via SNMP SET.',
                {'community': comm, 'severity_reason': 'default' if sev == 'CRITICAL' else 'weak'})

    def _check_vpn_psk(self):
        matches = re.findall(r'pre-shared-key (?:\d )?(\S+)', self.config)
        for psk in matches:
            # could be a type7 if prefixed: pre-shared-key * (masked) — skip
            if psk.startswith('*') or psk.isdigit():
                continue
            sev = 'HIGH' if _is_weak(psk) else 'INFO'
            self._finding('ASA_VPN_PSK', sev,
                f'VPN IKE pre-shared key: "{psk}"',
                'IKE PSK used for IPsec/IKEv2 tunnel auth. Weak PSK → offline dictionary attack '
                'against captured IKE_INIT exchange.',
                {'psk': psk, 'weak': _is_weak(psk)})

    def _check_snmpv3(self):
        matches = re.findall(
            r'snmp-server user (\S+) (\S+) v3 auth (\S+) (\S+)', self.config)
        for user, group, auth, priv in matches:
            if _is_weak(auth):
                self._finding('ASA_SNMPV3_AUTH', 'HIGH',
                    f'Weak SNMPv3 auth key for user "{user}": "{auth}"',
                    'SNMPv3 auth/priv keys protect MIB access integrity and confidentiality.',
                    {'user': user, 'auth_key': auth, 'priv_key': priv})

    def _check_private_key(self):
        if 'private-key' in self.config and 'BEGIN' in self.config:
            self._finding('ASA_PRIVATE_KEY_IN_CONFIG', 'CRITICAL',
                'Private key material found in running-config',
                'TLS/VPN private key exported in plaintext. Anyone with config access can '
                'decrypt all historical TLS sessions.',
                {})

    def _check_saml(self):
        matches = re.findall(r'saml idp trustpoint (\S+)', self.config)
        for tp in matches:
            if 'default' in tp.lower() or 'cisco' in tp.lower() or 'test' in tp.lower():
                self._finding('ASA_SAML_TRUSTPOINT', 'HIGH',
                    f'Suspicious SAML trustpoint name: "{tp}"',
                    'Default/test SAML trustpoint may use a known or self-signed cert.',
                    {'trustpoint': tp})

    def _check_webvpn(self):
        cookies = re.findall(r'webvpn cookie (\S+)', self.config)
        for c in cookies:
            if _is_weak(c):
                self._finding('ASA_WEBVPN_COOKIE', 'HIGH',
                    f'Weak WebVPN cookie secret: "{c}"',
                    'WebVPN session cookie secret used for HMAC integrity of clientless VPN cookies.',
                    {'cookie_secret': c})

    def _check_ike_psk(self):
        # IKEv1: crypto map ... set peer ... / tunnel-group ... ipsec-attributes / pre-shared-key
        # IKEv2: tunnel-group ... ipsec-attributes / ikev2 local-authentication pre-shared-key
        matches = re.findall(r'ikev2 (?:local|remote)-authentication pre-shared-key (\S+)', self.config)
        for psk in matches:
            sev = 'HIGH' if _is_weak(psk) else 'INFO'
            self._finding('ASA_IKEV2_PSK', sev,
                f'IKEv2 pre-shared key: "{psk}"',
                'IKEv2 PSK. Weak value → offline dictionary against captured IKE_SA_INIT exchange.',
                {'psk': psk, 'weak': _is_weak(psk)})


# ─────────────────────────────────────────────────────────────────────────────
class CiscoASALiveCredCheck:
    """
    Live default credential checks against a Cisco ASA management interface.

    Checks: HTTPS (ASDM /admin/), SSH, SNMP community.
    All checks run in parallel threads; results collected into findings.

    Requires: requests, paramiko (optional), pysnmp (optional)
    Authorized assessment targets only.
    """

    NAME = 'cisco_asa_live_cred'
    DESCRIPTION = 'Cisco ASA live default credential probe (HTTPS/SSH/SNMP)'

    DEFAULT_USERS = ['admin', 'cisco', 'enable', 'pix']
    DEFAULT_PASSWORDS = ['cisco', 'admin', 'password', 'default', '1234', '12345', '']
    DEFAULT_COMMUNITIES = ['public', 'private', 'cisco', 'community', 'admin']

    def __init__(self, host: str, timeout: int = 5,
                 usernames: list[str] | None = None,
                 passwords: list[str] | None = None,
                 communities: list[str] | None = None):
        self.host = host
        self.timeout = timeout
        self.usernames = usernames or self.DEFAULT_USERS
        self.passwords = passwords or self.DEFAULT_PASSWORDS
        self.communities = communities or self.DEFAULT_COMMUNITIES
        self._findings: list[dict] = []
        self._lock = threading.Lock()

    def _finding(self, fid, sev, title, detail, evidence=None):
        with self._lock:
            self._findings.append({
                'id': fid, 'severity': sev,
                'title': title, 'detail': detail,
                'evidence': evidence or {},
            })

    def run(self) -> list[dict]:
        threads = [
            threading.Thread(target=self._check_https, daemon=True),
            threading.Thread(target=self._check_ssh,   daemon=True),
            threading.Thread(target=self._check_snmp,  daemon=True),
            threading.Thread(target=self._check_tls_cert, daemon=True),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=self.timeout * len(self.usernames) * len(self.passwords) + 10)
        return self._findings

    def _check_https(self):
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            import urllib3
            urllib3.disable_warnings()
        except ImportError:
            self._finding('ASA_HTTPS_SKIP', 'INFO',
                'HTTPS check skipped', 'requests not installed.', {})
            return

        endpoints = ['/admin/', '/admin/exec/', '+webvpn+/index.html']
        for user in self.usernames:
            for pwd in self.passwords:
                for ep in endpoints:
                    try:
                        url = f'https://{self.host}{ep}'
                        r = requests.get(url,
                                         auth=HTTPBasicAuth(user, pwd),
                                         verify=False, timeout=self.timeout,
                                         allow_redirects=False)
                        if r.status_code in (200, 302, 301) and \
                           r.status_code not in (401, 403):
                            self._finding('ASA_DEFAULT_HTTPS_CRED', 'CRITICAL',
                                f'Default HTTPS credentials accepted: {user}/{pwd}',
                                f'ASA management interface at {url} returned {r.status_code} '
                                f'with default credentials.',
                                {'user': user, 'password': pwd,
                                 'endpoint': ep, 'status': r.status_code})
                            return
                    except Exception:
                        pass

    def _check_ssh(self):
        try:
            import paramiko
        except ImportError:
            self._finding('ASA_SSH_SKIP', 'INFO',
                'SSH check skipped', 'paramiko not installed.', {})
            return

        for user in self.usernames:
            for pwd in self.passwords:
                t = None
                try:
                    t = paramiko.Transport((self.host, 22))
                    t.connect(username=user, password=pwd)
                    self._finding('ASA_DEFAULT_SSH_CRED', 'CRITICAL',
                        f'Default SSH credentials accepted: {user}/{pwd}',
                        f'ASA SSH management at {self.host}:22 authenticated with default creds.',
                        {'user': user, 'password': pwd})
                    t.close()
                    return
                except paramiko.AuthenticationException:
                    pass
                except Exception:
                    pass
                finally:
                    if t and t.is_active():
                        t.close()

    def _check_snmp(self):
        try:
            from pysnmp.hlapi import (
                getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity,
            )
        except ImportError:
            self._finding('ASA_SNMP_SKIP', 'INFO',
                'SNMP check skipped', 'pysnmp not installed.', {})
            return

        for community in self.communities:
            try:
                iterator = getCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=0),
                    UdpTransportTarget(
                        (self.host, 161), timeout=2, retries=0),
                    ContextData(),
                    ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
                )
                err_indication, err_status, _, var_binds = next(iterator)
                if err_indication is None and not err_status:
                    descr = str(var_binds[0][1]) if var_binds else ''
                    self._finding('ASA_DEFAULT_SNMP_COMMUNITY', 'HIGH',
                        f'Default SNMP community accepted: "{community}"',
                        f'ASA SNMP at {self.host}:161 responded to community "{community}". '
                        f'sysDescr: {descr[:120]}',
                        {'community': community, 'sysDescr': descr[:120]})
                    return
            except Exception:
                pass

    def _check_tls_cert(self):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                    (self.host, 443), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.host) as s:
                    cert = s.getpeercert(binary_form=False)
                    if cert:
                        subject = {k: v for tup in cert.get('subject', [])
                                   for k, v in tup}
                        issuer  = {k: v for tup in cert.get('issuer', [])
                                   for k, v in tup}
                        is_self_signed = subject == issuer
                        org = subject.get('organizationName', '')
                        cn  = subject.get('commonName', '')
                        if is_self_signed or 'cisco' in org.lower() or \
                           'cisco' in cn.lower() or 'asa' in cn.lower():
                            self._finding('ASA_DEFAULT_TLS_CERT', 'MEDIUM',
                                f'Default or self-signed TLS certificate: CN={cn}, Org={org}',
                                'Default Cisco TLS cert indicates factory config or unconfigured PKI. '
                                'Self-signed = ASDM will not warn on MITM with any cert (av.class bypass).',
                                {'cn': cn, 'org': org, 'self_signed': is_self_signed,
                                 'issuer_cn': issuer.get('commonName', '')})
        except Exception:
            pass
