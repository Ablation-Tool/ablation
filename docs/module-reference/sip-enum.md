# SIP Enumeration

**File:** `modules/sip_enum.py`

## Why this exists

Four gaps existed before this module:

1. **SIP infrastructure had no full-coverage attack surface enumeration.** VoIP-specific probes — authentication bypass, extension enumeration, header injection, registration hijacking, DTMF exfiltration, covert channels — required manual scripting and were not part of the Ablation pipeline.

2. **H.323, SCCP (Skinny), and MGCP inspection surfaces were unprobed.** Legacy and Cisco VoIP protocols (H.323/Q.931, Cisco SCCP, MGCP) require exact packet framing not covered by generic scanners.

3. **ASA SIP fixup/normalization bypass detection required protocol-level crafting.** Conditions like bare-host Request-URI, Via spoofing, Content-Length:0 with non-empty body, and negative Expires bypass ASA SIP inspection; detecting them requires crafting malformed-but-parseable SIP messages.

4. **WebRTC signaling infrastructure (Janus, Jitsi, Coturn, Asterisk ARI) was unprobed.** Modern VoIP stacks expose REST and STUN/TURN surfaces not covered by SIP-specific tools.

---

## Scope

6006-line pure network I/O module. No filesystem reads. No subprocess calls. No lief usage. All probes are active (send + receive). Covers:
- SIP OPTIONS / REGISTER / INVITE / BYE / MESSAGE / NOTIFY / SUBSCRIBE / CANCEL probing
- SIP extension enumeration (OPTIONS differential, presence SUBSCRIBE)
- SIP authentication bypass (empty Authorization, zeroed Digest hash, Proxy-only auth)
- SIP registration hijacking (Expires:0 de-registration, forged Contact, contact disclosure)
- SIP header injection (CRLF injection, null byte in Contact, Via hijack, P-Asserted-Identity spoofing)
- SIP signaling manipulation (MESSAGE injection, CANCEL broadcast, NOTIFY injection, Max-Forwards:0)
- DTMF exfiltration surfaces (SIP INFO dtmf-relay, telephone-event NOTIFY, RFC 2833 RTP PT=101)
- RTP injection surface (sequence boundary, injection, DTMF digit theft)
- RTP/RTCP covert channel detection (dynamic PT 127, SSRC=0, RTCP APP "HACK", jumbo frames)
- SIP covert channel detection (binary octet-stream MESSAGE, PUBLISH/NOTIFY out-of-dialog, SIP-over-TCP)
- H.323 inspection surface (TCP/1720 Q.931 SETUP, H.245 tunneling, overlong alias bypass, UDP/1719 RAS GRQ)
- SCCP (Cisco Skinny) surface (RegisterMessage, KeepAlive, unsolicited OpenReceiveChannelAck)
- MGCP surface (AUEP wildcard, RQNT, CRCX without auth)
- ASA SIP fixup bypass (bare-host Request-URI, Via spoofing, Content-Length:0, negative Expires)
- SIP media interception (no SRTP, late media/offer-less INVITE, dialog SUBSCRIBE, SAVP absence)
- WebRTC: Janus Gateway REST API, Jitsi BOSH/config, Coturn STUN/TURN, Asterisk ARI

---

## Key API

```python
from modules.sip_enum import (
    SIPEnumerator,
    probe_h323_service,
    probe_sccp_skinny,
    probe_sip_options_extended,
    check_rtp_port_range,
    probe_webrtc_signaling,
    detect_sip_flood_surface,
    detect_tdos_indicators,
    detect_sip_eavesdropping_surface,
    probe_sip_authentication_weaknesses,
    detect_voip_eavesdrop_surface,
    detect_sip_interception_indicators,
    probe_rtp_injection_surface,
    detect_sip_signaling_manipulation,
    detect_dtmf_extraction_surface,
    probe_rtp_dtmf_digit_theft,
    detect_h323_inspection_surface,
    detect_sccp_skinny_surface,
    detect_mgcp_surface,
    probe_asa_sip_fixup_legacy,
    detect_voip_covert_channel,
    probe_rtp_covert_channel,
    probe_sip_authentication_bypass,
    probe_sip_enumeration,
    probe_sip_registration_hijacking,
    probe_sip_media_interception,
    probe_webrtc_signaling_exposure,
    probe_h323_and_media_gateway,
)

# Class-based full SIP surface scan
enum = SIPEnumerator(host='10.0.0.1', port=5060, timeout=5.0)
findings = enum.enumerate_all()

# Standalone probes (return list of finding dicts)
findings = probe_sip_authentication_bypass('10.0.0.1', port=5060)
findings += probe_sip_enumeration('10.0.0.1', port=5060)
findings += probe_sip_registration_hijacking('10.0.0.1', port=5060)
findings += probe_sip_media_interception('10.0.0.1', port=5060)
findings += detect_sip_signaling_manipulation('10.0.0.1', port=5060)
findings += detect_dtmf_extraction_surface('10.0.0.1', port=5060)
findings += probe_rtp_dtmf_digit_theft('10.0.0.1', rtp_port=8000)
findings += detect_h323_inspection_surface('10.0.0.1', port=1720)
findings += detect_sccp_skinny_surface('10.0.0.1', port=2000)
findings += detect_mgcp_surface('10.0.0.1', port=2427)
findings += probe_asa_sip_fixup_legacy('10.0.0.1', port=5060)
findings += detect_voip_covert_channel('10.0.0.1', port=5060)
findings += probe_rtp_covert_channel('10.0.0.1', rtp_port=16384)
findings += probe_webrtc_signaling_exposure('10.0.0.1', port=8443)
findings += probe_h323_and_media_gateway('10.0.0.1', port=1720)
```

All probe functions return `list[dict]` with keys: `severity`, `title`, `detail`, `host`, `port`.

---

## FORGE audit

Gate: **PASSED**. One dead-code fix applied.

| Fix | Location | Description |
|---|---|---|
| Duplicate `return findings` | `probe_rtp_covert_channel` (line 4567) | Removed unreachable second `return findings` at end of function |

**Security checks:**
- No file I/O anywhere in the module — no CWE-770 concerns.
- No `lief.parse()` — no CWE-755 (lief null return) concerns.
- No bare `except:` — all exception handlers use `except Exception:`, `except OSError:`, or `except (socket.timeout, OSError):`.
- All socket receives are bounded: `recvfrom(2048)`, `recvfrom(4096)`, `recvfrom(8192)`, `recvfrom(65535)` are UDP network buffers, not file reads.
- HTTP reads in `probe_webrtc_signaling_exposure._http_get()` bounded at `resp.read(65536)` (64 KB).
- All sockets use `settimeout()` before any send/receive operation.
- No subprocess calls.

**Known residual:**
- `probe_rtp_dtmf_digit_theft._port_unreachable()` uses raw ICMP socket requiring `CAP_NET_RAW`. On systems without the capability, it silently returns `False` (port assumed open). This is the correct safe fallback.
- `probe_webrtc_signaling_exposure` uses `ssl.CERT_NONE` — intentional for probing self-signed TLS on management ports.
