# SIP Enumeration

**File:** `modules/sip_enum.py`

## Why this exists

Three gaps existed before this module:

1. **SIP infrastructure exposure not enumerated in the Ablation pipeline.** VoIP attack surfaces — SIP registrar authentication bypass, Asterisk Manager Interface exposure, H.323 signaling, and SCCP (Skinny) — were not covered by any existing network enumeration module.

2. **SIP OPTIONS scanning required manual crafting.** Building a valid SIP OPTIONS request with the correct Via, Contact, and From headers for a target requires precise protocol knowledge. The module generates RFC-3261-compliant SIP messages for OPTIONS, REGISTER, and INVITE probes.

3. **Asterisk AMI default credential check was session-scripted.** `detect_asterisk_ami()` tests default AMI credentials and checks for unauthenticated command execution paths in one call.

## Key functions

| Function | Description |
|---|---|
| `enumerate_sip(host, port)` | Full SIP surface: OPTIONS, auth challenge, extension enum |
| `detect_asterisk_ami(host)` | Asterisk Manager Interface default credential check |
| `detect_h323_signaling(host, port)` | H.323 TPKT probe on TCP 1720 |
| `detect_sccp(host, port)` | Cisco Skinny (SCCP) protocol probe |
| `check_sip_websocket(host, port)` | SIP-over-WebSocket (RFC 7118) detection |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings.

- All socket reads are bounded: `recv(1024)` for SIP/AMI banners and H.323/SCCP responses, `recv(2048)` for WebSocket upgrade response, `recvfrom(4096)` for UDP SIP responses.
- No file reads. No HTTP response body reads. No lief.parse().
- All sockets have `settimeout()` before use.
