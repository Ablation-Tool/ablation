# SIP Attack Surface Detection

Detect telephony denial-of-service surfaces, eavesdropping vectors, call-interception primitives, authentication bypass conditions, signaling manipulation surfaces, and header injection attack paths across SIP deployments: using twelve standalone probe functions from `sip_enum.py`.

---

## Why this exists

1. **SIP servers that accept unlimited INVITE bursts without rate limiting, that do not require ACK before call setup completes, and that allow large Contact URI registration batches are vulnerable to telephony denial-of-service (TDoS) without any authentication credential.** Standard network scanners cannot identify these surfaces because TDoS vectors require SIP-dialect message construction: half-open INVITE floods INVITE without ACK consumes call-state memory, oversized Contact URI registration (100 unique Contact URIs per AoR saturates the registrar's binding table), and malformed INVITEs with no Via header test parser robustness. `detect_sip_flood_surface()` and `detect_tdos_indicators()` apply three distinct resource-exhaustion probes each, producing actionable `INVITE_FLOOD_SURFACE`, `REGISTER_EXHAUSTION`, and `TDOS_CALLER_ID_SPOOF` findings.

2. **SIP eavesdropping does not require decryption, it requires only the ability to subscribe to presence events, receive unsolicited NOTIFY messages, or intercept codec negotiation details from SDP bodies.** An adversary with network access to UDP/5060 can learn which extensions are on active calls SUBSCRIBE Event:presence, determine codec and media IP assignments from multi-codec SDP offers (PCMU vs G.729 vs iLBC), and identify RTCP out-of-band signaling ports that expose call quality metrics. `detect_sip_eavesdropping_surface()` and `detect_voip_eavesdrop_surface()` map these surfaces without media capture, identifying where SRTP enforcement is absent and where RTCP streams are reachable.

3. **SIP signaling manipulation: REFER-based blind call transfer, re-INVITE c= redirect to an attacker IP, forged UPDATE with fabricated To-tag, and SIP header injection: produces call-interception and privilege escalation primitives that are completely invisible to DLP and network IDS signatures because the traffic uses standard SIP method codes and valid SIP grammar.** `detect_sip_interception_indicators()`, `detect_sip_signaling_manipulation()`, `detect_sip_header_injection()`, `probe_sip_authentication_weaknesses()`, and `probe_sip_authentication_bypass()` cover the full manipulation and bypass surface, from nonce replay through P-Asserted-Identity spoofing.

---

## How it works

```mermaid
flowchart TD
    A(["detect_sip_flood_surface(host, port=5060)"]):::input --> B(["3 half-open INVITEs to ext 100 (no ACK sent)\nAny non-timeout response → INVITE_FLOOD_SURFACE (HIGH)\n(each call leg consumes server state without cleanup)"]):::output
    A:::input --> C(["Malformed INVITE: no Via header\nAny non-5xx → SIP_FLOOD_MALFORMED (HIGH)\n(parser should return 400 but may crash or accept)"]):::output
    A:::input --> D(["REGISTER Contact: <sip:x@probe.invalid:5060;tag=...> × 8KB URI\nAny non-413 → SIP_LARGE_CONTACT_ACCEPT (MEDIUM)"]):::output

    E(["detect_tdos_indicators(host, port=5060)"]):::input --> F(["INVITE From: sip:FBI@<host>\n100/180/200 → TDOS_CALLER_ID_SPOOF (HIGH)\n(Caller-ID spoofing accepted without PAI validation)"]):::output
    E:::input --> G(["10 rapid OPTIONS in 1s → measure response count\nAll 10 answered → TDOS_RATE_UNLIMITED (MEDIUM)\n(no rate limiting on keepalive traffic)"]):::output
    E:::input --> H(["100 REGISTER with unique Contact URIs for one AoR\n200 each → REGISTER_EXHAUSTION (HIGH)\n(no per-AoR Contact binding limit)"]):::output

    I(["detect_sip_eavesdropping_surface(host, port=5060)"]):::input --> J(["SUBSCRIBE Event:presence to ext 100\n200 → PRESENCE_SUBSCRIBE_OPEN (MEDIUM)\n(real-time call state without auth)"]):::output
    I:::input --> K(["Unsolicited NOTIFY to extension 100\nAny non-481/489 → UNSOLICITED_NOTIFY_ACCEPTED (MEDIUM)\n(out-of-dialog NOTIFY accepted without subscription state)"]):::output
    I:::input --> L(["INVITE SDP with PCMU + G729 + iLBC\nParse 200 SDP answer for codec selection\nSDP_CODEC_DISCLOSED (LOW) · codec fingerprint exposed"]):::output

    M(["detect_voip_eavesdrop_surface(host, port=5060)"]):::input --> N(["INVITE RTP/AVP → check SDP answer for SRTP/SAVP\n200 without SAVP → SRTP_NOT_ENFORCED (MEDIUM)\n(confirms unencrypted media path)"]):::output
    M:::input --> O(["UDP/5005 RTCP probe (RTP port+1)\nBinding response → RTCP_EXPOSED (MEDIUM)\n(call quality metrics + SSRC values exposed)"]):::output
    M:::input --> P(["STUN/TURN ChannelBind 0x0009 to UDP/3478\nNon-error response → TURN_CHANNEL_BIND_OPEN (HIGH)\n(relay channel allocatable without credential)"]):::output

    Q(["detect_sip_interception_indicators(host, port=5060)"]):::input --> R(["REFER sip:200@host Refer-To: sip:attacker@external\n202 Accepted → REFER_UNAUTH (CRITICAL)\n(blind call transfer to external number without auth)"]):::output
    Q:::input --> S(["UPDATE with fabricated To-tag (mid-dialog)\nAny non-481 → UPDATE_TAG_SPOOF (HIGH)\n(session parameter update accepted without dialog state)"]):::output
    Q:::input --> T(["PRACK for non-existent 1xx provisional\nAny non-481 → PRACK_TOPOLOGY_LEAK (MEDIUM)\n(PRACK reveals RFC3262 support · topology info)"]):::output
    Q:::input --> U(["re-INVITE with c=IN IP4 <attacker-ip>\n200 → REINVITE_MEDIA_REDIRECT (CRITICAL)\n(media redirected to attacker-controlled endpoint)"]):::output

    V(["detect_sip_signaling_manipulation(host, port=5060)"]):::input --> W(["SIP MESSAGE with injected X-header\n200 → MESSAGE_INJECTION_ACCEPT (HIGH)\n(arbitrary SIP message body and headers accepted)"]):::output
    V:::input --> X(["CANCEL for non-existent call-ID\nAny non-481 → CANCEL_BROADCAST_SURFACE (MEDIUM)\n(CANCEL without matching dialog not properly rejected)"]):::output
    V:::input --> Y(["NOTIFY with MWI Event:message-summary\nAny non-489 → MWI_NOTIFY_ACCEPTED (MEDIUM)\n(unsolicited MWI NOTIFY accepted by endpoint)"]):::output
    V:::input --> Z(["OPTIONS Max-Forwards: 0 (must return 483 Too Many Hops)\n200 instead of 483 → MAX_FORWARDS_BYPASS (MEDIUM)\n(loop-detection mechanism not enforced)"]):::output

    AA(["probe_sip_authentication_weaknesses(host, port=5060)"]):::input --> AB(["REGISTER with fabricated uuid4 nonce in Authorization\n200 → NONCE_REPLAY_ACCEPTED (CRITICAL)\n(server not maintaining nonce state · replay possible)"]):::output
    AA:::input --> AC(["REGISTER with empty Digest response=''\n200 → EMPTY_DIGEST_ACCEPTED (CRITICAL)\n(Digest validation entirely absent)"]):::output
    AA:::input --> AD(["REGISTER with Expires:0 (de-register)\n200 without prior 401 → UNAUTH_DEREGISTER (CRITICAL)"]):::output

    AE(["probe_sip_authentication_bypass(host, port=5060)"]):::input --> AF(["REGISTER with empty Authorization: Digest username=... header (all fields present, all empty)\n200 → SIP_AUTH_BYPASS (CRITICAL)\n(syntactically present but empty auth accepted)"]):::output
    AE:::input --> AG(["INVITE From: <sip:anonymous@anonymous.invalid>\n100/183/200 → SIP_UNAUTH_INVITE (HIGH)\n(anonymous INVITE accepted · no From validation)"]):::output
    AE:::input --> AH(["REGISTER Authorization: Digest response='00000000000000000000000000000000'\n200 → SIP_DIGEST_BYPASS (CRITICAL)\n(zeroed MD5 hash accepted · digest not recomputed)"]):::output
    AE:::input --> AI(["REGISTER → probe challenge type\n407 Proxy-Auth only (no WWW-Auth) → SIP_PROXY_AUTH_ONLY (MEDIUM)\n(endpoint relies on proxy; direct connections bypass auth)"]):::output

    AJ(["detect_sip_header_injection(host, port=5060)"]):::input --> AK(["INVITE From: 'X-Injected: ablation-header-test\\r\\nVia: ...' (CRLF in display name)\nRequest accepted → HEADER_INJECTION_CRLF (HIGH)\n(CRLF injection into SIP headers via display name)"]):::output
    AJ:::input --> AL(["REGISTER Contact: sip:x@host%00.example.com (null byte in URI)\nRequest accepted → CONTACT_NULL_BYTE (MEDIUM)\n(null byte in SIP URI not sanitized)"]):::output
    AJ:::input --> AM(["INVITE Via: SIP/2.0/UDP 203.0.113.1:5060 (RFC5737 TEST-NET)\nRequest processed → VIA_STACK_SPOOF (HIGH)\n(attacker can inject Via hop into response path)"]):::output
    AJ:::input --> AN(["INVITE P-Asserted-Identity: <sip:ceo@<host>>\nRequest accepted → PAI_SPOOFED (HIGH)\n(PAI not validated · caller ID manipulation for social engineering)"]):::output

    AO(["probe_rtp_injection_surface(host, rtp_port=8000)"]):::input --> AP(["RTP packet SSRC=0xDEADBEEF, PT=0 PCMU\nUDP open → RTP_INJECTION_SURFACE (HIGH)\n(unsolicited RTP accepted on media port)"]):::output
    AO:::input --> AQ(["SRTP downgrade probe: RTP to UDP/5004\nResponse or stream start → SRTP_DOWNGRADE (HIGH)\n(fallback to unencrypted RTP accepted)"]):::output
    AO:::input --> AR(["RTP seq=65535 (boundary wrap)\nNo error → RTP_SEQ_BOUNDARY (LOW)\n(sequence number rollover handled · no crash)"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#2e7d32,stroke-width:3px
    linkStyle 1 stroke:#2e7d32,stroke-width:3px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
    linkStyle 7 stroke:#2e7d32,stroke-width:3px
    linkStyle 8 stroke:#2e7d32,stroke-width:3px
    linkStyle 9 stroke:#2e7d32,stroke-width:3px
    linkStyle 10 stroke:#2e7d32,stroke-width:3px
    linkStyle 11 stroke:#2e7d32,stroke-width:3px
    linkStyle 12 stroke:#2e7d32,stroke-width:3px
    linkStyle 13 stroke:#2e7d32,stroke-width:3px
    linkStyle 14 stroke:#2e7d32,stroke-width:3px
    linkStyle 15 stroke:#2e7d32,stroke-width:3px
    linkStyle 16 stroke:#2e7d32,stroke-width:3px
    linkStyle 17 stroke:#2e7d32,stroke-width:3px
    linkStyle 18 stroke:#2e7d32,stroke-width:3px
    linkStyle 19 stroke:#2e7d32,stroke-width:3px
    linkStyle 20 stroke:#2e7d32,stroke-width:3px
    linkStyle 21 stroke:#2e7d32,stroke-width:3px
    linkStyle 22 stroke:#2e7d32,stroke-width:3px
    linkStyle 23 stroke:#2e7d32,stroke-width:3px
    linkStyle 24 stroke:#2e7d32,stroke-width:3px
    linkStyle 25 stroke:#2e7d32,stroke-width:3px
    linkStyle 26 stroke:#2e7d32,stroke-width:3px
    linkStyle 27 stroke:#2e7d32,stroke-width:3px
    linkStyle 28 stroke:#2e7d32,stroke-width:3px
    linkStyle 29 stroke:#2e7d32,stroke-width:3px
    linkStyle 30 stroke:#2e7d32,stroke-width:3px
    linkStyle 31 stroke:#2e7d32,stroke-width:3px
    linkStyle 32 stroke:#2e7d32,stroke-width:3px
    linkStyle 33 stroke:#2e7d32,stroke-width:3px
```

### Finding reference

| Finding code | Severity | Function | Trigger condition |
|:---|:---|:---|:---|
| `INVITE_FLOOD_SURFACE` | HIGH | `detect_sip_flood_surface` | Half-open INVITE accepted no ACK sent; server responds |
| `SIP_FLOOD_MALFORMED` | HIGH | `detect_sip_flood_surface` | Malformed INVITE (no Via) returns non-5xx response |
| `SIP_LARGE_CONTACT_ACCEPT` | MEDIUM | `detect_sip_flood_surface` | 8KB Contact URI accepted without 413 |
| `TDOS_CALLER_ID_SPOOF` | HIGH | `detect_tdos_indicators` | INVITE with spoofed Caller-ID accepted 100/180/200 |
| `TDOS_RATE_UNLIMITED` | MEDIUM | `detect_tdos_indicators` | 10 OPTIONS in 1s all answered: no rate limiting |
| `REGISTER_EXHAUSTION` | HIGH | `detect_tdos_indicators` | 100 unique Contact URIs registered for single AoR |
| `PRESENCE_SUBSCRIBE_OPEN` | MEDIUM | `detect_sip_eavesdropping_surface` | SUBSCRIBE Event:presence → 200 without auth |
| `UNSOLICITED_NOTIFY_ACCEPTED` | MEDIUM | `detect_sip_eavesdropping_surface` | Out-of-dialog NOTIFY accepted not 481/489 |
| `SDP_CODEC_DISCLOSED` | LOW | `detect_sip_eavesdropping_surface` | Multi-codec SDP response reveals codec priority |
| `SRTP_NOT_ENFORCED` | MEDIUM | `detect_voip_eavesdrop_surface` | INVITE with RTP/AVP answered without SAVP in SDP |
| `RTCP_EXPOSED` | MEDIUM | `detect_voip_eavesdrop_surface` | RTCP UDP port (RTP+1) responsive |
| `TURN_CHANNEL_BIND_OPEN` | HIGH | `detect_voip_eavesdrop_surface` | STUN/TURN ChannelBind (0x0009) non-error response |
| `REFER_UNAUTH` | CRITICAL | `detect_sip_interception_indicators` | REFER sip:external → 202 Accepted without auth |
| `UPDATE_TAG_SPOOF` | HIGH | `detect_sip_interception_indicators` | UPDATE with fabricated To-tag accepted (not 481) |
| `PRACK_TOPOLOGY_LEAK` | MEDIUM | `detect_sip_interception_indicators` | PRACK for non-existent provisional not rejected |
| `REINVITE_MEDIA_REDIRECT` | CRITICAL | `detect_sip_interception_indicators` | re-INVITE c= redirects media stream to attacker IP |
| `MESSAGE_INJECTION_ACCEPT` | HIGH | `detect_sip_signaling_manipulation` | SIP MESSAGE with injected X-header accepted |
| `CANCEL_BROADCAST_SURFACE` | MEDIUM | `detect_sip_signaling_manipulation` | CANCEL for non-existent dialog not rejected (not 481) |
| `MWI_NOTIFY_ACCEPTED` | MEDIUM | `detect_sip_signaling_manipulation` | Unsolicited MWI NOTIFY accepted (not 489) |
| `MAX_FORWARDS_BYPASS` | MEDIUM | `detect_sip_signaling_manipulation` | Max-Forwards:0 returns 200 instead of 483 |
| `NONCE_REPLAY_ACCEPTED` | CRITICAL | `probe_sip_authentication_weaknesses` | Fabricated nonce in Authorization accepted → 200 |
| `EMPTY_DIGEST_ACCEPTED` | CRITICAL | `probe_sip_authentication_weaknesses` | Empty Digest response="" accepted → 200 |
| `UNAUTH_DEREGISTER` | CRITICAL | `probe_sip_authentication_weaknesses` | Expires:0 REGISTER → 200 without 401 challenge |
| `SIP_AUTH_BYPASS` | CRITICAL | `probe_sip_authentication_bypass` | Empty Authorization header accepted → 200 |
| `SIP_UNAUTH_INVITE` | HIGH | `probe_sip_authentication_bypass` | Anonymous INVITE accepted 100/183/200 |
| `SIP_DIGEST_BYPASS` | CRITICAL | `probe_sip_authentication_bypass` | Zeroed 32-hex MD5 Digest response accepted → 200 |
| `SIP_PROXY_AUTH_ONLY` | MEDIUM | `probe_sip_authentication_bypass` | 407 Proxy-Auth only: no WWW-Authenticate on REGISTER |
| `HEADER_INJECTION_CRLF` | HIGH | `detect_sip_header_injection` | CRLF in From display name accepted: header injection |
| `CONTACT_NULL_BYTE` | MEDIUM | `detect_sip_header_injection` | Null byte (%00) in Contact URI not sanitized |
| `VIA_STACK_SPOOF` | HIGH | `detect_sip_header_injection` | Forged Via header with TEST-NET IP accepted |
| `PAI_SPOOFED` | HIGH | `detect_sip_header_injection` | P-Asserted-Identity with arbitrary caller accepted |
| `RTP_INJECTION_SURFACE` | HIGH | `probe_rtp_injection_surface` | Crafted RTP with SSRC=0xDEADBEEF accepted on media port |
| `SRTP_DOWNGRADE` | HIGH | `probe_rtp_injection_surface` | Fallback to RTP on UDP/5004 SRTP downgrade |

---

## Usage

```python
from modules.sip_enum import (
    detect_sip_flood_surface,
    detect_tdos_indicators,
    detect_sip_eavesdropping_surface,
    detect_voip_eavesdrop_surface,
    detect_sip_interception_indicators,
    detect_sip_signaling_manipulation,
    probe_sip_authentication_weaknesses,
    probe_sip_authentication_bypass,
    detect_sip_header_injection,
    probe_rtp_injection_surface,
)

TARGET = '<target>'
SIP_PORT = 5060
RTP_PORT = 10000  # observed from SDP negotiation or port scan

# TDoS / flood surface
for f in detect_sip_flood_surface(TARGET, port=SIP_PORT):
    print(f"[{f['severity']}] {f['title']}")

for f in detect_tdos_indicators(TARGET, port=SIP_PORT):
    print(f"[{f['severity']}] {f['title']}: {f['detail'][:80]}")

# Eavesdropping surface
for f in detect_sip_eavesdropping_surface(TARGET, port=SIP_PORT):
    print(f"[{f['severity']}] {f['title']}")

for f in detect_voip_eavesdrop_surface(TARGET, port=SIP_PORT):
    print(f"[{f['severity']}] {f['title']}")

# Call interception and signaling manipulation
for f in detect_sip_interception_indicators(TARGET, port=SIP_PORT):
    print(f"[{f['severity']}] {f['title']}: {f['detail'][:80]}")

for f in detect_sip_signaling_manipulation(TARGET, port=SIP_PORT):
    print(f"[{f['severity']}] {f['title']}")

# Authentication weakness and bypass
for f in probe_sip_authentication_weaknesses(TARGET, port=SIP_PORT):
    print(f"[{f['severity']}] {f['title']}")

for f in probe_sip_authentication_bypass(TARGET, port=SIP_PORT, timeout=10.0):
    print(f"[{f['severity']}] {f['title']}: {f['detail'][:80]}")

# Header injection
for f in detect_sip_header_injection(TARGET, port=SIP_PORT):
    print(f"[{f['severity']}] {f['title']}")

# RTP injection surface (requires observed media port)
for f in probe_rtp_injection_surface(TARGET, rtp_port=RTP_PORT, timeout=3.0):
    print(f"[{f['severity']}] {f['title']}")
```

---

## Example output

The following illustrates the output format for representative findings. Actual values: IP addresses, extension numbers, nonce values, header content: will reflect the specific target.

```
[CRITICAL] REFER_UNAUTH: <target>:<port> returned 202 Accepted to REFER sip:<ext>@<target>
  Refer-To: sip:<attacker-ext>@<external-domain>. RFC 3515 §2.4 requires authentication for
  REFER. Blind call transfer to external number accepted without credentials.
  Toll-fraud primitive: transfer active calls to premium-rate numbers.

[CRITICAL] SIP_DIGEST_BYPASS: <target>:<port> returned 200 OK to REGISTER with
  Authorization: Digest response="00000000000000000000000000000000". RFC 2617 §3.2.2
  requires server to recompute H(A1):nonce:H(A2); zeroed hash accepted — digest absent.

[CRITICAL] NONCE_REPLAY_ACCEPTED: <target>:<port> accepted Authorization with fabricated
  nonce value <uuid>. Server not maintaining nonce state. Nonce replay enables credential-free
  REGISTER for any extension.

[HIGH] TDOS_CALLER_ID_SPOOF: <target>:<port> returned <code> to INVITE
  From: "FBI" <sip:FBI@<target>>. No PAI validation. Caller-ID spoofing accepted.

[HIGH] VIA_STACK_SPOOF: <target>:<port> processed INVITE with
  Via: SIP/2.0/UDP 203.0.113.1:5060 (RFC5737 TEST-NET). Injected Via hop not rejected.
  Response routing can be hijacked via Via stack manipulation.

[HIGH] HEADER_INJECTION_CRLF: <target>:<port> accepted INVITE with CRLF sequence in
  From display name. Injected header 'X-Injected: ablation-header-test' propagated.
  SIP header injection via display name field confirmed.

[MEDIUM] SIP_PROXY_AUTH_ONLY: <target>:<port> issued 407 Proxy-Auth (no WWW-Authenticate)
  for REGISTER. RFC 3261 §22.3 requires 401/WWW-Auth for REGISTER. Direct connections
  that bypass the proxy accept REGISTER without challenge.
```

---

## False positives

**`TDOS_RATE_UNLIMITED` fires when the SIP server correctly responds to all 10 OPTIONS, but OPTIONS rate limiting is a policy decision, not an RFC violation.** RFC 3261 does not specify rate limits for OPTIONS responses. Many enterprise PBX deployments intentionally respond to all OPTIONS for keep-alive signaling. The finding is `MEDIUM` severity and should be escalated only when combined with `INVITE_FLOOD_SURFACE` evidence: unrestricted OPTIONS alone does not constitute a TDoS vulnerability without evidence that INVITE rate limiting is also absent.

**`HEADER_INJECTION_CRLF` requires confirming that the injected header propagates to a downstream system: some SIP proxies accept the request but strip CRLF sequences before forwarding.** The probe sends a REGISTER or INVITE with CRLF in the display name field and checks whether the server accepts the message non-400 response. This confirms the server does not sanitize CRLF before accepting the message, but does not confirm downstream propagation. Use a controlled proxy or SIP capture to verify that the `X-Injected` header appears in forwarded messages before escalating to HIGH.

**`SIP_UNAUTH_INVITE` is elevated to HIGH when anonymous INVITE is accepted, but anonymous INVITE is a legitimate SIP mechanism for emergency calls RFC 3325 Privacy header.** Some deployments intentionally permit anonymous INVITE for emergency services (E.911). Confirm whether the target is a PSTN gateway with emergency call policy, in which case anonymous INVITE acceptance is expected behavior. If the target is an enterprise PBX, anonymous INVITE without Require: Privacy is a finding; if it is a carrier gateway, confirm the policy before reporting.

---

## Pipeline position

**Before this module:** Run `sip-service-and-extension-discovery.md` probes first to confirm SIP responsiveness, identify the server type Asterisk, FreePBX, and CUCM, and obtain a baseline response code for unauthenticated REGISTER. Server type informs which authentication-bypass probes are most likely to succeed: Asterisk deployments are more susceptible to digest-bypass findings; CUCM deployments are more likely to show `SIP_PROXY_AUTH_ONLY`.

**After this module:** For `REFER_UNAUTH` and `REINVITE_MEDIA_REDIRECT` CRITICAL findings: construct a full call-hijacking proof-of-concept using `detect_dtmf_extraction_surface()` and `probe_rtp_covert_channel()` from `voip-protocol-and-covert-channels.md` to demonstrate the media-layer impact. For `SIP_DIGEST_BYPASS` or `NONCE_REPLAY_ACCEPTED`: enumerate all extensions via `SIPEnumerator.enumerate_extensions()` to identify all registrable AoRs. For `HEADER_INJECTION_CRLF`: escalate to manual SIP proxy analysis to test Log4j-class downstream injection impact. Write confirmed findings to `~/VDT/VULNERABILITIES-<ip>.md`.

---

## Reading findings

| Field | Content |
|:---|:---|
| `f['severity']` | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| `f['title']` | Finding code string such as `REFER_UNAUTH` and `SIP_DIGEST_BYPASS` |
| `f['detail']` | Full finding narrative: host:port, observed response code, protocol standard violated, specific attack impact, reference citations |
| `f['host']` | Target host IP or FQDN |
| `f['port']` | Target port for this finding's probe |

---

## See also

- [SIP Service and Extension Discovery](sip-service-and-extension-discovery.md): SIPEnumerator class, extension enumeration, registration hijacking, media interception posture
- [VoIP Protocol Inspection and Covert Channels](voip-protocol-and-covert-channels.md): DTMF extraction, RTP/RTCP covert channels, H.323/SCCP/MGCP legacy protocol deep inspection, ASA SIP fixup bypass, WebRTC infrastructure exposure
