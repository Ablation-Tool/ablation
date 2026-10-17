# Voice Abuse Indicators

Heuristics and probes for VoIP signaling manipulation, DTMF credential exposure, SIP/RTP covert channels, telephony denial-of-service susceptibility, and call-interception surfaces.

---

This page covers the voice abuse indicator probes in `sip_enum.py`. The full documentation is split across three reference pages aligned with attack-surface category:

- **[SIP Attack Surface Detection](sip-attack-surface-detection.md)** — TDoS/flood detection (`detect_sip_flood_surface`, `detect_tdos_indicators`), eavesdropping surfaces (`detect_sip_eavesdropping_surface`, `detect_voip_eavesdrop_surface`), signaling manipulation (`detect_sip_interception_indicators`, `detect_sip_signaling_manipulation`), authentication bypass (`probe_sip_authentication_weaknesses`, `probe_sip_authentication_bypass`), header injection (`detect_sip_header_injection`)
- **[VoIP Protocol Inspection and Covert Channels](voip-protocol-and-covert-channels.md)** — DTMF extraction (`detect_dtmf_extraction_surface`, `probe_rtp_dtmf_digit_theft`), SIP covert channels (`detect_voip_covert_channel`), RTP/RTCP covert channels (`probe_rtp_covert_channel`)

---

## Indicator category summary

| Category | Functions | Key finding codes |
|:---|:---|:---|
| Telephony DoS (TDoS) | `detect_sip_flood_surface`, `detect_tdos_indicators` | `INVITE_FLOOD_SURFACE`, `REGISTER_EXHAUSTION`, `TDOS_CALLER_ID_SPOOF` |
| Eavesdropping | `detect_sip_eavesdropping_surface`, `detect_voip_eavesdrop_surface` | `PRESENCE_SUBSCRIBE_OPEN`, `SRTP_NOT_ENFORCED`, `RTCP_EXPOSED` |
| Call interception | `detect_sip_interception_indicators` | `REFER_UNAUTH`, `REINVITE_MEDIA_REDIRECT` |
| Auth bypass | `probe_sip_authentication_bypass` | `SIP_DIGEST_BYPASS`, `SIP_AUTH_BYPASS`, `NONCE_REPLAY_ACCEPTED` |
| Header injection | `detect_sip_header_injection` | `HEADER_INJECTION_CRLF`, `VIA_STACK_SPOOF`, `PAI_SPOOFED` |
| DTMF extraction | `detect_dtmf_extraction_surface`, `probe_rtp_dtmf_digit_theft` | `DTMF_INFO_ACCEPTED`, `DTMF_BURST_INJECT` |
| Covert channels | `detect_voip_covert_channel`, `probe_rtp_covert_channel` | `SIP_BINARY_MESSAGE_COVERT`, `RTCP_APP_COVERT`, `RTP_DYNAMIC_PT_COVERT` |

---

## See also

- [SIP Attack Surface Detection](sip-attack-surface-detection.md) — TDoS, eavesdropping, interception, auth bypass, header injection
- [VoIP Protocol Inspection and Covert Channels](voip-protocol-and-covert-channels.md) — DTMF extraction, covert channels, legacy protocol deep inspection
- [SIP Service and Extension Discovery](sip-service-and-extension-discovery.md) — Extension enumeration, registration hijacking, media interception posture
