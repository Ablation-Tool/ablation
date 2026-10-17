# Legacy Voice Protocols

Probe H.323, SCCP/Skinny, MGCP, and media-gateway surfaces for unauthenticated access, cleartext signaling, and protocol-layer attack surfaces — using standalone functions from `sip_enum.py`.

---

This page covers the legacy telephony protocol probes in `sip_enum.py`. The full documentation is split across three reference pages aligned with attack-surface category:

- **[SIP Service and Extension Discovery](sip-service-and-extension-discovery.md)** — H.323 service detection (`probe_h323_service`), SCCP/Skinny basic probe (`probe_sccp_skinny`), RTP port range scanning (`check_rtp_port_range`)
- **[SIP Attack Surface Detection](sip-attack-surface-detection.md)** — SCCP deep surface (`detect_sccp_skinny_surface`), MGCP wildcard audit (`detect_mgcp_surface`), ASA SIP fixup bypass (`probe_asa_sip_fixup_legacy`)
- **[VoIP Protocol Inspection and Covert Channels](voip-protocol-and-covert-channels.md)** — H.323 inspection surface (`detect_h323_inspection_surface`), combined H.323+MGCP+SCCP probe (`probe_h323_and_media_gateway`), WebRTC infrastructure (`probe_webrtc_signaling_exposure`)

---

## Protocol summary

| Protocol | Port | Transport | Auth model | Key finding |
|:---|:---|:---|:---|:---|
| H.323 Q.931 | TCP/1720 | TCP | None (no TLS by default) | `H323_CALL_SETUP_RESPONSIVE` — call signaling accessible |
| H.323 RAS | UDP/1719 | UDP | None | `H323_GATEKEEPER_RESPONSIVE` — unauthenticated GRQ accepted |
| SCCP/Skinny | TCP/2000 | TCP | Certificate (CAPF, optional) | `SCCP_REGISTER_ACK` — phone registration without CAPF |
| SCCP-TLS | TCP/2443 | TLS | Required | Expected (indicates SCCP-TLS is enforced) |
| MGCP | UDP/2427 | UDP | IPsec (RFC 3435 §5, often absent) | `MGCP_CRCX_UNAUTH` — call creation without IPsec |

---

## See also

- [SIP Service and Extension Discovery](sip-service-and-extension-discovery.md) — H.323/SCCP basic probes, RTP range
- [SIP Attack Surface Detection](sip-attack-surface-detection.md) — SCCP deep, MGCP surface, ASA bypass
- [VoIP Protocol Inspection and Covert Channels](voip-protocol-and-covert-channels.md) — H.323 deep, combined gateway probe, WebRTC
