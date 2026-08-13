/*
  Cisco ASA LINA — RADIUS Class Attribute OU= Overflow Detection Rules
  Researcher: Independent security researcher
  Date: 2026-08-13
  No CVE assigned as of disclosure date.

  F1: Missing Message-Authenticator validation on Access-Accept (RFC 5080 §2.2)
  F2: OU= buffer overflow → pointer corruption → ACE via fake mgd_timer struct

  Generated with Cisco AI assistance during binary analysis of ASA 9.22.2.32
  BuildID: 88929a4c3f35a2c0786e01e63c2e64626666ef23

  Usage: yara cisco_asa_lina_radius_ou.yar /path/to/lina
*/

rule Cisco_ASA_LINA_Radius_OU_Overflow_F2
{
    meta:
        description = "Detects Cisco ASA LINA with RADIUS Class attribute OU= overflow (F2 pointer corruption)"
        severity    = "CRITICAL"
        cve         = "N/A (unassigned as of 2026-08-13)"

    strings:
        // "OU=" string in RO segment
        $ou_string  = "OU="

        // CMP rax,0x100 — the 256-byte extraction loop bound at 0x3a4bfa4
        $overflow_cmp = { 48 3d 00 01 00 00 }

        // LEA rsi,[...] + CALL — strstr("OU=") call pattern
        $strstr_call = { 48 8d 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? }

        // message-authenticator-required string (present in 9.22.x, absent in earlier)
        $ma_required = "message-authenticator-required"

    condition:
        $ou_string and $overflow_cmp and $strstr_call
}

rule Cisco_ASA_LINA_Radius_OU_Overflow_F1_Missing_MA
{
    meta:
        description = "Detects Cisco ASA LINA missing message-authenticator-required (F1 — all pre-9.22.x)"
        severity    = "HIGH"
        note        = "Absence of $ma_required string indicates no opt-in mitigation available"

    strings:
        $ou_string   = "OU="
        $overflow_cmp = { 48 3d 00 01 00 00 }
        $ma_required  = "message-authenticator-required"

    condition:
        $ou_string and $overflow_cmp and not $ma_required
}

rule Cisco_ASA_LINA_Radius_OU_Overflow_9_22_Mitigatable
{
    meta:
        description = "Detects ASA 9.22.x LINA — has message-authenticator-required but disabled by default"
        severity    = "HIGH"
        note        = "Mitigation available but requires explicit configuration"

    strings:
        $ou_string   = "OU="
        $overflow_cmp = { 48 3d 00 01 00 00 }
        $ma_required  = "message-authenticator-required"

    condition:
        $ou_string and $overflow_cmp and $ma_required
}
