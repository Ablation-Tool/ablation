"""
Cisco Intersight vROps Management Pack (adapter.pak v1.1.1) — RE Module
Source: vrops-adapter/adapter.pak extracted from UCS HyperFlex tooling
Content: adapter.zip + IntersightManager/conf/describe.xml (1.6MB resource schema)

The vROps adapter connects vRealize Operations to Cisco Intersight cloud API
using OAuth2 client_id / client_secret credentials. This module captures
security findings in the adapter's credential handling and TLS configuration.
"""

FIRMWARE = {
    "targets": [
        {
            "name": "Cisco Intersight vROps Management Pack",
            "file": "adapter.pak",
            "version": "1.1.1",
            "adapter_kind": "IntersightManager",
            "vcops_min": "8.10.0",
        },
    ],
    "component_files": {
        "IntersightManager/conf/describe.xml":  "Resource schema + credential definitions (1.6MB)",
        "IntersightManager.conf":               "Adapter runtime config (https, port 443, docker.io image)",
    },
    "findings": ["VROPS-F1"],
}

# ─────────────────────────────────────────────────────────
# VROPS-F1: verify_ssl defaults to "False" in describe.xml
#           TLS certificate verification disabled by default on Intersight OAuth connections
# ─────────────────────────────────────────────────────────
VROPS_F1 = {
    "id":       "VROPS-F1",
    "title":    "Cisco Intersight vROps adapter ResourceIdentifier verify_ssl defaults to 'False' "
                "in describe.xml — TLS certificate verification disabled by default",
    "status":   "CONFIRMED — extracted from IntersightManager/conf/describe.xml in adapter.zip",
    "severity": "HIGH",

    "source_file":   "IntersightManager/conf/describe.xml",
    "resource_kind": "IntersightManager_adapter_instance",
    "field_definition": (
        '<ResourceIdentifier default="False" key="verify_ssl" required="true" '
        'dispOrder="3" enum="true" type="string" identType="1">'
        '<enum value="True" nameKey="17" default="false"/>'
        '<enum value="False" nameKey="18" default="false"/>'
        '</ResourceIdentifier>'
    ),

    "credential_fields_exposed": {
        "client_id":     "Intersight OAuth2 client ID (password=false — stored in cleartext in vROps)",
        "client_secret": "Intersight OAuth2 client secret (password=true)",
        "proxy_pass":    "Proxy password (password=true)",
    },

    "description": (
        "When an administrator creates a new Cisco Intersight adapter instance in vROps, "
        "the verify_ssl field defaults to the string 'False'. This means TLS certificate "
        "verification against www.intersight.com (Cisco Intersight cloud) is disabled "
        "out of the box. A network-positioned attacker between the vROps node and the "
        "Intersight API endpoint can present a self-signed or mis-issued certificate and "
        "intercept or modify the HTTPS connection, capturing the OAuth2 client_secret "
        "transmitted in API authentication requests. The default is insecure; the user "
        "must explicitly override verify_ssl to 'True' to enable certificate validation."
    ),

    "attack_surface": (
        "TLS MITM against vROps-to-Intersight HTTPS — capture client_secret, replay "
        "for full Intersight tenant access (UCS inventory, server profiles, firmware, "
        "identities). Relevant on corporate network paths where vROps egresses through "
        "a proxy or intercepting gateway."
    ),

    "adapter_conf_note": (
        "IntersightManager.conf sets API_PROTOCOL=https and API_PORT=443 — "
        "HTTPS is used, but certificate validation is bypassed by the default verify_ssl=False."
    ),

    "remediation": (
        "Set verify_ssl=True on all existing and new Intersight adapter instances. "
        "Change the describe.xml default from 'False' to 'True' in future releases."
    ),
}

FINDINGS = [VROPS_F1]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:12s}] {f['id']}: {f['title'][:80]}")
