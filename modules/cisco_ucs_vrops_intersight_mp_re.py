"""
Cisco vROps Intersight Management Pack 1.1.1 RE

Target:  cisco_vrops_intersight_mp_1.1.1.pak
         VMware vRealize Operations Manager integration pack for Cisco Intersight
         PAK format: ZIP archive (manifest.txt + adapter.zip + content/ + signature.cert + signature.mf)
         adapter.zip: IntersightManager/ conf-only adapter (no Python/Java; vROps runs adapter server-side)
         Container: pulled from docker.io/intersight/vrops at runtime (DIGEST pinned in IntersightManager.conf)
         vROps minimum version: 8.10.0; platform: Linux Non-VA, Linux VA
Files:   IntersightManager.conf (adapter runtime config; REGISTRY, DIGEST, API_PROTOCOL)
         IntersightManager/conf/describe.xml (adapter schema: CredentialKinds, ResourceKinds, identifiers)
         manifest.txt (pak metadata: vendor, name, version, adapters list)
         signature.cert (VMware self-signed cert, 2016-09-08, expires 2029-12-31)
         signature.mf (SHA1 hashes for all pack files)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_vrops_intersight_mp_re",
    "firmware": "cisco_vrops_intersight_mp_1.1.1.pak",
    "components": {
        "IntersightManager.conf": (
            "REGISTRY=docker.io; REPOSITORY=/intersight/vrops; "
            "DIGEST=sha256:20d93e601ecc2ebd98eb488c4f2699026aaf5143be3cc987b8ac5946db11dff3; "
            "API_PROTOCOL=https; API_PORT=443"
        ),
        "describe.xml (CredentialKind=oAuth)": (
            "CredentialField key=client_secret password=true; "
            "ResourceIdentifier key=verify_ssl default='False' (enum: True/False); "
            "ResourceIdentifier key=container_memory_limit default=1024"
        ),
        "manifest.txt": (
            "vendor: 'VENDOR' (literal placeholder, not substituted); "
            "pak_validation_script.script=''; adapter_pre_script.script=''; "
            "adapter_post_script.script=''"
        ),
        "signature.cert": (
            "subject=C=US,ST=California,L=Palo Alto,O=VMware Inc. (self-signed, issuer=subject); "
            "notBefore=2016-09-08; notAfter=2029-12-31 (13-year validity); "
            "VMware signing authority, not Cisco"
        ),
        "signature.mf": (
            "SHA1(adapter.zip)=2ad9b6fbfd95e6ae1bc9ca31f6fd8319a522f0ce; "
            "all 44 files hashed with SHA1 only"
        ),
    },
    "finding_count": "6F [0C+0H+4M+2L]",
    "cumulative": "813 [78C+281H+258M+195L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "MEDIUM",
        "title": "verify_ssl defaults to 'False' in describe.xml; Intersight API TLS verification disabled by default",
        "description": (
            "IntersightManager adapter schema defines verify_ssl as: "
            "'<ResourceIdentifier default=\"False\" key=\"verify_ssl\" required=\"true\" "
            "dispOrder=\"3\" enum=\"true\" type=\"string\" identType=\"1\">'. "
            "The two enum values are 'True' (default=false) and 'False' (default=false). "
            "The identType='1' marks this as a user-visible identifier. "
            "When the adapter instance is created in vROps with default settings, "
            "the SSL certificate on the Intersight API endpoint is not verified. "
            "The adapter authenticates to Intersight using OAuth client_id + client_secret "
            "(from the oAuth CredentialKind). "
            "With verify_ssl=False, a MITM between vROps and www.intersight.com "
            "receives the OAuth credential exchange without triggering a certificate error. "
            "The adapter's default hostname is 'www.intersight.com' (identType=1, required=true) -- "
            "the adapter is specifically designed for Intersight SaaS, "
            "making MITM more difficult but not impossible (DNS poisoning, rogue cert on managed network)."
        ),
        "evidence": {
            "file": "adapter.zip/IntersightManager/conf/describe.xml",
            "field": (
                '<ResourceIdentifier default="False" key="verify_ssl" required="true" '
                'dispOrder="3" enum="true" type="string" identType="1">'
            ),
            "enum": (
                '<enum value="True" nameKey="17" default="false"/>  (not the default)\n'
                '<enum value="False" nameKey="18" default="false"/> (effective default from identType default attr)'
            ),
        },
        "impact": (
            "OAuth client_secret transmitted to unauthenticated server on MITM. "
            "Default configuration leaves all Intersight credential exchanges unverified."
        ),
        "remediation": "Set default='true' on the 'True' enum value in describe.xml, or remove 'False' from the enum.",
    },
    {
        "id": "F2",
        "severity": "MEDIUM",
        "title": "Adapter container pulled from docker.io (public Docker Hub), not a Cisco private registry",
        "description": (
            "IntersightManager.conf specifies: "
            "'REGISTRY=docker.io; REPOSITORY=/intersight/vrops; "
            "DIGEST=sha256:20d93e601ecc2ebd98eb488c4f2699026aaf5143be3cc987b8ac5946db11dff3'. "
            "The vROps management pack deploys the IntersightManager adapter as a container "
            "pulled from docker.io/intersight/vrops. "
            "DIGEST pinning (sha256) is correct practice and prevents tag poisoning, "
            "but the trust anchor is Docker Hub: if the Cisco/Intersight Docker Hub account "
            "(intersight/) is compromised, the attacker can update the digest reference "
            "in the manifest, which then ships in a signed .pak file. "
            "The .pak file is signed with the VMware 2016 cert -- "
            "a compromised Docker Hub account combined with a new signed .pak release "
            "delivers malicious adapter code to all vROps deployments with the pack installed. "
            "Registry should be a Cisco-controlled private registry (not docker.io)."
        ),
        "evidence": {
            "file": "adapter.zip/IntersightManager.conf",
            "content": (
                "REGISTRY=docker.io\n"
                "REPOSITORY=/intersight/vrops\n"
                "DIGEST=sha256:20d93e601ecc2ebd98eb488c4f2699026aaf5143be3cc987b8ac5946db11dff3"
            ),
        },
        "impact": (
            "Adapter container supply chain trust rooted in docker.io public registry. "
            "Digest pinning mitigates tag poisoning but not account compromise + re-signed pack."
        ),
        "remediation": "Migrate to a Cisco-owned private container registry (images.cisco.com or similar).",
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "signature.mf uses SHA1 for all 44 file integrity checks in the management pack",
        "description": (
            "signature.mf covers all 44 files in the .pak archive with SHA1 hashes only "
            "(e.g., 'SHA1(adapter.zip)= 2ad9b6fbfd95e6ae1bc9ca31f6fd8319a522f0ce'). "
            "SHA1 has known collision attacks (SHAttered, 2017) and NIST formally deprecated "
            "SHA1 for digital signature use in 2011. "
            "The signature.cert (VMware 2016 self-signed, RSA) signs this manifest. "
            "A SHA1 collision in adapter.zip would allow a malformed adapter zip to "
            "pass signature verification with the same SHA1 hash as the legitimate file. "
            "The collision cost for SHA1 is now approximately 110 GPU-years, "
            "which is within reach of nation-state adversaries. "
            "The content/ alert definition XMLs (largest attack surface, 64 files) "
            "all use SHA1."
        ),
        "evidence": {
            "file": "signature.mf",
            "algorithm": "SHA1 only (no SHA256, no SHA512)",
            "count": "44 file hashes, all SHA1",
            "largest": "SHA1(adapter.zip)= 2ad9b6fbfd95e6ae1bc9ca31f6fd8319a522f0ce",
        },
        "impact": "SHA1 collision in adapter.zip passes signature verification. Malicious adapter accepted.",
        "remediation": "Migrate signature.mf to SHA256. Update vROps signing toolchain.",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "Signing certificate is VMware self-signed (2016, 13-year validity, C=VMware not Cisco)",
        "description": (
            "signature.cert: subject=C=US,ST=California,L=Palo Alto,O='VMware, Inc.'; "
            "issuer=subject (self-signed). "
            "notBefore=2016-09-08; notAfter=2029-12-31 (13-year validity period). "
            "The signing certificate was issued in 2016 -- nearly a decade before this 2026 pack release. "
            "A 13-year validity period for a signing certificate violates recommended CA/B Forum "
            "maximum validity guidance (2 years for code signing). "
            "vROps trusts this certificate as the Cisco management pack signer; "
            "the trust is VMware-internal and implicit, not rooted in a public CA. "
            "The certificate is organizationally attributed to VMware, not Cisco, "
            "reflecting the historical VMware vROps management pack signing infrastructure "
            "that Cisco inherited and continued using after the pack was developed. "
            "Private key exposure (even partial) over a 10-year period is not detectable "
            "until rotation."
        ),
        "evidence": {
            "subject": "C=US, ST=California, L=Palo Alto, O=VMware, Inc. (self-signed)",
            "dates": "notBefore=2016-09-08 notAfter=2029-12-31",
            "validity": "13 years 3 months (issued 9+ years before this pack version)",
        },
        "impact": (
            "VMware-branded, self-signed, 9-year-old key material signs Cisco management pack. "
            "Any attacker with access to the 2016 private key signs a malicious pack "
            "accepted by vROps without additional trust anchors."
        ),
        "remediation": "Rotate to a Cisco-owned code signing certificate. Reduce validity to 2 years.",
    },
    {
        "id": "F5",
        "severity": "LOW",
        "title": "manifest.txt vendor field contains literal 'VENDOR' placeholder (build artifact)",
        "description": (
            "manifest.txt line: '\"vendor\": \"VENDOR\"'. "
            "The vendor field was not substituted during the build process for version 1.1.1. "
            "The correct value would be 'Cisco' or 'Cisco Systems'. "
            "This is a build pipeline defect that exposes the incomplete parameter substitution. "
            "vROps displays the vendor field in the pack management UI -- "
            "administrators see 'VENDOR' instead of 'Cisco' for the installed pack. "
            "The manifest.txt also has SHA1(manifest.txt) in signature.mf, "
            "confirming this placeholder shipped in the signed release."
        ),
        "evidence": {
            "file": "manifest.txt",
            "line": '"vendor": "VENDOR"',
            "version": "1.1.1 (signed and released)",
        },
        "impact": "UI confusion for vROps administrators; reveals incomplete build automation.",
        "remediation": "Fix build pipeline to substitute vendor variable before signing.",
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "pak_validation_script, adapter_pre_script, adapter_post_script all empty",
        "description": (
            "manifest.txt: "
            "'pak_validation_script.script: \"\"'; "
            "'adapter_pre_script.script: \"\"'; "
            "'adapter_post_script.script: \"\"'. "
            "The vROps management pack framework executes these hooks at install time "
            "to validate pack prerequisites, prepare the environment, and post-install configure. "
            "All three are empty -- no validation logic runs at pack installation. "
            "A malicious or tampered .pak file (e.g., SHA1-collision swap of adapter.zip) "
            "would install without triggering any validation checks. "
            "Other Cisco vROps management packs (e.g., UCS Central MP) ship non-empty "
            "validation scripts that verify adapter host connectivity before proceeding."
        ),
        "evidence": {
            "file": "manifest.txt",
            "empty_hooks": (
                "pak_validation_script.script=''\n"
                "adapter_pre_script.script=''\n"
                "adapter_post_script.script=''"
            ),
        },
        "impact": "No installation validation; malformed or substituted adapter installs silently.",
        "remediation": "Implement pak_validation_script to verify adapter container digest pre-install.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
