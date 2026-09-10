"""
Cisco Intersight vROps Management Pack 1.1.1 — RE Module
Source: cisco_vrops_intersight_mp_1.1.1.pak (/media/cowboy/research/Cisco-UCS/intersight/)
Format: ZIP (vROps MP pak); contains adapter.zip + alert definitions + signature files
Adapter type: container-backed (Docker image from Docker Hub, not bundled Python/JAR)

Architecture: vROps invokes a Docker container at adapter runtime.
  Image source: docker.io/intersight/vrops (Docker Hub)
  Pinned digest: sha256:20d93e601ecc2ebd98eb488c4f2699026aaf5143be3cc987b8ac5946db11dff3
  Adapter code is NOT bundled in the pak; this is configuration-only.

Credential kind: oAuth (client_id / client_secret — Intersight API key)
  Credential fields: client_id (string), client_secret (password), proxy_user, proxy_pass
"""

FIRMWARE = {
    "target":       "Cisco Intersight vROps Management Pack",
    "version":      "1.1.1",
    "source":       "cisco_vrops_intersight_mp_1.1.1.pak",
    "adapter_kind": "IntersightManager",
    "docker_image": "docker.io/intersight/vrops@sha256:20d93e601ecc2ebd98eb488c4f2699026aaf5143be3cc987b8ac5946db11dff3",
    "pak_type":     "container-backed — no bundled executable code; Docker image provides adapter runtime",
    "findings":     ["VROPS-ISA-F1", "VROPS-ISA-F2"],
}

# ─────────────────────────────────────────────────────────────────────────────
# VROPS-ISA-F1: signature.mf uses SHA1 for all pak file integrity checksums
#               — no cryptographic signature over the manifest
# ─────────────────────────────────────────────────────────────────────────────
VROPS_ISA_F1 = {
    "id":       "VROPS-ISA-F1",
    "title":    "vROps pak signature.mf uses SHA1 for all file integrity checksums — "
                "cryptographically broken hash; no digital signature over the manifest file itself",
    "status":   "CONFIRMED — signature.mf header and per-file SHA1 entries confirmed in pak",
    "severity": "LOW",

    "hash_algorithm":  "SHA1 (signature.mf: 'SHA1(filename)= <hex>')",
    "signature_cert":  "signature.cert present — VMware, Inc. CA (sha512WithRSAEncryption, valid until 2029-12-31)",
    "missing_artifact": "No .sig or .DSA file present — signature.cert is not used to sign the manifest",

    "format": (
        "signature.mf lists SHA1(filename)=<hash> for each pak file. "
        "The accompanying signature.cert (VMware CA) is not cryptographically linked to signature.mf — "
        "no PKCS7/detached signature file exists in the pak. "
        "SHA1 preimage resistance is broken on commodity hardware; "
        "an attacker modifying the pak can recalculate SHA1 hashes and update signature.mf "
        "without invalidating any cryptographic proof of authenticity."
    ),

    "vendor_placeholder": "manifest.txt 'vendor' field contains literal value 'VENDOR' — "
                          "pak was not properly configured before signing/publishing.",
}

# ─────────────────────────────────────────────────────────────────────────────
# VROPS-ISA-F2: Adapter runtime pulled from Docker Hub at install time —
#               external dependency with supply chain risk
# ─────────────────────────────────────────────────────────────────────────────
VROPS_ISA_F2 = {
    "id":       "VROPS-ISA-F2",
    "title":    "Container-backed vROps adapter fetches runtime from Docker Hub (docker.io/intersight/vrops) "
                "— external network dependency at adapter activation; digest-pinned but Docker Hub account control critical",
    "status":   "CONFIRMED — IntersightManager.conf REGISTRY=docker.io, REPOSITORY=/intersight/vrops, DIGEST=sha256:20d93e60...",
    "severity": "LOW",

    "registry":   "docker.io (Docker Hub)",
    "repository": "intersight/vrops",
    "digest":     "sha256:20d93e601ecc2ebd98eb488c4f2699026aaf5143be3cc987b8ac5946db11dff3",
    "api_port":   443,
    "api_proto":  "https",

    "assessment": (
        "The digest pin (sha256:20d93e60...) provides strong content addressing — the pulled image is "
        "cryptographically bound to this hash. The supply chain risk is in the Docker Hub account "
        "'intersight': if that account is compromised and the pak's DIGEST field is updated in a "
        "future release, all vROps instances that upgrade would pull attacker-controlled code. "
        "For 1.1.1 specifically, the digest is fixed and not attackable at runtime. "
        "vROps nodes must have outbound Docker Hub access during adapter activation — "
        "air-gapped deployments require local registry mirroring."
    ),

    "severity_note": "LOW standalone — digest pinning is the correct control; the risk is in future updates.",
}

FINDINGS = [VROPS_ISA_F1, VROPS_ISA_F2]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
