"""
Cisco HyperFlex (HX Data Platform) — RE Module
Firmware corpus: HX-ESXi-7.0U1 through HX-ESXi-8.0U3 (install ISOs + upgrade bundles)
Architecture: Cisco-customized ESXi + stCtlVM (storage controller VM, Debian/Linux)

HyperFlex stack:
  ESXi host:   Cisco custom VIBs (hxdp-*, hx-*, springpath-*) — kernel drivers + agents
  stCtlVM:     Debian Linux VM — HX Data Platform storage stack (C++/Python/Go binaries)
               ports: 443 (HX Connect REST API), 8080 (internal), 9090 (Prometheus), 3260 (iSCSI)
  HX Connect:  HTTPS REST API — cluster management, node enrollment, Intersight claim
  UCSM:        UCS Manager XML API integration (port 443 on UCSM)
  vCenter:     Plugin integration (remote plugin OVA: HTML5-remote-plugin-Appliance-3.0.0-1173.ova)

Extraction method:
  ISO (iso9660) -> VIBs at /packages/*.vib -> .tgz -> payloads
  Upgrade bundles (.zip) -> VIBs directly
  stCtlVM: embedded as OVA or installer package inside VIBs

Default credentials (HX Connect REST API):
  POST /rest/v1/tokens {username, password} -> hx-auth-token
  Brute: admin/admin, admin/C1sco12345, admin/Cisco123, admin/HXpassword1!,
         hxadmin/C1sco12345, admin/Password1!, root/password1!, root/Cisco123

Unauthenticated endpoints (HX Connect <4.5):
  GET /rest/v1/cluster  — cluster UUID, version, node count
  GET /rest/v1/version  — HXDP version string
  GET /rest/v1/about    — platform info

High-value authenticated endpoints:
  GET /rest/v1/nodes                        — node IPs, serial numbers, roles
  GET /rest/v1/intersight/connection        — Intersight claim code (device takeover pivot)
  GET /rest/v1/clusters/local/snapshots     — snapshot inventory
  GET /rest/v1/storage/disks               — disk topology + SN
  GET /rest/v1/cluster/security            — security config

Firmware corpus:
  storfs-packages-6.0.2b-44423.tgz — HXDP core packages (848MB)
  Cisco-HX-Data-Platform-Installer-v6.0.2b-44423-esx.ova — installer appliance (Ubuntu 64-bit, 24.8GB vdisk)
  cisco-hxdc_6.0.2b-44423_amd64.deb — Intersight Device Connector + image signing verifier
  cisco-openssl_1.1.1za_amd64.deb — private EOL OpenSSL fork + CiscoSSH replacement
  hx-iscsi_6.0.2b-44423_amd64.deb — iSCSI service (16MB ELF, not stripped)
  hx-os_6.0.2b-44423_amd64.deb — OS configs (auditd, iptables, syslog-ng)
  zookeeper_3.8.1_amd64.deb — distributed coordinator
  storfs-support-workflows-6.0.2b-44423.tgz — support debs + bootstrap workflow
  hxdp-connector bundle (inner): Go binary (UPX-packed, 25MB unpacked), version 1.0.11-20250305

Key services (from syslog-ng):
  storfs, iscsisvc, scvmclient, hxmanager, cip-monitor, replsvc, smbscvmclient, stmapper, networkMonitor
  hxmanager logs sent over TCP to syslog-ng localhost:514

Port topology (iptables_node_reset.rules):
  8092 — Springpath internal cluster bus (OUTPUT restricted to springpath/www-data)
  2003 — Graphite metrics (OUTPUT restricted to www-data)
  3260 — iSCSI (inbound from ESXi initiators)

Image signing (hxdc_release_img_verify, 32-bit ELF, not stripped):
  Cisco ROMMON code-sign library (cs_rommon_* functions — shared with IOS/NX-OS boot signing)
  RSA PKCS#1 + SHA-512; custom BigNum (RsaLibBigNum*), NOT OpenSSL
  Key storage: /opt/partner/cisco-hxdc/public-key (Cisco TLV format, multi-version with revocation)
  Bundle format: [gzip tar][440-byte Cisco RSA-3072 PKCS#1 signature]
  Dev keys: cs_rommon_platform_allow_dev_keys(0) called from main() — disabled in production

Auto-upgrade NFS path:
  Primary pushes bundle to /nfs/SYSTEM/hx_device_connector/bundle_data/hxdc_active_bundle
  Secondary nodes pull from NFS at startup; no NFS write-protection enforced in code

iscsisvc architecture (16MB PIE ELF, not stripped, statically compiled OpenSSL):
  IoVisor: ESXi-side kernel driver (stHypervisorSvc VIB); iscsisvc manages IoVisor registrations
  Iscsi_RegisterIoVisor / Iscsi_GetRedirectionInfo / Iscsi_Redirect — connection redirect/LB
  conn_worker_ev_pdu_exec — iSCSI PDU execution handler
  chap_decrypt_init / chap_decrypt_cleanup — CHAP (MD5) authentication only
  _add_dm_targets — dm-device mapper target manipulation
  PEM_write_PKCS8PrivateKey / crypt_keyslot_add_by_volume_key — LUKS integration

hxdp connector binary (Go, UPX-packed, stripped):
  Intersight cloud WebSocket endpoint: svc-static1.ucs-connect.com
  HashiCorp Vault API paths embedded: /pki/root/sign-self-issued, /sys/revoke-force/{prefix}
  SUDI certificate authentication to Intersight
  Emulator mode path: /.device_connector_emulator/intersight/catalog/Version

Findings: HX-F01 (HIGH) through HX-F10 (INFO).
"""

import socket
import ssl
import json
import urllib.request
import urllib.error
import urllib.parse
import os
import subprocess
from typing import Optional


# ─── Default Credentials ─────────────────────────────────────────────────────

HX_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "C1sco12345"),
    ("admin", "Cisco123"),
    ("admin", "cisco"),
    ("admin", "HXpassword1!"),
    ("hxadmin", "C1sco12345"),
    ("admin", "Password1!"),
    ("root", "password1!"),
    ("root", "Cisco123"),
]

HX_CONNECT_PORT = 443
HX_UNAUTH_PATHS = [
    "/rest/v1/cluster",
    "/rest/v1/version",
    "/rest/v1/about",
]

HX_AUTH_PATHS = {
    "nodes":            "/rest/v1/nodes",
    "datastores":       "/rest/v1/datastores",
    "alarms":           "/rest/v1/alarms",
    "snapshots":        "/rest/v1/clusters/local/snapshots",
    "disks":            "/rest/v1/storage/disks",
    "volumes":          "/rest/v1/volumes",
    "intersight_conn":  "/rest/v1/intersight/connection",
    "network":          "/rest/v1/network",
    "security":         "/rest/v1/cluster/security",
}

ISCSI_PORT = 3260
NFS_PORT   = 2049

UCSM_CREDS = [
    ("admin", "admin"),
    ("admin", "cisco"),
    ("admin", "C1sco12345"),
    ("admin", "password"),
]


# ─── Findings ────────────────────────────────────────────────────────────────

FINDINGS = {
    "HX-F01": {
        "title": "EOL OpenSSL 1.1.1 Private Fork Replaces System OpenSSL and SSH Daemon",
        "severity": "HIGH",
        "component": "cisco-openssl_1.1.1za_amd64.deb",
        "description": (
            "cisco-openssl package (CiscoSSL 1.1.1za.7.2.587, CiscoSSH 1.14.55.2) installs "
            "as a system replacement: libssl.so.1.1 and libcrypto.so.1.1 overwrite "
            "/lib/x86_64-linux-gnu/ originals; sshd overwrites /usr/sbin/sshd. "
            "OpenSSL 1.1.1 went EOL 2023-09-11. The 'za' suffix indicates a private Cisco "
            "patch lineage 26 cycles past the last public release (1.1.1w). "
            "CVE applicability is opaque — Cisco's backports are not disclosed."
        ),
        "code_evidence": {
            "post_install.sh": (
                "backupAndCopy libssl.so.1.1 /lib/x86_64-linux-gnu\n"
                "backupAndCopy libcrypto.so.1.1 /lib/x86_64-linux-gnu\n"
                "backupAndCopy sshd /usr/sbin\n"
                "backupAndCopy sshd_config /etc/ssh"
            ),
            "version": "CiscoSSL 1.1.1za.7.2.587 / CiscoSSH 1.14.55.2",
            "eol_date": "2023-09-11",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F02": {
        "title": "CiscoSSH sshd_config Sets PermitRootLogin yes by Default",
        "severity": "HIGH",
        "component": "cisco-openssl_1.1.1za_amd64.deb / /etc/ssh/sshd_config",
        "description": (
            "The CiscoSSH sshd_config installed to /etc/ssh/sshd_config sets "
            "PermitRootLogin yes. Combined with HX-F01 (system sshd replacement), "
            "root SSH login is permitted by default on every stCtlVM. "
            "Only ECDSA host key is used (RSA and ED25519 deprecated in this build)."
        ),
        "code_evidence": {
            "sshd_config line": "PermitRootLogin yes",
            "HostKey": "HostKey /etc/ssh/ssh_host_ecdsa_key (only)",
            "CiscoSSHFipsMode": "yes",
            "stsso_chroot": "Match group stsso -> ChrootDirectory /var/jail/",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F03": {
        "title": "vCenter Password Exposed via CLI Argument (argv / /proc/pid/cmdline)",
        "severity": "HIGH",
        "component": "storfs-packages / cluster-bootstrap.sh",
        "description": (
            "cluster-bootstrap.sh accepts vCenter credentials as command-line arguments "
            "(--vc-user, --vc-pwd). These are visible in /proc/<pid>/cmdline to any "
            "process with read access. On a shared stCtlVM, all local users or any "
            "process with read access to /proc can recover vCenter credentials during "
            "cluster bootstrap or upgrade."
        ),
        "code_evidence": {
            "option_parsing": "-p | --vc-pwd ) VC_PWD=\"$2\"; shift; shift ;;",
            "exposed_via": "/proc/pid/cmdline",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F04": {
        "title": "Factory-Default nginx TLS Certificate with Known Fingerprint on All Deployments",
        "severity": "MEDIUM",
        "component": "storfs-packages / cluster-bootstrap.sh / /etc/nginx/server.crt",
        "description": (
            "cluster-bootstrap.sh encodes the SHA1 fingerprint of the factory-default "
            "nginx TLS certificate: 28:71:47:9A:C0:58:72:40:C0:E7:9A:DB:39:2A:A3:1A:FD:97:BF:D7. "
            "This cert was shipped with every HyperFlex deployment. Any cluster that "
            "has not rotated its nginx cert (HX Connect REST API / HTTPS) still presents "
            "this known certificate. If the private key is recoverable from the installer "
            "VMDK, full TLS decryption against unrotated clusters is trivial."
        ),
        "code_evidence": {
            "OLD_STATIC_THUMBPRINT": "28:71:47:9A:C0:58:72:40:C0:E7:9A:DB:39:2A:A3:1A:FD:97:BF:D7",
            "key_path": "/etc/nginx/server.key",
            "cert_path": "/etc/nginx/server.crt",
        },
        "versions_affected": ["6.0.2b-44423", "all prior releases"],
        "note": "Key recovery from installer VMDK (/etc/nginx/server.key) is pending VMDK mount RE.",
    },
    "HX-F05": {
        "title": "cisco-openssl post_install.sh References Stale Version String",
        "severity": "MEDIUM",
        "component": "cisco-openssl_1.1.1za_amd64.deb / post_install.sh",
        "description": (
            "The post_install.sh in cisco-openssl contains "
            "'ciscossl_version=1.1.1l.7.2.289' while the installed package is "
            "version 1.1.1za.7.2.587. This stale hardcoded version string may be "
            "consumed by downstream version-checking logic or health checks, "
            "causing incorrect version reporting."
        ),
        "code_evidence": {
            "post_install.sh stale": "ciscossl_version=1.1.1l.7.2.289",
            "actual_package_version": "1.1.1za.7.2.587",
            "delta": "1.1.1l -> 1.1.1za (14 private patch cycles)",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F06": {
        "title": "NFS-Distributed Auto-Upgrade Bundle Path Without Write-Protection",
        "severity": "MEDIUM",
        "component": "cisco-hxdc / install-connector.sh / /nfs/SYSTEM/",
        "description": (
            "The Intersight Device Connector auto-upgrade mechanism distributes new "
            "connector bundles via NFS: primary node writes to "
            "/nfs/SYSTEM/hx_device_connector/bundle_data/hxdc_active_bundle; "
            "secondary nodes pick up from this path on startup. No write-protection "
            "is enforced in code — only filesystem permissions. If /nfs/SYSTEM is "
            "exported with no_root_squash or accessible to a compromised node, "
            "an attacker can inject a malicious connector bundle that is distributed "
            "to all cluster nodes and executed with the hx_device_connector service identity."
        ),
        "code_evidence": {
            "primary_push": "cp -f \"${src}\" ${hx_shared_active_bundle}  # no integrity check after copy",
            "nfs_path": "/nfs/SYSTEM/hx_device_connector/bundle_data/hxdc_active_bundle",
            "secondary_pickup": "hxdc_nfs_bundle_file=${hxdc_nfs_bundle_dir}/hxdc_active_bundle",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F07": {
        "title": "Device Connector Emulator Mode Path Exposed in Production Binary",
        "severity": "MEDIUM",
        "component": "hxdp-connector bundle / bin/hxdp",
        "description": (
            "The hxdp connector binary (Go, UPX-packed) contains the path "
            "/.device_connector_emulator/intersight/catalog/Version — "
            "an internal emulator/test mode accessible via the device connector's "
            "HTTP server. If this endpoint is reachable, it may expose device identity, "
            "catalog, or version information without full Intersight authentication."
        ),
        "code_evidence": {
            "string_in_binary": "/.device_connector_emulator/intersight/catalog/Version",
            "binary": "bin/hxdp (Go, UPX-packed, built 2025-03-05)",
            "intersight_endpoint": "svc-static1.ucs-connect.com (WebSocket)",
        },
        "versions_affected": ["1.0.11-20250305 (connector bundle)"],
    },
    "HX-F08": {
        "title": "Cisco ROMMON Code-Sign Library in Device Connector Verifier (Shared with IOS/NX-OS)",
        "severity": "INFO",
        "component": "cisco-hxdc / hxdc_release_img_verify (32-bit ELF, not stripped)",
        "description": (
            "hxdc_release_img_verify embeds Cisco's IOS/NX-OS ROMMON code-sign library "
            "(cs_rommon_*, code_sign_*, RsaLibBigNum* symbols). RSA PKCS#1 v1.5 + SHA-512. "
            "Custom BigNum implementation (not OpenSSL). Key storage at "
            "/opt/partner/cisco-hxdc/public-key in Cisco TLV format with key version "
            "rollover and revocation support. "
            "Dev keys disabled: main() calls cs_rommon_platform_allow_dev_keys(0). "
            "Bundle format: [gzip tar][440-byte appended signature]."
        ),
        "code_evidence": {
            "cs_rommon_platform_allow_dev_keys": (
                "08048b20: xor edx,edx -> call cs_rommon_platform_allow_dev_keys  ; arg=0, dev keys OFF"
            ),
            "key_storage": "/opt/partner/cisco-hxdc/public-key (binary TLV, Cisco format)",
            "sig_size": "440 bytes (RSA-3072 PKCS#1 + Cisco envelope overhead)",
            "name_in_binary": "Starship_Device_Connector_HX",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F09": {
        "title": "iscsisvc Uses CHAP (MD5) Authentication Only for iSCSI Initiators",
        "severity": "MEDIUM",
        "component": "hx-iscsi / iscsisvc (16MB ELF, not stripped)",
        "description": (
            "iscsisvc provides iSCSI storage access with CHAP authentication "
            "(chap_decrypt_init/chap_decrypt_cleanup). CHAP uses MD5 which is "
            "cryptographically weak. No evidence of mutual CHAP (bidirectional) "
            "in the function set. iSCSI sessions without strong authentication "
            "are vulnerable to initiator spoofing if the storage network is accessible."
        ),
        "code_evidence": {
            "chap_functions": "chap_decrypt_init, chap_decrypt_cleanup",
            "pdu_exec": "conn_worker_ev_pdu_exec (main PDU handler)",
            "redirect": "Iscsi_Redirect / Iscsi_GetRedirectionInfo (IoVisor-aware connection redirect)",
            "luks": "_add_dm_targets, crypt_keyslot_add_by_volume_key (LUKS integration)",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F10": {
        "title": "hxdp Connector Embeds HashiCorp Vault API Paths for Internal PKI",
        "severity": "INFO",
        "component": "hxdp-connector bundle / bin/hxdp",
        "description": (
            "The hxdp connector binary contains HashiCorp Vault API paths: "
            "/pki/root/sign-self-issued, /sys/config/ui/headers/?$, "
            "/sys/revoke-force/{prefix}, /sys/replication/reindex$. "
            "This indicates the connector either runs a local Vault agent or "
            "communicates with a Vault server for internal certificate management. "
            "The Vault PKI surface is additional attack scope beyond the Intersight API."
        ),
        "code_evidence": {
            "vault_paths": [
                "/pki/root/sign-self-issued",
                "/sys/config/ui/headers/?$",
                "/sys/revoke-force/{prefix}",
                "/sys/replication/reindex$",
            ],
            "sudi": "SUDI certificate authentication to Intersight",
            "cloud_endpoint": "svc-static1.ucs-connect.com",
        },
        "versions_affected": ["1.0.11-20250305 (connector bundle)"],
    },
}


# ─── Probe Functions ──────────────────────────────────────────────────────────

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _hx_request(host: str, path: str, method: str = "GET",
                 token: Optional[str] = None, body: Optional[dict] = None,
                 timeout: int = 8) -> Optional[dict]:
    url = f"https://{host}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("hx-auth-token", token)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return {"__http_error": e.code, "__reason": str(e.reason)}
    except Exception:
        return None


def probe_hx_connect(host: str, timeout: int = 8) -> dict:
    result = {
        "host": host, "port": HX_CONNECT_PORT, "reachable": False,
        "version": None, "unauth_data": {}, "cred_result": None,
        "auth_data": {}, "intersight_claim_code": None,
    }

    try:
        s = socket.create_connection((host, HX_CONNECT_PORT), timeout=timeout)
        s.close()
        result["reachable"] = True
    except Exception:
        return result

    for path in HX_UNAUTH_PATHS:
        data = _hx_request(host, path, timeout=timeout)
        if data and "__http_error" not in data:
            result["unauth_data"][path] = data
            if "version" in data or "hxVersion" in data:
                result["version"] = data.get("version") or data.get("hxVersion")

    token = None
    for user, passwd in HX_DEFAULT_CREDS:
        body = {"username": user, "password": passwd}
        resp = _hx_request(host, "/rest/v1/tokens", method="POST",
                           body=body, timeout=timeout)
        if resp and "token" in resp:
            token = resp["token"]
            result["cred_result"] = {"user": user, "pass": passwd}
            break
        if resp and "__http_error" in resp and resp["__http_error"] == 429:
            break

    if token:
        for key, path in HX_AUTH_PATHS.items():
            data = _hx_request(host, path, token=token, timeout=timeout)
            if data and "__http_error" not in data:
                result["auth_data"][key] = data

        conn = result["auth_data"].get("intersight_conn", {})
        result["intersight_claim_code"] = conn.get("claimCode") or conn.get("deviceId")

    return result


if __name__ == "__main__":
    import sys

    print("=== Cisco HyperFlex RE Module ===")
    print(f"Findings: {len(FINDINGS)} (HX-F01 through HX-F{max(int(k.split('-F')[1]) for k in FINDINGS)})")
    print()

    for fid, f in FINDINGS.items():
        sev = f["severity"]
        print(f"[{sev:8}] {fid}: {f['title']}")

    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"[*] Probing {target}")
        print(json.dumps(probe_hx_connect(target), indent=2))
