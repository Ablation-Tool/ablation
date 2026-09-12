"""
Cisco UCS HUU (Host Upgrade Utility) ISO RE

Target:  ucs-c220m8-huu-6.0.2.260143.iso
         C220 M8 Host Upgrade Utility, version 6.0.2.260143, 2026-06-17
         SquashFS-based bootable Linux for C-series server firmware updates
Files:   rootfs.img (squashfs, OpenEmbedded Linux, 2018)
         container.squashfs -> ucs-c220m8-huu-container-6.0.2.260143-base.tar.gz (2026)
         /usr/sbin/imgverify
         /etc/init.d/hsu-init
         /etc/init.sh (container)
         /etc/init-huu.sh (container)
         /hsu-keys/ (container)
Session: 38
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_huu_iso_re",
    "firmware": "ucs-c220m8-huu-6.0.2.260143.iso",
    "components": {
        "rootfs.img (squashfs)": (
            "Boot environment; OpenEmbedded Linux 2018; "
            "hsu-init, imgverify, hsu-verify-file, hsu-profile.sh"
        ),
        "container.squashfs (base.tar.gz)": (
            "nginx 1.x + gunicorn3 + Python 3.13 web UI container; "
            "extracted to /mnt/cdrom at boot; "
            "init.sh -> init-huu.sh launches hsu_wsgi:app on 127.0.0.1:8000 "
            "behind nginx on 0.0.0.0:80"
        ),
        "imgverify (/usr/sbin/imgverify)": (
            "Shell script; RSA-2048 signature verifier for container/rootfs/tools; "
            "exits 0 (success) if IMG_VERIFY != '1'; "
            "IMG_VERIFY not set in hsu-profile.sh or any profile script"
        ),
        "hsu-init (/etc/init.d/hsu-init)": (
            "Boot init; sources hsu-profile.sh; "
            "enables telnetd if CONFIG_SEC_UTILS_SIGN_MODE == dev OR is_cisco_server() fails; "
            "is_cisco_server() = ipmitool raw 0x36 0x4d 0x04 0x03; "
            "fails on VMs and non-Cisco hardware"
        ),
        "init.sh (container)": (
            "Container orchestrator; setup_rootfs() extracts rootfs.img, "
            "chroot $ROOTFS_DIR telnetd unconditional, "
            "create_user() huu_user with date+%s%N|md5sum|cut -c1-12 password; "
            "cred stored /tmp/huu.cred"
        ),
        "hsu-keys/ (container)": (
            "RSA-2048 DER+PEM keypairs: "
            "container-dev, container-rel, rootfs-dev, rootfs-rel, "
            "tools-dev, tools-rel, tools (7 keys); "
            "dev and rel keys both present in production ISO"
        ),
    },
    "finding_count": "6F [1C+3H+2M+0L]",
    "cumulative": "729 [67C+240H+230M+192L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "imgverify exits 0 (success) when IMG_VERIFY is not set to '1'",
        "description": (
            "imgverify (/usr/sbin/imgverify) guards signature verification of all "
            "container, rootfs, and tools images with: "
            "'if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi' "
            "as its first check. IMG_VERIFY is not set in hsu-profile.sh (the only "
            "sourced profile) or any observable script in the rootfs. "
            "The environment variable is absent at runtime, making the condition "
            "'\"\" != \"1\"' always true. imgverify returns exit code 0 (success) "
            "without performing any cryptographic verification. "
            "hsu-init calls 'if ! imgverify /tmp/*-container-*-base.tar.gz ...; "
            "then fatal ...; fi' - since imgverify always succeeds, a tampered "
            "container passes verification unconditionally. "
            "The same path covers rootfs.img and tools verification."
        ),
        "evidence": {
            "file": "/usr/sbin/imgverify",
            "code": (
                "#!/bin/sh\n"
                "set -x\n"
                "src_file=$1\n"
                "pub_key_file=$2\n"
                "\n"
                "if [ \"$IMG_VERIFY\" != \"1\" ]; then\n"
                "    exit 0\n"
                "fi\n"
                "\n"
                "# ... RSA-2048 openssl dgst verification (never reached) ..."
            ),
            "profile_script": "/etc/profile.d/hsu-profile.sh",
            "profile_relevant_vars": (
                "# IMG_VERIFY: NOT PRESENT\n"
                "# CONFIG_SEC_UTILS_SIGN_MODE: NOT PRESENT\n"
                "# HSU_KERNEL_IMGVERIFY: NOT PRESENT\n"
                "export PATH=$PATH:/usr/sbin:/sbin\n"
                "export ISO_MNTPATH=/tmp/mnt\n"
                "export CONTAINER_MNT_TYPE=compressed_base"
            ),
            "call_site": (
                "hsu-init: "
                "'if ! imgverify /tmp/*-container-*-base.tar.gz >> /tmp/imgverify.log 2>&1; "
                "then fatal \"Base container signature verification failed!\"; fi'"
            ),
        },
        "impact": (
            "Complete bypass of firmware image integrity protection. "
            "Attacker with access to the ISO or PXE boot environment can replace "
            "the container or rootfs with arbitrary code. "
            "Verification appears to succeed; no error is logged. "
            "Affects all HUU deployments where IMG_VERIFY is not manually set."
        ),
        "remediation": (
            "Set IMG_VERIFY=1 in /etc/profile.d/hsu-profile.sh. "
            "Invert the guard logic: fail closed when IMG_VERIFY is unset "
            "rather than defaulting to bypass."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "Unconditional telnetd enabled in rootfs chroot after 60 seconds",
        "description": (
            "Container init.sh setup_rootfs() function unconditionally launches telnetd "
            "inside the rootfs chroot after a 60-second sleep: "
            "'sleep 60; chroot $ROOTFS_DIR sh -c \"sh /initramfs/etc/enable_usb_nic.sh\"; "
            "chroot $ROOTFS_DIR sh -c \"telnetd\"'. "
            "This path has no conditional check on sign mode, hardware type, or any "
            "configuration flag. It runs on every HUU boot regardless of deployment context. "
            "The rootfs shadow file contains no password hash for root (root:*); "
            "huu_user is created by create_user() immediately before setup_rootfs() "
            "returns, giving telnet access via the weak time-derived credential (F4)."
        ),
        "evidence": {
            "file": "container base.tar.gz: /etc/init.sh",
            "function": "setup_rootfs()",
            "code": (
                "# Wait for rootfs initialization and then enable telnetd\n"
                "sleep 60\n"
                "chroot $ROOTFS_DIR sh -c \"sh /initramfs/etc/enable_usb_nic.sh\"\n"
                "chroot $ROOTFS_DIR sh -c \"telnetd\""
            ),
            "rootfs_shadow": "root:*:15069:0:99999:7::: (locked; no login shell via password)",
            "huu_user": "created dynamically by create_user() before telnetd starts",
        },
        "impact": (
            "Telnet service exposed on management network on every HUU boot. "
            "Any attacker who can reach the management network interface during firmware "
            "update operations can attempt authentication. "
            "Combined with F4, huu_user provides authenticated shell access."
        ),
        "remediation": (
            "Remove unconditional telnetd from setup_rootfs(). "
            "If remote management is required, use SSH with host key verification."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "Telnetd enabled on non-Cisco hardware and dev sign mode",
        "description": (
            "hsu-init (/etc/init.d/hsu-init) in the rootfs enables telnetd in two paths "
            "before the container launches: "
            "(1) CONFIG_SEC_UTILS_SIGN_MODE == 'dev': sources hsu-profile.sh which does not "
            "set this variable, so the check depends on kernel command line or external "
            "injection; "
            "(2) is_cisco_server() failure: calls 'ipmitool raw 0x36 0x4d 0x04 0x03' "
            "to detect Cisco USB NIC support. This command fails on VMs, non-Cisco hardware, "
            "and any environment where the Cisco IPMI OEM extension is absent. "
            "When is_cisco_server() fails, telnetd is enabled unconditionally: "
            "'if ! is_cisco_server; then echo \"Enabling telnetd...\"; telnetd; fi'. "
            "HUU is used for initial firmware provisioning, including on hardware that "
            "has not yet been configured with Cisco IPMI extensions."
        ),
        "evidence": {
            "file": "/etc/init.d/hsu-init",
            "code": (
                "is_cisco_server() {\n"
                "    if ipmitool raw 0x36 0x4d 0x04 0x03; then\n"
                "        touch /opt/cisco/cisco_server\n"
                "        return 0\n"
                "    else\n"
                "        return 1\n"
                "    fi\n"
                "}\n"
                "\n"
                "if [ $CONFIG_SEC_UTILS_SIGN_MODE == \"dev\" ]; then\n"
                "    echo \"Enabling telnetd...\"\n"
                "    telnetd\n"
                "fi\n"
                "\n"
                "if ! is_cisco_server; then\n"
                "    echo \"Enabling telnetd...\"\n"
                "    telnetd\n"
                "fi"
            ),
        },
        "impact": (
            "Telnetd active on initial boot in any virtualized or non-Cisco-hardware "
            "deployment. Management network exposure before any application-layer auth. "
            "Compound with F2: two independent telnetd activation paths operate "
            "simultaneously in non-Cisco environments."
        ),
        "remediation": (
            "Remove both telnetd blocks from hsu-init. "
            "If diagnostic access is required, gate on an explicit signed boot parameter."
        ),
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "huu_user password derived from nanosecond epoch timestamp via MD5",
        "description": (
            "container init.sh create_user() generates the password for the huu_user "
            "account using: "
            "PASSWORD=$(date +%s%N | md5sum | cut -c1-12). "
            "date +%s%N outputs seconds since epoch concatenated with nanoseconds "
            "(e.g., '1757614823123456789'). The MD5 hash of this value is computed "
            "and the first 12 hex characters are used as the password. "
            "The password space is constrained to the nanosecond timestamp at the moment "
            "create_user() executes, which is approximately 60 seconds after HUU boot. "
            "If an attacker can estimate the boot time from network observations "
            "(DHCP requests, ARP, management traffic), the search space is bounded "
            "to a narrow time window. "
            "The generated credential is stored in plaintext at /tmp/huu.cred "
            "('$USERNAME:$PASSWORD'), readable by any process running in the container. "
            "The account is used by telnetd (F2) for shell access."
        ),
        "evidence": {
            "file": "container base.tar.gz: /etc/init.sh",
            "function": "create_user()",
            "code": (
                "create_user() {\n"
                "  USERNAME=\"huu_user\"\n"
                "  PASSWORD=$(date +%s%N | md5sum | cut -c1-12)\n"
                "  echo \"$USERNAME:$PASSWORD\" > /tmp/huu.cred\n"
                "\n"
                "  chroot $ROOTFS_DIR sh -c \"useradd $USERNAME\"\n"
                "  chroot $ROOTFS_DIR sh -c \"echo '$USERNAME:$PASSWORD' | chpasswd\"\n"
                "}"
            ),
            "cred_path": "/tmp/huu.cred",
            "password_format": "first 12 hex chars of MD5(date +%s%N)",
            "example": "boot_ns=1757614823123456789 -> md5='a3f7...' -> pw='a3f7b2c91e04'",
        },
        "impact": (
            "Time-predictable telnet credential. An attacker who observes HUU boot "
            "network traffic can bound the timestamp to a ~1-second window, reducing "
            "brute-force space to ~10^9 nanosecond candidates per second offset. "
            "The plaintext /tmp/huu.cred is readable by any root process in the container "
            "without additional privilege."
        ),
        "remediation": (
            "Generate huu_user password from a cryptographically random source "
            "(/dev/urandom). Remove /tmp/huu.cred after account creation."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "HUU web UI served over HTTP only; TLS configured but not activated",
        "description": (
            "nginx is configured to listen on 0.0.0.0:80 (HTTP only) via "
            "/etc/nginx/sites-enabled/default_server. "
            "The main nginx.conf includes 'ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3' "
            "at the http block level, but no vhost includes ssl_certificate or "
            "'listen 443 ssl'. TLS protocol support is declared without being activated. "
            "The HUU web UI exposes firmware inventory, component versions, and "
            "firmware update initiation over plaintext HTTP on the management network. "
            "The gunicorn backend (hsu_wsgi:app) binds to 127.0.0.1:8000; "
            "nginx proxies all traffic from the network without encryption. "
            "Additionally, TLSv1.0 and TLSv1.1 are included in ssl_protocols, "
            "which are deprecated protocols (RFC 8996)."
        ),
        "evidence": {
            "file_site": "container base.tar.gz: /etc/nginx/sites-available/default_server",
            "site_config": (
                "server {\n"
                "    listen 80 default_server;\n"
                "    listen [::]:80 default_server;\n"
                "    root /var/www/localhost/html;\n"
                "    # no ssl_certificate, no listen 443 ssl\n"
                "}"
            ),
            "file_main": "container base.tar.gz: /etc/nginx/nginx.conf",
            "ssl_config": (
                "# Declared but never activated:\n"
                "ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;"
            ),
            "gunicorn_bind": "127.0.0.1:8000 (hsu_wsgi:app)",
            "nginx_bind": "0.0.0.0:80",
        },
        "impact": (
            "All HUU management traffic (firmware queries, inventory reads, "
            "update operations) transmitted in cleartext on the management LAN. "
            "Network-adjacent attacker can intercept firmware update commands "
            "and server responses."
        ),
        "remediation": (
            "Generate a self-signed TLS certificate at boot and activate "
            "'listen 443 ssl' with ssl_certificate in the nginx vhost. "
            "Remove TLSv1.0 and TLSv1.1 from ssl_protocols."
        ),
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "Dev verification keys shipped in production ISO",
        "description": (
            "The /hsu-keys/ directory in the container base.tar.gz contains "
            "both development and release RSA-2048 keypairs for all three "
            "verification domains: "
            "container-dev-verify-key.{der,pem}, container-rel-verify-key.{der,pem}, "
            "rootfs-dev-verify-key.{der,pem}, rootfs-rel-verify-key.{der,pem}, "
            "tools-dev-verify-key.{der,pem}, tools-rel-verify-key.{der,pem}, "
            "tools-verify-key.{der,pem} (7 keypairs total). "
            "Production builds should contain only rel keys. "
            "hsu-init selects between dev and rel keys based on "
            "'run_mode' from /opt/cisco/run_mode (set at runtime, not present in rootfs). "
            "Presence of dev keys enables acceptance of dev-signed firmware in any "
            "deployment where run_mode is set to DEV or absent. "
            "Combined with F1 (imgverify bypass), key selection is moot in default "
            "deployments; however, if IMG_VERIFY=1 were set, dev keys would enable "
            "loading of dev-signed firmware in production hardware."
        ),
        "evidence": {
            "file": "container base.tar.gz: /hsu-keys/",
            "keys": [
                "container-dev-verify-key.der", "container-dev-verify-key.pem",
                "container-rel-verify-key.der", "container-rel-verify-key.pem",
                "rootfs-dev-verify-key.der", "rootfs-dev-verify-key.pem",
                "rootfs-rel-verify-key.der", "rootfs-rel-verify-key.pem",
                "tools-dev-verify-key.der", "tools-dev-verify-key.pem",
                "tools-rel-verify-key.der", "tools-rel-verify-key.pem",
                "tools-verify-key.der", "tools-verify-key.pem",
            ],
            "key_selection_code": (
                "run_mode=`cat /opt/cisco/run_mode`\n"
                "if [ $run_mode == 'DEV' ] ; then\n"
                "    export IMGVERIFY_PUB_KEY_FILE=/hsu-keys/tools-dev-verify-key.pem\n"
                "elif [ $run_mode == 'REL' ] ; then\n"
                "    export IMGVERIFY_PUB_KEY_FILE=/hsu-keys/tools-rel-verify-key.pem\n"
                "fi"
            ),
        },
        "impact": (
            "Dev-signed firmware images accepted on hardware where run_mode evaluates "
            "to DEV (absent or unset). If F1 is remediated and IMG_VERIFY=1 is set, "
            "dev keys remain as a residual acceptance path for non-production firmware."
        ),
        "remediation": (
            "Strip dev verification keys from production ISO builds. "
            "Key selection should fail closed when run_mode is absent."
        ),
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
