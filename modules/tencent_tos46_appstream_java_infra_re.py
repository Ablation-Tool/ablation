"""
TencentOS 4.6 AppStream — Java infrastructure package RE.

Sources analyzed from Drive (tencent-re/4.6/AppStream-source/):
  WALinuxAgent-2.8.0.11-7.tl4.ap.1.src.rpm  — Azure Linux Agent for TOS 4.6
  apache-sshd-2.9.2-2.tl4.src.rpm           — Apache MINA SSHD with CVE-2026-56452 fix

WALinuxAgent: distribution adaptation patch only.
apache-sshd: SCP path traversal vulnerability patched (CVE-2026-56452 / GHSA ab3672f).
"""

WALINUXAGENT = {
    "package": "WALinuxAgent-2.8.0.11-7.tl4.ap.1",
    "upstream": "https://github.com/Azure/WALinuxAgent v2.8.0.11",
    "license": "ASL 2.0",
    "maintainer": "TencentOS Team <tencent_os@tencent.com>",
    "patch_date": "2024-11-19",
    "release_tag": ".ap.1",
    "release_tag_meaning": (
        "'.ap.1' = Autopatch revision 1 applied by TencentOS Team. "
        "The base package (2.8.0.11-7) is from OpenCloudOS (releng@opencloudos.tech). "
        "Tencent adds one patch on top: support-TencentOS.patch."
    ),
    "tencent_patch": {
        "file": "support-TencentOS.patch",
        "changes": {
            "init/TencentOS/waagent.service": (
                "Adds a TOS-specific systemd service unit for waagent. "
                "Requires: network-online.target, sshd.service, sshd-keygen.service. "
                "After: network-online.target. "
                "Type=simple, ExecStart=/usr/bin/python3 -u /usr/sbin/waagent -daemon. "
                "Restart=always, RestartSec=5, Slice=azure.slice, CPUAccounting=yes."
            ),
            "setup.py": (
                "Adds 'TencentOS' as a recognized distribution name in setup.py. "
                "When lnx-distro=TencentOS: installs py3 waagent binary, config, logrotate, "
                "udev rules, and TOS-specific systemd service files."
            ),
        },
        "security_impact": "None — pure distribution detection/installation adaptation.",
    },
    "context": {
        "deployment": (
            "WALinuxAgent runs on Azure VMs. TOS 4.6 instances deployed on Azure "
            "(Tencent x Azure multi-cloud or Azure China region) install this agent. "
            "The agent handles: VM provisioning, SSH key injection, extension management, "
            "disk resizing, and Azure platform communication."
        ),
        "privilege": "Runs as root (waagent.service). Communicates with Azure fabric controller.",
        "data_collection": (
            "Azure fabric controller receives: VM hostname, IP, disk layout, "
            "agent heartbeats. TOS-specific changes do not add data collection beyond "
            "standard Azure agent telemetry."
        ),
    },
    "version_history": [
        "2.8.0.11-1 (2023-03-20): rockerzhu@tencent.com — initial build",
        "2.8.0.11-2 through 2.8.0.11-6: OpenCloudOS rebuilds",
        "2.8.0.11-7.ap.1 (2024-11-19): TencentOS Autopatch for ts4",
    ],
}

APACHE_SSHD = {
    "package": "apache-sshd-2.9.2-2.tl4",
    "upstream": "https://mina.apache.org/sshd-project — Apache MINA SSHD v2.9.2",
    "license": "ASL 2.0 and ISC",
    "patches": {
        "0001 (APR)": "Remove optional tomcat-apr dependency (Red Hat packaging patch; not security relevant)",
        "CVE-2026-56452": "SCP path traversal fix — see FINDINGS below",
    },
    "role": (
        "100% Java SSH client/server library. Used by: Apache ServiceMix, Apache Karaf, "
        "Jenkins SSH agent, Apache Camel, CXF, and any Java service on TOS 4.6 that "
        "implements SCP/SFTP server or client functionality."
    ),
    "cve_2026_56452": {
        "id": "CVE-2026-56452",
        "ghsa": "GHSA ab3672f",
        "title": "SCP path traversal — arbitrary file write outside target directory",
        "upstream_fix_commit": "ab3672f03161cd9f5f7d622bff0335e513c9994d",
        "upstream_author": "Thomas Wolf <twolf@apache.org>",
        "upstream_date": "2026-06-18",
        "tencent_backport_author": "Zhao Zhen <jeremiazhao@tencent.com>",
        "tencent_backport_date": "2026-07-22",
        "class": "path traversal / arbitrary file write",
        "affected_components": [
            "sshd-scp/src/main/java/org/apache/sshd/scp/common/ScpFileOpener.java",
            "sshd-scp/src/main/java/org/apache/sshd/scp/common/helpers/LocalFileScpTargetStreamResolver.java",
        ],
        "root_cause": (
            "SCP protocol C (copy file) and D (directory) commands include a filename "
            "in the command line. In the receive path, apache-sshd resolved this filename "
            "directly without validation: "
            "  name.replace('/', File.separatorChar)  "
            "This only converted Unix slashes to OS-native separators. "
            "A malicious SCP server could send a C command with filename '../outside.txt' "
            "or '../../etc/cron.d/evil' — the Path.resolve() call would escape the "
            "intended target directory and write the file anywhere the Java process "
            "can write."
        ),
        "vulnerable_code": (
            "# Old resolveIncomingFilePath() in ScpFileOpener:\n"
            "String localName = name.replace('/', File.separatorChar)\n"
            "file = localPath.resolve(localName)\n"
            "\n"
            "# Old resolveTargetStream() in LocalFileScpTargetStreamResolver:\n"
            "String localName = name.replace('/', File.separatorChar)  # Windows compat\n"
            "file = path.resolve(localName)"
        ),
        "fix": (
            "New checkRemoteFileName(FileSystem fs, String fileName) validates:\n"
            "  1. Not null/empty\n"
            "  2. Not '.' or '..'\n"
            "  3. No '/' in filename (directory separator in name)\n"
            "  4. No '\\\\' or ':' (Windows path chars, if Win32)\n"
            "  5. Not an absolute path (fs.getPath(fileName).isAbsolute() must be false)\n"
            "  6. fileName.equals(p.getFileName().toString()) — name does not resolve "
            "     to something different when interpreted as a path component\n"
            "Throws InvalidPathException on violation -> ScpException with ScpAckInfo.ERROR."
        ),
        "attack_scenario": (
            "Scenario 1 — Malicious SCP server:\n"
            "  A Java app uses apache-sshd's SCP client to download files from a server.\n"
            "  Attacker controls the server and sends: 'C0644 100 ../../../etc/cron.d/pwn'\n"
            "  Client writes the payload to /etc/cron.d/pwn (if running as root) or\n"
            "  any writable directory outside the intended download path.\n"
            "\n"
            "Scenario 2 — Malicious SCP client connecting to a server:\n"
            "  If the application accepts SCP uploads from a remote client, "
            "  an attacker can escape the upload directory by crafting SCP C/D commands."
        ),
        "test_cases": [
            "receiveFileNameCannotEscapeRequestedDirectory — ../outside.txt",
            "receiveFileNameCannotOverwriteExistingFileOutsideRequestedDirectory — ../simulated-autoloaded-config.txt",
            "receiveFileNameCannotEscapeRequestedDirectory (dir) — ../outside-dir via D command",
        ],
        "prior_cve": "CVE-2022-45047 (Java deserialization via SSH agent forwarding) — fixed in 2.9.2-1",
        "severity_assessment": "HIGH — arbitrary file write; impact depends on process privilege and deployment",
    },
    "version_history": [
        "2.8.0-1 (2023-04-25): cunshunxia@tencent.com — initial build",
        "2.8.0-2 through 2.8.0-5: OpenCloudOS rebuilds",
        "2.9.2-1 (2025-03-07): jackxjchen@tencent.com — upgrade to 2.9.2, fix CVE-2022-45047",
        "2.9.2-2 (2026-07-22): jeremiazhao@tencent.com — backport CVE-2026-56452 SCP path traversal fix",
    ],
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "package": "apache-sshd",
        "cve": "CVE-2026-56452",
        "ghsa": "GHSA ab3672f",
        "title": "SCP path traversal: malicious server/client can write files outside intended directory",
        "detail": (
            "apache-sshd 2.9.2-1.tl4 and earlier do not validate SCP C/D command filenames. "
            "A filename like '../outside.txt' escapes the target directory via Path.resolve(). "
            "Fixed in 2.9.2-2.tl4 (backported 2026-07-22) by adding checkRemoteFileName() "
            "which enforces: no dots, no separators, no absolute paths, filename identity check. "
            "Upstream fix commit: ab3672f. Any TOS 4.6 system running 2.9.2-1 is vulnerable."
        ),
        "affected": "apache-sshd < 2.9.2-2.tl4 (all prior TOS 4.6 AppStream versions)",
        "fixed": "apache-sshd-2.9.2-2.tl4",
    },
    {
        "id": "F2",
        "severity": "INFO",
        "package": "WALinuxAgent",
        "title": "WALinuxAgent on TOS 4.6: Tencent distribution patch is cosmetic — systemd unit + setup.py only",
        "detail": (
            "support-TencentOS.patch adds TOS distribution detection to WALinuxAgent's setup.py "
            "and a TOS-specific waagent.service unit. No changes to agent logic, telemetry, "
            "or communication with Azure fabric. The agent's security posture on TOS is "
            "identical to other RHEL-family distributions (root service, Azure telemetry, "
            "SSH key injection, extension execution)."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "package": "WALinuxAgent",
        "title": "WALinuxAgent root service: TOS 4.6 cloud instances on Azure receive SSH keys and run extensions as root",
        "detail": (
            "waagent runs as root on every Azure-hosted TOS 4.6 VM. "
            "Azure fabric can inject SSH public keys, run VM extensions, and resize disks. "
            "This is the intended Azure control plane — not a Tencent-specific modification. "
            "The slice=azure.slice CPUAccounting provides resource isolation for Azure extensions."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 AppStream Java infrastructure RE")
    print()
    print("WALinuxAgent-2.8.0.11-7.tl4.ap.1:")
    print(f"  Tencent patch: {WALINUXAGENT['tencent_patch']['file']} — distribution detection only")
    print(f"  Security delta from upstream: none")
    print()
    print("apache-sshd-2.9.2-2.tl4:")
    cve = APACHE_SSHD['cve_2026_56452']
    print(f"  CVE-2026-56452 (GHSA ab3672f) — SCP path traversal")
    print(f"  Root cause: name.replace('/', sep) without traversal check")
    print(f"  Fix: checkRemoteFileName() validates no '..'/'/'/'abs path'/identity")
    print(f"  Backported {cve['tencent_backport_date']} by {cve['tencent_backport_author']}")
    print(f"  Prior: CVE-2022-45047 (Java deserialization) — fixed in 2.9.2-1")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
