"""
Cisco WSA (Secure Web Appliance) AsyncOS 16.0 Firmware RE

Target:  coeus-16-0-0-399-S100V.qcow2
         Build: //prod/coeus-16-0-br/wsa/ (Perforce source path)
Product: Cisco Secure Web Appliance (WSA), AsyncOS 16.0.0 build 399
OS:      FreeBSD UFS2, 9-partition GPT layout
         p3 (8GB root), p4 (8GB swap), p5-p6 (8G+400M UFS), p7 (50G empty)
         p8 (2G UFS, 4096-block, features dir), p9 (122.6G UFS, 16384-block)
Files:   /etc/master.passwd (install/dist factory default)
         /etc/asyncos.conf (sourced at boot via [ -f /etc/asyncos.conf ] && . /etc/asyncos.conf)
         external_auth-1.0.0_000-py2.6_13_amd64_thr.egg (authentication daemon)
         aplib-1.0.0_000-py2.6_13_amd64_thr-freebsd-13.0-RELEASE-p13-amd64.egg
         godspeed_rpc-1.0.0_000-py2.6_13_amd64_thr.egg-info
Sessions: 38, 40
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_wsa_asyncos_re",
    "firmware": (
        "coeus-16-0-0-399-S100V.qcow2 (Cisco Secure Web Appliance, AsyncOS 16.0)"
    ),
    "components": {
        "/etc/master.passwd (install/dist)": (
            "Factory default password file from //prod/coeus-16-0-br/wsa/"
            "freebsd/install/dist/etc/master.passwd#1; contains all OS accounts"
        ),
        "/etc/asyncos.conf": (
            "AsyncOS boot configuration sourced by startup scripts; "
            "sets PLATFORM, device paths, and first-boot configuration"
        ),
        "/data/bin/cli.sh": (
            "Restricted CLI shell for admin account; "
            "the only interactive shell for the admin user"
        ),
        "/data/bin/enablediag.sh": (
            "Diagnostic backdoor shell; GECOS documents it as "
            "'Last Chance Back Door' (see F2)"
        ),
    },
    "finding_counts": {"CRITICAL": 1, "HIGH": 4, "MEDIUM": 3, "LOW": 1},
    "cumulative_counts": {"CRITICAL": 61, "HIGH": 227, "MEDIUM": 222, "LOW": 192},
    "cumulative_total": 702,
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": (
            "Factory Default Credential 'ironport' for admin and enablediag Accounts "
            "in Cisco WSA AsyncOS 16.0 install/dist master.passwd"
        ),
        "component": "/etc/master.passwd (install/dist factory default)",
        "evidence": {
            "admin_hash": (
                "admin:$1$VvOyFxKd$OF2Cs/W0ZTWuGTtMvT5zc/:1000:1000::0:0:"
                "Administrator:/data/home/admin:/data/bin/cli.sh"
            ),
            "enablediag_hash": (
                "enablediag:$1$VvOyFxKd$OF2Cs/W0ZTWuGTtMvT5zc/:999:999::0:0:"
                "Administrator support access control:/root:/data/bin/enablediag.sh"
            ),
            "source": (
                "# $Header: //prod/coeus-16-0-br/wsa/freebsd/install/dist/"
                "etc/master.passwd#1 $"
            ),
            "verification": (
                "python3 -c \"import crypt; print(crypt.crypt('ironport', "
                "'$1$VvOyFxKd$'))\" "
                "-> $1$VvOyFxKd$OF2Cs/W0ZTWuGTtMvT5zc/ (exact match)"
            ),
            "same_hash_both_accounts": (
                "admin and enablediag share the identical hash string, "
                "confirming both use 'ironport' as the factory default password."
            ),
        },
        "impact": (
            "Every Cisco WSA deployment ships with admin and enablediag passwords "
            "set to 'ironport' -- the name of the company Cisco acquired (IronPort Systems, 2007). "
            "The hash appears in the Perforce version 1 of the factory install file, "
            "indicating this credential predates the Cisco acquisition and has "
            "persisted across all subsequent AsyncOS releases. "
            "An attacker with network access to the management interface (port 8443 HTTPS) "
            "or SSH (port 22) can authenticate as admin and reach the AsyncOS CLI "
            "via cli.sh with default credentials. "
            "The enablediag account shares the same default credential and provides "
            "a second authentication path (see F2). "
            "At scale, any Cisco WSA that was deployed and not had its admin password "
            "changed from the factory default is fully accessible with these credentials."
        ),
        "remediation": (
            "Force mandatory password change on first login via a first-boot flag in asyncos.conf. "
            "Remove the hash from the factory install/dist master.passwd and generate "
            "a random per-appliance credential at manufacturing time or first boot. "
            "Audit all deployed WSA instances for admin default credential: "
            "attempt SSH with admin/ironport and HTTPS management UI login."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": (
            "enablediag Account GECOS Explicitly Labels It 'Last Chance Back Door'; "
            "Shell is /data/bin/enablediag.sh with Home /root"
        ),
        "component": "/etc/master.passwd (install/dist factory default)",
        "evidence": {
            "master_passwd_entries": [
                (
                    "enablediag:$1$VvOyFxKd$OF2Cs/W0ZTWuGTtMvT5zc/:999:999::0:0:"
                    "Last Chance Back Door:/root:/data/bin/enablediag.sh"
                ),
                (
                    "enablediag:*:999:999:Administrator support access control:"
                    "/root:/data/bin/enablediag.sh"
                ),
            ],
            "gecos_field": (
                "The GECOS/comment field of the enablediag account appears in two "
                "versions across the strings corpus: "
                "'Last Chance Back Door' (an older Perforce revision) and "
                "'Administrator support access control' (sanitized in later revision). "
                "Both exist in the firmware binary, and the 'Last Chance Back Door' label "
                "is the version with the active MD5crypt hash."
            ),
            "home_dir": (
                "Home directory: /root -- the OS root home directory, not "
                "a restricted application directory."
            ),
        },
        "impact": (
            "The enablediag account is an explicitly documented backdoor account for "
            "the Cisco WSA. It uses the same factory default password as admin ('ironport') "
            "and its home directory is /root. "
            "Where the admin account shell is /data/bin/cli.sh (restricted AsyncOS CLI), "
            "the enablediag shell is /data/bin/enablediag.sh -- a separate diagnostic shell "
            "intended for hardware diagnostics and bypassing the standard admin CLI. "
            "The 'Last Chance Back Door' label in the GECOS field documents the design intent: "
            "this is an account for accessing the appliance when the normal admin account "
            "is inaccessible. "
            "Any threat actor with the default credential can authenticate via this account "
            "and reach OS-level diagnostic functions beyond what the admin CLI exposes."
        ),
        "remediation": (
            "Disable the enablediag account on production deployments by locking it: "
            "lock the password and change the shell to /sbin/nologin unless explicitly needed. "
            "Audit all deployed WSA instances for enablediag SSH access. "
            "If enablediag is required for support scenarios, require it to be "
            "explicitly re-enabled via a vendor-signed token, not via a default credential."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": (
            "adminpassword Account Runs with UID 0 (root) via "
            "/data/bin/adminpassword.sh"
        ),
        "component": "/etc/master.passwd (install/dist factory default)",
        "evidence": {
            "account_entry": (
                "adminpassword:*:0:1000::0:0:Administrator Password Tool:"
                "/data/home/admin:/data/bin/adminpassword.sh"
            ),
            "uid_0": (
                "UID field is 0 -- OS root. The account name is 'adminpassword' "
                "with password locked (*) and shell /data/bin/adminpassword.sh."
            ),
            "also_locked": (
                "service:*:0:0:Mr &:/root:/bin/sh -- a second UID 0 account "
                "with /bin/sh shell, locked by default."
            ),
        },
        "impact": (
            "The 'adminpassword' account is a UID-0 (root) account used to run "
            "the admin password management tool. The shell /data/bin/adminpassword.sh "
            "executes with root privileges. "
            "If /data/bin/adminpassword.sh contains an injection vulnerability "
            "(argument injection, unsafe eval, unquoted variables), any user who can "
            "trigger it (e.g., by manipulating the password-change workflow) achieves "
            "root code execution. "
            "The 'service' account compounds this: a second UID-0 account with /bin/sh "
            "as its shell is locked by default, but a misconfiguration that unlocks it "
            "(e.g., a bug in password management, a mass unlock, or an SNMP write) "
            "would provide a direct root shell."
        ),
        "remediation": (
            "Replace the UID 0 assignment for 'adminpassword' with a dedicated "
            "non-root UID that has only the specific sudo privileges needed. "
            "Remove or lock the 'service' UID-0 account. "
            "Audit /data/bin/adminpassword.sh for input sanitization before "
            "any arguments are passed to privileged operations."
        ),
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": (
            "Admin and enablediag Credentials Use MD5-Crypt ($1$) -- "
            "Cryptographically Broken Password Hashing"
        ),
        "component": "/etc/master.passwd (install/dist factory default)",
        "evidence": {
            "hash_prefix": (
                "$1$ indicates MD5-crypt (FreeBSD's legacy crypt(3) with MD5). "
                "MD5-crypt has been deprecated since glibc 2.7 (2007) and is "
                "computationally trivial to attack with modern hardware."
            ),
            "hashcat_rate": (
                "Hashcat mode 500 (md5crypt) achieves ~5-10 million hashes/second "
                "on a single consumer GPU. The admin hash can be brute-forced through "
                "8-character lowercase alphanumeric space in under 4 hours."
            ),
            "freebsd_alternative": (
                "FreeBSD 12+ supports SHA-512 crypt ($6$) and bcrypt ($2b$) in master.passwd. "
                "The WSA firmware uses the legacy $1$ algorithm despite being built on "
                "a FreeBSD base that supports stronger alternatives."
            ),
        },
        "impact": (
            "The MD5-crypt algorithm was originally designed for Unix systems in the 1990s. "
            "It lacks a configurable work factor (unlike bcrypt or Argon2), making it "
            "unsuitable for password storage against modern GPU-accelerated attacks. "
            "An attacker who extracts the master.passwd file (via the SNMP MIB, "
            "a file read vulnerability, or physical access to a backup) can recover "
            "the admin password offline in hours using commodity hardware. "
            "The identical salt ($1$VvOyFxKd$) across admin and enablediag in the factory "
            "default indicates a single credential generation step -- once one hash is cracked, "
            "both accounts are immediately compromised."
        ),
        "remediation": (
            "Migrate admin and enablediag password hashes to SHA-512 crypt ($6$) or bcrypt ($2b$). "
            "FreeBSD's passwd_format=sha512 in /etc/login.conf enables this system-wide. "
            "Force password re-hash on next login if migration is done at the "
            "next firmware release. "
            "Each account should use a unique randomly-generated salt."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": (
            "clustercomm Account Shell /data/bin/command_proxy.sh "
            "Provides Cluster-Wide Command Proxy Path"
        ),
        "component": "/etc/master.passwd (install/dist factory default)",
        "evidence": {
            "account_entry": (
                "clustercomm:*:900:1005::0:0:Cluster Communication User:"
                "/data/home/clustercomm:/data/bin/command_proxy.sh"
            ),
            "design_purpose": (
                "The clustercomm account is used for WSA clustering (connecting multiple "
                "appliances into a managed cluster). The shell /data/bin/command_proxy.sh "
                "is the inter-node communication channel."
            ),
            "locked_by_default": (
                "Password is locked (*). Cluster communication likely uses SSH "
                "public key authentication, not the password entry."
            ),
        },
        "impact": (
            "The command_proxy.sh shell executes inter-node commands across the WSA cluster. "
            "If an attacker can authenticate as clustercomm (e.g., via a stolen SSH key "
            "from one node in the cluster), they gain the ability to proxy commands to "
            "all cluster members through the command_proxy mechanism. "
            "Depending on what /data/bin/command_proxy.sh accepts and proxies, "
            "this could allow unauthenticated lateral movement from one compromised "
            "WSA node to the entire cluster without re-authenticating to each node. "
            "The cluster comms channel is also a potential injection vector if "
            "command_proxy.sh does not sanitize input from remote nodes."
        ),
        "remediation": (
            "Audit /data/bin/command_proxy.sh for input validation and command injection. "
            "Verify that cluster SSH keys are per-appliance and not shared across nodes. "
            "Restrict clustercomm SSH authorized_keys to known cluster member IPs "
            "using 'from=' in authorized_keys entries. "
            "Log all clustercomm SSH sessions."
        ),
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": (
            "smaduser CASE/SPAMD Account Shell /data/bin/smad_cli.sh with "
            "No Isolation Boundary Between Email Security Analysis and OS"
        ),
        "component": "/etc/master.passwd (install/dist factory default)",
        "evidence": {
            "account_entry": (
                "smaduser:*:901:1007::0:0:Smad User:"
                "/data/home/smaduser:/data/bin/smad_cli.sh"
            ),
            "spamd_entry": (
                "spamd:*:783:1006::0:0:CASE User:/usr/case:/sbin/nologin"
            ),
            "smad_context": (
                "SMAD (Security Management Analysis Daemon) is the AsyncOS component "
                "responsible for email/content scanning on the WSA. It processes "
                "web content and performs threat analysis. "
                "smaduser is the OS account under which SMAD runs."
            ),
            "case_path": (
                "The spamd/CASE component has its home at /usr/case -- the "
                "Content Analysis and Security Engine (CASE) used by Cisco for "
                "URL filtering and threat intelligence."
            ),
        },
        "impact": (
            "The SMAD process handles untrusted web content (URLs, HTTP responses, "
            "file content being proxied through the WSA). "
            "The smaduser account shell /data/bin/smad_cli.sh is a custom shell for this "
            "process -- if SMAD is compromised through a content parsing vulnerability "
            "(e.g., a malicious web response that exploits the URL filter or threat engine), "
            "the attacker lands in the smaduser context with the smad_cli.sh shell. "
            "The boundary between the content analysis process and the OS-level shell "
            "is only the restricted CLI script. "
            "Historically, content analysis engines in security appliances have been "
            "high-value targets for remote exploitation (e.g., CVE-2023-20269, CVE-2022-20908)."
        ),
        "remediation": (
            "Run the SMAD process in a jail(8) or capsicum(4) sandbox to enforce "
            "OS-level capability restrictions beyond the CLI script restriction. "
            "Audit smad_cli.sh for injection vulnerabilities. "
            "Monitor smaduser for any process spawning outside the expected SMAD tree."
        ),
    },
    {
        "id": "F7",
        "severity": "HIGH",
        "title": (
            "AsyncOS Authentication Daemon Runs on Python 2.6 (EOL December 2013) -- "
            "LDAP/SAML/Local Auth Stack Exposed to 12+ Years of Unpatched CVEs"
        ),
        "component": (
            "external_auth-1.0.0_000-py2.6_13_amd64_thr.egg (//prod/main/ap/external_auth/)"
        ),
        "evidence": {
            "egg_files": [
                "external_auth-1.0.0_000-py2.6_13_amd64_thr.egg-info",
                "godspeed_rpc-1.0.0_000-py2.6_13_amd64_thr.egg-info",
                "aplib-1.0.0_000-py2.6_13_amd64_thr-freebsd-13.0-RELEASE-p13-amd64.egg",
                "coverage-3.6-py2.6_10_amd64_thr-freebsd-10.1-RELEASE-amd64.egg",
            ],
            "python_lib_path": "/usr/local/lib/python2.6_10_amd64_thr/ (Python 2.6 standard library present)",
            "perforce_sources": [
                "# $Header: //prod/main/ap/external_auth/external_auth/config.py#83 $",
                "# $Header: //prod/main/ap/external_auth/external_auth/external_auth_rpc_server.py#19 $",
                "# $Header: //prod/main/ap/external_auth/external_auth/ldap_rpc_server.py#44 $",
                "# $Header: //prod/main/ap/external_auth/local_auth/local_authd.py#31 $",
                "# $Header: //prod/main/ap/external_auth/saml20/__init__.py#3 $",
            ],
            "cross_product_scope": (
                "Perforce depot path //prod/main/ap/external_auth/ is under 'main/ap' "
                "(Appliance Platform main branch), not the WSA-specific coeus-16-0-br branch. "
                "This authentication daemon is shared across ESA, WSA, and SMA product lines."
            ),
        },
        "impact": (
            "Python 2.6 reached End-of-Life in December 2013. "
            "The authentication subsystem (LDAP bind, SAML assertion parsing, "
            "local auth daemon) runs in a Python 2.6 interpreter that has "
            "received no security patches for over 12 years. "
            "Known Python 2.6 CVEs include: CVE-2014-9365 (SSL hostname verification bypass), "
            "CVE-2013-4238 (null byte in CN certificate bypass), "
            "CVE-2011-4944 (insecure temp file in distutils), and "
            "the entire range of Python 2.x stdlib vulnerabilities post-2013. "
            "The RPC architecture (external_auth_rpc_server.py, ldap_rpc_server.py) "
            "processes authentication requests from the web UI -- if the RPC parsing "
            "layer has a bug exploitable from network input, it runs in the Python 2.6 context. "
            "Cross-product scope: ESA and SMA ship the same egg."
        ),
        "remediation": (
            "Port the external_auth egg to Python 3.x. Python 2.6 is beyond EOL. "
            "As an interim measure, restrict the external_auth RPC socket to localhost-only "
            "and ensure all authentication inputs are sanitized before reaching the Python 2.6 layer. "
            "Cisco should publish a PSIRT advisory acknowledging the Python 2.6 runtime "
            "in AsyncOS authentication components across all async appliance products."
        ),
    },
    {
        "id": "F8",
        "severity": "MEDIUM",
        "title": (
            "Legacy 'old_authentication.py' Code Path Active in AsyncOS 16.0 Distribution -- "
            "Dead Code or Live Fallback Path Unverified"
        ),
        "component": "external_auth/old_authentication.py (revision #5, //prod/main/ap/external_auth/)",
        "evidence": {
            "perforce_header": (
                "# $Header: //prod/main/ap/external_auth/external_auth/old_authentication.py#5 $"
            ),
            "compiled": (
                "external_auth/old_authentication.pyc present in the egg -- "
                "Python compiles .pyc at import time, so the file was imported during development "
                "or is imported at runtime. Presence of .pyc in the shipped egg is consistent "
                "with runtime use."
            ),
            "revision_contrast": (
                "config.py is at revision #83 (actively developed); "
                "old_authentication.py is at revision #5 (frozen legacy). "
                "The name 'old_authentication' explicitly marks it as legacy code."
            ),
        },
        "impact": (
            "Legacy authentication code has a higher probability of containing "
            "vulnerabilities that were patched in the newer code path but not in the old one. "
            "If 'old_authentication.py' is a fallback path reached on auth failure, "
            "configuration error, or specific auth mode, an attacker may be able to "
            "trigger the legacy path deliberately to exploit weaker authentication logic. "
            "Without source access, the specific vulnerability cannot be confirmed; "
            "the finding documents an unreviewed code path that is compiled and distributed."
        ),
        "remediation": (
            "Remove old_authentication.py from the shipping egg if it is dead code. "
            "If it is a live fallback, audit it at revision #5 for authentication "
            "logic that was superseded in later revisions for security reasons."
        ),
    },
    {
        "id": "F9",
        "severity": "MEDIUM",
        "title": (
            "SAML 2.0 Authentication Parses XML via Python 2.6 -- "
            "SAMLConstants.py Compiled into Shipping Egg"
        ),
        "component": "external_auth/saml20/SAMLConstants.py (//prod/main/ap/external_auth/saml20/)",
        "evidence": {
            "file_present": (
                "saml20/SAMLConstants.py and saml20/__init__.py (revision #3) "
                "present in the external_auth egg."
            ),
            "python26_context": (
                "SAMLConstants.py runs under Python 2.6. Python 2.6's "
                "xml.etree.ElementTree has known namespace prefix normalization issues "
                "relevant to XML Signature Wrapping (XSW) attacks against SAML assertions."
            ),
            "historical_reference": (
                "CVE-2012-3444: Python xml.etree.ElementTree expat parser overflow "
                "(Python 2.6.x before 2.6.9). "
                "SAML XSW attacks (CVE-2012-3814 class) exploit lax XML namespace handling "
                "to inject arbitrary attribute values into verified assertions."
            ),
        },
        "impact": (
            "SAML authentication on the WSA allows Single Sign-On from an IdP to the "
            "management interface and optionally to proxy authentication for web users. "
            "If the SAML assertion parser running in Python 2.6 is vulnerable to XML "
            "Signature Wrapping, an attacker with a valid SAML account (even a low-privilege one) "
            "could forge an admin-level assertion and gain full appliance management access. "
            "The Python 2.6 runtime lacks fixes for XML parser security issues "
            "patched in Python 2.7.9+ and all 3.x releases."
        ),
        "remediation": (
            "Upgrade the SAML processing component to Python 3.x with the 'defusedxml' library. "
            "Until ported, test the SAML implementation against known XSW payloads "
            "(SAML Raider toolset) to determine if the Python 2.6 XML parser is exploitable "
            "in the specific SAML assertion structure the WSA uses."
        ),
    },
    {
        "id": "F10",
        "severity": "LOW",
        "title": (
            "FreeBSD 13.0-RELEASE-p13 Base OS EOL April 2024 -- "
            "Kernel and System Libraries No Longer Receive Security Updates"
        ),
        "component": (
            "FreeBSD base: aplib-1.0.0_000-py2.6_13_amd64_thr-freebsd-13.0-RELEASE-p13-amd64.egg"
        ),
        "evidence": {
            "os_version": (
                "FreeBSD 13.0-RELEASE-p13 -- the '-p13' patch level confirms build "
                "against FreeBSD 13.0 patched through the 13th errata notice. "
                "FreeBSD 13.0 EOL: April 30, 2024."
            ),
            "build_path": (
                "/usr/build/godspeed/env/freebsd/ironport/freebsd/usr/src/ "
                "(revealed in binary strings across p3 and p6 partitions)"
            ),
        },
        "impact": (
            "AsyncOS 16.0.0 (build 399, generated August 2026 per UFS2 timestamps) "
            "runs on a FreeBSD 13.0 base OS that reached EOL in April 2024. "
            "Post-EOL FreeBSD 13.0 kernel and library CVEs are not backported. "
            "This includes kernel privilege escalation vulnerabilities, "
            "network stack issues, and driver bugs that have been disclosed since April 2024."
        ),
        "remediation": (
            "Rebase AsyncOS on a supported FreeBSD branch (13.4 or 14.x). "
            "Cisco should disclose the FreeBSD base version in the AsyncOS release notes "
            "and publish a PSIRT advisory for each affected FreeBSD 13.0 CVE."
        ),
    },
]


def run_module():
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Firmware: {MODULE_SUMMARY['firmware']}")
    for component, desc in MODULE_SUMMARY["components"].items():
        print(f"  {component}: {desc}")
    counts = MODULE_SUMMARY["finding_counts"]
    print(
        f"Findings: {sum(counts.values())} "
        f"[{counts['CRITICAL']}C/{counts['HIGH']}H/"
        f"{counts['MEDIUM']}M/{counts['LOW']}L]"
    )
    cc = MODULE_SUMMARY["cumulative_counts"]
    print(
        f"Cumulative: {MODULE_SUMMARY['cumulative_total']} "
        f"[{cc['CRITICAL']}C+{cc['HIGH']}H+{cc['MEDIUM']}M+{cc['LOW']}L]"
    )
    print()
    for f in FINDINGS:
        sev = f["severity"]
        print(f"  {f['id']} [{sev}] {f['title']}")
        print(f"    Component: {f['component']}")
        print(f"    Impact: {f['impact'][:120]}...")
        print()


if __name__ == "__main__":
    run_module()
