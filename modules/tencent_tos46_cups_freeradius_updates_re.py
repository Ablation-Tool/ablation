"""
TencentOS 4.6 — CUPS 2.4.6 new CVE patch stack + FreeRADIUS 3.2.x LDAP fix.

Sources:
  scratchpad/cups_work/ — CUPS 2.4.6-*.tl4 patch stack
  scratchpad/fr32-re/   — FreeRADIUS 3.2.6 TOS 4.6 patches
"""

CUPS_METADATA = {
    "package": "cups-2.4.6",
    "tos_version": "TOS 4.6",
    "patches": [
        "cups-2.4.6-CVE-2026-27447.patch",
        "backport-CVE-2025-58436.patch",
        "backport-CVE-2025-58436-after-fix-an-infinite-loop-issue-in-GTK.patch",
        "backport-CVE-2025-61915.patch",
        "backport-CVE-2023-4504.patch",
        "0001-Fix-delays-printing-to-lpd-when-reserved-ports-are-e.patch",
        "0001-Use-purge-job-instead-of-purge-jobs-when-canceling-a.patch",
        "0004-Fix-domain-socket-handling.patch",
        "0005-CVE-2024-47175-and-further-hardening.patch",
        "backport-Fix-builds-against-GSSAPI-Kerberos.patch",
    ],
}

CUPS_CVES = {
    "CVE-2026-27447": {
        "title": "Scheduler treats Unix group membership as case-insensitive — auth bypass",
        "file": "scheduler/auth.c",
        "function": "cupsdCheckGroup",
        "author": "Michael R Sweet <msweet@msweet.org>",
        "adapted_by": "PkgAgent (opencloudos-stream)",
        "ai_ported": True,
        "description": (
            "cupsdCheckGroup() compared the requesting username against group member entries "
            "using _cups_strcasecmp() — case-insensitive comparison. "
            "On Linux, getpwnam() and getgrnam() are always case-sensitive (POSIX-conformant). "
            "A user named 'ADMIN' would match a group member entry 'admin', granting access "
            "to printer queues and administrative endpoints restricted to that group. "
            "Additionally, the NULL check on 'user' was missing: the function could dereference "
            "a NULL user pointer when 'group != NULL' and 'user == NULL', causing NULL deref crash."
        ),
        "vulnerable_code": "_cups_strcasecmp(username, group->gr_mem[i])  /* case-insensitive! */",
        "fixed_code": "if (user && group) { ... if (!strcmp(user->pw_name, group->gr_mem[i])) }",
        "class": "authorization-bypass",
        "impact": "Attacker with a username that case-matches a privileged group member can manage printers.",
    },
    "CVE-2025-58436": {
        "title": "Slow-client DoS — single-threaded cupsd stalled by adversarial HTTP client",
        "files": ["cups/http.c", "cups/http-private.h", "cups/tls-openssl.c", "scheduler/client.c"],
        "author": "Zdenek Dohnal (Red Hat)",
        "description": (
            "cupsd is single-threaded. A client that sends HTTP requests extremely slowly "
            "(byte at a time) forces cupsd to wait for the full request before handling other "
            "connections, creating a DoS against legitimate print clients. "
            "Two paths exploitable: "
            "(1) Unencrypted: cupsd blocks reading until full line received; "
            "(2) TLS: TLS handshake blocks before full ClientHello is received. "
            "Fix: unencrypted path now checks for complete line before processing; "
            "TLS path waits for full ClientHello packet before starting handshake. "
            "RFC 2817 section 3.1 optional HTTPS upgrade support REMOVED as a side effect. "
            "New constant _HTTP_MAX_BUFFER=32768 defines the read buffer ceiling."
        ),
        "impact": "Remote DoS against print servers without authentication.",
        "class": "resource-exhaustion",
        "pre_auth": True,
    },
    "CVE-2025-61915": {
        "title": "Three bugs: IPv6 OOB write + ErrorPolicy NULL deref + PeerCred cupsd.conf overwrite",
        "files": [
            "scheduler/auth.c", "scheduler/auth.h", "scheduler/client.c",
            "scheduler/conf.c", "conf/cups-files.conf.in",
        ],
        "reporter": "@SilverPlate3; additional finding by Mike Sweet",
        "authors": "Zdenek Dohnal (Red Hat)",
        "class": "multiple",
        "sub_findings": [
            {
                "title": "IPv6 address parsing: out-of-bounds write",
                "file": "scheduler/client.c",
                "description": "IPv6 address handling in client parsing writes beyond buffer boundary.",
                "class": "heap-overflow",
            },
            {
                "title": "ErrorPolicy: NULL dereference when value is empty string",
                "file": "scheduler/conf.c",
                "description": "Reading an empty ErrorPolicy directive causes NULL deref crash in cupsd.",
                "class": "null-deref",
            },
            {
                "title": "PeerCred domain socket: cupsd.conf overwrite via admin-group member",
                "files": ["scheduler/auth.c", "conf/cups-files.conf.in"],
                "description": (
                    "cupsd honors Unix PeerCred authentication on its domain socket. "
                    "A local user whose username is in a CUPS system group could authenticate "
                    "via domain socket and overwrite cupsd.conf with malicious content. "
                    "Fix: new 'PeerCred' directive in cups-files.conf (default=Yes for backwards "
                    "compatibility) allows administrators to disable PeerCred authentication. "
                    "When PeerCred=No, domain socket users must use normal HTTP authentication."
                ),
                "class": "local-privilege-escalation",
                "impact": "Local user with printer group access can overwrite cupsd.conf → root command execution.",
            },
        ],
    },
    "CVE-2024-47175": {
        "title": "PPD file injection via crafted IPP response",
        "description": "CUPS trusted a crafted printer's IPP response to inject PPD data; hardening applied.",
        "class": "command-injection",
        "pre_auth": True,
    },
    "CVE-2023-4504": {
        "title": "Heap buffer overflow in PPD file parsing",
        "class": "heap-overflow",
        "pre_auth": True,
    },
}

FREERADIUS_PATCHES = {
    "package": "freeradius-server-3.2.6",
    "tos_version": "TOS 4.6",
    "freeradius-ldap-infinite-timeout-on-starttls": {
        "file": "src/modules/rlm_ldap/ldap.c",
        "function": "mod_conn_create",
        "author": "Antonio Torres (Red Hat)",
        "description": (
            "rlm_ldap mod_conn_create() applied the configured net_timeout to LDAP connections "
            "regardless of whether StartTLS or LDAPS was in use. "
            "libldap uses non-blocking sockets during StartTLS by default, causing the TLS "
            "handshake to time out before completing — FreeRADIUS fails to connect to LDAP. "
            "Fix: detect TLS in use (start_tls flag, port==636, or ldaps:// URI prefix) and "
            "skip net_timeout in that case, letting libldap use its own infinite default timeout."
        ),
        "vulnerable_code": "if (inst->net_timeout) { tv.tv_sec = inst->net_timeout; ... }",
        "fixed_code": (
            "bool using_tls = inst->start_tls || inst->port == 636 "
            "|| strncmp(inst->server, 'ldaps://', 8) == 0;\n"
            "if (inst->net_timeout && !using_tls) { ... }"
        ),
        "security_note": (
            "Authentication infrastructure impact: if the StartTLS handshake times out, "
            "FreeRADIUS falls through to the failure_action, which in many configs is "
            "userPolicyNtfy=reject or (more dangerously) fail_on_error=no with a fallback "
            "authentication path. Triggering this bug from a network position between "
            "FreeRADIUS and the LDAP server (MITM or delay injection) could force a fallback "
            "to a weaker auth path."
        ),
        "class": "auth-infrastructure-failure",
    },
    "system-crypto-policy": {
        "patch": "freeradius-Use-system-crypto-policy-by-default.patch",
        "description": "FreeRADIUS uses TOS system crypto-policy by default (RHEL/Tencent standard)",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2026-27447",
        "package": "cups-2.4.6",
        "title": "Group membership case-insensitive comparison — auth bypass in cupsdCheckGroup",
        "detail": (
            "strcasecmp(username, group_member) matches 'ADMIN' to 'admin'. "
            "Attacker crafts username matching a privileged group member in different case. "
            "Grants printer management access. AI-ported by PkgAgent."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "cve": "CVE-2025-61915-3",
        "package": "cups-2.4.6",
        "title": "PeerCred domain socket: cupsd.conf overwrite by admin-group member",
        "detail": (
            "Domain socket PeerCred auth allows any CUPS system group member to overwrite "
            "cupsd.conf. Group membership check was case-insensitive (see CVE-2026-27447). "
            "Chain: craft username matching group member (cased) -> PeerCred auth -> cupsd.conf write "
            "-> root command execution on next restart."
        ),
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "cve": "CVE-2025-58436",
        "package": "cups-2.4.6",
        "title": "Slow-client DoS — single-threaded cupsd stalled pre-auth",
        "detail": (
            "Unauthenticated client sends HTTP bytes one at a time, stalling cupsd "
            "(single-threaded) for all other clients. Both plain HTTP and TLS paths affected."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "cve": "CVE-2025-61915-1",
        "package": "cups-2.4.6",
        "title": "IPv6 address parsing OOB write in scheduler/client.c",
        "detail": "Buffer boundary not enforced during IPv6 address parsing; heap OOB write.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "cve": "CVE-2025-61915-2",
        "package": "cups-2.4.6",
        "title": "Empty ErrorPolicy value causes NULL deref crash in cupsd",
        "detail": "ErrorPolicy= with no value; downstream dereference of NULL from config parser.",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "package": "freeradius-server-3.2.6",
        "title": "LDAP StartTLS: net_timeout kills TLS handshake — authentication infrastructure DoS",
        "detail": (
            "LDAP connection timeout applied during TLS handshake; libldap non-blocking socket "
            "means handshake never completes in time. Network attacker can induce delay on "
            "LDAP path to trigger fallback auth in FreeRADIUS."
        ),
    },
    {
        "id": "F7",
        "severity": "INFO",
        "cve": "CVE-2026-27447",
        "package": "cups-2.4.6",
        "title": "CVE-2026-27447 CUPS auth bypass ported by PkgAgent AI system",
        "detail": (
            "Patch carries 'Adapted-by: PkgAgent (modified to adapt to opencloudos-stream)'. "
            "4th instance of AI-ported security patches in TOS 4.6 srpm stack."
        ),
    },
]

if __name__ == '__main__':
    print("CUPS 2.4.6 + FreeRADIUS 3.2.6 — TOS 4.6 patch stack RE")
    print()
    print("CUPS CVEs:")
    for cve_id, cve in CUPS_CVES.items():
        ai = " [AI-PORTED]" if cve.get("ai_ported") else ""
        print(f"  {cve_id}: {cve['title'][:65]}{ai}")
    print()
    print("FreeRADIUS patches:")
    for k, v in FREERADIUS_PATCHES.items():
        if k in ("package", "tos_version"):
            continue
        print(f"  {k}: {v.get('description', v.get('title',''))[:60]}")
    print()
    for f in FINDINGS:
        cve = f"[{f.get('cve', '')}]" if f.get('cve') else "[INFO]"
        print(f"  [{f['severity']:6s}] {f['id']}: {cve} {f['title'][:60]}")
