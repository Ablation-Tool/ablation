"""
TencentOS — polkit SRPM CVE patch stack RE.

Package: polkit-0.115-13.el8_5.2
Source: scratchpad/polkit.spec (615 lines)
Base: upstream polkit 0.115 (RHEL 8 backport base)
TOS version: consumed as-is from RHEL 8 patch lineage

polkit provides policy-based privilege escalation. Two SUID-root binaries ship:
  %attr(4755,root,root) /usr/bin/pkexec
  %attr(4755,root,root) /usr/lib/polkit-1/polkit-agent-helper-1

Both are setuid root. Any memory corruption vulnerability in these binaries
constitutes a local privilege escalation to root.
"""

PACKAGE_METADATA = {
    "name": "polkit",
    "version": "0.115",
    "release": "13.el8_5.2",
    "suid_binaries": [
        "/usr/bin/pkexec",
        "/usr/lib/polkit-1/polkit-agent-helper-1",
    ],
    "suid_mode": "4755",
    "suid_owner": "root:root",
    "scripting_engine": "mozjs60 (SpiderMonkey 60)",
    "ipc": "D-Bus (system bus)",
}

PATCHES = {
    "Patch1": "polkit-0.115-bus-conn-msg-ssh.patch — D-Bus connection message handling for SSH",
    "Patch2": "polkit-0.115-pkttyagent-auth-errmsg-debug.patch — auth error to debug level",
    "Patch3": "polkit-0.115-polkitagentlistener-res-leak.patch — resource leak fix",
    "Patch4": "polkit-0.115-spawning-zombie-processes.patch — zombie reap fix",
    "Patch5": "CVE-2018-19788",
    "Patch6": "CVE-2019-6133",
    "Patch7": "polkit-0.115-pkttyagent-tty-echo-off-on-fail.patch",
    "Patch8": "polkit-0.115-allow-uid-of-1.patch — allow UID 1 (daemon) to auth",
    "Patch9": "polkit-0.115-move-to-mozjs60.patch — JS engine upgrade",
    "Patch10": "polkit-0.115-jsauthority-memleak.patch — JS authority memory leak",
    "Patch11": "polkit-0.115-pkttyagent-tcsaflush-batch-erase.patch",
    "Patch12": "CVE-2021-3560",
    "Patch13": "CVE-2021-4034",
    "Patch14": "CVE-2021-4115",
}

CVES = {
    "CVE-2018-1116": {
        "title": "Temporary auth bypass via heap overflow (fixed in 0.115 release itself)",
        "severity": "MEDIUM",
        "description": (
            "Heap overflow in polkit 0.114 and earlier. 0.115 was the fix release. "
            "Patch is the version upgrade itself — the polkit.spec starts at 0.115."
        ),
        "fixed_by": "version upgrade to 0.115",
        "patched_in_tos": True,
    },
    "CVE-2018-19788": {
        "title": "Integer overflow with high UIDs — privilege escalation",
        "severity": "HIGH",
        "cvss3": 8.0,
        "description": (
            "polkit before 0.115-5 fails to check for integer overflow when checking "
            "if a UID exceeds 2^31. A local user with a UID >= 2147483648 (i.e., in the "
            "range that wraps to negative when stored as int32) would bypass polkit "
            "authorization checks because the sign check fails. "
            "Affected: any user created with a high UID (e.g., systemd-nspawn creates "
            "container users starting at 0x10000). "
            "Fix: explicit uint32 check on all UID comparisons."
        ),
        "patch": "polkit-0.115-CVE-2018-19788.patch",
        "patched_in_tos": True,
        "pre_auth": False,
        "local_only": True,
        "class": "integer-overflow",
    },
    "CVE-2019-6133": {
        "title": "PID reuse via slow fork — stale authentication cached for new process",
        "severity": "MEDIUM",
        "cvss3": 7.3,
        "description": (
            "polkit caches authentication decisions by PID. If process A authenticates "
            "successfully, then exits, and a new process B reuses A's PID before the "
            "cache entry expires, process B inherits A's authentication. "
            "Exploitable via a fork-and-exec race: parent process authenticates; "
            "forks and delays child exec; child inherits the PID that gets cached "
            "auth for the parent's identity. "
            "Fix: include process start time in cache key (auth tied to PID+starttime tuple)."
        ),
        "patch": "polkit-0.115-CVE-2019-6133.patch",
        "patched_in_tos": True,
        "pre_auth": False,
        "local_only": True,
        "class": "race-condition",
    },
    "CVE-2021-3560": {
        "title": "Early D-Bus disconnect: auth decision made for disconnected client",
        "severity": "HIGH",
        "cvss3": 7.8,
        "description": (
            "polkitd processes D-Bus auth requests by: (1) receive request from client, "
            "(2) check client UID via D-Bus GetConnectionUnixUser, (3) make auth decision. "
            "If the client disconnects between steps 1 and 2, D-Bus returns an error for "
            "GetConnectionUnixUser. polkitd previously mishandled this error: it continued "
            "processing with an uninitialized or zero-value UID, potentially granting "
            "root-equivalent authorization. "
            "Exploitable: client sends privileged request, immediately disconnects — "
            "polkitd processes the request with UID 0 as the caller. "
            "Fix: treat D-Bus error on UID lookup as denial."
        ),
        "patch": "polkit-0.115-CVE-2021-3560.patch",
        "patched_in_tos": True,
        "pre_auth": False,
        "local_only": True,
        "class": "race-condition",
        "notes": "Exploited in the wild before patch release (May 2021).",
    },
    "CVE-2021-4034": {
        "title": "PwnKit: pkexec argv[] out-of-bounds write — local root LPE",
        "severity": "CRITICAL",
        "cvss3": 7.8,
        "description": (
            "pkexec (SUID root) mishandles the argc=0 case when processing its argument vector. "
            "The vulnerability is in the argument parsing loop: pkexec walks argv[] and argc "
            "looking for its own path. When argc=0 (or argv is crafted), pkexec reads beyond "
            "the end of argv[] into envp[] territory. "
            "An attacker who can exec pkexec with argc=0 can inject a crafted envp[] entry "
            "that pkexec rewrites as an argv[] entry. This write is in a SUID-root context. "
            "By placing a crafted string in envp that pkexec writes back to envp (thinking "
            "it is argv), an attacker achieves an out-of-bounds write in the SUID-root "
            "pkexec process, resulting in controlled execution as root. "
            "All polkit versions from 2009 (first release) through 0.120 were vulnerable. "
            "Named 'PwnKit' by Qualys Research (January 2022). "
            "CVSS 7.8 LOCAL: no network access required; any local user → root."
        ),
        "patch": "polkit-0.115-CVE-2021-4034.patch",
        "patched_in_tos": True,
        "pre_auth": False,
        "local_only": True,
        "class": "out-of-bounds-write",
        "exploit_public": True,
        "discovered_by": "Qualys Research Team",
        "published": "2022-01-25",
        "notes": (
            "pkexec mode: 4755 root root — setuid root binary. "
            "Exploit requires local shell access only. "
            "Multiple public exploit PoCs available. "
            "TOS ships the patch (Patch13); unpatched systems are trivially exploitable."
        ),
    },
    "CVE-2021-4115": {
        "title": "File descriptor exhaustion (GHSL-2021-077) — auth bypass via FD starvation",
        "severity": "MEDIUM",
        "cvss3": 5.5,
        "description": (
            "polkitd can be forced to exhaust its available file descriptors. "
            "When polkitd's FD table is full, certain auth operations fail in a way "
            "that grants authorization rather than denying. "
            "An attacker who can open many files/sockets and send polkit requests "
            "can trigger the FD exhaustion condition and bypass authorization. "
            "GitHub Security Lab (GHSL) advisory 2021-077. "
            "Fix: explicit FD limit checks and denial-on-error for FD operations."
        ),
        "patch": "polkit-0.115-CVE-2021-4115.patch",
        "patched_in_tos": True,
        "pre_auth": False,
        "local_only": True,
        "class": "resource-exhaustion",
    },
}

MOZJS_NOTE = {
    "description": (
        "polkit embeds SpiderMonkey (mozjs60) as its JavaScript policy evaluation engine. "
        "Patch9 upgrades to mozjs60. The JS engine executes .rules files in /etc/polkit-1/rules.d/ "
        "and /usr/share/polkit-1/rules.d/. Any JS engine vulnerability that can be "
        "triggered through a crafted .rules file (or through the polkit IPC call that "
        "triggers rule evaluation) affects polkitd (running as root)."
    ),
    "rules_dirs": [
        "/etc/polkit-1/rules.d/",
        "/usr/share/polkit-1/rules.d/",
    ],
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "cve": "CVE-2021-4034",
        "title": "PwnKit: SUID pkexec argv OOB write → local root (patched in TOS)",
        "detail": (
            "pkexec mode 4755 root root. CVE-2021-4034 (Qualys, published 2022-01-25): "
            "argc=0 case allows envp[]-to-argv[] pointer rewrite in SUID context. "
            "Any local user → root. All polkit versions since 2009 affected. "
            "TOS applies Patch13 (fixed). Unpatched instances: trivially exploitable via "
            "public PoCs."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "cve": "CVE-2021-3560",
        "title": "D-Bus early disconnect: auth decision with uninitialized UID (patched)",
        "detail": (
            "Client disconnects immediately after sending privileged polkit request. "
            "polkitd's GetConnectionUnixUser returns error; prior to patch, polkitd "
            "processed request with UID 0 → root-level authorization granted. "
            "Exploited in the wild (May 2021). TOS patches applied."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "cve": "CVE-2018-19788",
        "title": "Integer overflow on high UIDs: auth bypass for UID >= 2^31",
        "detail": (
            "UID stored as int32; values >= 2147483648 sign-wrap to negative. "
            "Polkit sign check passes for wrapped UIDs, granting authorization. "
            "Container users (systemd-nspawn assigns high UIDs) are affected. "
            "TOS patches applied."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "cve": "CVE-2019-6133",
        "title": "PID reuse race: stale auth cache entry inherited by new process",
        "detail": (
            "Auth cache keyed by PID only. Slow fork + exec race: parent authenticates, "
            "exits; child reuses PID before cache expires → child inherits parent auth. "
            "Fixed by adding process start time to cache key. TOS patches applied."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "cve": "CVE-2021-4115",
        "title": "FD exhaustion auth bypass: polkitd grants auth when FD table is full",
        "detail": (
            "Attacker opens many FDs; sends polkit request; FD exhaustion causes auth "
            "path to return grant instead of deny. GHSL-2021-077. TOS patches applied."
        ),
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "pkexec and polkit-agent-helper-1 are SUID root — attack surface note",
        "detail": (
            "Both /usr/bin/pkexec and /usr/lib/polkit-1/polkit-agent-helper-1 ship "
            "with mode 4755 root:root. Any future memory corruption in these binaries "
            "is a local root path. The SpiderMonkey JS engine (mozjs60) in polkitd "
            "adds JS engine CVEs as an indirect polkit attack surface."
        ),
    },
]

if __name__ == '__main__':
    print("polkit 0.115 TOS CVE stack RE")
    print(f"  version: {PACKAGE_METADATA['version']}-{PACKAGE_METADATA['release']}")
    print(f"  SUID binaries: {', '.join(PACKAGE_METADATA['suid_binaries'])}")
    print()
    print("CVE patch stack:")
    for cve_id, cve in CVES.items():
        patched = "[PATCHED]" if cve.get('patched_in_tos') else "[UNPATCHED]"
        print(f"  {patched} {cve_id} ({cve['severity']}): {cve['title'][:60]}")
    print()
    for f in FINDINGS:
        cve = f"[{f.get('cve', '')}] " if f.get('cve') else ""
        print(f"  [{f['severity']:8s}] {f['id']}: {cve}{f['title'][:65]}")
