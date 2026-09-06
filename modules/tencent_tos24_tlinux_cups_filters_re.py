"""
TencentOS 2.4 (TLinux 2) — cups-filters-1.0.35-29.tl2.3 SRPM RE.

Source from Drive: tencent-re/2.4/tlinux-srpms/cups-filters-1.0.35-29.tl2.3.src.rpm
Base: RHEL 7 cups-filters 1.0.35; three security revisions applied Sep-Oct 2024.
TOS 2.4 is the RHEL 7-equivalent TLinux generation; RHEL 7 EoL was Jun 30 2024,
making this a critical support window package.
"""

PACKAGE = {
    "package": "cups-filters-1.0.35-29.tl2.3",
    "upstream": "cups-filters 1.0.35 (OpenPrinting)",
    "base": "RHEL 7 / CentOS 7 cups-filters-1.0.35-29",
    "license": "GPLv2",
    "maintainer": "Bryan Mason <bmason@redhat.com> (Red Hat backport)",
    "role": (
        "Printing filter conversion library and cups-browsed daemon. "
        "cups-browsed auto-discovers and configures printers on the network via IPP/Bonjour/CUPS browsing. "
        "This is a security-critical package: it listens on network ports, processes untrusted "
        "network input (IPP attributes, PPD files), and executes filter commands as root. "
        "On TOS 2.4: installed on every system with CUPS printing enabled."
    ),
    "security_revision_history": {
        "29.1 (Sep 30 2024)": [
            "CVE-2024-47176 — cups-browsed UDP 631 trust-any-packet",
            "CVE-2024-47076 — cfGetPrinterAttributes IPP attribute no sanitization",
            "CVE-2024-47175 — remote command injection via PPD file",
        ],
        "29.2 (Oct 1 2024)": ["RHEL-60323 — version bump"],
        "29.3 (Oct 1 2024)": [
            "cups-browsed-add-cupsfilter-checks.patch — verifies cups-browsed.conf; "
            "adds cupsFilter space/tab variants to PPD scrubbing; strips *FoomaticRIPCommandLine",
            "0001-cups-browsed-Fixed-freeing-of-literal-string.patch — free of DomainSocket literal",
        ],
    },
}

CVE_2024_47176 = {
    "id": "CVE-2024-47176",
    "cvss3": "9.9 CRITICAL",
    "title": "cups-browsed binds UDP INADDR_ANY:631 and trusts any packet from any source",
    "disclosure": "September 2024 (Simone Margaritelli / evilsocket)",
    "root_cause": (
        "cups-browsed listens on UDP port 631 (0.0.0.0:631) for CUPS browsing broadcast packets. "
        "The daemon accepts and processes printer announcements from any IP address without validation. "
        "An attacker on any network can send a crafted UDP packet to port 631: "
        "  cups-browsed receives it, treats it as a valid printer announcement, "
        "  creates a local CUPS queue pointing to the attacker's IPP server. "
        "This is the initial access vector — by itself it creates a malicious printer queue. "
        "The queue is created but not immediately exploited; exploitation happens when a user prints to it."
    ),
    "exploitation_chain": (
        "CVE-2024-47176 is only the entry point. Full chain requires all four CVEs: "
        "1. CVE-2024-47176: attacker UDP → cups-browsed creates queue pointing to attacker IPP server "
        "2. CVE-2024-47076: cups-browsed fetches IPP attributes from attacker server (cfGetPrinterAttributes); "
        "   attacker returns malicious IPP attributes including crafted PPD URLs/directives "
        "3. CVE-2024-47175: malicious IPP attributes written into PPD file without sanitization — "
        "   PPD is generated/updated by cups-browsed from attacker-controlled data "
        "4. CVE-2024-47177 (cups package, not cups-filters): when user prints to the queue, "
        "   CUPS processes the PPD and executes FoomaticRIPCommandLine as root — COMMAND EXECUTION "
        "Full chain: unauthenticated network access → cups-browsed UDP → attacker IPP → malicious PPD "
        "→ print job → root command execution on any system with cups-browsed running and port 631 reachable."
    ),
    "affected": "cups-browsed all versions up to 2.x when BrowseRemoteProtocols = CUPS (default)",
    "fix": "Disable CUPS browsing (BrowseRemoteProtocols=none) or restrict UDP 631 via firewall",
}

CVE_2024_47175 = {
    "id": "CVE-2024-47175",
    "cvss3": "8.4 HIGH",
    "title": "Remote command injection via attacker-controlled PPD file — FoomaticRIPCommandLine not stripped",
    "root_cause": (
        "cups-browsed receives printer attributes from remote IPP servers and uses them to "
        "generate PPD (PostScript Printer Description) files. The generated PPD may contain "
        "directives that are executed by CUPS when a print job is processed. "
        "Foomatic is a printer driver framework that executes shell commands specified in PPD files "
        "via *FoomaticRIPCommandLine — this line specifies a command to run when processing print jobs. "
        "If an attacker can inject a *FoomaticRIPCommandLine line into a PPD file that cups-browsed "
        "creates, printing to that queue executes arbitrary commands as root (the CUPS daemon user). "
        "The original fix (29.1) stripped *cupsFilter: and *cupsFilter2: lines from pass-through PPDs "
        "but missed: "
        "  (a) whitespace variants: *cupsFilter SPACE, *cupsFilter TAB, *cupsFilter2 SPACE, *cupsFilter2 TAB "
        "  (b) *FoomaticRIPCommandLine entirely (not stripped by the original check) "
    ),
    "bypass": (
        "The 29.1 patch used strncmp(line, '*cupsFilter:', 12) — exact colon match. "
        "A PPD line '*cupsFilter programname 100 rastertoX' (with a space, as valid PPD syntax) "
        "bypassed the check entirely. *FoomaticRIPCommandLine was never checked in 29.1. "
        "Patch 29.3 (cups-browsed-add-cupsfilter-checks.patch) adds: "
        "  !strncmp(line, '*cupsFilter ', 12)   — space variant "
        "  !strncmp(line, '*cupsFilter\\t', 12)  — tab variant "
        "  !strncmp(line, '*cupsFilter2 ', 13)  — space variant "
        "  !strncmp(line, '*cupsFilter2\\t', 13) — tab variant "
        "And: if strncmp(line, '*FoomaticRIPCommandLine', 23) == 0: skip the line (log and discard). "
    ),
    "severity": "HIGH — complete patch bypass in 29.1; 29.3 required for full remediation",
}

CVE_2024_47076 = {
    "id": "CVE-2024-47076",
    "cvss3": "8.6 HIGH",
    "title": "cfGetPrinterAttributes API does not sanitize returned IPP attributes",
    "root_cause": (
        "When cups-browsed creates a queue for a remote printer, it calls cfGetPrinterAttributes() "
        "to fetch printer capabilities via IPP. An attacker controlling an IPP server can return "
        "malicious IPP attributes (including PPD URL, PPD content, filter directives). "
        "The attributes are not sanitized before being used to generate local PPD files. "
        "This is the link between CVE-2024-47176 (queue creation) and CVE-2024-47175 (PPD injection). "
    ),
    "fix": "Input sanitization added to cfGetPrinterAttributes output processing (part of 29.1).",
    "severity": "HIGH — enables PPD injection chain when combined with CVE-2024-47176",
}

ADDITIONAL_PATCHES = {
    "cups-browsed-remove-entry.patch": {
        "description": (
            "Refactors cups-browsed printer entry removal logic. "
            "Adds remove_printer_entry() function that properly handles duplicate printer chains: "
            "when a duplicate printer is removed, its master printer is rescheduled for update. "
            "Fixes use-after-free when a master queue's duplicate is removed while the master "
            "is in STATUS_DISAPPEARED state — the old code had STATUS_DISAPPEARED checks that "
            "prevented rescheduling, leaving stale state."
        ),
        "size": "8.6KB",
        "class": "use-after-free / memory management",
        "authors": "Zdenek Dohnal <zdohnal@redhat.com> (Red Hat)",
    },
    "0001-cups-browsed-Fixed-freeing-of-literal-string.patch": {
        "description": (
            "DomainSocket memory management fix. "
            "DomainSocket is set from config or defaults to CUPS_DEFAULT_DOMAINSOCKET (a compile-time literal). "
            "Old: if DomainSocket == NULL && value: DomainSocket = strdup(value) — but later: "
            "  DomainSocket = CUPS_DEFAULT_DOMAINSOCKET (literal, not heap); free(DomainSocket) → SIGSEGV. "
            "Fix: always strdup() DomainSocket from both config and default value; "
            "free() prior value before reassignment."
        ),
        "class": "free of literal string → SIGSEGV",
        "author": "Bryan Mason (Red Hat)",
    },
    "cups-browsed-socket-leak.patch": {
        "description": "Fixes file descriptor leak when cups-browsed loses its socket connection",
        "class": "resource leak",
        "author": "Zdenek Dohnal (Red Hat)",
    },
    "cups-browsed-memory-leaks.patch": {
        "description": "Multiple memory leak fixes in cups-browsed — printer entry cleanup on shutdown",
        "class": "memory leak",
        "author": "Zdenek Dohnal (Red Hat)",
    },
    "0001-Fixing-covscan-issues.patch": {
        "description": "Static analysis (Coverity) fixes — null dereference, resource management",
        "class": "various static analysis findings",
    },
}

HISTORICAL_CVE_PATCHES = {
    "cups-filters-CVE-2013-6475.patch": {
        "description": "pdftoopvp: heap/stack overflow in PDF processing (2013 — informational)",
        "note": "pdftoopvp not shipped in this build",
    },
    "cups-filters-CVE-2015-3258-3279.patch": {
        "description": "texttopdf heap buffer overflow (CVE-2015-3258, CVE-2015-3279) — 2015 historical fix",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "cve": "CVE-2024-47176",
        "chain": ["CVE-2024-47176", "CVE-2024-47076", "CVE-2024-47175", "CVE-2024-47177"],
        "title": "cups-browsed UDP 631 any-source trust — entry point for unauthenticated RCE chain",
        "detail": (
            "cups-browsed accepts printer announcements from any UDP source on port 631. "
            "An attacker on the same network sends a crafted packet → cups-browsed creates "
            "a local CUPS queue pointing to attacker's IPP server. "
            "This is step 1 of a 4-CVE chain culminating in root command execution when user prints. "
            "Fixed in 29.1 (Sep 30 2024 RHEL backport). "
            "TOS 2.4 systems running cups-browsed before 29.1.tl2 were fully exposed."
        ),
        "affected": "cups-filters-1.0.35 < 29.1.tl2 on TOS 2.4",
        "fixed": "cups-filters-1.0.35-29.1.tl2",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "cve": "CVE-2024-47175",
        "chain_position": "step 3 of 4",
        "title": "PPD command injection via FoomaticRIPCommandLine — bypass in 29.1 patch",
        "detail": (
            "29.1 stripped *cupsFilter: and *cupsFilter2: (colon variants only). "
            "PPD syntax allows *cupsFilter<space> and *cupsFilter<tab> — not stripped by 29.1. "
            "*FoomaticRIPCommandLine never checked — attacker PPD with this directive executes "
            "arbitrary shell commands when user prints (CUPS daemon runs as root). "
            "29.3 (cups-browsed-add-cupsfilter-checks.patch) fixes both gaps. "
            "Window between 29.1 and 29.3 (Sep 30 → Oct 1 2024) had incomplete mitigation."
        ),
        "affected": "cups-filters-1.0.35-29.1.tl2 (incomplete fix); fully fixed in 29.3.tl2",
        "fixed": "cups-filters-1.0.35-29.3.tl2",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "cve": "CVE-2024-47076",
        "title": "IPP attribute no sanitization — cups-browsed trusts attacker IPP server response",
        "detail": (
            "cfGetPrinterAttributes() fetches IPP attributes from the remote IPP server. "
            "Attacker returns malicious attributes (PPD URL, filter directives, Foomatic commands). "
            "No sanitization before use in PPD generation. "
            "This is the bridge between the UDP initial access and the PPD command injection. "
            "Fixed in 29.1."
        ),
        "affected": "cups-filters-1.0.35 < 29.1.tl2",
        "fixed": "cups-filters-1.0.35-29.1.tl2",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "cups-browsed use-after-free in printer entry removal — segfault on STATUS_DISAPPEARED",
        "detail": (
            "cups-browsed-remove-entry.patch: when master queue in STATUS_DISAPPEARED state, "
            "duplicate removal left master in stale state — subsequent access segfaults. "
            "cups-browsed-remove-entry.patch adds proper duplicate chain handling via "
            "remove_printer_entry() that correctly reschedules master regardless of STATUS."
        ),
        "affected": "cups-filters-1.0.35-29.tl2 and earlier",
        "fixed": "cups-filters-1.0.35-29.tl2.3 (exact revision unknown)",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "cups-browsed free() on literal string CUPS_DEFAULT_DOMAINSOCKET — SIGSEGV on restart",
        "detail": (
            "DomainSocket defaults to CUPS_DEFAULT_DOMAINSOCKET (compile-time string literal in BSS/rodata). "
            "Calling free() on a literal causes undefined behavior (typically SIGSEGV or heap corruption). "
            "Triggered when cups-browsed.conf specifies DomainSocket on a system that previously "
            "started with the default. Fix: strdup() the default, making it heap-allocated before free()."
        ),
        "fixed": "cups-filters-1.0.35-29.3.tl2",
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "TOS 2.4 cups-filters is RHEL 7 backport — no Tencent-specific patches; Red Hat authored",
        "detail": (
            "All security patches authored by Red Hat engineers (Bryan Mason, Zdenek Dohnal) and "
            "directly backported from upstream RHEL 7 errata. "
            "TOS 2.4 acts as an RHEL 7 downstream here — no Tencent-specific security logic. "
            "TOS 2.4 package tracks RHEL 7 security updates with minimal delta."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 2.4 cups-filters-1.0.35-29.tl2.3 RE")
    print()
    print("CVE cluster Sep-Oct 2024 (CUPS OpenPrinting critical RCE chain):")
    print("  CVE-2024-47176: cups-browsed UDP 631 any-source → malicious printer queue (CRITICAL)")
    print("  CVE-2024-47076: IPP attributes no sanitization → attacker PPD content")
    print("  CVE-2024-47175: PPD *FoomaticRIPCommandLine + cupsFilter whitespace bypass → RCE")
    print()
    print("Patch gaps: 29.1 fix incomplete — cupsFilter space/tab variants + FoomaticRIPCommandLine missed")
    print("29.3 required for complete mitigation (Oct 1 2024, one day after initial fix)")
    print()
    for f in FINDINGS:
        cve = f.get('cve', '')
        label = f"{cve} " if cve else ""
        print(f"  [{f['severity']:8s}] {f['id']}: {label}{f['title'][:62]}")
