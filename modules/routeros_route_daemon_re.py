"""
RouterOS 7.24.2 — Route Daemon Binary RE
Target binary: /nova/bin/route (from routeros-7.24.2.npk, squashfs-root)
Platform: x86 CHR (Cloud Hosted Router), ELF 32-bit LSB Intel 80386
Binary: ELF32, dynamically linked, stripped, 1.5MB
Source: routeros-7.24.2.npk → squashfs-root → /nova/bin/route
Build date: 2026-09-03 10:22:41 (squashfs mtime)
Analysis date: 2026-09-08
Method: static binary analysis — nm -D symbol sweep, objdump disassembly, call-site tracing,
        prologue analysis, frame layout calculation, string extraction

ELF LOAD SEGMENTS:
  LOAD  file=0x000000  VA=0x08048000  R    (ELF header, PLT)
  LOAD  file=0x00b000  VA=0x08053000  R E  (text, 0x1506c5 bytes)
  LOAD  file=0x15c000  VA=0x081a4000  R    (rodata / string pool)
  LOAD  file=0x17dd2c  VA=0x081c6d2c  RW   (data / bss)
  BSS:  VA=0x081c7d20  size=0x62278 (401016 bytes)

PROTOCOL LANDSCAPE:
  Routing protocols handled by route daemon (from string pool):
    OSPF: instance, area, interface, ext-cost, ext-tag, router-id, cost, type, fwd, dn
    RIPv2: cost, tag, ext-cost, ext-tag
    BGP:  weight, origin, med, out-med, local-pref, aigp, as-path, communities,
          extended-communities, large-communities, ve-block-size, peer-as, origin-as,
          BGP-VPLS, BGP-VPN (bgp-mpls-vpn, cisco-bgp-vpls), RPKI (rpki-verify)
    MPLS: label, peer, LDP (local/remote, filterin/filterout, iface, instance, neigh),
          RSVP (iface, path, tun), MPLS MTU control (nv::kernelSetMplsMtu)
    Static routes, connected routes, route redistribution
    Nova store paths: /nova/store/r5/routing/ospf/*, /nova/store/r5/mpls/*,
                      /nova/store/r5/routing/bgp/rpki

IMPORT SYMBOL SWEEP (nm -D):
  recvfrom   — 2 call sites: 0x8140e43 (stack buffer), 0x814eaa1 (global buffer)
  recvmmsg   — 1 call site: 0x80e55ea (batch-5 processing)
  recvmsg    — present (Nova bus IPC)
  sprintf    — 1 call site at 0x8108a4f, format "%u" (unsigned int, bounded)
  sscanf     — 2 call sites: "%llu %llu" (two uint64), "%8x-%8x %*4c ... %128s"
  memmove    — 73 call sites (routing table data structure operations)
  execve     — 1 call site at 0x819674e (path: "/proc/self/exe" — self-restart only)
  fscanf     — present (proc filesystem reads)
  malloc/realloc — present (rapp::Heap wrapper: 0x4322, 0x89e4, 0x89fe)
  SHA1/SHA256/SHA384/SHA512/MD5/HMAC vtables — present (OSPF MD5 auth, BGP MD5/SHA HMAC)
  vfork      — present (forked execution in restart path)

DANGEROUS SYMBOL NOTES:
  strcpy  — ABSENT (safe: not imported)
  strcat  — ABSENT (safe: not imported)
  gets    — ABSENT (safe: not imported)
  system  — ABSENT (safe: not imported)
  popen   — ABSENT (safe: not imported)

=== FINDING: MTIK-ROUTE-F01 — UNDOCUMENTED PROTOCOL DISCRIMINATOR ON RAW SOCKET ===

LOCATION: Function at VA 0x8140e0e, first check after recvfrom at 0x8140e43
CONTEXT:
  The function opens a recv loop on a socket fd passed as argument. It receives
  up to 0xffff (65535) bytes per iteration. After recvfrom returns a positive value,
  it checks the FIRST BYTE of the received datagram against a magic value:

  0x8140e8a:  cmpb $0x86,-0x10017(%ebp)   ; first byte of received data
  0x8140e91:  jne 0x8140fad               ; discard if != 0x86

  This is a proprietary MikroTik protocol discriminator. Packets matching 0x86 as
  the first application-layer byte proceed to full processing; all others are silently
  discarded. Following a match, the source IP is extracted from the sockaddr_in and
  a tree lookup is performed.

IMPLICATIONS:
  - The route daemon maintains a raw/UDP socket that accepts MikroTik-proprietary
    protocol packets. This is not documented in public RouterOS specs.
  - Attack surface: any host on a reachable network that can send UDP/raw packets
    with byte[0] == 0x86 reaches the full parsing chain — without authentication.
  - The receive limit is 65535 bytes, but the receiving frame is properly sized at
    0x10064 bytes (see MTIK-ROUTE-F02 below). Buffer overflow at recv layer: NO.
  - The parsing chain AFTER the 0x86 check is the interesting attack surface — it
    performs IPAddr extraction and a tree traversal. TLV parsing, if any, was not
    confirmed to be bounded.

CANDIDATE STATUS: NEEDS FURTHER ANALYSIS — parsing chain post-discriminator not traced.

=== FINDING: MTIK-ROUTE-F02 — LARGE RECV BUFFER FRAME ANALYSIS ===

LOCATION: Function at VA 0x8140e0e, recvfrom at 0x8140e43
PROLOGUE:
  0x8140e0e: push %ebp / mov %esp,%ebp
  0x8140e11: push %edi / push %esi / push %ebx
  0x8140e1a: sub $0x10064,%esp           ; frame = 65636 bytes
  Buffer at: lea -0x10017(%ebp),%eax     ; buffer = EBP-65559
  Recv max:  push $0xffff                ; 65535 bytes

FRAME SAFETY CALCULATION:
  Buffer start: EBP - 0x10017 = EBP - 65559
  Max recv:     0xffff = 65535 bytes
  Buffer end:   (EBP - 65559) + 65535 = EBP - 24
  Saved EBX at: EBP - 12 (not reached)
  Return addr:  EBP + 4   (not reached)
  Margin:       24 bytes below saved-register area — NO OVERFLOW AT RECV LAYER.

  sockaddr_in at EBP-0x10048 (65608 bytes below EBP) — below the receive buffer.
  Initialized to size 0x1c (28) before recvfrom call.

VERDICT: recvfrom layer is NOT directly exploitable for stack overflow. Frame is
  correctly sized for 65535-byte UDP datagram reception. Protocol logic downstream
  of the 0x86 discriminator requires separate analysis.

=== FINDING: MTIK-ROUTE-F03 — recvmmsg BATCH PROCESSING / GLOBAL BUFFER IOVEC ===

LOCATION: Function at VA 0x80e5536, recvmmsg at 0x80e55ea
PROLOGUE:
  0x80e5536: push %ebp / mov %esp,%ebp
  0x80e553b: push %edi / push %esi / push %ebx
  0x80e5551: sub $0x47c,%esp             ; frame = 1148 bytes
  mmsghdr array: lea -0x338(%ebp),%ebx  ; 5 × 32-byte mmsghdr structs
  vlen:          push $0x5               ; 5 messages per recvmmsg call

IOVEC SETUP:
  Loop: initializes 5 mmsghdr entries. Key fields observed:
    msg_namelen = 0x80 (128 bytes, source address buffer)
    msg_iovlen  = 0x1  (1 iovec per message)
    msg_controllen = 0x80 (128 bytes, control message buffer)

  Global pointer: 0x81d54f8 (BSS) dereferenced → EDI
  Iov buffer base: lea 0x50000(%edi)     ; global_buf + 0x50000 (320KB offset into
                                         ; a pre-allocated heap region from rapp::Heap)
  This means the ACTUAL DATA RECEIVE BUFFERS are not on the stack but in a heap
  region. The iov_len for each buffer was not directly observed in the prologue
  but the loop structures suggest fixed-size per-message allocations.

IMPLICATION:
  recvmmsg processes 5 datagrams per syscall from the same socket fd. If iov_len
  is not bounded per-iovec (or if the heap buffer is reused across iterations without
  proper length tracking), a crafted sequence of datagrams could cause heap corruption.
  The heap allocator is rapp::Heap (MikroTik custom, not glibc malloc metadata attacks
  necessarily applicable — but custom heaps often lack hardening).

STATUS: CANDIDATE — iov_len per recv buffer not confirmed. rapp::Heap structure at
  0x81d54f8 requires dynamic analysis or further static tracing.

=== FINDING: MTIK-ROUTE-F04 — execve("/proc/self/exe") SELF-RESTART MECHANISM ===

LOCATION: 0x819674e
DISASSEMBLY:
  0x8196741: lea -0x1160(%ebp),%eax   ; argv array on stack
  0x8196748: push %eax                ; argv
  0x8196749: push $0x81c4a42          ; path = "/proc/self/exe"
  0x819674e: call execve@plt
  0x8196753: movl $0x7f,(%esp)        ; exit(127) if execve fails

PATH STRING: "/proc/self/exe" — confirmed via VA-to-file-offset mapping.

VERDICT: NOT a command injection vector. The path is a hardcoded rodata constant.
  The route daemon restarts itself by executing its own process image (classic
  daemon restart idiom). Triggered internally (signal handler or IPC message).

SECONDARY QUESTION: If a SNMP MIB-II system restart OID (sysObjectID sub-tree) or
  an authenticated BGP session teardown triggers this code path, it may be reachable
  as a DoS primitive — forces a full BGP/OSPF convergence cycle on restart.

=== FINDING: MTIK-ROUTE-F05 — PROC FILESYSTEM PATH PARSING ===

LOCATION: sscanf call at 0x8163979, format string at VA 0x81be839
FORMAT: "%8x-%8x %*4c %*8x %*2x:%*2x %*d %128s"

This is /proc/<pid>/maps format parsing. The route daemon reads its own memory map.
The %128s specifier reads a 128-char path string into a buffer at -0x9c(%ebp) = 156
bytes from EBP. Max read = 128 chars + null = 129 bytes. Buffer = 156 bytes.
No overflow at this call site.

Purpose: likely used during self-restart (reading mapped regions before execve) or
  for shared library path resolution.

=== CRYPTO VTABLE LANDSCAPE ===

Vtables present in route binary:
  _ZTV4SHA1    — SHA1 (OSPF MD5-like auth, BGP MD5 session key)
  _ZTV6SHA256  — SHA256 (BGP Graceful Restart HMAC, RPKI RTR session auth)
  _ZTV6SHA384  — SHA384
  _ZTV6SHA512  — SHA512
  _ZTV3MD5     — MD5 (OSPF MD5 authentication type 2)
  _ZN4HMAC6updateEPKvj — HMAC update function

  HMAC is used for BGP MD5 TCP-AO session authentication and OSPF SHA-HMAC
  authentication (RFC 5709). Weak OSPF auth (type 1 = cleartext, type 2 = MD5)
  is configurable in RouterOS — if the target uses type 1, OSPF packets are
  unauthenticated at the crypto layer even though the protocol accepts them.

RPKI (Route Origin Validation):
  String "rpki-verify" present — the route daemon performs RPKI validation.
  BGP RPKI RTR sessions (/nova/store/r5/routing/bgp/rpki) communicate with
  external RPKI validators. If the RTR session uses an unverified TLS certificate
  or no authentication, an attacker who intercepts the RTR session can inject
  invalid route origin records → routing table manipulation.

=== ATTACK SURFACE SUMMARY ===

  Tier 1 (pre-auth, from network):
    - Raw/UDP socket handler (0x86 discriminator) — unknown parsing depth
    - recvmmsg batch path — heap buffer, iov_len needs verification

  Tier 2 (after routing protocol auth negotiation):
    - OSPF MD5/SHA-HMAC — if type 1 cleartext auth configured, skip to tier 1
    - BGP MD5 TCP-AO — MD5 still in use for BGP session auth despite known weaknesses
    - RPKI RTR session — if unauthenticated, routing table integrity at risk

  Tier 3 (post-auth):
    - 73 memmove call sites in routing data structures — correctness-critical
    - rapp::Heap — custom heap allocator, hardening characteristics unknown

=== RECOMMENDED NEXT STEPS ===

  1. Dynamic analysis of 0x80e55ea iov_len initialization — run under QEMU x86,
     set watchpoint at iovec struct, observe iov_len value.
  2. Protocol RE for 0x86 magic byte — capture traffic on RouterOS MNDP/discovery
     UDP sockets and compare first byte to 0x86.
  3. BGP UPDATE message parser — not directly traced here; likely in a sub-function
     of the recvmsg/Nova bus path. BGP parser bugs = BGP peer-adjacent pre-auth.
  4. OSPF LSA parser tracing — sub-function from the raw recv path.
"""

# ─── Runtime validation stub ──────────────────────────────────────────────────

BINARY_PATH = "/nova/bin/route"
BINARY_SHA256 = None  # not yet extracted from live target
VERSION = "7.24.2"

FINDINGS = [
    {
        "id": "MTIK-ROUTE-F01",
        "severity": "MEDIUM",
        "title": "Undocumented raw socket handler with proprietary protocol discriminator",
        "va": 0x8140e8a,
        "description": (
            "Route daemon accepts datagrams with byte[0] == 0x86 on a raw/UDP socket. "
            "Protocol is proprietary, undocumented. Full parsing chain post-discriminator "
            "not yet traced. Pre-auth attack surface from any adjacent network."
        ),
        "status": "CANDIDATE — parsing chain not fully traced",
        "cve": None,
    },
    {
        "id": "MTIK-ROUTE-F02",
        "severity": "INFO",
        "title": "Large recvfrom buffer correctly bounded (65535 bytes, frame 65636 bytes)",
        "va": 0x8140e43,
        "description": (
            "24-byte safety margin between buffer fill and saved-register area. "
            "No overflow at the recv layer. Downstream parsing is the risk surface."
        ),
        "status": "CLOSED — not exploitable at recv layer",
        "cve": None,
    },
    {
        "id": "MTIK-ROUTE-F03",
        "severity": "MEDIUM",
        "title": "recvmmsg batch-5 processing with heap-backed iovec buffers",
        "va": 0x80e55ea,
        "description": (
            "5 datagrams processed per recvmmsg call. iov_base points into rapp::Heap "
            "region (global_ptr + 0x50000). iov_len not directly observed — requires "
            "dynamic analysis. rapp::Heap hardening characteristics unknown."
        ),
        "status": "CANDIDATE — requires dynamic analysis",
        "cve": None,
    },
    {
        "id": "MTIK-ROUTE-F04",
        "severity": "LOW",
        "title": "execve('/proc/self/exe') self-restart — not user-controlled",
        "va": 0x819674e,
        "description": (
            "Route daemon restarts itself via execve('/proc/self/exe'). Path is a "
            "hardcoded constant. Not a command injection vector. Potential DoS if "
            "externally triggerable (e.g., via SNMP MIB write or BGP teardown)."
        ),
        "status": "CLOSED as RCE — potential DoS trigger under investigation",
        "cve": None,
    },
    {
        "id": "MTIK-ROUTE-F05",
        "severity": "INFO",
        "title": "RPKI RTR session — routing table manipulation if RTR unverified",
        "va": None,
        "description": (
            "Route daemon performs RPKI validation via RTR sessions. If TLS cert "
            "verification is absent or RTR uses cleartext, a MITM can inject invalid "
            "ROA records causing BGP route origin validation failures or false accepts."
        ),
        "status": "CANDIDATE — RTR TLS verification not confirmed",
        "cve": None,
    },
]


def describe():
    print(f"RouterOS {VERSION} /nova/bin/route — RE findings summary")
    for f in FINDINGS:
        va = f"VA 0x{f['va']:08x}" if f['va'] else "N/A"
        print(f"  [{f['severity']:6s}] {f['id']} @ {va}: {f['title']}")
        print(f"           Status: {f['status']}")


if __name__ == "__main__":
    describe()
