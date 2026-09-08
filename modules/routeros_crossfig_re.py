"""
RouterOS 7.24.2 — /nova/bin/crossfig RE module
Binary: crossfig (104KB, x86-32 ELF stripped, dynamically linked)
SHA path: ~/mikrotik-re/bins/crossfig

Role: Routing configuration synchronizer. Reads routing state from Nova store
(BGP, OSPF v2/v3, RIP, RIPng, MPLS, BFD, VRF, net devices, route filters),
encodes and decodes route prefixes via librappsup.so, and maintains the routing
table (RTrie) used to forward packets.

PLT imports (security-relevant):
  prefixUnpack@plt  : external (librappsup.so) — deserializes Prfx from nv::message
  prefixPack@plt    : external (librappsup.so) — serializes Prfx into nv::message
  prfxMsgHas@plt    : external (librappsup.so) — tests if nv::message has a prefix field
  RTrie::insert@plt : external — inserts a route into the radix trie
  RTrie::lookup@plt : external — longest-prefix match in the radix trie
  RTrie::setData@plt: external — sets arbitrary *void data pointer on a trie node
  RTrie::clear@plt  : external — bulk-clears the trie
  Prfx::prfxMsg@plt : external — prefix <-> message serialization bridge
  free/malloc       : heap management (stdlib)
  memcmp            : byte comparison (stdlib)
  stat              : file existence check
  unlink            : file removal

ABSENT: strcpy, strcat, sprintf, snprintf, execve, ptrace — this binary has no
memory-unsafe string ops and no process execution. Memory safety is entirely
delegated to librappsup.so, which was NOT extracted from the NPK and cannot be
analyzed directly.

librappsup.so analysis constraint:
  librappsup.so is not present in ~/mikrotik-re/bins/. It is embedded elsewhere
  in the NPK or in a separate package. All three critical entry points
  (prefixUnpack, prefixPack, prfxMsgHas) are black boxes — their internal
  bounds checking, heap allocation strategy, and error handling cannot be
  assessed from crossfig's text segment alone.

Nova store paths (routing attack surface):
  BGP:
    /nova/store/bgconf/general
    /nova/store/bgconf/peer
    /nova/store/bgconf/network
    /nova/store/bgconf/vrf
    /nova/store/r5/routing/bgp/instance
    /nova/store/r5/routing/ubgp/cfg
    /nova/store/r5/routing/ubgp/conn
    /nova/store/r5/routing/ubgp/inst
  OSPF v2:
    /nova/store/ospfconf/gen
    /nova/store/ospfconf/area
    /nova/store/ospfconf/iface
    /nova/store/ospfconf/nbmanbr
    /nova/store/ospfconf/net
    /nova/store/ospfconf/range
    /nova/store/ospfconf/vlink
    /nova/store/r5/routing/ospf/instance
    /nova/store/r5/routing/ospf/area
    /nova/store/r5/routing/ospf/iface
    /nova/store/r5/routing/ospf/iface_raw
    /nova/store/r5/routing/ospf/neighbor
    /nova/store/r5/routing/ospf/range
  OSPF v3:
    /nova/store/ospfv3/gen
    /nova/store/ospfv3/area
    /nova/store/ospfv3/iface
    /nova/store/ospfv3/nbmanbr
    /nova/store/ospfv3/range
    /nova/store/ospfv3/vlink
  RIP / RIPng:
    /nova/store/rip/general
    /nova/store/rip/interface
    /nova/store/rip/neigh
    /nova/store/rip/ripkey
    /nova/store/ripng/general
    /nova/store/ripng/interface
    /nova/store/r5/routing/rip/inst
    /nova/store/r5/routing/rip/auth
    /nova/store/r5/routing/rip/ifc-tmpl
    /nova/store/r5/routing/rip/neighbor
  MPLS / LDP / RSVP:
    /nova/store/mpls/main
    /nova/store/mpls/iface
    /nova/store/mpls/instance
    /nova/store/mpls/peers
    /nova/store/mpls/libin       — label import filter
    /nova/store/mpls/libout      — label export filter
    /nova/store/mpls/filterin    — MPLS filter inbound
    /nova/store/mpls/filterout   — MPLS filter outbound
    /nova/store/mpls/bgpvpls
    /nova/store/mpls/ciscobgpvpls
    /nova/store/mpls/rsvpiface
    /nova/store/mpls/rsvppath
    /nova/store/r5/mpls/main
    /nova/store/r5/mpls/iface
    /nova/store/r5/mpls/ldp/instance
    /nova/store/r5/mpls/ldp/iface
    /nova/store/r5/mpls/ldp/local
    /nova/store/r5/mpls/ldp/neigh
    /nova/store/r5/mpls/ldp/remote
    /nova/store/r5/mpls/ldp/filterin
    /nova/store/r5/mpls/ldp/filterout
    /nova/store/r5/mpls/rsvp/iface
    /nova/store/r5/mpls/rsvp/path
    /nova/store/r5/mpls/rsvp/tun
    /nova/store/r5/mpls/bgpvpls
  Routing table / filters / VRF:
    /nova/store/r5/routing/routing-table
    /nova/store/r5/routing/route
    /nova/store/r5/routing/rule
    /nova/store/r5/routing/filter/frule
    /nova/store/r5/routing/filter/ns
    /nova/store/r5/routing/copy
    /nova/store/r5/routing/routing-table
    /nova/store/r5/ip/route/rule
    /nova/store/r5/bfd/cfg
    /nova/store/r5/version
    /nova/store/routing/filter
    /nova/store/routing/rt
    /nova/store/routing/rule
    /nova/store/routing/vrf
    /nova/store/net/vrf
    /nova/store/net/routes
    /nova/store/net/routes6
    /nova/store/net/address-list
    /nova/store/net/address-list6
    /nova/store/net/addrs
    /nova/store/net/addrs6
    /nova/store/net/devices
    /nova/store/net/devlist
    /nova/store/net/devlist-member
    /nova/store/net/ipt-filter
    /nova/store/net/ipt-mangle
    /nova/store/net/ipt-nat
    /nova/store/net/ipt6-filter
    /nova/store/net/ipt6-mangle
    /nova/store/bfd/iface
  Trigger file:
    /rw/FORCE_CROSSFIG — if present, forces full routing config reload

PackSpec: describes the binary layout of a prefix field in an nv::message.
  Determines which bits of the message buffer become prefix length, address
  family, and raw address bytes. Controlled by crossfig's compiled routing logic,
  not by the incoming message — however, the *data* bytes that PackSpec is applied
  to come from a Nova message and are therefore attacker-influenced if the Nova
  message source is attacker-controlled.

RTrie: custom radix trie from librappsup.so.
  RTrie::setData(Node*, void*) — associates arbitrary data pointer with a trie
  node. If the data pointer is derived from a Nova message field without bounds
  checking, a dangling pointer or type confusion is possible on route removal.

----- FINDINGS SUMMARY -----
MTIK-CROSSFIG-F01 HIGH   7.5  prefixUnpack librappsup.so — unanalyzable deserialization on attacker-reachable Nova message
MTIK-CROSSFIG-F02 HIGH   7.2  RTrie::setData void* — arbitrary pointer stored per trie node from Nova-sourced data
MTIK-CROSSFIG-F03 MEDIUM 6.5  MPLS label filter (libin/libout) — label range from Nova store, bounds unverifiable without librappsup
MTIK-CROSSFIG-F04 MEDIUM 5.3  nv::Store::set writable from Nova — routing config integrity without bus authentication
MTIK-CROSSFIG-F05 INFO   0.0  No unsafe stdlib string ops, no execve — CLEAN
"""

# ---------------------------------------------------------------------------
# librappsup.so interface (external, unanalyzable)
# ---------------------------------------------------------------------------

LIBRAPPSUP_INTERFACE = {
    'library':     'librappsup.so',
    'status':      'NOT EXTRACTED — absent from ~/mikrotik-re/bins/',
    'note':        (
        'All memory safety for route prefix handling is inside this library. '
        'crossfig contains NO unsafe string ops; every potential memory issue '
        'routes through one of these three external entry points.'
    ),
    'entry_points': [
        {
            'symbol':   '_Z12prefixUnpackPK8PackSpecRKN2nv7messageE4Prfx',
            'name':     'prefixUnpack',
            'sig':      'Prfx prefixUnpack(PackSpec const*, nv::message const&)',
            'role':     'Deserializes a route prefix from a Nova message field. '
                        'PackSpec determines field layout; message bytes are attacker-influenced.',
            'risk':     'HIGH — primary deserialization entry point for attacker-controlled Nova data',
        },
        {
            'symbol':   '_Z10prefixPackPK8PackSpecPN2nv7messageERK4Prfx',
            'name':     'prefixPack',
            'sig':      'void prefixPack(PackSpec const*, nv::message*, Prfx const&)',
            'role':     'Serializes a Prfx back into a Nova message.',
            'risk':     'LOW — output direction; attacker influence limited to what crossfig wrote',
        },
        {
            'symbol':   '_Z10prfxMsgHasRKN2nv7messageEPK8PackSpec',
            'name':     'prfxMsgHas',
            'sig':      'bool prfxMsgHas(nv::message const&, PackSpec const*)',
            'role':     'Tests whether a Nova message contains a valid prefix field per PackSpec.',
            'risk':     'MEDIUM — if false-positive on malformed message, skips prefixUnpack '
                        'null-check and proceeds with uninitialized Prfx',
        },
    ],
}

# ---------------------------------------------------------------------------
# RTrie operations
# ---------------------------------------------------------------------------

RTRIE_OPERATIONS = {
    'description': (
        'RTrie is a custom radix trie (binary trie over IP prefix bits) from librappsup.so. '
        'crossfig uses it as the in-process routing table. Each trie node can hold a void* '
        'data pointer set via RTrie::setData(Node*, void*). '
        'The source of the void* is determined by crossfig logic that processes Nova store messages.'
    ),
    'setData_sig':   'void RTrie::setData(RTrie::Node*, void*)',
    'lookup_sig':    'RTrie::Node const* RTrie::lookup(unsigned char const*, unsigned int) const',
    'insert_sig':    'RTrie::Node* RTrie::insert(unsigned char const*, unsigned int)',
    'clear_sig':     'void RTrie::clear(function_ref<void(RTrie::Node*)>)',
    'risk': (
        'RTrie::setData associates a void* with each route. If the data pointer is a stack '
        'address or a Nova-message-heap allocation that is freed after the trie insert, '
        'the RTrie node holds a dangling pointer. Route lookup (RTrie::lookup) returns '
        'this pointer to callers. Without librappsup.so source, the data lifetime is unverifiable.'
    ),
}

# ---------------------------------------------------------------------------
# Nova store operations
# ---------------------------------------------------------------------------

NOVA_STORE_OPS = {
    'nv_Store_get':       '_ZN2nv5Store3getEj',
    'nv_Store_set':       '_ZN2nv5Store3setEjRKNS_7messageE',
    'nv_Store_remove':    '_ZN2nv5Store3removeEj',
    'nv_Store_removeAll': '_ZN2nv5Store9removeAllEv',
    'note': (
        'nv::Store::set(uint id, nv::message const&) writes routing configuration directly '
        'to the Nova persistent store. The id is a 32-bit slot identifier; the message carries '
        'the routing entry. Because Nova bus has no inter-daemon authentication (MTIK-NOVA-F03), '
        'any process on the Nova bus can call Store::set with an arbitrary id and message, '
        'overwriting crossfig routing state without authorization.'
    ),
}

# ---------------------------------------------------------------------------
# MPLS label filter paths
# ---------------------------------------------------------------------------

MPLS_FILTER_PATHS = {
    'libin':    '/nova/store/mpls/libin',
    'libout':   '/nova/store/mpls/libout',
    'filterin': '/nova/store/mpls/filterin',
    'filterout': '/nova/store/mpls/filterout',
    'note': (
        'MPLS label import (libin) and export (libout) filters are stored in Nova store '
        'and read by crossfig. The filter entries specify label ranges (MPLS labels are '
        '20-bit values, range 0-1048575). If the label range field in the Nova message is '
        'not bounds-checked before use in RTrie insertion, a malformed label value could '
        'corrupt the trie. Without librappsup.so, the insert bounds check is unverifiable.'
    ),
}

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

FINDINGS = [
    {
        'id':       'MTIK-CROSSFIG-F01',
        'severity': 'HIGH',
        'cvss':     7.5,
        'title':    'prefixUnpack in librappsup.so — unanalyzable deserialization on attacker-reachable Nova message',
        'detail': (
            'crossfig::prefixUnpack(PackSpec const*, nv::message const&) is the primary '
            'entry point for route prefix deserialization. All routing store paths '
            '(BGP peers, OSPF areas, RIP neighbors, MPLS label bindings, routing table '
            'entries) ultimately pass through this function when a Nova message is converted '
            'to an in-process Prfx object. '
            'The nv::message input is attacker-reachable: any process on the Nova bus '
            '(no inter-daemon auth — MTIK-NOVA-F03) can send a crafted routing update '
            'to crossfig via one of the 40+ Nova store paths. '
            'librappsup.so is not available for analysis; its internal allocation size '
            'calculation, length field handling, and error return path on malformed '
            'prefix data cannot be assessed. '
            'Attack chain: '
            '(1) Nova bus access (compromised daemon or unauthenticated bus socket); '
            '(2) Craft nv::message with oversized or malformed prefix field; '
            '(3) crossfig calls prefixUnpack; '
            '(4) If librappsup.so does not bound-check the prefix length field, '
            'heap corruption or OOB read occurs inside crossfig''s process. '
            'crossfig runs as root; heap corruption → code execution.'
        ),
        'evidence': {
            'entry_point': 'prefixUnpack (external, librappsup.so)',
            'reachable_via': '40+ /nova/store/* paths (see module header)',
            'nova_auth': 'NONE (MTIK-NOVA-F03)',
            'librappsup_analyzed': False,
        },
        'recommendation': (
            'Extract and analyze librappsup.so from the MikroTik NPK or router filesystem. '
            'Fuzz prefixUnpack with malformed Nova messages: zero-length prefixes, '
            'AF_MAX+1 address families, prefix lengths > 128 for IPv6 or > 32 for IPv4. '
            'Add input validation in crossfig before calling prefixUnpack: '
            'check nv::message address-family and prefix-length fields against known-safe '
            'ranges before passing the message to the library.'
        ),
        'status': 'UNCONFIRMED — requires librappsup.so extraction and analysis',
        'cve': None,
    },
    {
        'id':       'MTIK-CROSSFIG-F02',
        'severity': 'HIGH',
        'cvss':     7.2,
        'title':    'RTrie::setData void* — arbitrary pointer stored per trie node from Nova-sourced data',
        'detail': (
            'RTrie::setData(Node*, void*) stores an arbitrary void* on each route node. '
            'The data pointer is set by crossfig code that processes Nova store messages. '
            'If the data pointer is the address of a Nova message buffer that is freed after '
            'the RTrie insert (heap-use-after-free), subsequent RTrie::lookup calls return '
            'the dangling pointer to callers, who dereference it as a typed route struct. '
            'Trigger: '
            '(1) Attacker sends a routing update Nova message that triggers RTrie::insert + setData; '
            '(2) Immediately sends a delete message for the same route, freeing the Nova message '
            'heap allocation that the void* points to; '
            '(3) Sends a lookup-triggering update to the same prefix; '
            '(4) crossfig dereferences the freed pointer as a route struct, giving the attacker '
            'type confusion over freed heap memory. '
            'Without librappsup.so, the exact lifetime of the void* data cannot be traced.'
        ),
        'evidence': {
            'setData_sym': '_ZN5RTrie7setDataEPNS_4NodeEPv',
            'lookup_sym':  '_ZNK5RTrie6lookupEPKhj',
            'data_source': 'Nova store message processing (attacker-influenced)',
        },
        'recommendation': (
            'Ensure all void* pointers stored in RTrie nodes have lifetimes that exceed '
            'the trie node lifetime. '
            'Use reference-counted or arena-allocated route structs rather than raw heap '
            'pointers associated with message buffers. '
            'Add RTrie::clear callback (already present) to null-out data pointers on remove.'
        ),
        'status': 'UNCONFIRMED — requires librappsup.so and crossfig data-lifetime trace',
        'cve': None,
    },
    {
        'id':       'MTIK-CROSSFIG-F03',
        'severity': 'MEDIUM',
        'cvss':     6.5,
        'title':    'MPLS label filter (libin/libout) — label range from Nova store, bounds unverifiable',
        'detail': (
            'crossfig reads MPLS label import (/nova/store/mpls/libin) and export '
            '(/nova/store/mpls/libout) filter entries from the Nova store. '
            'MPLS labels are 20-bit values (valid range 0x00000–0xFFFFF = 1048575). '
            'If the Nova message label range field is not validated before being passed '
            'to prefixUnpack or RTrie::insert as a key length, a label value > 20 bits '
            'could cause a trie insert to walk past the end of the allocated key buffer. '
            'The validation occurs (if at all) inside librappsup.so — unanalyzable. '
            'MPLS label filtering is reachable from the Nova bus by any daemon that can '
            'write to /nova/store/mpls/libin or libout (no ACL observed on store paths).'
        ),
        'evidence': {
            'libin_path':   '/nova/store/mpls/libin',
            'libout_path':  '/nova/store/mpls/libout',
            'label_bits':   20,
            'label_max':    0xFFFFF,
            'bounds_check': 'UNVERIFIABLE without librappsup.so',
        },
        'recommendation': (
            'Add explicit label range validation in crossfig before passing label Nova '
            'message fields to librappsup: assert label <= 0xFFFFF. '
            'Reject store messages with out-of-range label values at the Nova store '
            'consumer level, before any library call.'
        ),
        'status': 'UNCONFIRMED — requires librappsup.so analysis',
        'cve': None,
    },
    {
        'id':       'MTIK-CROSSFIG-F04',
        'severity': 'MEDIUM',
        'cvss':     5.3,
        'title':    'nv::Store::set writable from Nova bus — routing config integrity without auth',
        'detail': (
            'crossfig registers as a Nova store consumer on 40+ routing paths and calls '
            'nv::Store::set(id, message) to write routing state. '
            'Nova bus has no inter-daemon authentication (MTIK-NOVA-F03). '
            'A compromised daemon can write to any Nova store path including crossfig''s '
            'routing paths, injecting or overwriting BGP peer configs, OSPF area parameters, '
            'RIP authentication keys (/nova/store/rip/ripkey), or MPLS filter rules. '
            'This is a data-integrity finding: the attacker does not get code execution '
            'directly, but can manipulate the routing table to redirect traffic (BGP peer '
            'injection), disable authentication (RIP ripkey overwrite), or cause routing loops '
            '(OSPF area misconfiguration).'
        ),
        'evidence': {
            'nova_auth':     'NONE (MTIK-NOVA-F03)',
            'store_set_sym': '_ZN2nv5Store3setEjRKNS_7messageE',
            'high_value_paths': [
                '/nova/store/rip/ripkey',
                '/nova/store/bgconf/peer',
                '/nova/store/mpls/filterin',
                '/nova/store/r5/routing/filter/frule',
            ],
        },
        'recommendation': (
            'Enforce write ACLs on Nova store paths: only the daemon that owns a store '
            'path should be able to write to it (enforced by the Nova bus, not crossfig). '
            'Sign routing configuration updates with a per-boot HMAC before writing to store; '
            'verify on read. Treat Nova bus compromise as a high-severity finding in its own right.'
        ),
        'status': 'CONFIRMED (architectural) — Nova bus write access is unauthenticated',
        'cve': None,
    },
    {
        'id':       'MTIK-CROSSFIG-F05',
        'severity': 'INFO',
        'cvss':     0.0,
        'title':    'No unsafe stdlib string ops, no execve — CLEAN',
        'detail': (
            'crossfig imports only: free, malloc, memcmp, stat, unlink from libc. '
            'No strcpy, strcat, sprintf, snprintf, sscanf, execve, system, or ptrace. '
            'All memory handling for route data is delegated to librappsup.so. '
            'crossfig''s own code is memory-safe with respect to stdlib string functions. '
            '/rw/FORCE_CROSSFIG is accessed via stat() only — existence check, no content read. '
            'CLEAN for this category.'
        ),
        'evidence': {
            'unsafe_libc': 'NONE in crossfig text segment',
            'force_file':  '/rw/FORCE_CROSSFIG — stat() only, no open/read',
        },
        'recommendation': 'No action required for crossfig itself.',
        'status': 'CLEAN',
        'cve': None,
    },
]
