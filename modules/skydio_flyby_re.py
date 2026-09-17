#!/usr/bin/env python3
"""
skydio_flyby_re.py — Semantic RE sweep of libflyby_jni.so

Target: Skydio X10/X10D/R10 flight software JNI bridge (ARM64, stripped, 60MB)
Binary: /media/cowboy/research/Skydio/intel-vdt/re-material/libflyby_jni.so
BuildID: b867c6540e28e1f2edc3ec0d6ecfc08f6ecbe4b2

Confirmed proto surface (from strings analysis):
  iot_api.IOTTokenExchangeRequest{client_key, device_id} -> {auth_token, api_endpoint}
  cloud_api.FindReleaseRequest{vehicle_id, vehicle_release_key} -> {download_url, StsTemporaryCredentials}
  cloud_api.AuthenticateRequest{email, client_key, device_id} -> {access_token, refresh_token}
  cloud_api.FindControllerReleaseRequest{controller_release_key} -> {download_url}

VDT Query Profiles:
  Q1: IoT token exchange — auth bypass, replay, serial spoofing
  Q2: DCON download handler — token validation, path traversal
  Q3: FindRelease / firmware signing — signature bypass
  Q4: MAVLink parser — buffer overflow in packet handling
  Q5: CloudClient HTTP — SSRF, header injection, cert validation skip
  Q6: Memory management — memcpy with packet-controlled length
  Q7: Crypto — weak RNG, hardcoded key material

Usage:
  python3 modules/skydio_flyby_re.py
  python3 modules/skydio_flyby_re.py --binary /path/to/libflyby_jni.so
  python3 modules/skydio_flyby_re.py --query Q1 --top 15
  python3 modules/skydio_flyby_re.py --all-queries
"""
import sys
import os
import re
import json
import struct
import argparse
import numpy as np
from pathlib import Path

# Ensure ablation modules on path
sys.path.insert(0, str(Path(__file__).parent))

import capstone
from semantic_search import SemanticSearcher, describe_function, normalize_asm

BINARY_DEFAULT = "/media/cowboy/research/Skydio/intel-vdt/re-material/libflyby_jni.so"

# ── Manually confirmed function addresses (updated 2026-09-17) ────────────────
# All from manual disassembly of libflyby_jni.so (BuildID b867c6540e28e1f2edc3ec0d6ecfc08f6ecbe4b2)
CONFIRMED_ADDRS = {
    # wire_proxy core dispatch
    0x025c27a4: "WireProxy::HandleIncomingPacket -- packet type dispatcher (jump table @0x32cdfe2)",
    0x025c2b6c: "HandleIncomingPacket type=2 STREAM path -> ParseFromArray(WireProxyRequest, payload, data_size) F25 LOCUS",
    0x025c0504: "WireProxy::ParseInfo -- type=3 UNK alt trigger, F25 alt",
    0x025c2bb8: "WireProxy::SendDatagram -- type=1 DGRAM path",

    # USB callers of HandleIncomingPacket (only two direct callers)
    0x02097e70:  "UsbHandler::DidReadLinkData -- SAFE: data_size=vector.end()-begin()",
    0x02097f44:  "UsbHandler::HandleUsbLinkMessage -- data_size=arg_w4 from USB protocol",
    0x02097ff4:  "UsbHandler::DidReadLcmData -- dispatches via vtable[4]",
    0x017e1e4c:  "Java_com_skydio_djinni_IUsbHandler_CppProxy_native_didReadLinkData -- JNI bridge",

    # TCP accept / relay path
    0x025cb7b4:  "WireProxy::AcceptNewStream -- TCP accept callback (called when listen fd readable)",
    0x025ccdb0:  "WireProxy::ReadStreamData -- per-client TCP relay; calls Recv+FindReplaceHost+WriteOutput; DOES NOT CALL HandleIncomingPacket",
    0x025bfd3c:  "WireProxy::WriteOutput -- forwards LCM packet to all connected TCP streams",
    0x025ba7e0:  "PrepTCPSocket -- sets SendBufferSize + SendSendTimeout; socket param config only",

    # UDP relay path
    0x025ceebc:  "WireProxy::ReadDatagram -- UDP relay; calls RecvFrom+WriteOutput; DOES NOT CALL HandleIncomingPacket",
    0x025bd458:  "WireProxy::OpenUdpSocket -- binds UDP socket, registers recv callback",

    # TCP server setup
    0x025bbab4:  "WireProxy::Initialize -- subscribes 2 Skybus channels, calls OpenTcpSocket",
    0x025bc604:  "WireProxy::OpenTcpSocket -- binds TCP server, registers AcceptNewStream callback",
    0x025bcd4c:  "StreamSocket::Listen(5) -- TCP listen",

    # Per-client fd callback
    0x025d5c20:  "per-client fd callback operator() -- ldr WireProxy* from closure, call ReadStreamData(connection_index)",

    # Other
    0x025c3714:  "WireProxy::SendStreamData -- INFO type=0 subtype=0 path",
    0x025bfc1c:  "WireProxy::WriteInfo -- publishes WireProxyInfo.tcp_port on Skybus WIRE_PROXY_INFO_PB",

    # Callee functions
    0x016a8aa0:  "PLT: WireProxy::ReadStreamData",
    0x016c2c10:  "PLT: WireProxy::RemoveStreamNoLock",
    0x01661ff0:  "PLT: WireProxy::WriteOutput",
    0x016c5bf0:  "PLT: AcEventLoop::AddFileDescriptorCallback",
    0x01695470:  "PLT: PrepTCPSocket",
    0x016bd6d0:  "PLT: StreamSocket::Recv",
    0x0169a0c0:  "PLT: WireProxy::FindReplaceHost -- rewrites embedded hostnames in relayed payload",
    0x016b4890:  "PLT: DatagramSocket::RecvFrom",

    # F25 vulnerability primitive
    0x0165ddf0:  "google::protobuf::MessageLite::ParseFromArray(void const*, int) -- F25 sink",
}

# ── WireProxy architecture note ───────────────────────────────────────────────
# External TCP/UDP sockets are RELAY-ONLY paths (ReadStreamData, ReadDatagram -> WriteOutput).
# HandleIncomingPacket is ONLY called from UsbHandler (USB physical interface).
# F25 is USB-physical-access-only; TCP/UDP external paths do not reach HandleIncomingPacket.
# Skybus subscriptions (callbacks at WireProxy+0x180, WireProxy+0x1c8) receive internal IPC only.

# ── ELF ARM64 function extraction ─────────────────────────────────────────────

def parse_elf64_sections(data: bytes) -> dict:
    """Parse ELF64 header and section table."""
    if data[:4] != b'\x7fELF':
        raise ValueError("Not an ELF file")
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]

    sections = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name_off = struct.unpack_from('<I', data, off)[0]
        sh_type = struct.unpack_from('<I', data, off + 4)[0]
        sh_addr = struct.unpack_from('<Q', data, off + 16)[0]
        sh_offset = struct.unpack_from('<Q', data, off + 24)[0]
        sh_size = struct.unpack_from('<Q', data, off + 32)[0]
        sections[i] = {
            'name_off': sh_name_off, 'type': sh_type,
            'addr': sh_addr, 'offset': sh_offset, 'size': sh_size
        }

    # Resolve section names
    strshdr = sections.get(e_shstrndx, {})
    stroff = strshdr.get('offset', 0)
    named = {}
    for idx, s in sections.items():
        noff = stroff + s['name_off']
        end = data.index(b'\x00', noff)
        name = data[noff:end].decode(errors='replace')
        named[name] = s
    return named


def find_arm64_function_starts(data: bytes, text_off: int, text_size: int, text_addr: int) -> list:
    """
    Heuristic ARM64 function start detection.
    ARM64 function prologues commonly start with:
      stp x29, x30, [sp, #-N]!   (frame setup)
      sub sp, sp, #N              (stack allocation without frame)
      stp x19, x20, [sp, ...]    (callee-save registers)
    4-byte aligned, common prologue patterns.
    """
    starts = set()
    text = data[text_off:text_off + text_size]

    # Pattern 1: stp x29, x30, [sp, #-N]! encoding: fd7bbeA9 (common range)
    # Pattern 2: stp x29, x30, [sp, ...] fd 7b 9? a9
    # Pattern 3: sub sp, sp, #N — encoding: ff43??d1 or ff83??d1
    for i in range(0, len(text) - 4, 4):
        w = struct.unpack_from('<I', text, i)[0]
        # stp x29, x30, [sp, #-N]!
        if (w & 0xFFE07FFF) == 0xA9BF7BFD:
            starts.add(text_addr + i)
        # stp x29, x30, [sp, N] (non-pre-index)
        elif (w & 0xFFC07FFF) == 0xA9007BFD:
            starts.add(text_addr + i)
        # sub sp, sp, #imm
        elif (w & 0xFFC003FF) == 0xD10003FF:
            starts.add(text_addr + i)

    return sorted(starts)


def extract_functions(data: bytes, max_funcs: int = 6000) -> list:
    """Extract function records {addr, offset, code} from ARM64 ELF."""
    sections = parse_elf64_sections(data)
    text = sections.get('.text', {})
    if not text:
        # Try PT_LOAD executable segment heuristic
        print("  [!] No .text section — using PT_LOAD heuristic")
        # Fallback: scan whole binary
        text = {'offset': 0, 'size': len(data), 'addr': 0}

    t_off = text['offset']
    t_size = text['size']
    t_addr = text['addr']

    print(f"  [*] .text @ file offset 0x{t_off:x}, size {t_size//1024}KB, VA 0x{t_addr:x}")
    starts = find_arm64_function_starts(data, t_off, t_size, t_addr)
    print(f"  [*] Found {len(starts):,} function prologue candidates")

    if len(starts) > max_funcs:
        # Sample evenly + keep all if < limit
        step = len(starts) // max_funcs
        starts = starts[::step][:max_funcs]
        print(f"  [*] Sampling to {len(starts):,} functions")

    funcs = []
    for i, addr in enumerate(starts):
        next_addr = starts[i + 1] if i + 1 < len(starts) else addr + 256
        size = min(next_addr - addr, 512)  # cap at 512 bytes per function
        foff = t_off + (addr - t_addr)
        if foff < 0 or foff + size > len(data):
            continue
        code = data[foff:foff + size]
        funcs.append({'addr': addr, 'offset': foff, 'code': code, 'size': size})

    return funcs


def extract_functions_from_live(data: bytes, live_addrs: 'set[int]',
                                 addr_lo: int = 0x016e54c0,
                                 addr_hi: int = 0x0315ad30,
                                 max_insn_bytes: int = 256) -> list:
    """Build function records using live addresses as function starts.

    Skips prologue heuristics entirely. Uses caller/RELA-derived addresses
    as ground-truth entry points. For libflyby_jni.so the ELF maps VA==fileoff
    so file_offset = addr directly.

    addr_lo/addr_hi default to the .text section bounds of libflyby_jni.so
    (VA 0x016e54c0 to 0x0315ad30 = .rodata start).
    """
    starts = sorted(a for a in live_addrs if addr_lo <= a < addr_hi)
    funcs = []
    for i, addr in enumerate(starts):
        next_addr = starts[i + 1] if i + 1 < len(starts) else addr + max_insn_bytes
        size = min(next_addr - addr, max_insn_bytes)
        foff = addr  # VA == fileoff for this binary
        if foff < 0 or foff + size > len(data):
            continue
        code = data[foff:foff + size]
        funcs.append({'addr': addr, 'offset': foff, 'code': code, 'size': size})
    return funcs


# ── Disassembly + description ──────────────────────────────────────────────────

def disasm_arm64(code: bytes, addr: int, max_insns: int = 60) -> list:
    """Disassemble ARM64 bytes with capstone."""
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = False
    insns = []
    for insn in md.disasm(code, addr):
        insns.append(f"{insn.mnemonic} {insn.op_str}".strip())
        if len(insns) >= max_insns:
            break
    return insns


def build_func_descriptions(data: bytes, funcs: list) -> list:
    """Build semantic description strings for all functions."""
    described = []
    for f in funcs:
        insns = disasm_arm64(f['code'], f['addr'])
        if len(insns) < 3:
            continue
        asm_norm = normalize_asm(insns)
        # Role heuristic from call pattern
        calls = [i for i in insns if 'bl ' in i or 'blr ' in i]
        callees = []
        for c in calls[:6]:
            m = re.search(r'#(0x[0-9a-fA-F]+|\d+)', c)
            if m:
                callees.append(m.group(1))
        # Vuln heuristic: memcpy/memset with large imm or reg-derived length
        vuln_hints = []
        asm_str = ' '.join(insns)
        if 'memcpy' in asm_str or 'memmove' in asm_str:
            vuln_hints.append('calls memcpy/memmove')
        if 'memset' in asm_str:
            vuln_hints.append('calls memset')
        if 'sprintf' in asm_str or 'snprintf' in asm_str:
            vuln_hints.append('calls sprintf/snprintf')
        if 'recv' in asm_str or 'read' in asm_str:
            vuln_hints.append('network/file read')
        if 'strcpy' in asm_str or 'strcat' in asm_str:
            vuln_hints.append('unsafe string ops')

        desc = (
            f"func_0x{f['addr']:x} | "
            f"calls: {', '.join(callees[:4]) or 'none'} | "
            f"asm: {' '.join(asm_norm[:30])} | "
            f"vuln: {'; '.join(vuln_hints) or 'none'}"
        )
        described.append({**f, 'desc': desc, 'insns': insns, 'callees': callees})
    return described


# ── VDT query profiles ─────────────────────────────────────────────────────────

QUERY_PROFILES = {
    'Q1_iot_exchange': (
        "IOTTokenExchange auth handler | "
        "validates client_key field against registered serial | "
        "calls protobuf parse, string compare, token generate | "
        "vuln: serial format not validated, replay token accepted"
    ),
    'Q2_dcon_download': (
        "DCON download token validation | "
        "parses JWT or auth_token from HTTP header | "
        "calls base64 decode, HMAC verify, token lookup | "
        "vuln: token not bound to requesting IP, replay window too large"
    ),
    'Q3_find_release_signing': (
        "firmware release signature verification | "
        "verifies PKCS7 or Ed25519 signature on release manifest | "
        "calls EVP_DigestVerify, RSA_verify, or ECDSA_do_verify | "
        "vuln: signature check skipped on offline path, weak hash accepted"
    ),
    'Q4_mavlink_parser': (
        "MAVLink packet parser | "
        "reads 0xFD magic byte, parses header fields len sysid compid msgid | "
        "calls memcpy with packet.len as length parameter | "
        "vuln: packet.len not bounds-checked before memcpy into fixed buffer"
    ),
    'Q5_http_client': (
        "CloudClient HTTP request builder | "
        "constructs Authorization header with ApiToken | "
        "calls SSL_write, certificate verification, URL format | "
        "vuln: cert validation disabled for internal endpoints, header injection"
    ),
    'Q6_memcpy_length': (
        "memcpy with packet-derived length | "
        "reads length field from network buffer or protobuf | "
        "copies to fixed-size stack or heap buffer | "
        "vuln: length from untrusted source, no upper-bound check before copy"
    ),
    'Q7_crypto_rng': (
        "cryptographic random number or key generation | "
        "calls RAND_bytes, getrandom, or reads /dev/urandom | "
        "generates session token or auth nonce | "
        "vuln: falls back to weak PRNG, seed from predictable source"
    ),
    'Q8_firmware_update': (
        "OTA firmware update handler | "
        "downloads firmware binary to storage path | "
        "verifies hash before flash write | "
        "vuln: path traversal in filename, hash verified after write"
    ),
    'Q9_serial_validation': (
        "device serial number validation | "
        "parses SkydioX10- prefix serial format | "
        "validates against registered device database | "
        "vuln: prefix-only check accepted, numeric suffix unbounded"
    ),
    'Q10_protobuf_parse': (
        "protobuf message deserialization | "
        "decodes varint length-prefixed fields | "
        "allocates buffer based on decoded length | "
        "vuln: integer overflow in length calculation, heap overflow on decode"
    ),
}


# ── Semantic sweep ─────────────────────────────────────────────────────────────

def load_live_addrs(path: str) -> 'set[int]':
    """Load live function addresses from a hex-address-per-line file."""
    live: set[int] = set()
    with open(path, 'r') as fh:
        for line in fh:
            line = line.strip()
            if line:
                live.add(int(line, 16))
    return live


def run_sweep(binary_path: str, query_key: str = None, top_n: int = 10, cache: bool = True,
              live_filter: 'set[int] | None' = None,
              live_direct: 'set[int] | None' = None,
              addr_lo: int = 0x016e54c0,
              addr_hi: int = 0x0315ad30) -> dict:
    print(f"\n[*] Skydio libflyby_jni.so — Semantic RE Sweep")
    print(f"[*] Binary: {binary_path}")
    print(f"[*] Size: {os.path.getsize(binary_path)//1024//1024}MB")
    if live_direct is not None:
        print(f"[*] Mode: LIVE-DIRECT ({len(live_direct):,} live addrs as function starts, no prologue scan)\n")
    elif live_filter is not None:
        print(f"[*] Mode: prologue-scan + liveness filter ({len(live_filter):,} live addrs)\n")
    else:
        print(f"[*] Mode: prologue-scan only (dead code included)\n")

    with open(binary_path, 'rb') as f:
        data = f.read()

    if live_direct is not None:
        # Bypass prologue scanning entirely. Use live addresses as function starts.
        # Cache key includes the live set hash to avoid stale cache collisions.
        import hashlib as _hl
        lhash = _hl.sha256(
            ','.join(str(a) for a in sorted(live_direct)).encode()
        ).hexdigest()[:12]
        cache_path = Path(binary_path).with_suffix(f'.live_{lhash}.funcs.json')
        if cache and cache_path.exists():
            print(f"[*] Loading cached live-direct descriptors from {cache_path.name}")
            with open(cache_path) as f:
                described = json.load(f)
            print(f"[*] Loaded {len(described):,} functions from cache")
        else:
            in_range = sum(1 for a in live_direct if addr_lo <= a < addr_hi)
            print(f"[*] Extracting from {in_range:,} live addresses in [0x{addr_lo:x}, 0x{addr_hi:x})...")
            funcs = extract_functions_from_live(data, live_direct, addr_lo=addr_lo, addr_hi=addr_hi)
            print(f"[*] Building semantic descriptions ({len(funcs):,} functions)...")
            described = build_func_descriptions(data, funcs)
            if cache:
                cacheable = [{k: v for k, v in f.items() if k != 'code'} for f in described]
                with open(cache_path, 'w') as f:
                    json.dump(cacheable, f)
                print(f"[*] Cached {len(described):,} descriptors -> {cache_path.name}")
    else:
        cache_path = Path(binary_path).with_suffix('.funcs.json')
        if cache and cache_path.exists():
            print(f"[*] Loading cached function descriptors from {cache_path}")
            with open(cache_path) as f:
                described = json.load(f)
            print(f"[*] Loaded {len(described):,} functions from cache")
        else:
            print("[*] Extracting functions...")
            funcs = extract_functions(data)
            print(f"[*] Building semantic descriptions ({len(funcs):,} functions)...")
            described = build_func_descriptions(data, funcs)
            if cache:
                cacheable = [{k: v for k, v in f.items() if k != 'code'} for f in described]
                with open(cache_path, 'w') as f:
                    json.dump(cacheable, f)
                print(f"[*] Cached {len(described):,} descriptors -> {cache_path}")

        if live_filter is not None:
            before = len(described)
            described = [f for f in described if f['addr'] in live_filter]
            print(f"[*] Liveness filter: {before:,} -> {len(described):,} functions "
                  f"({before - len(described):,} dead-code entries removed)")

    print(f"[*] Building BERT embeddings for {len(described):,} functions...")
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')
    descs = [f['desc'] for f in described]
    corpus_vecs = model.encode(descs, batch_size=256, show_progress_bar=True, normalize_embeddings=True)
    print(f"[*] Encoded {len(corpus_vecs):,} functions\n")

    queries = {query_key: QUERY_PROFILES[query_key]} if query_key else QUERY_PROFILES
    all_results = {}

    for qkey, qtext in queries.items():
        qvec = model.encode(qtext, normalize_embeddings=True)
        scores = corpus_vecs @ qvec
        top_idx = np.argsort(scores)[::-1][:top_n]

        print(f"\n{'='*72}")
        print(f"[{qkey}] TOP {top_n}")
        print(f"Query: {qtext[:100]}...")
        print(f"{'='*72}")

        hits = []
        for rank, idx in enumerate(top_idx):
            f = described[idx]
            score = float(scores[idx])
            print(f"  [{rank+1:2d}] score={score:.4f}  addr=0x{f['addr']:08x}  "
                  f"calls={','.join(f.get('callees', [])[:3])}")
            print(f"       {f['desc'][:110]}")
            hits.append({'rank': rank+1, 'score': score, 'addr': f['addr'],
                        'desc': f['desc'], 'insns': f.get('insns', [])[:20]})

        all_results[qkey] = hits

    return all_results


def save_report(results: dict, binary_path: str):
    """Save sweep results as ablation findings module."""
    report_path = Path(binary_path).with_suffix('.sweep_report.json')
    with open(report_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Report saved -> {report_path}")

    # Also write to ablation reports/
    report_dir = Path(__file__).parent.parent / 'reports'
    report_dir.mkdir(exist_ok=True)
    dest = report_dir / 'skydio_flyby_sweep.json'
    with open(dest, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"[+] Ablation report -> {dest}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default=BINARY_DEFAULT)
    parser.add_argument('--query', choices=list(QUERY_PROFILES.keys()), default=None)
    parser.add_argument('--all-queries', action='store_true')
    parser.add_argument('--top', type=int, default=10)
    parser.add_argument('--no-cache', action='store_true')
    parser.add_argument('--live-filter', default=None, metavar='PATH',
                        help='Path to hex-address-per-line live function set. '
                             'Restricts the prologue-scanned corpus to reachable functions only.')
    parser.add_argument('--live-direct', default=None, metavar='PATH',
                        help='Path to hex-address-per-line live function set. '
                             'Replaces prologue scanning entirely: uses live addresses as function starts. '
                             'Much higher precision on stripped binaries. '
                             'Default range: .text [0x016e54c0, 0x0315ad30] (libflyby_jni.so).')
    parser.add_argument('--addr-lo', default=None,
                        help='Lower bound for --live-direct address range (hex, e.g. 0x01700000). '
                             'Default: .text section start 0x016e54c0.')
    parser.add_argument('--addr-hi', default=None,
                        help='Upper bound for --live-direct address range (hex, e.g. 0x01800000). '
                             'Default: .rodata start 0x0315ad30.')
    args = parser.parse_args()

    if not os.path.exists(args.binary):
        print(f"[!] Binary not found: {args.binary}")
        print(f"    Copy libflyby_jni.so from APK split first:")
        print(f"    python3 -c \"import zipfile; z=zipfile.ZipFile('.../config.arm64_v8a.apk'); open('{args.binary}','wb').write(z.read('lib/arm64-v8a/libflyby_jni.so'))\"")
        sys.exit(1)

    live_addrs = None
    if args.live_filter or args.live_direct:
        path = args.live_direct or args.live_filter
        print(f"[*] Loading live function set from {path}...")
        live_addrs = load_live_addrs(path)
        print(f"[*] {len(live_addrs):,} live addresses loaded")

    addr_lo = int(args.addr_lo, 16) if args.addr_lo else 0x016e54c0
    addr_hi = int(args.addr_hi, 16) if args.addr_hi else 0x0315ad30

    query_key = args.query if not args.all_queries else None
    results = run_sweep(args.binary, query_key, args.top, cache=not args.no_cache,
                        live_filter=live_addrs if args.live_filter else None,
                        live_direct=live_addrs if args.live_direct else None,
                        addr_lo=addr_lo, addr_hi=addr_hi)
    save_report(results, args.binary)

    print("\n[*] Next steps:")
    print("    1. Review top hits for Q1_iot_exchange, Q4_mavlink_parser, Q6_memcpy_length")
    print("    2. Disassemble candidate addresses with arm_disasm.py")
    print("    3. Trace call graph from each candidate with arm_symbolic.py")
    print("    4. Document confirmed findings as ablation module findings")


if __name__ == '__main__':
    main()
