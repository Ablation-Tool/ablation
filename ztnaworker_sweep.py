"""
ztnaworker.exe semantic sweep -- ablation-semantic-first
Target: FortiClientEMS 7.2.9 ztnaworker.exe (34MB PE32+ Go binary)
Port 9990 -- ZTNA policy enforcement worker
"""

import sys
import os
import struct
import numpy as np
import capstone

sys.path.insert(0, os.path.dirname(__file__))
from modules.semantic_search import describe_function

from sentence_transformers import SentenceTransformer

BINARY = "/tmp/ems_contents/Program Files/Fortinet/FortiClientEMS/ztnaworker.exe"
IMAGE_BASE = 0x400000
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
MAX_INSNS = 300
TOP_N = 12

# ZTNA-specific vuln profiles
VULN_PROFILES = [
    ("ztna_auth_bypass",
     "ZTNA_AUTH | role=access_control | calls: verify check validate | "
     "vuln: authentication check skipped or bypassed via early return or constant comparison"),

    ("command_injection",
     "COMMAND_EXEC | role=shell | calls: system popen exec cmd | "
     "vuln: system or exec called with string from untrusted input without sanitization"),

    ("tls_cert_validation",
     "TLS_HANDLER | role=certificate | calls: verify x509 cert tls | "
     "vuln: certificate validation skipped or peer cert not verified in TLS handshake"),

    ("hardcoded_credential",
     "CREDENTIAL_STORE | role=authentication | calls: compare equal | "
     "vuln: hardcoded password key secret token compared against user input or network data"),

    ("grpc_packet_parse",
     "GRPC_HANDLER | role=packet_parser | calls: decode unmarshal read recv | "
     "vuln: length from gRPC frame used in memory operation without validation against frame bounds"),

    ("memory_corruption",
     "BUFFER_HANDLER | role=buffer_copy | calls: copy memcpy memmove | "
     "vuln: memcpy or copy called with length from untrusted field without upper bound check"),

    ("privilege_escalation",
     "POLICY_ENFORCER | role=privilege | calls: setuid chmod chown sudo | "
     "vuln: privilege elevation based on ZTNA tag or policy that can be forged by attacker"),

    ("ztna_tag_forge",
     "TAG_HANDLER | role=tag_validation | calls: tag verify hmac | "
     "vuln: ZTNA posture tag accepted without cryptographic verification of origin"),

    ("unauth_rpc_surface",
     "RPC_HANDLER | role=rpc | calls: handle serve listen | "
     "vuln: RPC endpoint accessible without authentication, allows unauthenticated policy query"),

    ("sql_injection",
     "DB_HANDLER | role=database | calls: query exec db sql | "
     "vuln: SQL query constructed from untrusted field without parameterization"),

    # P19 insight: size_type + signed arithmetic = unsigned wraparound into huge value
    # Go equivalent: int->uint cast of network-supplied length used in make/copy/growslice
    ("unsigned_len_wraparound",
     "PACKET_PARSER | role=length_arithmetic | calls: read recv copy make growslice append | "
     "vuln: length or size from network packet cast signed to unsigned or truncated; "
     "allocation or slice operation uses wrapped value as size without upper bound check; "
     "small negative int wraps to UINT64_MAX causing heap underallocation"),

    # P15 insight: unsynchronized async goroutine access to shared state = data race = UB
    # Go equivalent: two goroutines read/write shared map or slice without sync.Mutex or atomic
    ("goroutine_data_race",
     "CONCURRENT_HANDLER | role=shared_state | calls: goroutine sync mutex atomic chan lock | "
     "vuln: ZTNA tag map policy cache or session table accessed from concurrent goroutines "
     "without mutex lock or atomic load store; concurrent map write causes runtime panic or "
     "silent data corruption of policy enforcement state"),

    # goEMS.conf ZipAPIResp=yes -- ztnaworker decompresses API responses; input may also be compressed
    # P18 insight: moved-from / no-size-check on buffer; here: no decompressed-size limit
    ("zip_bomb_decompress",
     "ZIP_HANDLER | role=decompressor | calls: decompress inflate gzip flate zlib read | "
     "vuln: gzip or flate compressed data from network decompressed into buffer without "
     "checking decompressed size against limit; attacker sends 42-byte zip expanding to "
     "gigabytes exhausting heap; ZipAPIResp=yes surface confirmed in goEMS.conf"),

    # C++ Memory Management Ch10 arena pattern: bump-pointer reuse; Go equivalent: growslice
    # with attacker-controlled cap argument bypasses bounds = OOB write on backing array
    ("growslice_oob",
     "SLICE_GROW | role=buffer_resize | calls: growslice append makeslice newobject | "
     "vuln: append or growslice called with attacker-controlled new length; signed integer "
     "comparison for capacity check wraps negative when len overflows int32 boundary "
     "allowing heap underallocation followed by out-of-bounds write into adjacent object"),
]

# COFF interest keywords -- only encode functions matching these
INTEREST_KEYWORDS = [
    "ztna", "tls", "auth", "cert", "token", "policy", "tag", "grpc",
    "handler", "parse", "decode", "verify", "validate", "check",
    "command", "cmd", "exec", "sql", "db", "query", "register", "login",
    "endpoint", "route", "proxy", "forward", "tunnel", "hmac", "sign",
    "crypto", "aes", "rsa", "key", "password", "secret", "credential",
    "unprotected", "bypass", "redirect", "saml", "oidc", "jwt",
    "posture", "compliance", "enforce", "access", "acl", "permit",
    "deny", "allow", "rule", "firewall", "port", "network", "packet",
    "buffer", "read", "write", "recv", "send", "listen", "serve",
    # Go concurrency / allocator (P15, P19, Memory Ch10)
    "goroutine", "atomic", "mutex", "sync", "race", "lock", "chan",
    "inflate", "gzip", "zip", "flate", "zlib", "decompress", "compress",
    "growslice", "makeslice", "append", "newobject", "mallocgc",
    "slice", "length", "capacity", "convert", "uint", "int32", "int64",
    # Go interface / nil dispatch (P22 virtual-in-ctor equivalent)
    "interface", "itab", "iface", "typeassert", "panic", "recover",
]


def parse_pe(raw):
    pe_off = struct.unpack_from('<I', raw, 0x3C)[0]
    num_sec = struct.unpack_from('<H', raw, pe_off + 6)[0]
    opt_sz = struct.unpack_from('<H', raw, pe_off + 20)[0]
    sec_off = pe_off + 24 + opt_sz
    img_base = struct.unpack_from('<Q', raw, pe_off + 24 + 24)[0]

    sections = []
    for i in range(num_sec):
        o = sec_off + i * 40
        name = raw[o:o+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsz, va, rsz, ro = struct.unpack_from('<IIII', raw, o + 8)
        sections.append({'name': name, 'va': va, 'ro': ro, 'vsz': vsz, 'rsz': rsz})

    sym_ptr = struct.unpack_from('<I', raw, pe_off + 12)[0]
    sym_cnt = struct.unpack_from('<I', raw, pe_off + 16)[0]
    return img_base, sections, sym_ptr, sym_cnt


def scan_coff_functions(raw, sym_ptr, sym_cnt):
    """Return list of (name, va_offset, section_idx) for function symbols in .text."""
    if sym_ptr == 0 or sym_cnt == 0:
        return []
    strtab_off = sym_ptr + sym_cnt * 18
    results = []
    i = 0
    while i < sym_cnt:
        off = sym_ptr + i * 18
        nb = raw[off:off+8]
        if nb[:4] == b'\x00\x00\x00\x00':
            idx = struct.unpack_from('<I', nb, 4)[0]
            try:
                end = raw.index(b'\x00', strtab_off + idx)
                name = raw[strtab_off + idx:end].decode('utf-8', errors='replace')
            except Exception:
                name = ''
        else:
            name = nb.rstrip(b'\x00').decode('utf-8', errors='replace')
        val = struct.unpack_from('<I', raw, off + 8)[0]
        sec = struct.unpack_from('<H', raw, off + 12)[0]
        sym_type = struct.unpack_from('<H', raw, off + 14)[0]
        aux_count = raw[off + 17]
        # Section 1 = .text; type 0x20 = function, but Go uses type=0 with class=2 (external)
        # Use section==1 and nonzero value as proxy for text function
        if sec == 1 and val > 0 and name:
            results.append((name, val, sec))
        i += 1 + aux_count
    return results


def is_interesting(name):
    nl = name.lower()
    return any(kw in nl for kw in INTEREST_KEYWORDS)


def disasm_function(raw, va, sections, md):
    """Disassemble function at va; stop at ret."""
    text_sec = sections[0]  # .text is always first
    text_va = text_sec['va'] + IMAGE_BASE
    text_ro = text_sec['ro']
    foff = text_ro + (va - text_sec['va'])
    if foff < 0 or foff >= len(raw):
        return [], []
    insns = []
    calls = []
    blob = raw[foff:foff + MAX_INSNS * 15]
    for insn in md.disasm(blob, IMAGE_BASE + va):
        mnem = insn.mnemonic
        ops = insn.op_str.strip()
        insns.append(f"{mnem} {ops}".strip())
        if mnem in ("call", "callq") and "0x" in ops:
            try:
                calls.append(hex(int(ops, 16)))
            except ValueError:
                calls.append(ops)
        if mnem in ("ret", "retn", "retq"):
            break
        if len(insns) >= MAX_INSNS:
            break
    return insns, calls


def main():
    print(f"Loading {BINARY}")
    with open(BINARY, 'rb') as f:
        raw = f.read()
    print(f"Size: {len(raw):,} bytes")

    img_base, sections, sym_ptr, sym_cnt = parse_pe(raw)
    print(f"ImageBase=0x{img_base:X}  Sections={len(sections)}  COFF_syms={sym_cnt}")
    if img_base != IMAGE_BASE:
        print(f"WARNING: IMAGE_BASE mismatch: expected 0x{IMAGE_BASE:X} got 0x{img_base:X}")

    for s in sections[:5]:
        print(f"  {s['name']:8s} VA=0x{s['va']:08X} RO=0x{s['ro']:08X} VSZ={s['vsz']//1024}KB")

    print("\nScanning COFF symbol table...")
    all_funcs = scan_coff_functions(raw, sym_ptr, sym_cnt)
    print(f"  Total .text symbols: {len(all_funcs)}")

    interesting = [(n, v, s) for n, v, s in all_funcs if is_interesting(n)]
    print(f"  Interesting (keyword match): {len(interesting)}")

    # Also sample top-1000 by name length as coverage for unnamed patterns
    other = [(n, v, s) for n, v, s in all_funcs if not is_interesting(n)]
    sampled_other = other[:500]

    corpus_funcs = interesting + sampled_other
    print(f"  Total sweep corpus: {len(corpus_funcs)}")

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False

    descs = []
    metas = []
    skipped = 0
    for name, val, sec in corpus_funcs:
        insns, calls = disasm_function(raw, val, sections, md)
        if len(insns) < 4:
            skipped += 1
            continue
        desc = describe_function(
            name=name,
            role="unknown",
            call_targets=calls,
            strings=[],
            vuln_notes="",
            asm_lines=insns[:80],
        )
        descs.append(desc)
        va = IMAGE_BASE + val
        metas.append({"name": name, "va": hex(va), "val": hex(val), "calls": calls, "n_insns": len(insns)})

    print(f"\nFunctions encoded: {len(descs)}  skipped(<4 insns): {skipped}")

    print(f"Encoding with {MODEL_NAME}...")
    model = SentenceTransformer(MODEL_NAME, device="cpu")
    corpus_vecs = model.encode(descs, normalize_embeddings=True, batch_size=32, show_progress_bar=True)

    print("\n" + "="*60)
    print("ZTNAWORKER VULNERABILITY SWEEP RESULTS")
    print("="*60)

    all_results = {}
    for profile_name, query in VULN_PROFILES:
        qvec = model.encode(query, normalize_embeddings=True)
        scores = corpus_vecs @ qvec
        top_idx = np.argsort(scores)[::-1][:TOP_N]
        hits = []
        for idx in top_idx:
            m = metas[idx]
            score = float(scores[idx])
            if score < 0.25:
                break
            hits.append({
                "va": m["va"],
                "name": m["name"],
                "score": round(score, 3),
                "n_insns": m["n_insns"],
                "calls": m["calls"][:6],
            })
        all_results[profile_name] = hits
        print(f"\n[{profile_name}]")
        for h in hits[:4]:
            short_name = h["name"].split("/")[-1] if "/" in h["name"] else h["name"]
            print(f"  {h['va']}  score={h['score']}  {short_name}")
            if h["calls"]:
                print(f"    calls: {h['calls'][:4]}")

    print("\n" + "="*60)
    print("TOP CANDIDATE FUNCTIONS (cross-profile frequency)")
    print("="*60)
    freq = {}
    for hits in all_results.values():
        for h in hits:
            freq[h["va"]] = freq.get(h["va"], {"count": 0, "name": h["name"], "scores": []})
            freq[h["va"]]["count"] += 1
            freq[h["va"]]["scores"].append(h["score"])

    ranked = sorted(freq.items(), key=lambda x: (x[1]["count"], max(x[1]["scores"])), reverse=True)
    for va, info in ranked[:15]:
        short = info["name"].split("/")[-1] if "/" in info["name"] else info["name"]
        print(f"  {va}  count={info['count']}  avg_score={sum(info['scores'])/len(info['scores']):.3f}  {short}")

    return all_results


if __name__ == "__main__":
    main()
