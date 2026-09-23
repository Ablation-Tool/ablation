#!/usr/bin/env python3
"""
go_adconnector_sweep.py -- semantic vuln sweep for adconnector_linux_amd64 (Go binary).

Targets fortinet.com/ems/* and github.com/go-ldap/* packages.
Uses pclntab for function names + VAs, eh_frame for sizes.
Saves top findings to modules/fortinet_forticlient_ems_745_re.py.

Usage:
    python3 sweeps/go_adconnector_sweep.py [--all-packages] [--top N]
"""

import sys
import struct
import argparse
from pathlib import Path
from datetime import datetime
import numpy as np
import capstone

sys.path.insert(0, str(Path(__file__).parent.parent))

from ablation.analyzers.go_pclntab import GoFuncTable
from ablation.analyzers import SemanticSearcher, describe_function

BINARY = "/tmp/adconnector_linux_amd64"
MAX_FUNC_BYTES = 2048

# Package prefixes to sweep (edit with --all-packages to sweep all)
TARGET_PKGS = (
    "fortinet.com/ems/",
    "fortinet.com/goEMSCommon/",
    "github.com/go-ldap/",
    "vendor/github.com/go-ldap/",
)

# Go-specific vuln query profiles
GO_VULN_PROFILES = [
    ("ldap_injection",
     "FUNC | calls: ldap.Search ldap.SearchWithPaging | "
     "vuln: LDAP search filter constructed from untrusted input without escapeFilter, "
     "allows LDAP injection via user-controlled attribute values or wildcards"),

    ("ldap_injection_filter_build",
     "FUNC | role: LDAP filter builder | "
     "vuln: LDAP filter string constructed by string concatenation or Sprintf with "
     "user-controlled fields, attacker injects )(& to alter search scope or bypass auth"),

    ("sql_injection",
     "FUNC | calls: database/sql Query Exec QueryRow | "
     "vuln: SQL query built by string concatenation with user-controlled domain name, "
     "username, or GUID without parameterized queries"),

    ("auth_bypass",
     "FUNC | role: authentication handler | "
     "vuln: authentication check bypassed by empty credentials, null bind LDAP, "
     "or logic error allowing unauthenticated access"),

    ("ldap_null_bind",
     "FUNC | calls: ldap.Bind ldap.UnauthenticatedBind | "
     "vuln: LDAP null bind or anonymous bind allowed when credentials are empty, "
     "treating unauthenticated bind as successful authentication"),

    ("credential_exposure",
     "FUNC | role: credential handler decrypt | "
     "vuln: plaintext password or API key logged, stored insecurely, or "
     "DecodeEncryptedString uses weak reversible cipher"),

    ("cert_validation_bypass",
     "FUNC | role: TLS certificate verifier | "
     "vuln: TLS certificate validation skipped, InsecureSkipVerify set, "
     "or custom verifier does not check hostname against CN/SANs"),

    ("proto_deserialization",
     "FUNC | calls: proto.Unmarshal protobuf Decode | "
     "vuln: protobuf message from network deserialized without size or field validation, "
     "attacker sends crafted message causing panic or memory corruption"),

    ("domain_sync_injection",
     "FUNC | role: domain sync handler | "
     "vuln: LDAP base DN or search filter derived from externally-provided domain config "
     "without sanitization, allows LDAP scope expansion"),

    ("search_req_injection",
     "FUNC | role: search request handler | "
     "vuln: incoming search request parameters used directly in LDAP filter construction "
     "without input validation or character escaping"),
]


def load_fde_sizes(binary_path: str) -> dict:
    """Return {VA: size} from .eh_frame FDE entries."""
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.dwarf.callframe import FDE
        result = {}
        with open(binary_path, "rb") as fh:
            elf = ELFFile(fh)
            di = elf.get_dwarf_info()
            for e in di.EH_CFI_entries():
                if isinstance(e, FDE) and e["initial_location"] > 0 and e["address_range"] > 0:
                    result[e["initial_location"]] = e["address_range"]
        return result
    except Exception as e:
        print(f"[!] eh_frame load failed: {e}")
        return {}


def extract_go_funcs(data: bytes, names: dict, fde_sizes: dict,
                     target_pkgs: tuple, max_bytes: int = 2048) -> list:
    """
    Disassemble Go functions and build description dicts.
    names: {VA -> package.FuncName}
    fde_sizes: {VA -> size} from eh_frame
    Returns list of {'va', 'name', 'desc', 'calls'} dicts.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False

    # Sort VAs for next-function size estimation
    sorted_vas = sorted(names.keys())
    va_idx = {va: i for i, va in enumerate(sorted_vas)}

    # Load sections for VA->file-offset mapping
    sections = []
    try:
        import lief as _lief
        b = _lief.parse(BINARY)
        for sect in b.sections:
            sections.append((sect.virtual_address, int(sect.offset), int(sect.size)))
    except Exception:
        pass

    def va_to_offset(va: int) -> int:
        for svaddr, soff, ssz in sections:
            if svaddr <= va < svaddr + ssz:
                return soff + (va - svaddr)
        return -1

    funcs = []
    n_skipped = 0

    for va, name in names.items():
        if not any(name.startswith(pkg) for pkg in target_pkgs):
            continue
        if "type:" in name or ".eq." in name or ".hash." in name:
            continue

        # Determine function size
        size = fde_sizes.get(va)
        if size is None:
            # Fall back to distance to next known function
            idx = va_idx.get(va, -1)
            if idx >= 0 and idx + 1 < len(sorted_vas):
                next_va = sorted_vas[idx + 1]
                size = next_va - va
            else:
                size = max_bytes
        size = min(size, max_bytes)
        if size < 8:
            continue

        # Get file offset
        file_off = va_to_offset(va)
        if file_off < 0 or file_off + size > len(data):
            n_skipped += 1
            continue

        chunk = data[file_off: file_off + size]
        if not chunk:
            n_skipped += 1
            continue

        # Disassemble
        lines = []
        calls = []
        for insn in md.disasm(chunk, va):
            text = f"{insn.mnemonic} {insn.op_str}".strip()
            lines.append(text)
            if insn.mnemonic in ("call", "callq") and insn.op_str.startswith("0x"):
                try:
                    target = int(insn.op_str, 16)
                    callee_name = names.get(target, insn.op_str)
                    # Shorten: keep last two path components
                    short = callee_name.split("/")[-1] if "/" in callee_name else callee_name
                    calls.append(short)
                except ValueError:
                    pass

        if len(lines) < 3:
            n_skipped += 1
            continue

        # Short name: last two components
        short_name = "/".join(name.split("/")[-2:]) if "/" in name else name

        desc = describe_function(
            name=short_name,
            role="FUNC",
            call_targets=calls[:12],
            strings=[],
            asm_lines=lines,
        )
        funcs.append({"va": va, "name": name, "short_name": short_name, "desc": desc, "calls": calls})

    print(f"[*] Skipped {n_skipped} funcs (offset mapping failed or too small)")
    return funcs


def run_sweep(binary_path: str, all_packages: bool = False, top_k: int = 5) -> dict:
    from sentence_transformers import SentenceTransformer

    print(f"[*] Loading binary: {binary_path}")
    data = open(binary_path, "rb").read()
    print(f"[*] Binary size: {len(data) / 1024 / 1024:.1f} MB")

    print("[*] Parsing Go pclntab ...")
    ft = GoFuncTable.from_binary(data)
    if not ft:
        print("[!] No pclntab found -- aborting")
        return {}
    print(f"[*] pclntab: {ft.n_funcs} functions, text_start={ft.text_start:#x}, go={ft.go_version}")
    print(f"[*] Named functions: {len(ft.names)}")

    print("[*] Loading eh_frame FDE sizes ...")
    fde_sizes = load_fde_sizes(binary_path)
    print(f"[*] FDE size entries: {len(fde_sizes)}")

    target_pkgs = None if all_packages else TARGET_PKGS
    if all_packages:
        print("[*] Sweeping ALL packages (slow)")
        target_pkgs = ("",)  # match everything
    else:
        print(f"[*] Target packages: {TARGET_PKGS}")

    print("[*] Extracting and disassembling functions ...")
    funcs = extract_go_funcs(data, ft.names, fde_sizes, target_pkgs or TARGET_PKGS)
    print(f"[*] Functions to encode: {len(funcs)}")

    if not funcs:
        print("[!] No functions extracted -- check package filters")
        return {}

    print("[*] Loading sentence transformer ...")
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")

    print("[*] Encoding corpus ...")
    corpus = model.encode(
        [f["desc"] for f in funcs],
        normalize_embeddings=True,
        batch_size=128,
        show_progress_bar=True,
    ).astype(np.float32)

    results = {}
    for profile_name, query in GO_VULN_PROFILES:
        qvec = model.encode(query, normalize_embeddings=True).astype(np.float32)
        scores = corpus @ qvec
        top = np.argsort(scores)[::-1][:top_k]
        results[profile_name] = [
            (float(scores[i]), funcs[i]["va"], funcs[i]["calls"], funcs[i]["name"])
            for i in top
        ]

    return results, funcs, ft


def print_results(results: dict, min_score: float = 0.50) -> None:
    for profile_name, hits in results.items():
        above = [(s, va, calls, name) for s, va, calls, name in hits if s >= min_score]
        if not above:
            continue
        print(f"\n=== {profile_name} ===")
        for score, va, calls, name in above:
            calls_short = calls[:4]
            print(f"  {va:#010x}  score={score:.4f}  {name}")
            if calls_short:
                print(f"             calls: {calls_short}")


def main():
    ap = argparse.ArgumentParser(description="Go binary semantic sweep for adconnector")
    ap.add_argument("--binary", default=BINARY, help="Path to binary")
    ap.add_argument("--all-packages", action="store_true", help="Sweep all packages (slow)")
    ap.add_argument("--top", type=int, default=5, help="Candidates per profile")
    ap.add_argument("--min-score", type=float, default=0.50, help="Min score threshold")
    args = ap.parse_args()

    out = run_sweep(args.binary, all_packages=args.all_packages, top_k=args.top)
    if not out:
        return
    results, funcs, ft = out
    print_results(results, min_score=args.min_score)

    # Name-pattern triage: high-value function names
    print("\n=== NAME-PATTERN TRIAGE ===")
    high_value_patterns = [
        "LDAP", "ldap", "Filter", "filter", "Escape", "escape",
        "Auth", "auth", "Bind", "bind", "Decrypt", "decrypt",
        "Cert", "cert", "Verify", "verify", "Search", "search",
        "Inject", "inject", "Sanitize", "sanitize", "Cleanup", "cleanup",
        "Credential", "credential", "Password", "password",
    ]
    for va, name in sorted(ft.names.items()):
        if not any(name.startswith(pkg) for pkg in TARGET_PKGS):
            continue
        short = name.split("/")[-1] if "/" in name else name
        if any(pat in short for pat in high_value_patterns):
            print(f"  {va:#010x}  {name}")


if __name__ == "__main__":
    main()
