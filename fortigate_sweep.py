"""
FortiGate 8.0.0 binary semantic sweep -- FGT_VM64-v8.0.0.F-build0167
Targets: libips.so.new (IPS engine), libav.so.new (AV engine)
Both are pre-auth attack surface: process untrusted network traffic and files.
"""

import sys, os, json, numpy as np
sys.path.insert(0, os.path.dirname(__file__))
import fortinet_sweep
from fortinet_sweep import sweep, VULN_PROFILES

FGT_DATAFS = os.path.expanduser("~/ablation/fortigate-work/extract/datafs")

TARGETS = [
    ("libips.so.new", "FortiGate IPS engine -- pre-auth, processes all network traffic, rule matching"),
    ("libav.so.new",  "FortiGate AV engine -- file format parsing, decompression, MIME/archive scanning"),
]

# FortiGate-specific vulnerability profiles added to the base set
FGT_VULN_PROFILES = VULN_PROFILES + [
    ("ips_pkt_len_overflow",
     "IPS_ENGINE | role=packet_decode | calls: memcpy memmove recv | "
     "vuln: network packet field (TCP/UDP/IP header value) used as copy length "
     "without upper bound check; heap or stack overflow in IPS packet decoder"),

    ("ips_signature_parse",
     "IPS_RULE_ENGINE | role=sig_db_parse | calls: memcpy atoi strtol strncpy | "
     "vuln: binary signature database format (FIDS/IPS rule blob) reads 16-bit or 32-bit "
     "length field without checking against available buffer; heap overflow in sig parser"),

    ("av_decomp_output_overflow",
     "AV_ENGINE | role=decompressor | calls: inflate zlib_inflate lz4_decompress uncompress | "
     "vuln: decompression output size not bounded against output buffer; avail_out not set "
     "or ratio check missing; can be triggered by crafted archive attachment"),

    ("av_mime_boundary_overflow",
     "AV_MIME_PARSER | role=content_decode | calls: strncpy memcpy base64_decode | "
     "vuln: MIME Content-Type boundary or Content-Length field from email/HTTP "
     "used as copy length without upper bound; heap overflow in MIME parser"),

    ("ssl_inspection_buffer_overflow",
     "SSL_INSPECTOR | role=tls_record_parse | calls: memcpy malloc realloc recv | "
     "vuln: TLS record length from ClientHello or certificate used as alloc/copy size "
     "without validation; pre-auth stack or heap overflow in deep packet inspection"),
]


def run_all(output_file: str = None):
    orig_profiles = fortinet_sweep.VULN_PROFILES
    fortinet_sweep.VULN_PROFILES = FGT_VULN_PROFILES

    all_results = {}
    for lib_name, label in TARGETS:
        path = os.path.join(FGT_DATAFS, "lib", lib_name)
        if not os.path.exists(path):
            print(f"[SKIP] {lib_name} not found at {path}")
            continue
        results, metas, descs, corpus_vecs, model = sweep(path, label)
        all_results[lib_name] = {
            "label": label,
            "n_functions": len(metas),
            "hits": results,
        }

    fortinet_sweep.VULN_PROFILES = orig_profiles

    if output_file:
        with open(output_file, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nResults written to {output_file}")

    return all_results


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/fgt_sweep_results.json"
    run_all(out)
