"""
cac_struct_re.py -- Structural RE of CAC proprietary command layer.

Analogous to lina BERT semantic sweep but for JavaCard APDU protocol:
  Track 1: APDU behavioral sweep -- enumerate CLA/INS/P1/P2 space across
            all selecteble AID contexts; find HID ActivID proprietary
            commands (non-spec INS codes that return != 6D00/6E00)
  Track 2: Semantic structural mapping -- encode each responding command
            as a behavioral descriptor, cluster via BERT cosine similarity
            to discover function families and hidden command groups

Card: HID Global ActivID Applet 2.7.4 on Alcor Micro AU9540 reader
Spec baseline: NIST SP 800-73-4 (any responding INS outside this = proprietary)
Transport: pyscard direct PC/SC (auto T=0 with GET RESPONSE chaining)
           ~3ms/APDU vs ~500ms/opensc-tool subprocess

Usage:
    python3 cac_struct_re.py [--quick] [--save sweep.json] [--no-cluster]

Committed to ablation.
"""

from __future__ import annotations

import json
import os
import re
import struct
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

from smartcard.System import readers as sc_readers

# ──────────────────────────────────────────────────────────────────────────────
# PIV spec baseline (NIST SP 800-73-4 defined INS codes)
# ──────────────────────────────────────────────────────────────────────────────

PIV_SPEC_INS = {
    0x20: "VERIFY",
    0x24: "CHANGE REFERENCE DATA",
    0x2C: "RESET RETRY COUNTER",
    0x44: "GENERATE ASYMMETRIC KEY PAIR",
    0x47: "GENERATE ASYMMETRIC KEY PAIR (alt)",
    0x87: "GENERAL AUTHENTICATE",
    0xA4: "SELECT",
    0xB0: "READ BINARY",
    0xC0: "GET RESPONSE",
    0xCB: "GET DATA",
    0xDB: "PUT DATA",
    0x84: "GET CHALLENGE",
}

# SW codes worth flagging
SW_LABELS = {
    "9000": "success",
    "6100": "success+data",
    "6982": "security_not_satisfied",
    "6985": "conditions_of_use",
    "6986": "command_not_allowed",
    "6A80": "incorrect_cmd_data",
    "6A81": "function_not_supported",
    "6A82": "file_not_found",
    "6A86": "incorrect_p1p2",
    "6A88": "reference_data_not_found",
    "6300": "verification_failed",
    "6700": "wrong_length",
    "6800": "no_information",
}

# Non-PIV AIDs to enumerate
CANDIDATE_AIDS = {
    "PIV":              bytes.fromhex("A000000308000010000100"),
    "CAC_Access":       bytes.fromhex("A000000116"),
    "HID_ActivID":      bytes.fromhex("A0000005271002"),
    "HID_ActivID_2":    bytes.fromhex("A000000327210101"),
    "GlobalPlatform":   bytes.fromhex("A000000151000000"),
    "CardManager":      bytes.fromhex("A000000003000000"),
    "DoD_CDS":          bytes.fromhex("A000000372724446"),
    "PKI_Auth":         bytes.fromhex("A0000000791000"),
    "PKI_Email":        bytes.fromhex("A0000000791001"),
}

# Extra P1/P2 combos for narrow re-sweep of proprietary INS
P1P2_EXTRAS = [
    (0x00, 0x00), (0x00, 0x01), (0x04, 0x00),
    (0x00, 0x9E), (0x3F, 0xFF), (0xFF, 0x00), (0xFF, 0xFF),
]

# ──────────────────────────────────────────────────────────────────────────────
# PC/SC connection
# ──────────────────────────────────────────────────────────────────────────────

class CardConn:
    """Direct PC/SC connection with T=0 GET RESPONSE chaining."""

    def __init__(self):
        rs = sc_readers()
        if not rs:
            raise RuntimeError("no PC/SC readers found")
        self.reader = rs[0]
        self.conn   = self.reader.createConnection()
        self.conn.connect()

    def transmit(self, apdu: list[int]) -> tuple[bytes, str]:
        """Send APDU, chain GET RESPONSE if SW=61xx. Return (data, sw)."""
        try:
            data, sw1, sw2 = self.conn.transmit(apdu)
        except Exception:
            # Certain APDUs cause T=0 transaction failure at transport layer.
            # Reconnect and return sentinel so sweep continues.
            try:
                self.conn.disconnect()
            except Exception:
                pass
            try:
                self.conn = self.reader.createConnection()
                self.conn.connect()
                # Re-select PIV to restore context
                aid = [0xA0,0x00,0x00,0x03,0x08,0x00,0x00,0x10,0x00,0x01,0x00]
                self.conn.transmit([0x00,0xA4,0x04,0x00,len(aid)]+aid+[0x00])
            except Exception:
                pass
            return b"", "XXXX"  # sentinel: transport error, not card SW

        if sw1 == 0x61:
            try:
                data2, sw1, sw2 = self.conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
                data = data + data2
            except Exception:
                pass
        return bytes(data), f"{sw1:02X}{sw2:02X}"

    def select_piv(self) -> str:
        aid = [0xA0,0x00,0x00,0x03,0x08,0x00,0x00,0x10,0x00,0x01,0x00]
        _, sw = self.transmit([0x00,0xA4,0x04,0x00,len(aid)] + aid + [0x00])
        return sw

    def select_aid(self, aid_bytes: bytes) -> str:
        aid = list(aid_bytes)
        _, sw = self.transmit([0x00,0xA4,0x04,0x00,len(aid)] + aid + [0x00])
        return sw

    def disconnect(self):
        try:
            self.conn.disconnect()
        except Exception:
            pass


def wait_for_card(timeout_s: float = 120.0) -> CardConn:
    deadline = time.monotonic() + timeout_s
    shown    = False
    while time.monotonic() < deadline:
        try:
            rs = sc_readers()
            if rs:
                conn = rs[0].createConnection()
                conn.connect()
                conn.disconnect()
                if shown:
                    print("  Card detected.", flush=True)
                return CardConn()
        except Exception:
            pass
        if not shown:
            print("  [Insert CAC card to continue...]", flush=True)
            shown = True
        time.sleep(0.5)
    raise TimeoutError(f"no card within {timeout_s}s")


# ──────────────────────────────────────────────────────────────────────────────
# ATR decode
# ──────────────────────────────────────────────────────────────────────────────

def decode_atr(card: CardConn) -> dict:
    import subprocess
    r = subprocess.run(["opensc-tool", "--atr"], capture_output=True, timeout=5)
    raw = re.sub(r'[^0-9a-fA-F]', '', r.stdout.decode())
    result = {"raw": raw, "reader": str(card.reader)}
    if not raw:
        return result
    data = bytes.fromhex(raw)
    result["convention"] = "Direct" if data[0] == 0x3B else "Inverse"
    if len(data) > 1:
        k = data[1] & 0x0F
        # Skip interface bytes to get historical bytes
        idx  = 2
        byte = data[1]
        while byte & 0x80 and idx < len(data):
            yi   = (byte >> 4) & 0x0F
            next_b = 0
            for bit in (0x1, 0x2, 0x4, 0x8):
                if yi & bit and idx < len(data):
                    next_b = data[idx]; idx += 1
            byte = next_b
        hist = data[idx: idx + k]
        result["historical_hex"]   = hist.hex()
        result["historical_ascii"] = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in hist)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Track 1: APDU behavioral sweep
# ──────────────────────────────────────────────────────────────────────────────

SKIP_SW = {"6D00", "6E00", "6800", "6881", "", "XXXX"}  # "not supported" + transport errors

def sweep_ins(card: CardConn, context: str, cla: int = 0x00,
              p1: int = 0x00, p2: int = 0x00,
              ins_range: range = range(0x00, 0x100)) -> list[dict]:
    """
    Probe all INS codes in ins_range with given CLA/P1/P2.
    Re-SELECTs PIV AID every 32 probes to avoid session drift.
    """
    findings = []
    for i, ins in enumerate(ins_range):
        if i > 0 and i % 32 == 0:
            card.select_piv()
        data, sw = card.transmit([cla, ins, p1, p2])
        if sw not in SKIP_SW:
            findings.append({
                "context": context,
                "cla":     f"{cla:02X}",
                "ins":     f"{ins:02X}",
                "p1":      f"{p1:02X}",
                "p2":      f"{p2:02X}",
                "sw":      sw,
                "data_len": len(data),
                "data_head": data[:8].hex() if data else "",
                "sw_label": SW_LABELS.get(sw, sw),
                "spec":    PIV_SPEC_INS.get(ins, "PROPRIETARY"),
            })
    return findings


def sweep_p1p2(card: CardConn, context: str, ins: int, cla: int = 0x00) -> list[dict]:
    """Re-sweep a specific INS across P1P2_EXTRAS to map its argument space."""
    findings = []
    for p1, p2 in P1P2_EXTRAS:
        data, sw = card.transmit([cla, ins, p1, p2])
        if sw not in SKIP_SW:
            findings.append({
                "context": context,
                "cla": f"{cla:02X}", "ins": f"{ins:02X}",
                "p1": f"{p1:02X}", "p2": f"{p2:02X}",
                "sw": sw, "data_len": len(data),
                "sw_label": SW_LABELS.get(sw, sw),
                "spec": PIV_SPEC_INS.get(ins, "PROPRIETARY"),
            })
    return findings


def sweep_length_probe(card: CardConn, ins: int, sw_on_empty: str) -> dict:
    """
    For commands that fail on empty (wrong_length / 6700), try lengths 1-255
    to find what the card accepts. Returns {length: sw}.
    """
    if sw_on_empty not in {"6700"}:
        return {}
    hits = {}
    for lc in [1, 2, 4, 8, 16, 32, 64, 128, 256]:
        data_bytes = [0xAA] * min(lc, 255)
        apdu = [0x00, ins, 0x00, 0x00, len(data_bytes)] + data_bytes
        _, sw = card.transmit(apdu)
        if sw != "6700":
            hits[lc] = sw
    return hits


# ──────────────────────────────────────────────────────────────────────────────
# Track 2: Semantic structural mapping
# ──────────────────────────────────────────────────────────────────────────────

def build_descriptor(f: dict) -> str:
    """
    Convert APDU finding to semantic descriptor for BERT encoding.
    Follows ablation's describe_function() pattern.
    """
    ins = f.get("ins", "??").upper()
    sw  = f.get("sw", "")
    lbl = f.get("sw_label", "")
    spec = f.get("spec", "PROPRIETARY")
    ctx  = f.get("context", "")
    dlen = f.get("data_len", 0)

    if sw == "9000":
        role = "executes and returns data" if dlen else "executes successfully"
    elif sw.startswith("61"):
        role = f"executes and queues {dlen} bytes response"
    elif sw == "6982":
        role = "gated by PIN or security authentication"
    elif sw == "6985":
        role = "conditionally available (lifecycle or state dependency)"
    elif sw == "6A80":
        role = "opcode accepted but command data format rejected"
    elif sw == "6A82":
        role = "references a file or object that requires prior SELECT"
    elif sw == "6A86":
        role = "opcode accepted but P1/P2 parameters rejected"
    elif sw == "6700":
        role = "opcode accepted but requires specific data length"
    elif sw == "6300":
        role = "validates a credential or counter value"
    else:
        role = f"responds with {sw}"

    return (
        f"CMD_{ins} | context:{ctx} | class:{'PIV_SPEC' if spec != 'PROPRIETARY' else 'PROPRIETARY'} | "
        f"role:{role} | sw:{sw}:{lbl} | data_len:{dlen}"
    )


def cluster_bert(findings: list[dict]) -> list[dict]:
    try:
        from sentence_transformers import SentenceTransformer
        import numpy as np
    except ImportError:
        print("  [sentence-transformers not available; skipping BERT cluster]")
        return findings

    descs  = [f["desc"] for f in findings]
    model  = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
    vecs   = model.encode(descs, normalize_embeddings=True)
    sim    = vecs @ vecs.T

    labels = [-1] * len(findings)
    cid    = 0
    for i in range(len(findings)):
        if labels[i] != -1:
            continue
        labels[i] = cid
        for j in range(i + 1, len(findings)):
            if labels[j] == -1 and sim[i, j] > 0.82:
                labels[j] = cid
        cid += 1

    for f, lbl in zip(findings, labels):
        f["cluster"] = lbl

    clusters: dict[int, list] = defaultdict(list)
    for f in findings:
        clusters[f["cluster"]].append(f)

    print(f"\n  BERT semantic clusters (cosine >0.82):")
    for c in sorted(clusters):
        members = clusters[c]
        # Name the cluster by majority role
        roles = [m["desc"].split("role:")[1].split("|")[0].strip() for m in members]
        top_role = max(set(roles), key=roles.count)[:50]
        print(f"\n  Cluster {c} -- {top_role} ({len(members)} commands)")
        for m in sorted(members, key=lambda x: (x.get("context",""), x.get("ins",""))):
            prop = " ** PROPRIETARY" if m.get("spec") == "PROPRIETARY" else ""
            print(f"    [{m.get('context','?'):15}] CLA={m.get('cla','??')} INS={m.get('ins','??')} "
                  f"P1={m.get('p1','??')} SW={m.get('sw','')}  {m.get('sw_label','')}{prop}")

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def run(quick: bool = False, save: Optional[str] = None, cluster: bool = True):
    print("=" * 72)
    print("CAC Structural RE -- Proprietary APDU Layer Sweep")
    print("  Track 1: Behavioral sweep (pyscard ~3ms/APDU)")
    print("  Track 2: BERT semantic clustering")
    print("=" * 72)

    card = wait_for_card()

    # ── [A] ATR ───────────────────────────────────────────────────────────────
    print("\n[A] ATR + Reader")
    atr = decode_atr(card)
    print(f"  Reader:   {atr.get('reader','?')}")
    print(f"  ATR:      {atr.get('raw','?')}")
    print(f"  Conv:     {atr.get('convention','?')}")
    print(f"  Hist hex: {atr.get('historical_hex','?')}")
    print(f"  Hist str: {atr.get('historical_ascii','?')}")

    all_findings: list[dict] = []

    # ── [B] PIV AID -- CLA=00 full INS sweep ─────────────────────────────────
    print("\n[B] PIV AID -- CLA=00 full INS sweep (256 commands)")
    sw_sel = card.select_piv()
    print(f"  SELECT PIV: SW={sw_sel}")
    t0 = time.perf_counter()
    piv_findings = sweep_ins(card, "PIV", cla=0x00)
    elapsed = time.perf_counter() - t0
    print(f"  Sweep done in {elapsed:.2f}s -- {len(piv_findings)} responding commands")
    for f in piv_findings:
        prop = "  ** PROPRIETARY" if f["spec"] == "PROPRIETARY" else ""
        print(f"  INS={f['ins']} SW={f['sw']:6}  {f['sw_label']:30s}  "
              f"{f['spec']}{prop}")
    all_findings.extend(piv_findings)

    # ── [C] PIV AID -- CLA=80 sweep (HID ActivID proprietary class) ──────────
    print("\n[C] PIV AID -- CLA=0x80 sweep (HID proprietary class byte)")
    card.select_piv()
    t0 = time.perf_counter()
    cla80 = sweep_ins(card, "PIV_CLA80", cla=0x80)
    elapsed = time.perf_counter() - t0
    print(f"  Sweep done in {elapsed:.2f}s -- {len(cla80)} responding commands")
    for f in cla80:
        print(f"  CLA=80 INS={f['ins']} SW={f['sw']:6}  {f['sw_label']}")
    all_findings.extend(cla80)

    # ── [D] P1/P2 sweep for proprietary commands ─────────────────────────────
    prop_ins = set(int(f["ins"], 16) for f in all_findings if f.get("spec") == "PROPRIETARY")
    if prop_ins:
        print(f"\n[D] Proprietary INS P1/P2 sweep ({len(prop_ins)} commands)")
        card.select_piv()
        for ins in sorted(prop_ins):
            sub = sweep_p1p2(card, "PIV_prop", ins)
            for s in sub:
                if s["sw"] not in {f["sw"] for f in all_findings
                                   if f.get("ins") == f"{ins:02X}"}:
                    print(f"  INS={s['ins']} P1={s['p1']} P2={s['p2']}  "
                          f"SW={s['sw']}  {s.get('sw_label','')}")
                    all_findings.append(s)
            # Length probe for 6700 responses
            for f in all_findings:
                if f.get("ins") == f"{ins:02X}" and f.get("sw") == "6700":
                    lhits = sweep_length_probe(card, ins, "6700")
                    if lhits:
                        print(f"  INS={ins:02X} length probe: {lhits}")

    # ── [E] Known AID enumeration ─────────────────────────────────────────────
    print("\n[E] AID enumeration + per-AID INS sweep")
    for name, aid_bytes in CANDIDATE_AIDS.items():
        sw = card.select_aid(aid_bytes)
        if sw in {"9000", "6100", "6139"}:
            print(f"  {name:20s}  {aid_bytes.hex()}  FOUND SW={sw}")
            if quick:
                continue
            # Quick INS sweep in this AID context
            sub = sweep_ins(card, name, cla=0x00)
            prop_sub = [x for x in sub if x.get("spec") == "PROPRIETARY"]
            if prop_sub:
                print(f"    -> {len(prop_sub)} proprietary commands")
                for p in prop_sub:
                    print(f"    INS={p['ins']} SW={p['sw']}  {p.get('sw_label','')}")
            all_findings.extend(sub)
            # Restore PIV context
            card.select_piv()
        else:
            print(f"  {name:20s}  {aid_bytes.hex()}  SW={sw}")

    # ── [F] Track 2: Semantic structural mapping ──────────────────────────────
    print(f"\n[F] Track 2: Semantic structural mapping ({len(all_findings)} findings)")
    for f in all_findings:
        f["desc"] = build_descriptor(f)

    # Summary table of proprietary commands
    prop_all = [f for f in all_findings if f.get("spec") == "PROPRIETARY"]
    print(f"\n  Proprietary commands (delta from PIV spec): {len(prop_all)}")
    if prop_all:
        print(f"  {'CTX':15} {'CLA':3} {'INS':3} {'P1':3} {'P2':3} {'SW':6}  Role")
        print(f"  {'-'*15} {'-'*3} {'-'*3} {'-'*3} {'-'*3} {'-'*6}  {'-'*40}")
        for f in sorted(prop_all, key=lambda x: (x.get("context",""), x.get("ins",""))):
            role = f["desc"].split("role:")[1].split("|")[0].strip()[:40]
            print(f"  {f.get('context','?'):15} {f.get('cla','??'):3} "
                  f"{f.get('ins','??'):3} {f.get('p1','00'):3} {f.get('p2','00'):3} "
                  f"{f.get('sw',''):6}  {role}")

    # BERT cluster
    if cluster and all_findings:
        cluster_bert(all_findings)

    # ── Save ──────────────────────────────────────────────────────────────────
    if save:
        Path(save).write_text(json.dumps({"atr": atr, "findings": all_findings}, indent=2))
        print(f"\n  Saved -> {save}")

    card.disconnect()
    print("\n" + "=" * 72)
    print("Structural sweep complete.")
    print("=" * 72)
    return all_findings


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="CAC proprietary APDU structural RE")
    ap.add_argument("--quick",      action="store_true",
                    help="skip per-AID INS sweeps, just enumerate AIDs")
    ap.add_argument("--save",       type=str, default=None)
    ap.add_argument("--no-cluster", dest="cluster", action="store_false")
    args = ap.parse_args()
    run(quick=args.quick, save=args.save, cluster=args.cluster)
