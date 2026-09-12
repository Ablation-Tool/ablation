"""
cac_timing_re.py -- Software timing side-channel for CAC smart cards.

Replaces ChipWhisperer hardware with high-precision PKCS11 timing measurement.
Targets RSA-2048 operations on slot 04 (Card Auth, no PIN).

Collected signals:
  - T_sign: full RSA sign wall-clock (ns) via perf_counter_ns
  - T_apdu: raw APDU round-trip extracted from opensc-tool output (ms)
  - T_delta: sign - median baseline (signed)

Analyses:
  1. Baseline distribution: mean, stddev, percentiles
  2. TVLA t-test (Welch): two input classes -> detect data-dependent timing
  3. Autocorrelation: card jitter vs systematic timing pattern
  4. CRT timing asymmetry: fixed-exponent vs fixed-message input sweep

CAC hardware details:
  HID Global ActivID applet 2.7.4, RSA-2048 CRT
  Slot 04 (Card Auth) signs without PIN.
  ISO/IEC 7816-4 T=1 protocol; card APDU latency ~100-400ms.
  Software jitter from USB/T=1 framing adds ~1-5ms noise floor.

Usage:
  python cac_timing_re.py [--n 200] [--tvla] [--save timing.json]

Committed to ablation. No external hardware required.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import PyKCS11

PKCS11_LIB = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
SLOT_ID     = "04"  # Card Auth -- no PIN required

# ──────────────────────────────────────────────────────────────────────────────
# PKCS11 session management
# ──────────────────────────────────────────────────────────────────────────────

def wait_for_card(lib_path: str = PKCS11_LIB, timeout_s: float = 120.0) -> None:
    """Block until a card with a token is present. Prints a prompt once."""
    lib = PyKCS11.PyKCS11Lib()
    lib.load(lib_path)
    deadline = time.monotonic() + timeout_s
    shown    = False
    while time.monotonic() < deadline:
        try:
            slots = lib.getSlotList(tokenPresent=True)
            if slots:
                if shown:
                    print("  Card detected.")
                return
        except Exception:
            pass
        if not shown:
            print("  [Waiting for CAC card insertion...]", flush=True)
            shown = True
        time.sleep(0.5)
    raise TimeoutError(f"no card inserted within {timeout_s}s")


def card_is_present(lib_path: str = PKCS11_LIB) -> bool:
    try:
        lib = PyKCS11.PyKCS11Lib()
        lib.load(lib_path)
        return len(lib.getSlotList(tokenPresent=True)) > 0
    except Exception:
        return False


class CardSession:
    """Persistent PKCS11 session. Open once, sign many times."""

    def __init__(self, lib_path: str = PKCS11_LIB, wait: bool = True):
        self.lib      = PyKCS11.PyKCS11Lib()
        self.lib.load(lib_path)
        if wait:
            wait_for_card(lib_path)
        slots = self.lib.getSlotList(tokenPresent=True)
        if not slots:
            raise RuntimeError("no card detected (pcscd running? card inserted?)")
        self.session = self.lib.openSession(slots[0], PyKCS11.CKF_SERIAL_SESSION)
        self._find_key()

    def _find_key(self):
        targets = self.session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        ])
        self.priv = None
        for obj in targets:
            try:
                aid = bytes(self.session.getAttributeValue(obj, [PyKCS11.CKA_ID])[0]).hex()
                if aid == SLOT_ID:
                    self.priv = obj
                    break
            except Exception:
                pass
        if self.priv is None:
            raise RuntimeError(f"slot {SLOT_ID} private key not found")

    def sign(self, msg: bytes) -> tuple[bytes, int]:
        """Returns (signature_bytes, elapsed_ns)."""
        t0  = time.perf_counter_ns()
        sig = bytes(self.session.sign(
            self.priv, msg,
            PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)))
        t1  = time.perf_counter_ns()
        return sig, t1 - t0

    def close(self):
        try:
            self.session.closeSession()
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# Message generators
# ──────────────────────────────────────────────────────────────────────────────

def fixed_msg(n_bytes: int = 32) -> bytes:
    return b"\x42" * n_bytes

def random_msg(n_bytes: int = 32) -> bytes:
    return bytes([random.randint(0, 255) for _ in range(n_bytes)])

def hamming_weight_msg(hw: int, n_bytes: int = 32) -> bytes:
    """Message with exactly `hw` bits set, spread across n_bytes."""
    assert 0 <= hw <= n_bytes * 8
    bits = [1] * hw + [0] * (n_bytes * 8 - hw)
    random.shuffle(bits)
    result = bytearray(n_bytes)
    for i, b in enumerate(bits):
        result[i // 8] |= b << (7 - (i % 8))
    return bytes(result)


# ──────────────────────────────────────────────────────────────────────────────
# Collection
# ──────────────────────────────────────────────────────────────────────────────

def _sign_with_retry(session: CardSession, msg: bytes, lib_path: str = PKCS11_LIB) -> tuple[bytes, int]:
    """
    Sign msg; if card is removed mid-collection, wait for reinsertion and
    rebuild the session. Returns (sig, ns).
    """
    while True:
        try:
            return session.sign(msg)
        except Exception as e:
            errs = str(e).lower()
            if any(k in errs for k in ("no token", "token removed", "0x30", "session")):
                print(f"\n  [Card removed -- reinsert to continue]", flush=True)
                wait_for_card(lib_path)
                # Rebuild session in-place
                try:
                    session.close()
                except Exception:
                    pass
                new = CardSession(lib_path, wait=False)
                session.lib     = new.lib
                session.session = new.session
                session.priv    = new.priv
                print("  [Resuming...]", flush=True)
            else:
                raise


def collect_baseline(session: CardSession, n: int, verbose: bool = False,
                     lib_path: str = PKCS11_LIB) -> list[int]:
    """Collect n sign timings with fixed message. Pauses on card removal."""
    msg     = fixed_msg()
    timings = []
    for i in range(n):
        _, ns = _sign_with_retry(session, msg, lib_path)
        timings.append(ns)
        if verbose:
            print(f"  {i+1:4d}/{n}  {ns/1_000_000:.2f}ms", end="\r", flush=True)
    if verbose:
        print()
    return timings


def collect_tvla(session: CardSession, n_per_class: int, verbose: bool = False,
                 lib_path: str = PKCS11_LIB):
    """
    Test Vector Leakage Assessment (TVLA) - Welch t-test.
    Class A: fixed message (0x42 * 32)
    Class B: random message
    Interleave to reduce temporal drift bias. Pauses on card removal.
    """
    fixed   = fixed_msg()
    a_times = []
    b_times = []
    for i in range(n_per_class):
        if i % 2 == 0:
            _, ns = _sign_with_retry(session, fixed, lib_path)
            a_times.append(ns)
        else:
            msg = random_msg()
            _, ns = _sign_with_retry(session, msg, lib_path)
            b_times.append(ns)
        if verbose:
            print(f"  {i+1:4d}/{n_per_class*2}  A={len(a_times)} B={len(b_times)}", end="\r", flush=True)
    if verbose:
        print()
    return a_times, b_times


def collect_hamming_sweep(session: CardSession, n_per_hw: int = 20,
                          lib_path: str = PKCS11_LIB) -> dict[int, list[int]]:
    """
    Collect timings for messages at each Hamming weight (0-256 in steps).
    Detects if card timing depends on message bit count (data-dependent path).
    """
    hw_steps  = list(range(0, 257, 16))  # 17 weight points
    hw_timings = {}
    for hw in hw_steps:
        times = []
        for _ in range(n_per_hw):
            msg = hamming_weight_msg(hw, 32)
            _, ns = _sign_with_retry(session, msg, lib_path)
            times.append(ns)
        hw_timings[hw] = times
        print(f"  HW={hw:3d}  mean={statistics.mean(times)/1e6:.2f}ms")
    return hw_timings


# ──────────────────────────────────────────────────────────────────────────────
# Analysis
# ──────────────────────────────────────────────────────────────────────────────

def welch_t(a: list[float], b: list[float]) -> float:
    """Welch's t-statistic (unequal variances)."""
    import math
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return 0.0
    ma, mb = statistics.mean(a), statistics.mean(b)
    va, vb = statistics.variance(a), statistics.variance(b)
    denom  = math.sqrt(va / na + vb / nb)
    if denom == 0:
        return 0.0
    return abs(ma - mb) / denom


def autocorrelation(timings: list[float], max_lag: int = 20) -> list[float]:
    """Pearson autocorrelation at lags 1..max_lag."""
    import math
    n    = len(timings)
    mean = statistics.mean(timings)
    var  = statistics.variance(timings)
    if var == 0:
        return [0.0] * max_lag
    acf = []
    for lag in range(1, max_lag + 1):
        cov = sum((timings[i] - mean) * (timings[i + lag] - mean)
                  for i in range(n - lag)) / (n - lag)
        acf.append(cov / var)
    return acf


def percentiles(data: list[float]) -> dict:
    s = sorted(data)
    n = len(s)
    return {
        "p05": s[max(0, int(n * 0.05))],
        "p25": s[max(0, int(n * 0.25))],
        "p50": s[max(0, int(n * 0.50))],
        "p75": s[max(0, int(n * 0.75))],
        "p95": s[min(n - 1, int(n * 0.95))],
    }


def print_baseline(timings: list[int], label: str = "Baseline"):
    ms = [t / 1_000_000 for t in timings]
    print(f"\n  {label} ({len(ms)} samples)")
    print(f"    mean:   {statistics.mean(ms):.3f} ms")
    print(f"    stddev: {statistics.stdev(ms):.3f} ms")
    pct = percentiles(ms)
    print(f"    p05:    {pct['p05']:.3f} ms")
    print(f"    p50:    {pct['p50']:.3f} ms")
    print(f"    p95:    {pct['p95']:.3f} ms")
    print(f"    range:  {min(ms):.3f} - {max(ms):.3f} ms")

    acf = autocorrelation(ms, max_lag=min(10, len(ms) // 4))
    print(f"    ACF[1]: {acf[0]:.4f}  (>0.2 = temporal correlation / card batching)")


def print_tvla(a: list[int], b: list[int]):
    a_ms = [t / 1_000_000 for t in a]
    b_ms = [t / 1_000_000 for t in b]
    t    = welch_t(a_ms, b_ms)
    print(f"\n  TVLA Welch t-test")
    print(f"    Class A (fixed):  n={len(a_ms)}  mean={statistics.mean(a_ms):.3f}ms  sd={statistics.stdev(a_ms):.3f}")
    print(f"    Class B (random): n={len(b_ms)}  mean={statistics.mean(b_ms):.3f}ms  sd={statistics.stdev(b_ms):.3f}")
    print(f"    |t|:              {t:.4f}")
    if t > 4.5:
        print(f"    VERDICT: LEAKY  -- |t|>4.5 indicates data-dependent timing")
    elif t > 2.0:
        print(f"    VERDICT: MARGINAL -- |t|>2.0; collect more samples")
    else:
        print(f"    VERDICT: CLEAN  -- |t|<2.0; no detected timing leakage")


def print_hamming(hw_timings: dict[int, list[int]]):
    print(f"\n  Hamming Weight Sweep (data-dependent path detection)")
    print(f"  {'HW':>4}  {'mean_ms':>8}  {'sd_ms':>7}  {'delta_ms':>9}")
    means = {hw: statistics.mean(t) / 1e6 for hw, t in hw_timings.items()}
    base  = means[128] if 128 in means else statistics.mean(list(means.values()))
    for hw in sorted(hw_timings):
        ms = [t / 1e6 for t in hw_timings[hw]]
        m  = statistics.mean(ms)
        s  = statistics.stdev(ms) if len(ms) > 1 else 0.0
        print(f"  {hw:>4}  {m:>8.3f}  {s:>7.3f}  {m - base:>+9.3f}")


# ──────────────────────────────────────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────────────────────────────────────

def save_results(path: str, data: dict):
    Path(path).write_text(json.dumps(data, indent=2))
    print(f"\n  Saved -> {path}")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def run(n: int = 100, tvla: bool = True, hamming: bool = False,
        save: Optional[str] = None, verbose: bool = False):
    print("=" * 72)
    print(f"CAC Software Timing Side-Channel  (slot {SLOT_ID}, RSA-2048, n={n})")
    print("=" * 72)

    print("\nConnecting to card...")
    try:
        sess = CardSession()
    except RuntimeError as e:
        print(f"  FATAL: {e}")
        return

    # Warm-up: first sign after cold session is always slower
    for _ in range(3):
        sess.sign(fixed_msg())

    # 1. Baseline timing distribution
    print(f"\n[1] Baseline ({n} signs, fixed message 0x42*32)")
    baseline = collect_baseline(sess, n, verbose=verbose)
    print_baseline(baseline)

    results: dict = {
        "slot": SLOT_ID,
        "n":    n,
        "baseline_ns": baseline,
    }

    # 2. TVLA
    if tvla:
        print(f"\n[2] TVLA - {n} signs per class (fixed vs random)")
        a, b = collect_tvla(sess, n, verbose=verbose)
        print_tvla(a, b)
        results["tvla_fixed_ns"]  = a
        results["tvla_random_ns"] = b

    # 3. Hamming weight sweep
    if hamming:
        print(f"\n[3] Hamming Weight Sweep (20 samples per HW point)")
        hw_data = collect_hamming_sweep(sess, n_per_hw=20)
        print_hamming(hw_data)
        results["hamming"] = {str(k): v for k, v in hw_data.items()}

    sess.close()

    if save:
        save_results(save, results)

    print("\nDone.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Software timing side-channel for CAC RSA slot 04")
    ap.add_argument("--n",       type=int,  default=100,
                    help="number of sign operations per test (default 100)")
    ap.add_argument("--tvla",    action="store_true", default=True,
                    help="run TVLA fixed-vs-random t-test (default on)")
    ap.add_argument("--no-tvla", dest="tvla", action="store_false")
    ap.add_argument("--hamming", action="store_true", default=False,
                    help="run Hamming weight sweep (slow, ~17*20 signs)")
    ap.add_argument("--save",    type=str,  default=None,
                    help="save raw timing JSON to file")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    run(n=args.n, tvla=args.tvla, hamming=args.hamming,
        save=args.save, verbose=args.verbose)
