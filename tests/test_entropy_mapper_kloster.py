"""Unit and parity tests for Bridge 1B: Theorem 13 -> Ablation EntropyMapper."""

from __future__ import annotations

import builtins
import random
from pathlib import Path

import pytest

import ablation.analyzers.entropy_mapper as em


def _write_bytes(tmp_path: Path, name: str, payload: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(payload)
    return path


def _uniform_cipher_bytes(length: int, seed: int = 20260113) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(length))


def _structured_code_bytes(length: int, seed: int = 1) -> bytes:
    # Realistic x86-64 opcode/operand distribution yielding H in [4.7, 6.2] (CODE regime)
    rng = random.Random(seed)
    opcodes = (
        list(range(0x00, 0x10))
        + [0x20, 0x24, 0x28, 0x31, 0x38, 0x41, 0x45, 0x48, 0x4C, 0x53, 0x54, 0x55, 0x5D]
        + [0x74, 0x75, 0x76, 0x7D, 0x7F, 0x83, 0x84, 0x85, 0x89, 0x8B, 0x8D, 0x90]
        + [0xC0, 0xC3, 0xC7, 0xC9, 0xD0, 0xE0, 0xE5, 0xE8, 0xEB, 0xEC, 0xF0, 0xFC, 0xFE, 0xFF]
    )
    weights = [8] * 4 + [5] * 12 + [3] * (len(opcodes) - 16)
    return bytes(rng.choices(opcodes, weights=weights, k=length))


def test_standalone_fallback_matches_guiai_when_available(monkeypatch) -> None:
    """Pure-Python Theorem 13 fallback matches guiai.gem.kloster_stopping_law and works standalone."""
    counts = [12, 0, 3, 1, 0, 0, 18, 2] + [0] * 248
    py_stats = em._kloster_unbiased_chi2_stats_py(counts)
    assert py_stats["samples"] == 36
    assert py_stats["z_kloster"] > 5.0

    probs = [c / 36.0 for c in counts]
    py_smin = em._predict_kloster_min_samples_py(probs, z_threshold=4.0)
    assert 2 <= py_smin < 50

    py_ctrl = em._FallbackKlosterStoppingController(n_bins=256, delta=0.005, max_samples=256)
    indices = [idx for idx, cnt in enumerate(counts) for _ in range(cnt)]
    py_verdict = py_ctrl.observe_batch(indices)
    assert py_verdict["action"] == "DECIDE_SIGNAL"

    if em._HAS_GUIAI_KLOSTER:
        gem_stats = em._gem_unbiased_chi2_stats(counts)
        for key in ("n_bins", "samples", "m2_plugin", "m2_unbiased", "excess_chi2", "null_sd", "z_kloster", "m4_root"):
            assert abs(py_stats[key] - gem_stats[key]) <= 1e-6
        assert py_smin == em._gem_predict_min_samples(probs, z_threshold=4.0)
        gem_ctrl = em._GemStoppingController(n_bins=256, delta=0.005, max_samples=256)
        gem_verdict = gem_ctrl.observe_batch(indices)
        assert gem_verdict["action"] == py_verdict["action"]
        assert abs(gem_verdict["z_kloster"] - py_verdict["z_kloster"]) <= 1e-6

    # Verify standalone behavior even when guiai imports are explicitly blocked
    real_import = builtins.__import__

    def _block_guiai(name, *args, **kwargs):
        if name == "guiai" or name.startswith("guiai."):
            raise ImportError("blocked guiai for standalone test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _block_guiai)
    monkeypatch.setattr(em, "_HAS_GUIAI_KLOSTER", False)
    monkeypatch.setattr(em, "kloster_unbiased_chi2_stats", em._kloster_unbiased_chi2_stats_py)
    monkeypatch.setattr(em, "predict_kloster_min_samples", em._predict_kloster_min_samples_py)
    monkeypatch.setattr(em, "KlosterSequentialStoppingController", em._FallbackKlosterStoppingController)
    assert em.kloster_unbiased_chi2_stats(counts)["z_kloster"] == py_stats["z_kloster"]


@pytest.mark.parametrize("slice_size", [64, 128, 256])
def test_small_slice_encrypted_vs_code_and_padding(tmp_path: Path, slice_size: int) -> None:
    """Theorem 13 eliminates finite-sample Shannon downward bias on <512 B encrypted slices."""
    enc_path = _write_bytes(tmp_path, f"enc_{slice_size}.bin", _uniform_cipher_bytes(slice_size, seed=20260115))
    enc_res = em.EntropyMapper(str(enc_path), window_size=slice_size).run()
    assert len(enc_res.windows) == 1
    win_enc = enc_res.windows[0]
    assert win_enc.entropy < 7.35  # finite-sample Shannon is biased below ~8.0 on <512 B!
    assert win_enc.cls == "ENCRYPTED"
    assert win_enc.excess_chi2 < 0.5
    assert win_enc.z_kloster < enc_res.kloster_stopping_summary["z_threshold_single"]

    # Also prove that disabling Theorem 13 (use_kloster=False) misclassifies 64B/128B cipher as CODE
    if slice_size <= 128:
        naive_res = em.EntropyMapper(str(enc_path), window_size=slice_size, use_kloster=False).run()
        assert naive_res.windows[0].entropy < 7.2
        assert naive_res.windows[0].cls == "CODE"

    code_path = _write_bytes(tmp_path, f"code_{slice_size}.bin", _structured_code_bytes(slice_size))
    code_res = em.EntropyMapper(str(code_path), window_size=slice_size).run()
    win_code = code_res.windows[0]
    assert win_code.cls == "CODE"
    assert win_code.z_kloster >= code_res.kloster_stopping_summary["z_threshold_single"]
    assert win_code.kloster_action == "DECIDE_SIGNAL"

    pad_path = _write_bytes(tmp_path, f"pad_{slice_size}.bin", b"\x00" * slice_size)
    pad_res = em.EntropyMapper(str(pad_path), window_size=slice_size).run()
    assert pad_res.windows[0].cls == "PADDING"


def test_mixed_firmware_binary_isolates_small_encrypted_island(tmp_path: Path) -> None:
    """Mixed firmware [PADDING 512B | CODE 512B | ENCRYPTED 256B | SPARSE 256B] finds encrypted island."""
    padding = b"\x00" * 512
    code = _structured_code_bytes(512)
    encrypted = _uniform_cipher_bytes(256, seed=9911)
    sparse = (b"BOOT_HEADER_OK::ZOE_AB_IMAGE_V1\n" * 8)[:256]
    fw = _write_bytes(tmp_path, "mixed_fw.bin", padding + code + encrypted + sparse)

    res = em.EntropyMapper(str(fw), window_size=128).run()
    enc_ranges = res.encrypted_ranges()
    assert enc_ranges == [(1024, 1280)]
    assert len(res.code_ranges()) >= 1
    assert res.kloster_stopping_summary["reclassified_encrypted_windows"] == 2


def test_scan_kloster_stopping_abstains_on_encrypted_and_stops_on_code(tmp_path: Path) -> None:
    """Streaming sequential stopping abstains on uniform cipher bytes and stops early on code."""
    enc_path = _write_bytes(tmp_path, "stream_enc.bin", _uniform_cipher_bytes(1024, seed=4242))
    code_path = _write_bytes(tmp_path, "stream_code.bin", _structured_code_bytes(1024))

    enc_verdict = em.EntropyMapper(str(enc_path)).scan_kloster_stopping(max_samples=512, chunk_size=64)
    code_verdict = em.EntropyMapper(str(code_path)).scan_kloster_stopping(max_samples=512, chunk_size=64)

    assert enc_verdict["action"] == "ABSTAIN_INSUFFICIENT_EVIDENCE"
    assert enc_verdict["samples"] == 512
    assert code_verdict["action"] == "DECIDE_SIGNAL"
    assert code_verdict["budget_fraction_used"] < 0.5


def test_real_binary_regression_safety_no_encrypted_false_positives() -> None:
    """Real /bin/true preserves regions, summary format, and zero false ENCRYPTED windows."""
    res = em.EntropyMapper("/bin/true").run()
    assert len(res.regions) > 0
    assert res.kloster_stopping_summary["reclassified_encrypted_windows"] == 0
    assert "EntropyMapper: /bin/true" in res.summary()
    assert "H=" in res.summary()


@pytest.mark.parametrize("n_bytes", [1, 8, 11, 64, 256])
def test_scan_kloster_stopping_abstains_at_eof_below_max_samples(tmp_path: Path, n_bytes: int) -> None:
    """EOF reached below max_samples without DECIDE_SIGNAL transitions GATHER_MORE -> ABSTAIN."""
    p = _write_bytes(tmp_path, f"eof_{n_bytes}.bin", _uniform_cipher_bytes(n_bytes, seed=2026 + n_bytes))
    verdict = em.EntropyMapper(str(p)).scan_kloster_stopping(max_samples=512, chunk_size=64)
    assert verdict["samples"] == n_bytes
    assert verdict["action"] == "ABSTAIN_INSUFFICIENT_EVIDENCE"
    assert verdict.get("eof_reached") is True
