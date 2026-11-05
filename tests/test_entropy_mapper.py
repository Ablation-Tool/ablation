from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np
import pytest

from ablation.analyzers.entropy_mapper import (
    EntropyMapper,
    EntropyRegion,
    _entropy_numpy,
    _entropy_of,
)
from ablation.cli import cmd_analyze


def _reference_entropy(data, window, step):
    arr = np.frombuffer(data, dtype=np.uint8)
    for offset in range(0, len(arr) - window + 1, step):
        chunk = arr[offset:offset + window]
        counts = np.bincount(chunk, minlength=256).astype(np.float64)
        probabilities = counts[counts > 0] / counts.sum()
        yield offset, float(-np.sum(probabilities * np.log2(probabilities)))


def test_batched_entropy_matches_original_algorithm():
    rng = np.random.default_rng(7)
    data = (
        rng.bytes(4096)
        + bytes(1024)
        + bytes(range(256)) * 9
        + b"trailing bytes"
    )
    for window, step in ((1, 1), (3, 2), (64, 32), (256, 256), (256, 64), (1024, 333)):
        expected = list(_reference_entropy(data, window, step))
        actual = list(_entropy_numpy(data, window, step))
        assert [offset for offset, _ in expected] == [offset for offset, _ in actual]
        assert [entropy for _, entropy in actual] == pytest.approx(
            [entropy for _, entropy in expected], abs=1e-12
        )


def test_known_entropy_empty_short_and_fallback_cases():
    assert list(_entropy_numpy(b"", 256, 256)) == []
    assert list(_entropy_numpy(b"abc", 256, 256)) == []
    assert list(_entropy_numpy(bytes(256), 256, 256)) == [(0, 0.0)]
    assert list(_entropy_numpy(bytes(range(256)), 256, 256)) == [(0, 8.0)]
    assert list(_entropy_numpy(bytes(range(256)) + b"tail", 256, 256)) == [(0, 8.0)]
    with patch.dict(sys.modules, {"numpy": None}):
        assert list(_entropy_numpy(b"abc", 2, 1)) == [
            (0, _entropy_of(b"ab")),
            (1, _entropy_of(b"bc")),
        ]


@pytest.mark.parametrize("window, step", [(0, 1), (-1, 1), (True, 1), (1.5, 1), (1, 0), (1, -1), (1, False), (1, 1.5)])
def test_invalid_window_and_step_are_rejected(window, step):
    with pytest.raises(ValueError):
        list(_entropy_numpy(b"data", window, step))


def test_entropy_result_and_regions(tmp_path):
    path = tmp_path / "fixture.bin"
    path.write_bytes(bytes(256) + bytes(range(256)))
    result = EntropyMapper(str(path)).run()
    assert result.file_size == 512
    assert len(result.windows) == 2
    assert result.windows[0].entropy == 0
    assert result.windows[1].entropy == 8
    assert [(region.offset_start, region.offset_end) for region in result.regions] == [(0, 256), (256, 512)]


def test_analyze_entropy_uses_public_run_api(tmp_path, capsys):
    path = tmp_path / "fixture.bin"
    path.write_bytes(b"data")
    context = SimpleNamespace(summary=lambda: "synthetic context", arch="")
    region = EntropyRegion(0, 4, "PADDING", 0.0, 0.0, 0.0)
    with (
        patch("ablation.analyzers.binary_context.BinaryContext.load_or_build", return_value=context),
        patch("ablation.analyzers.entropy_mapper.EntropyMapper") as mapper,
    ):
        mapper.return_value.run.return_value = SimpleNamespace(regions=[region])
        cmd_analyze(SimpleNamespace(binary=str(path), entropy=True))
    mapper.return_value.run.assert_called_once_with()
    output = capsys.readouterr().out
    assert "Entropy regions (1 found)" in output
    assert "0x00000000 - 0x00000004" in output
