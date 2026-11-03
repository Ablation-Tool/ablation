from types import SimpleNamespace

import pytest

from ablation.analyzers import dynamic_sandbox
from ablation.analyzers.dynamic_sandbox import DynamicSandbox, LeafFunctionChecker


class FakeXref:
    def __init__(self, callees=(), error=None):
        self._built = True
        self._callees = callees
        self._error = error

    def callees_of(self, _va):
        if self._error:
            raise self._error
        return self._callees


class FakeUC:
    def __init__(self):
        self.memory = {}
        self.maps = []
        self.restored = False

    def mem_map(self, start, size, permissions):
        self.maps.append((start, size, permissions))

    def mem_write(self, address, data):
        self.memory[address] = bytes(data)

    def mem_read(self, address, size):
        return self.memory[address][:size]

    def context_restore(self, _snapshot):
        self.restored = True


def test_leaf_check_denies_missing_context_and_verification_errors():
    checker = LeafFunctionChecker(callees_map={}, plt_range=None)
    assert not checker.is_leaf(0x1000)

    failing = LeafFunctionChecker.from_xref_graph(FakeXref(error=RuntimeError("broken")))
    assert not failing.is_leaf(0x1000)


def test_leaf_check_denies_external_or_unclassified_callees():
    external = LeafFunctionChecker.from_xref_graph(FakeXref([0x2000]), (0x2000, 0x3000))
    assert not external.is_leaf(0x1000)

    unknown = LeafFunctionChecker.from_xref_graph(FakeXref([0x4000]), None)
    assert not unknown.is_leaf(0x1000)

    leaf = LeafFunctionChecker.from_xref_graph(FakeXref([]), None)
    assert leaf.is_leaf(0x1000)


def test_overlapping_segments_are_mapped_once_and_all_bytes_written(monkeypatch):
    monkeypatch.setattr(dynamic_sandbox, "unicorn", SimpleNamespace(UC_PROT_ALL=7), raising=False)
    sandbox = DynamicSandbox.__new__(DynamicSandbox)
    sandbox._uc = FakeUC()
    sandbox._segments = [(0x1003, b"abc"), (0x1800, b"def")]

    sandbox._map_segments()

    assert sandbox._uc.maps == [(0x1000, 0x1000, 7)]
    assert sandbox._uc.memory == {0x1003: b"abc", 0x1800: b"def"}


def test_restore_covers_every_segment():
    sandbox = DynamicSandbox.__new__(DynamicSandbox)
    sandbox._uc = FakeUC()
    sandbox._segments = [(0x1000, b"abc"), (0x2000, b"def")]
    sandbox._uc.mem_write(0x1000, b"abc")
    sandbox._uc.mem_write(0x2000, b"def")
    sandbox._snap = object()
    sandbox._mem_snap = sandbox._read_all_mapped()
    sandbox._uc.mem_write(0x1000, b"xxx")
    sandbox._uc.mem_write(0x2000, b"yyy")

    sandbox._restore()

    assert sandbox._uc.restored
    assert sandbox._uc.memory == {0x1000: b"abc", 0x2000: b"def"}


def test_uncleared_function_never_reaches_restore_or_execution():
    sandbox = DynamicSandbox.__new__(DynamicSandbox)
    sandbox._leaf_checker = LeafFunctionChecker(callees_map={}, plt_range=None)
    sandbox._uc = FakeUC()
    sandbox._segments = []
    sandbox._mem_snap = {}
    sandbox._snap = object()

    with pytest.raises(ValueError, match="not cleared"):
        sandbox.run_function(0x1000)

    assert not sandbox._uc.restored
