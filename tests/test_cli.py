from pathlib import Path
from types import SimpleNamespace

import pytest

import ablation.cli as cli
from ablation.analyzers.binary_context import BinaryContext, _detect_arch
from ablation.analyzers.taint_tracker_arm32 import ARM32TaintTracker
from ablation.analyzers.taint_tracker_arm64 import ARM64TaintTracker
from ablation.analyzers.taint_tracker_x86 import TaintTracker
from ablation.analyzers.taint_tracker_x86_32 import X86_32TaintTracker
from ablation.analyzers.xref_graph import XRefGraph


def _args(**overrides):
    values = {
        'binary': '/fake',
        'interprocedural': False,
        'flow_sensitive': False,
        'depth': 4,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _context(monkeypatch, arch):
    monkeypatch.setattr(cli, '_require_binary', lambda path: Path(path))
    monkeypatch.setattr(
        BinaryContext, 'load_or_build', lambda path: SimpleNamespace(arch=arch)
    )


@pytest.mark.parametrize('arch,handler', [
    ('mips32', 'cmd_mips'),
    ('mips64', 'cmd_mips64'),
    ('ppc32', 'cmd_ppc32'),
    ('ppc64', 'cmd_ppc64'),
    ('riscv32', 'cmd_riscv32'),
    ('riscv64', 'cmd_riscv64'),
    ('loongarch64', 'cmd_loongarch64'),
    ('arc', 'cmd_arc'),
])
def test_taint_delegates_to_architecture_handler(monkeypatch, arch, handler):
    _context(monkeypatch, arch)
    monkeypatch.setattr(cli, '_elf_endian', lambda path: 'big')
    called = {}

    def fake_handler(args):
        called['args'] = args

    monkeypatch.setattr(cli, handler, fake_handler)
    args = _args()
    cli.cmd_taint(args)

    assert called['args'] is args
    assert args.le is False
    assert args.be is True
    assert args.json is None
    assert args.full is False


def test_taint_arm64_uses_arm64_tracker(monkeypatch):
    _context(monkeypatch, 'arm64')
    called = {}

    class Tracker:
        def run(self):
            called['run'] = True
            return []

    monkeypatch.setattr(ARM64TaintTracker, 'from_context', lambda ctx: Tracker())
    cli.cmd_taint(_args())
    assert called == {'run': True}


def test_taint_arm64_interprocedural_depth(monkeypatch):
    _context(monkeypatch, 'arm64')
    called = {}

    class Tracker:
        def run_interprocedural(self, depth=4):
            called['depth'] = depth
            return []

    monkeypatch.setattr(ARM64TaintTracker, 'from_context', lambda ctx: Tracker())
    cli.cmd_taint(_args(interprocedural=True, depth=7))
    assert called == {'depth': 7}


def test_taint_x86_32_uses_32_bit_tracker(monkeypatch):
    _context(monkeypatch, 'x86_32')

    class Tracker:
        def run_interprocedural(self):
            return []

    monkeypatch.setattr(X86_32TaintTracker, 'from_path', lambda path: Tracker())
    cli.cmd_taint(_args())


def test_taint_arm32_uses_arm32_tracker(monkeypatch):
    _context(monkeypatch, 'arm32')

    class Tracker:
        def run_interprocedural(self):
            return []

    monkeypatch.setattr(ARM32TaintTracker, 'from_context', lambda ctx: Tracker())
    cli.cmd_taint(_args())


def test_taint_x86_64_keeps_xref_workflow(monkeypatch):
    _context(monkeypatch, 'x86_64')

    class Xref:
        _plt = {}

        def build(self):
            return self

    monkeypatch.setattr(XRefGraph, 'from_path', lambda path: Xref())
    monkeypatch.setattr(TaintTracker, 'run', lambda self: [])
    cli.cmd_taint(_args(binary='/usr/bin/ls'))


def test_taint_rejects_flow_sensitive_on_non_x86(monkeypatch):
    _context(monkeypatch, 'arm64')
    with pytest.raises(SystemExit, match='only for x86-64'):
        cli.cmd_taint(_args(flow_sensitive=True))


def test_taint_rejects_unknown_architecture(monkeypatch):
    _context(monkeypatch, 'unknown')
    with pytest.raises(SystemExit, match='not supported'):
        cli.cmd_taint(_args())


def test_elf_endian_reads_elf_identity(tmp_path):
    path = tmp_path / 'target.elf'
    path.write_bytes(b'\x7fELF\x02\x02')
    assert cli._elf_endian(str(path)) == 'big'
    path.write_bytes(b'\x7fELF\x01\x01')
    assert cli._elf_endian(str(path)) == 'little'
    path.write_bytes(b'not an elf')
    assert cli._elf_endian(str(path), default='big') == 'big'


def test_detect_arch_returns_unknown_for_invalid_object():
    assert _detect_arch(object()) == 'unknown'
