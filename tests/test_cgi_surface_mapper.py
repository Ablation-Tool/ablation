"""Tests for CGISurfaceMapper."""

import textwrap
from pathlib import Path

import pytest

from ablation.analyzers.cgi_surface_mapper import CGISurfaceMapper, CGIHandler, CGISurface


# ---------------------------------------------------------------------------
# Fixture: fake rootfs
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_rootfs(tmp_path):
    """Create a minimal fake rootfs with CGI handlers."""
    cgi_bin = tmp_path / 'usr' / 'share' / 'www' / 'cgi-bin'
    admin_dir = cgi_bin / 'admin'
    admin_dir.mkdir(parents=True)

    # Shell CGI with ARG_PROPAGATED sink (upload handler)
    upload = admin_dir / 'upload.cgi'
    upload.write_text(textwrap.dedent("""\
        #!/bin/sh
        SCRIPT=$1
        ${SCRIPT} install /tmp/pkg
    """))

    # Shell CGI with only literal commands
    safe = cgi_bin / 'status.cgi'
    safe.write_text(textwrap.dedent("""\
        #!/bin/sh
        /usr/bin/uptime
        /bin/cat /proc/meminfo
    """))

    # ELF binary CGI
    elf_cgi = cgi_bin / 'camctrl.cgi'
    elf_cgi.write_bytes(b'\x7fELF' + b'\x00' * 60)

    # Script with eval
    eval_cgi = cgi_bin / 'action.sh'
    eval_cgi.write_text(textwrap.dedent("""\
        #!/bin/sh
        eval "$(confclient -g cmd)"
    """))

    return tmp_path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCGISurfaceMapper:

    def test_finds_cgi_handlers(self, fake_rootfs):
        mapper = CGISurfaceMapper.from_rootfs(str(fake_rootfs))
        surface = mapper.map()
        assert len(surface.handlers) >= 3

    def test_classifies_shell_and_elf(self, fake_rootfs):
        mapper = CGISurfaceMapper.from_rootfs(str(fake_rootfs))
        surface = mapper.map()
        types = {h.handler_type for h in surface.handlers}
        assert 'shell' in types
        assert 'elf' in types

    def test_arg_propagated_shell_detected(self, fake_rootfs):
        mapper = CGISurfaceMapper.from_rootfs(str(fake_rootfs))
        surface = mapper.map()
        ap = [h for h in surface.shell_handlers if h.max_verdict == 'ARG_PROPAGATED']
        assert ap, "Shell handler with $1 in command position should be ARG_PROPAGATED"

    def test_eval_sink_detected(self, fake_rootfs):
        mapper = CGISurfaceMapper.from_rootfs(str(fake_rootfs))
        surface = mapper.map()
        ev = [h for h in surface.shell_handlers if h.max_verdict == 'EVAL_SINK']
        assert ev, "Handler with eval$(confclient ...) should be EVAL_SINK"

    def test_rodata_const_safe_handler(self, fake_rootfs):
        mapper = CGISurfaceMapper.from_rootfs(str(fake_rootfs))
        surface = mapper.map()
        rc = [h for h in surface.shell_handlers if h.max_verdict == 'RODATA_CONST']
        assert rc, "status.cgi with only literal commands should be RODATA_CONST"

    def test_risky_property(self, fake_rootfs):
        mapper = CGISurfaceMapper.from_rootfs(str(fake_rootfs))
        surface = mapper.map()
        assert len(surface.risky) >= 2  # upload.cgi + action.sh

    def test_sorted_by_priority(self, fake_rootfs):
        mapper = CGISurfaceMapper.from_rootfs(str(fake_rootfs))
        surface = mapper.map()
        from ablation.analyzers.cgi_surface_mapper import _VERDICT_PRIORITY
        priorities = [h.priority for h in surface.handlers]
        assert priorities == sorted(priorities)

    def test_elf_handlers_list(self, fake_rootfs):
        mapper = CGISurfaceMapper.from_rootfs(str(fake_rootfs))
        surface = mapper.map()
        elfs = surface.elf_handlers
        assert len(elfs) == 1
        assert 'camctrl.cgi' in elfs[0].rel_path

    def test_auth_hint_admin(self, fake_rootfs):
        mapper = CGISurfaceMapper.from_rootfs(str(fake_rootfs))
        surface = mapper.map()
        admin_handlers = [h for h in surface.handlers if h.auth_hint == 'admin']
        assert admin_handlers, "Handlers in /admin/ dir should have auth_hint='admin'"

    def test_report_contains_summary(self, fake_rootfs):
        mapper = CGISurfaceMapper.from_rootfs(str(fake_rootfs))
        surface = mapper.map()
        report = CGISurfaceMapper.report(surface)
        assert 'CGISurfaceMapper' in report
        assert 'Total handlers' in report
        assert 'Shell handlers' in report
        assert 'ELF handlers' in report

    def test_report_shows_sink_detail_for_risky(self, fake_rootfs):
        mapper = CGISurfaceMapper.from_rootfs(str(fake_rootfs))
        surface = mapper.map()
        report = CGISurfaceMapper.report(surface)
        # Risky handlers should show sink line details
        assert 'ARG_PROPAGATED' in report or 'EVAL_SINK' in report

    def test_empty_rootfs_no_crash(self, tmp_path):
        mapper = CGISurfaceMapper.from_rootfs(str(tmp_path))
        surface = mapper.map()
        assert surface.handlers == []

    def test_custom_cgi_dirs(self, tmp_path):
        custom_dir = tmp_path / 'custom_cgi'
        custom_dir.mkdir()
        script = custom_dir / 'handler.sh'
        script.write_text('#!/bin/sh\n$1 run\n')
        mapper = CGISurfaceMapper.from_rootfs(
            str(tmp_path),
            cgi_dirs=[str(custom_dir)],
        )
        surface = mapper.map()
        assert any(h.handler_type == 'shell' for h in surface.handlers)


# ---------------------------------------------------------------------------
# VIVOTEK regression
# ---------------------------------------------------------------------------

VIVOTEK_ROOTFS = Path('/media/cowboy/research/VIVOTEK/FD8369A/rootfs_mount')

@pytest.mark.skipif(not VIVOTEK_ROOTFS.exists(), reason='VIVOTEK rootfs not mounted')
class TestVivotekCGISurface:

    def test_upload_vadp_surfaces_as_arg_propagated(self):
        mapper = CGISurfaceMapper.from_rootfs(str(VIVOTEK_ROOTFS))
        surface = mapper.map()
        # upload_vadp must appear as ARG_PROPAGATED
        upload = [h for h in surface.handlers
                  if 'upload_vadp' in h.rel_path and h.max_verdict == 'ARG_PROPAGATED']
        assert upload, "upload_vadp must surface as ARG_PROPAGATED"

    def test_elf_cgi_handlers_present(self):
        mapper = CGISurfaceMapper.from_rootfs(str(VIVOTEK_ROOTFS))
        surface = mapper.map()
        assert len(surface.elf_handlers) >= 3  # camctrl, eventscript, export_language

    def test_risky_handlers_count(self):
        mapper = CGISurfaceMapper.from_rootfs(str(VIVOTEK_ROOTFS))
        surface = mapper.map()
        assert len(surface.risky) >= 3
