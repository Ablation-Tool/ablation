"""
Tests for ShellSinkClassifier.

Covers: provenance tracking, exec-sink detection (VAR_CMD / EVAL / SOURCE / SH_C),
verdict assignment, from_path/from_dir constructors, report() output.
"""

import textwrap
import tempfile
import os
from pathlib import Path

import pytest

from ablation.analyzers.shell_sink_classifier import ShellSinkClassifier, ShellSinkResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _classify(script_text: str) -> list[ShellSinkResult]:
    """Write *script_text* to a temp file and classify it."""
    with tempfile.NamedTemporaryFile(
        mode='w', suffix='.sh', delete=False, prefix='test_ssc_'
    ) as f:
        f.write(script_text)
        fpath = f.name
    try:
        clf = ShellSinkClassifier.from_path(fpath)
        return clf.classify()
    finally:
        os.unlink(fpath)


def _verdicts(results: list[ShellSinkResult]) -> list[str]:
    return [r.verdict for r in results]


def _sink_types(results: list[ShellSinkResult]) -> list[str]:
    return [r.sink_type for r in results]


def _lines(results: list[ShellSinkResult]) -> list[int]:
    return [r.line_num for r in results]


# ===========================================================================
# 1. Variable provenance — EXTERNAL sources
# ===========================================================================

class TestExternalProvenance:

    def test_positional_param_arg_propagated(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            INIT_SCR=$1
            ${INIT_SCR} install /tmp/pkg
        """))
        ap = [r for r in results if r.verdict == 'ARG_PROPAGATED']
        assert ap, "Expected ARG_PROPAGATED for positional param in command position"
        assert 'INIT_SCR' in ap[0].vars_involved

    def test_at_star_params_arg_propagated(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            CMD=$@
            $CMD extra_arg
        """))
        ap = [r for r in results if r.verdict == 'ARG_PROPAGATED']
        assert ap

    def test_xmlparser_external(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            SCRIPT=`xmlparser -x /vadp/initscr -f /tmp/pkg/vadp.xml`
            /tmp/pkg/${SCRIPT} chkver /tmp/pkg
        """))
        ap = [r for r in results if r.verdict == 'ARG_PROPAGATED']
        assert ap, "xmlparser output must be EXTERNAL"

    def test_confclient_external(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            VAL=$(confclient -g mykey)
            ${VAL} start
        """))
        ap = [r for r in results if r.verdict == 'ARG_PROPAGATED']
        assert ap, "confclient output must be EXTERNAL"

    def test_read_stdin_external(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            read USER_CMD
            ${USER_CMD} arg1
        """))
        ap = [r for r in results if r.verdict == 'ARG_PROPAGATED']
        assert ap, "read from stdin must be EXTERNAL"

    def test_cgi_env_external(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            CMD=$QUERY_STRING
            $CMD
        """))
        ap = [r for r in results if r.verdict == 'ARG_PROPAGATED']
        assert ap, "QUERY_STRING must be EXTERNAL"

    def test_http_env_prefix_external(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            HVAL=$HTTP_HOST
            /bin/echo ${HVAL}
        """))
        # /bin/echo is not a VAR_CMD; but this should still track HVAL as EXTERNAL
        # The actual sink would be if HVAL were used in command position
        clf = ShellSinkClassifier.from_path(__file__)  # dummy
        # Just verify provenance is tracked
        prov = clf._classify_value_provenance('$HTTP_HOST', {})
        assert prov == 'EXTERNAL'


# ===========================================================================
# 2. Variable provenance — INTERNAL / RODATA_CONST
# ===========================================================================

class TestInternalProvenance:

    def test_literal_assignment_rodata_const(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            CONF_PATH="/etc/config"
            ${CONF_PATH}/init.sh
        """))
        rc = [r for r in results if r.verdict == 'RODATA_CONST']
        assert rc, "Literal path variable should yield RODATA_CONST"

    def test_chained_literal_assignment(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            BASE="/usr/bin"
            TOOL="${BASE}/mytool"
            ${TOOL} --check
        """))
        rc = [r for r in results if r.verdict == 'RODATA_CONST']
        assert rc

    def test_no_false_positive_on_literal_command(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            /usr/bin/mytool --flag value
            echo hello
            ls -la /tmp
        """))
        # No variable references in command position — should produce no VAR_CMD results
        var_cmd = [r for r in results if r.sink_type == 'VAR_CMD']
        assert not var_cmd


# ===========================================================================
# 3. UNKNOWN provenance
# ===========================================================================

class TestUnknownProvenance:

    def test_unknown_global_var(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            # TOOL is set elsewhere, not in this script
            ${TOOL} --run
        """))
        unk = [r for r in results if r.verdict == 'UNKNOWN']
        assert unk, "Unresolved variable in command position must be UNKNOWN"

    def test_command_subst_non_external_cmd_is_unknown(self):
        """Non-external-set command substitution defaults to UNKNOWN (conservative)."""
        clf = ShellSinkClassifier.from_path(__file__)
        prov = clf._classify_value_provenance('$(some_custom_tool)', {})
        assert prov == 'UNKNOWN'


# ===========================================================================
# 4. Eval sink
# ===========================================================================

class TestEvalSink:

    def test_eval_always_eval_sink(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            eval "/bin/echo hello"
        """))
        ev = [r for r in results if r.sink_type == 'EVAL']
        assert ev, "eval must always be flagged as EVAL_SINK"
        assert ev[0].verdict == 'EVAL_SINK'

    def test_eval_with_external_var(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            CMD=$1
            eval "${CMD}"
        """))
        ev = [r for r in results if r.sink_type == 'EVAL']
        assert ev
        assert ev[0].verdict == 'EVAL_SINK'
        assert 'CMD' in ev[0].vars_involved

    def test_eval_literal_still_eval_sink(self):
        """Even a literal eval is flagged EVAL_SINK — always needs review."""
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            eval "export FOO=bar"
        """))
        ev = [r for r in results if r.sink_type == 'EVAL']
        assert ev
        assert ev[0].verdict == 'EVAL_SINK'


# ===========================================================================
# 5. Source / dot sink
# ===========================================================================

class TestSourceSink:

    def test_source_literal_rodata_const(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            source /etc/common_functions
        """))
        src = [r for r in results if r.sink_type == 'SOURCE']
        assert src
        assert src[0].verdict == 'RODATA_CONST'

    def test_dot_variable_arg_propagated(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            MODULE=$1
            . ${MODULE}
        """))
        src = [r for r in results if r.sink_type == 'SOURCE']
        assert src
        assert src[0].verdict == 'ARG_PROPAGATED'


# ===========================================================================
# 6. sh -c sink
# ===========================================================================

class TestShCSink:

    def test_sh_c_literal_rodata_const(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            sh -c "ls /tmp"
        """))
        shc = [r for r in results if r.sink_type == 'SH_C']
        assert shc
        assert shc[0].verdict == 'RODATA_CONST'

    def test_sh_c_external_arg_propagated(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            CMD=$1
            /bin/sh -c "${CMD}"
        """))
        shc = [r for r in results if r.sink_type == 'SH_C']
        assert shc
        assert shc[0].verdict == 'ARG_PROPAGATED'


# ===========================================================================
# 7. Line number accuracy
# ===========================================================================

class TestLineNumbers:

    def test_line_number_correct(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            # line 2
            INIT=$1
            # line 4
            ${INIT} install
        """))
        ap = [r for r in results if r.verdict == 'ARG_PROPAGATED' and r.sink_type == 'VAR_CMD']
        assert ap
        assert ap[0].line_num == 5  # ${INIT} install is on line 5


# ===========================================================================
# 8. VIVOTEK upload_vadp critical findings
# ===========================================================================

class TestVivotekUploadVadp:
    """Regression test: ShellSinkClassifier must catch VIVOTEK-001 and VIVOTEK-002."""

    VADP_PATH = Path(
        '/media/cowboy/research/VIVOTEK/FD8369A/rootfs_mount/usr/bin/upload_vadp'
    )

    @pytest.mark.skipif(
        not VADP_PATH.exists(),
        reason="VIVOTEK FD8369A rootfs not mounted"
    )
    def test_vivotek_001_detected_line554(self):
        clf = ShellSinkClassifier.from_path(str(self.VADP_PATH))
        results = clf.classify()
        # VIVOTEK-001: ${NEW_PACK}/${NEW_INIT_SCR} chkver at line ~554
        hit = [r for r in results
               if r.line_num == 554 and r.verdict == 'ARG_PROPAGATED']
        assert hit, "VIVOTEK-001 (line 554 VAR_CMD ARG_PROPAGATED) not detected"
        assert 'NEW_PACK' in hit[0].vars_involved or 'NEW_INIT_SCR' in hit[0].vars_involved

    @pytest.mark.skipif(
        not VADP_PATH.exists(),
        reason="VIVOTEK FD8369A rootfs not mounted"
    )
    def test_vivotek_002_detected_line980(self):
        clf = ShellSinkClassifier.from_path(str(self.VADP_PATH))
        results = clf.classify()
        # VIVOTEK-002: ${NEW_PACK}/${NEW_INIT_SCR} upgrade at line ~980
        hit = [r for r in results
               if r.line_num == 980 and r.verdict == 'ARG_PROPAGATED']
        assert hit, "VIVOTEK-002 (line 980 VAR_CMD ARG_PROPAGATED) not detected"

    @pytest.mark.skipif(
        not VADP_PATH.exists(),
        reason="VIVOTEK FD8369A rootfs not mounted"
    )
    def test_eval_sinks_detected(self):
        clf = ShellSinkClassifier.from_path(str(self.VADP_PATH))
        results = clf.classify()
        eval_sinks = [r for r in results if r.sink_type == 'EVAL']
        assert len(eval_sinks) >= 5, "Expected multiple EVAL sinks in upload_vadp"


# ===========================================================================
# 9. from_dir constructor
# ===========================================================================

class TestFromDir:

    def test_from_dir_finds_sh_files(self, tmp_path):
        script = tmp_path / "test.sh"
        script.write_text("#!/bin/sh\nCMD=$1\n${CMD} run\n")
        clf = ShellSinkClassifier.from_dir(str(tmp_path))
        results = clf.classify()
        ap = [r for r in results if r.verdict == 'ARG_PROPAGATED']
        assert ap

    def test_from_dir_skips_non_shell(self, tmp_path):
        non_shell = tmp_path / "config.conf"
        non_shell.write_text("key=value\n")
        clf = ShellSinkClassifier.from_dir(str(tmp_path))
        results = clf.classify()
        assert not results  # no shell scripts

    def test_from_dir_detects_cgi_by_shebang(self, tmp_path):
        cgi = tmp_path / "handler.cgi"
        cgi.write_text("#!/bin/sh\nSCRIPT=$1\n${SCRIPT} start\n")
        clf = ShellSinkClassifier.from_dir(str(tmp_path), exts={'.cgi'})
        results = clf.classify()
        assert any(r.verdict == 'ARG_PROPAGATED' for r in results)


# ===========================================================================
# 10. report() output
# ===========================================================================

class TestReport:

    def test_report_no_results(self):
        out = ShellSinkClassifier.report([])
        assert 'no exec-class sinks' in out

    def test_report_contains_verdict(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            CMD=$1
            ${CMD} run
        """))
        out = ShellSinkClassifier.report(results)
        assert 'ARG_PROPAGATED' in out

    def test_report_summary_line(self):
        results = _classify(textwrap.dedent("""\
            #!/bin/sh
            CMD=$1
            ${CMD} run
            eval "ls /tmp"
        """))
        out = ShellSinkClassifier.report(results)
        assert 'Summary:' in out
        assert 'ARG_PROPAGATED=' in out
        assert 'EVAL_SINK=' in out
