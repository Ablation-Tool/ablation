import pytest

from ablation.analyzers.junos_overlay import candidate_name, recover_overlay
from ablation.analyzers.mips_string_xrefs import StringXref


class Context:
    def __init__(self):
        self.strings = {
            0x1000: "compare_vrf_group_lists",
            0x2000: "%s: invalid blob size %d",
            0x3000: "vrf_group_insert_vrf_entry",
        }
        self.func_starts = []
        self.bulk = None

    def set_names_bulk(self, names):
        self.bulk = names
        return len(names)


def test_candidate_name_is_conservative():
    assert candidate_name("compare_vrf_group_lists") == "compare_vrf_group_lists"
    assert candidate_name("%s: invalid blob") is None
    assert candidate_name("Invalid") is None
    assert candidate_name("main") is None


def test_overlay_persists_only_symbols():
    ctx = Context()
    xrefs = [
        StringXref(0x400000, 0x400100, "a1", 0x1000),
        StringXref(0x400000, 0x400104, "a1", 0x2000),
        StringXref(0x500000, 0x500100, "a1", 0x3000),
        StringXref(0, 0x500104, "a1", 0x3000),
    ]

    result = recover_overlay(ctx, xrefs)

    assert result.names == {0x400000: "compare_vrf_group_lists", 0x500000: "vrf_group_insert_vrf_entry"}
    assert result.names_added == 2
    assert result.function_starts_added == 2
    assert ctx.func_starts == [0x400000, 0x500000]
    assert ctx.bulk[0x400000] == ("compare_vrf_group_lists", "junos_trace")


@pytest.mark.integration
def test_real_nsd_overlay():
    from pathlib import Path
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.mips_string_xrefs import MIPSStringXrefResolver
    binary = Path("/media/cowboy/research/Juniper/srx/15.1X49/extracted/D170.4/junos-root-xorriso/usr/sbin/nsd")
    if not binary.exists():
        pytest.skip("SRX integration fixture is unavailable")

    ctx = BinaryContext.build(str(binary))
    targets = {va for va, value in ctx.strings.items() if value in {"compare_vrf_group_lists", "vrf_group_insert_vrf_entry"}}
    results = MIPSStringXrefResolver(binary).resolve(targets)
    result = recover_overlay(ctx, results)

    assert result.names
    assert "compare_vrf_group_lists" in result.names.values()
    assert "vrf_group_insert_vrf_entry" in result.names.values()
    assert ctx.names_count() >= len(result.names)
