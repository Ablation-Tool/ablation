"""Unit tests for IPBusAddrParser and IPBusRegisterMap."""

import pytest
from ablation.analyzers.ipbus_addr_parser import (
    IPBusAddrParser,
    IPBusRegisterMap,
    IPBusNode,
)


# ── fixtures ──────────────────────────────────────────────────────────────────

SIMPLE_XML = """\
<node id="root" address="0x0">
  <node id="csr" address="0x2" permission="rw" description="control status"/>
  <node id="id"  address="0x0" permission="r"  description="firmware ID"/>
</node>
"""

NESTED_XML = """\
<node id="top" address="0x0">
  <node id="ctrl" address="0x10" permission="rw">
    <node id="enable" mask="0x0001"/>
    <node id="reset"  mask="0x0002"/>
  </node>
  <node id="status" address="0x11" permission="r" description="read-only status"/>
  <node id="data"   address="0x20" permission="rw"/>
</node>
"""

WRITE_ONLY_XML = """\
<node id="root" address="0x0">
  <node id="cmd" address="0x5" permission="w" description="write-only command"/>
  <node id="val" address="0x6" permission="rw"/>
</node>
"""

MALFORMED_XML = "<<< not valid XML >>>"

EMPTY_XML = """\
<node id="empty"/>
"""

WRAPPER_ROOT_XML = """\
<ipbus>
  <node id="reg0" address="0x0" permission="rw"/>
  <node id="reg1" address="0x1" permission="r"/>
</ipbus>
"""


# ── helper ────────────────────────────────────────────────────────────────────

def parse(xml: str) -> IPBusRegisterMap:
    return IPBusAddrParser.from_string(xml, label='test').parse()


# ── basic parsing tests ───────────────────────────────────────────────────────

def test_parse_simple_node_count() -> None:
    """Simple XML with two child nodes should produce two entries."""
    m = parse(SIMPLE_XML)
    assert len(m.flat) >= 2


def test_parse_address_values() -> None:
    """Absolute addresses are inherited correctly from the parent."""
    m = parse(SIMPLE_XML)
    assert any(n.abs_addr == 0x2 for n in m.flat.values())
    assert any(n.abs_addr == 0x0 for n in m.flat.values())


def test_parse_permissions_rw() -> None:
    """Permission 'rw' is parsed correctly."""
    m = parse(SIMPLE_XML)
    csr = m.path_map.get('root.csr')
    assert csr is not None
    assert csr.permission == 'rw'
    assert csr.is_writable


def test_parse_permissions_read_only() -> None:
    """Permission 'r' is parsed and not writable."""
    m = parse(SIMPLE_XML)
    id_node = m.path_map.get('root.id')
    assert id_node is not None
    assert id_node.permission == 'r'
    assert not id_node.is_writable


def test_parse_description() -> None:
    """Description attribute is preserved."""
    m = parse(SIMPLE_XML)
    csr = m.path_map.get('root.csr')
    assert csr is not None
    assert 'control' in csr.description.lower()


# ── nested structure tests ────────────────────────────────────────────────────

def test_nested_absolute_address() -> None:
    """Child absolute address = parent absolute + child offset."""
    m = parse(NESTED_XML)
    # 'top' is at 0x0, 'ctrl' at 0x10, so top.ctrl is at 0x10
    ctrl = m.path_map.get('top.ctrl')
    assert ctrl is not None, f'top.ctrl not in {list(m.path_map.keys())}'
    assert ctrl.abs_addr == 0x10


def test_nested_leaves_in_path_map() -> None:
    """Leaf bitmask nodes appear in path_map under their parent's path."""
    m = parse(NESTED_XML)
    assert 'top.ctrl.enable' in m.path_map
    assert 'top.ctrl.reset' in m.path_map


def test_nested_bitmask_values() -> None:
    """Bitmask fields are parsed as integers."""
    m = parse(NESTED_XML)
    enable = m.path_map['top.ctrl.enable']
    reset  = m.path_map['top.ctrl.reset']
    assert enable.mask == 0x0001
    assert reset.mask == 0x0002


def test_nested_is_leaf() -> None:
    """Leaf nodes (no children) have is_leaf=True."""
    m = parse(NESTED_XML)
    status = m.path_map.get('top.status')
    assert status is not None
    assert status.is_leaf


def test_nested_non_leaf() -> None:
    """Container nodes (has children) have is_leaf=False."""
    m = parse(NESTED_XML)
    ctrl = m.path_map.get('top.ctrl')
    assert ctrl is not None
    assert not ctrl.is_leaf


# ── writable / readable filters ───────────────────────────────────────────────

def test_writable_filter() -> None:
    """writable() returns only nodes with 'w' in permission."""
    m = parse(NESTED_XML)
    writable = m.writable()
    for n in writable:
        assert n.is_writable, f'{n.path} returned as writable but permission={n.permission!r}'


def test_write_only_in_writable() -> None:
    """Permission 'w' (write-only) is also included in writable()."""
    m = parse(WRITE_ONLY_XML)
    paths = {n.path for n in m.writable()}
    assert any('cmd' in p for p in paths), f'write-only node not in writable: {paths}'


def test_read_only_not_in_writable() -> None:
    """Permission 'r' nodes do not appear in writable()."""
    m = parse(NESTED_XML)
    read_only_paths = {n.path for n in m.writable() if n.permission == 'r'}
    assert not read_only_paths, f'read-only nodes appeared in writable(): {read_only_paths}'


def test_readable_filter() -> None:
    """readable() returns nodes with 'r' in permission."""
    m = parse(NESTED_XML)
    readable = m.readable()
    for n in readable:
        assert 'r' in n.permission, f'{n.path} in readable but permission={n.permission!r}'


# ── lookup_addr ───────────────────────────────────────────────────────────────

def test_lookup_addr_hit() -> None:
    """lookup_addr returns the node at the given word address."""
    m = parse(SIMPLE_XML)
    node = m.lookup_addr(0x2)
    assert node is not None
    assert 'csr' in node.path


def test_lookup_addr_miss() -> None:
    """lookup_addr returns None for unmapped addresses."""
    m = parse(SIMPLE_XML)
    node = m.lookup_addr(0x999)
    assert node is None


# ── byte_addr ─────────────────────────────────────────────────────────────────

def test_byte_addr_is_word_addr_times_four() -> None:
    """byte_addr = abs_addr * 4 (IPBus word addresses are 4 bytes each)."""
    m = parse(SIMPLE_XML)
    csr = m.path_map.get('root.csr')
    assert csr is not None
    assert csr.byte_addr == csr.abs_addr * 4


# ── walk ──────────────────────────────────────────────────────────────────────

def test_walk_visits_all_leaves() -> None:
    """walk() visits every node including nested leaves."""
    m = parse(NESTED_XML)
    all_paths = {n.path for n in m.walk()}
    assert 'top.ctrl.enable' in all_paths
    assert 'top.ctrl.reset' in all_paths
    assert 'top.status' in all_paths


# ── edge cases ────────────────────────────────────────────────────────────────

def test_malformed_xml_returns_empty() -> None:
    """Malformed XML does not raise; returns empty register map."""
    m = parse(MALFORMED_XML)
    assert len(m.flat) == 0
    assert len(m.path_map) == 0


def test_empty_node_parses() -> None:
    """A single empty node (no children, no address) parses without error."""
    m = parse(EMPTY_XML)
    # Should produce at least one entry (or zero if only the root with no children)
    assert isinstance(m, IPBusRegisterMap)


def test_wrapper_root_parses() -> None:
    """Non-<node> wrapper roots (e.g. <ipbus>) are handled."""
    m = parse(WRAPPER_ROOT_XML)
    paths = set(m.path_map.keys())
    assert any('reg0' in p for p in paths), f'reg0 not found in {paths}'
    assert any('reg1' in p for p in paths), f'reg1 not found in {paths}'


def test_from_string_label_stored() -> None:
    """from_string preserves the label in the register map."""
    m = IPBusAddrParser.from_string(SIMPLE_XML, label='my_table').parse()
    assert m.source == 'my_table'


# ── report smoke test ─────────────────────────────────────────────────────────

def test_report_produces_string() -> None:
    """report() returns a non-empty string without raising."""
    parser = IPBusAddrParser.from_string(NESTED_XML, label='test')
    m = parser.parse()
    out = parser.report(m)
    assert isinstance(out, str)
    assert len(out) > 0
    assert 'ctrl' in out
