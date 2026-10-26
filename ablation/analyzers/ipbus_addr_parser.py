"""
ipbus_addr_parser.py: parse IPBus XML address tables into a structured register map.

Gap this fills:
  IPBus firmware (CERN ATLAS GEP, EMP framework, TriDAS) embeds register maps
  as XML address tables. These tables map symbolic names to 32-bit word offsets,
  permissions (r/w/rw), and bitmasks. Without parsing them, register addresses
  from live IPBus captures are opaque 32-bit offsets. This module fills
  IPBUS-ADDR-TABLE-GAP-001: no ablation module existed to reconstruct the
  symbolic register map from IPBus XML files found in firmware packages.

IPBus XML format (uHAL / IPbus Software Suite):
  <node id="module" address="0x0">
    <node id="reg_name" address="0x0" permission="rw" description="...">
      <node id="field_name" mask="0x000f" description="..."/>
    </node>
  </node>

Address model:
  - Addresses are 32-bit word addresses (byte_addr = word_addr × 4).
  - Child addresses are relative to their parent (absolute = parent_abs + child).
  - mask attributes define bit fields within a register.
  - permission: 'r' read-only, 'w' write-only, 'rw' read-write (default 'rw').

Findings emitted (IPBusRegisterMap):
  - nodes: hierarchical tree of IPBusNode objects
  - flat: Dict[abs_word_addr, IPBusNode] for direct address lookup
  - risky: list of nodes with 'w' or 'rw' permission (writable from network)

Usage:
    from ablation.analyzers.ipbus_addr_parser import IPBusAddrParser

    parser = IPBusAddrParser.from_file('/path/to/addr_table.xml')
    reg_map = parser.parse()

    # Print all registers
    print(parser.report(reg_map))

    # Lookup by address
    node = reg_map.flat.get(0x4)
    if node:
        print(node.full_path, node.permission)

    # Find all writable nodes
    for node in reg_map.writable():
        print(f'0x{node.abs_addr:08x}  {node.full_path}  [{node.permission}]')
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional


@dataclass
class IPBusNode:
    """One node in an IPBus address table — register, block, or bit-field."""
    id:          str
    abs_addr:    int         # absolute word address (relative to base 0x0)
    permission:  str         # 'r', 'w', 'rw', or '' (inherits from parent)
    mask:        Optional[int]  # bit mask for sub-register fields; None = full word
    description: str
    path:        str         # dotted path from root, e.g. 'module.reg.field'
    children:    List['IPBusNode'] = field(default_factory=list)

    @property
    def full_path(self) -> str:
        return self.path

    @property
    def is_leaf(self) -> bool:
        return not self.children

    @property
    def is_writable(self) -> bool:
        return 'w' in self.permission

    @property
    def byte_addr(self) -> int:
        return self.abs_addr * 4

    def fmt(self, indent: int = 0) -> str:
        pad = '  ' * indent
        mask_str = f' mask=0x{self.mask:08x}' if self.mask is not None else ''
        perm_str = f' [{self.permission}]' if self.permission else ''
        desc_str = f'  # {self.description}' if self.description else ''
        line = (f'{pad}0x{self.abs_addr:08x}{mask_str}  '
                f'{self.id}{perm_str}{desc_str}')
        lines = [line]
        for child in self.children:
            lines.append(child.fmt(indent + 1))
        return '\n'.join(lines)


@dataclass
class IPBusRegisterMap:
    """Parsed register map: hierarchical tree + flat address lookup."""
    source:   str                       # XML file path
    nodes:    List[IPBusNode]           # top-level nodes
    flat:     Dict[int, IPBusNode]      # abs_word_addr → leaf node (deepest named node)
    path_map: Dict[str, IPBusNode]      # dotted_path → node

    def writable(self) -> List[IPBusNode]:
        """All nodes with write permission, sorted by address."""
        return sorted(
            [n for n in self.flat.values() if n.is_writable],
            key=lambda n: n.abs_addr,
        )

    def readable(self) -> List[IPBusNode]:
        return sorted(
            [n for n in self.flat.values() if 'r' in n.permission],
            key=lambda n: n.abs_addr,
        )

    def lookup_addr(self, word_addr: int) -> Optional[IPBusNode]:
        """Return the leaf node at word_addr, or None."""
        return self.flat.get(word_addr)

    def lookup_path(self, dotted_path: str) -> Optional[IPBusNode]:
        return self.path_map.get(dotted_path)

    def walk(self) -> Iterator[IPBusNode]:
        """Depth-first walk over all nodes."""
        stack = list(self.nodes)
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(node.children))


class IPBusAddrParser:
    """
    Parse IPBus XML address tables (uHAL format) into a structured register map.

    Handles:
    - Relative child addresses (parent + child offset)
    - Nested bit-field nodes (mask attribute)
    - Permission inheritance (child inherits parent if unset)
    - address="$(ADDRTABLE.*)" macro references (replaced with 0x0; re-parse needed)
    """

    def __init__(self, xml_source: str, source_label: str = ''):
        self._xml_source = xml_source
        self._source_label = source_label

    @classmethod
    def from_file(cls, path: str) -> 'IPBusAddrParser':
        return cls(
            xml_source=Path(path).read_text(errors='replace'),
            source_label=str(path),
        )

    @classmethod
    def from_string(cls, xml_text: str, label: str = '<string>') -> 'IPBusAddrParser':
        return cls(xml_source=xml_text, source_label=label)

    # ── parsing ───────────────────────────────────────────────────────────────

    def _parse_addr(self, raw: Optional[str], parent_abs: int) -> int:
        """Parse an address attribute string to an absolute word address."""
        if not raw:
            return parent_abs
        raw = raw.strip()
        # Macro reference like $(ADDRTABLE.X) — treat as 0 relative
        if raw.startswith('$('):
            return parent_abs
        try:
            offset = int(raw, 0)
            return parent_abs + offset
        except ValueError:
            return parent_abs

    def _parse_mask(self, raw: Optional[str]) -> Optional[int]:
        if not raw:
            return None
        try:
            return int(raw.strip(), 0)
        except ValueError:
            return None

    def _parse_permission(self, raw: Optional[str], parent_perm: str) -> str:
        if not raw:
            return parent_perm or 'rw'
        return raw.strip().lower()

    def _parse_node(
        self,
        elem: ET.Element,
        parent_abs: int,
        parent_perm: str,
        parent_path: str,
    ) -> IPBusNode:
        node_id    = elem.get('id', '<unnamed>')
        raw_addr   = elem.get('address')
        raw_perm   = elem.get('permission')
        raw_mask   = elem.get('mask')
        description = elem.get('description', '')

        abs_addr  = self._parse_addr(raw_addr, parent_abs)
        permission = self._parse_permission(raw_perm, parent_perm)
        mask      = self._parse_mask(raw_mask)
        path      = f'{parent_path}.{node_id}' if parent_path else node_id

        node = IPBusNode(
            id=node_id,
            abs_addr=abs_addr,
            permission=permission,
            mask=mask,
            description=description,
            path=path,
        )
        for child_elem in elem:
            if child_elem.tag == 'node':
                child_node = self._parse_node(child_elem, abs_addr, permission, path)
                node.children.append(child_node)

        return node

    def parse(self) -> IPBusRegisterMap:
        """Parse the XML and return an IPBusRegisterMap."""
        try:
            root = ET.fromstring(self._xml_source)
        except ET.ParseError as e:
            return IPBusRegisterMap(
                source=self._source_label,
                nodes=[],
                flat={},
                path_map={},
            )

        # Root element may itself be a <node> or a wrapper element
        top_nodes: List[IPBusNode] = []
        if root.tag == 'node':
            top_nodes.append(self._parse_node(root, 0, 'rw', ''))
        else:
            for child in root:
                if child.tag == 'node':
                    top_nodes.append(self._parse_node(child, 0, 'rw', ''))

        # Build flat map: address → deepest (leaf) node at each address
        flat: Dict[int, IPBusNode]  = {}
        path_map: Dict[str, IPBusNode] = {}

        def _flatten(node: IPBusNode) -> None:
            path_map[node.path] = node
            if node.is_leaf:
                # Leaf nodes own their address slot
                flat.setdefault(node.abs_addr, node)
                flat[node.abs_addr] = node  # last write wins (deepest)
            else:
                # Container: recurse, but also register at its own address
                flat.setdefault(node.abs_addr, node)
                for child in node.children:
                    _flatten(child)

        for n in top_nodes:
            _flatten(n)

        return IPBusRegisterMap(
            source=self._source_label,
            nodes=top_nodes,
            flat=flat,
            path_map=path_map,
        )

    # ── reporting ─────────────────────────────────────────────────────────────

    def report(self, reg_map: Optional[IPBusRegisterMap] = None) -> str:
        if reg_map is None:
            reg_map = self.parse()
        if not reg_map.nodes:
            return f'[ipbus_addr_parser] {self._source_label}: no nodes parsed\n'

        lines = [
            f'[ipbus_addr_parser] {self._source_label}',
            f'  {len(reg_map.flat)} addresses  {len(reg_map.writable())} writable',
            '',
        ]
        for node in reg_map.nodes:
            lines.append(node.fmt())
        return '\n'.join(lines) + '\n'
