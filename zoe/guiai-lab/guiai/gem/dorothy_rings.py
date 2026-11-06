"""Dorothy Rings: Disk Usage (Baobab) navigation of the CCF ontology.

Each sector's angle is the structure's subtree volume from the annotation
labels, so the biggest regions read like the biggest folders. Centering a
structure drills down; the breadcrumb walks back up.
"""

from __future__ import annotations

import math

from .dorothy import CANVAS_HEIGHT, CANVAS_WIDTH, LEGEND_LEFT, _text
from .dorothy_data import load_graph, load_volumes, subtree_volumes
from .model import Scene

TAU = 2 * math.pi
MIN_ANGLE = 0.03
RING_LEFT = 60
RING_TOP = 110
RING_SIZE = 1000


def build_tree(graph):
    by_id = {record["id"]: record for record in graph}
    children = {}
    for record in graph:
        children.setdefault(record["parent_structure_id"], []).append(record["id"])
    return by_id, children


def ring_sectors(by_id, children, volumes, center, max_depth=3):
    if center not in by_id:
        raise ValueError(f"structure {center} is not in the CCF graph")
    if not 1 <= max_depth <= 5:
        raise ValueError("ring depth must be 1-5")
    radius = RING_SIZE / 2
    thickness = radius / (max_depth + 1)
    sectors = []
    omitted = 0
    root = {"id": center, "depth": 0, "inner": 0.0, "outer": thickness, "start": 0.0, "angle": TAU}
    pending = [root]
    while pending:
        parent = pending.pop()
        descendants = sorted(children.get(parent["id"], []), key=lambda identifier: (-volumes.get(identifier, 0), by_id[identifier]["acronym"].casefold(), identifier))
        if parent["depth"] >= max_depth:
            continue
        start = parent["start"]
        for identifier in descendants:
            weight = volumes.get(identifier, 0)
            if not weight:
                continue
            angle = parent["angle"] * weight / volumes[parent["id"]]
            if angle < MIN_ANGLE:
                omitted += 1
                continue
            depth = parent["depth"] + 1
            sector = {"id": identifier, "depth": depth, "inner": depth * thickness, "outer": (depth + 1) * thickness, "start": start, "angle": angle}
            sectors.append(sector)
            pending.append(sector)
            start += angle
    return sectors, omitted, thickness


def _sector_points(sector, cx, cy):
    inner, outer, start, angle = sector["inner"], sector["outer"], sector["start"], sector["angle"]
    steps = max(2, math.ceil(angle / 0.035))
    points = []
    for index in range(steps + 1):
        theta = start + angle * index / steps
        points.append([cx + outer * math.cos(theta), cy + outer * math.sin(theta)])
    if inner > 0:
        for index in range(steps, -1, -1):
            theta = start + angle * index / steps
            points.append([cx + inner * math.cos(theta), cy + inner * math.sin(theta)])
    return points


def rings_scene(graph, volumes, center=997, max_depth=3):
    by_id, children = build_tree(graph)
    sectors, omitted, thickness = ring_sectors(by_id, children, volumes, center, max_depth)
    cx, cy = RING_LEFT + RING_SIZE / 2, RING_TOP + RING_SIZE / 2
    objects = []
    for sector in sectors:
        record = by_id[sector["id"]]
        objects.append({
            "id": f"sector-{sector['id']}", "type": "polygon",
            "points": _sector_points(sector, cx, cy),
            "fill": record["color"], "stroke": "white", "width": 2,
        })
    center_record = by_id[center]
    objects.append({
        "id": "center-disc", "type": "ellipse", "center": [cx, cy],
        "radii": [thickness, thickness], "fill": center_record["color"], "stroke": "white", "width": 2,
    })
    center_name = center_record["acronym"] if center != 997 else "Brain"
    objects.append(_text("center-label", [cx - len(center_name) * 8, cy + 8], center_name, 26))
    ancestors = []
    current = center_record
    while current is not None:
        ancestors.append(current["acronym"])
        current = by_id.get(current["parent_structure_id"])
    breadcrumb = " / ".join(reversed(ancestors))
    objects.append(_text("breadcrumb", [60, 50], breadcrumb[:64], 22))
    objects.append(_text("rings-title", [LEGEND_LEFT, 56], "Dorothy · Rings", 30))
    subtitle = center_record["name"] if center != 997 else "Whole brain · CCFv3 (2017)"
    objects.append(_text("rings-subtitle", [LEGEND_LEFT, 88], subtitle[:38], 20))
    total = volumes[center] * 25 ** 3 / 1e9
    objects.append(_text("rings-total", [LEGEND_LEFT, 116], f"{total:.1f} mm³ subtree volume", 20))
    top = 160
    ordered = sorted(children.get(center, []), key=lambda identifier: (-volumes.get(identifier, 0), identifier))
    shown = [identifier for identifier in ordered if volumes.get(identifier, 0)]
    limit = 12
    for index, identifier in enumerate(shown[:limit]):
        record = by_id[identifier]
        share = volumes[identifier] / volumes[center]
        y = top + index * 66
        objects.append({
            "id": f"swatch-{identifier}", "type": "rectangle",
            "bounds": [LEGEND_LEFT, y, LEGEND_LEFT + 26, y + 26],
            "fill": record["color"], "stroke": "black", "width": 1,
        })
        objects.append(_text(f"legend-{identifier}", [LEGEND_LEFT + 38, y + 22], f"{record['acronym']} · {share:.1%}", 24))
        objects.append(_text(f"volume-{identifier}", [LEGEND_LEFT + 38, y + 46], f"{volumes[identifier] * 25 ** 3 / 1e9:.2f} mm³", 18))
    footer = top + min(len(shown), limit) * 66 + 20
    if len(shown) > limit:
        rest = sum(volumes[identifier] for identifier in shown[limit:])
        objects.append(_text("more", [LEGEND_LEFT, footer], f"+{len(shown) - limit} more · {rest / volumes[center]:.1%}", 20))
        footer += 30
    objects.append(_text("semantics", [LEGEND_LEFT, footer + 10], "Angle = subtree CCF volume", 18))
    objects.append(_text("omitted", [LEGEND_LEFT, footer + 36], f"{len(sectors)} sectors · {omitted} below angle limit", 18))
    objects.append(_text("renderer", [LEGEND_LEFT, footer + 70], "Deterministic software render", 18))
    objects.append(_text("renderer-detail", [LEGEND_LEFT, footer + 94], "Baobab annular layout", 18))
    objects.append(_text("credit", [LEGEND_LEFT, footer + 128], "Data: Allen Institute · CCFv3", 18))
    objects.append(_text("scope", [LEGEND_LEFT, footer + 162], "Volumes from annotation_25.nrrd;", 16))
    objects.append(_text("scope-2", [LEGEND_LEFT, footer + 184], "angle is not importance or function", 16))
    scene = Scene.from_dict({
        "schema_version": 1,
        "id": f"dorothy-rings-{center}",
        "title": f"Dorothy · Rings {center_record['name']}",
        "canvas": {"width": CANVAS_WIDTH, "height": CANVAS_HEIGHT},
        "objects": objects,
        "constraints": [{"type": "inside_canvas", "object": "*"}],
    })
    report = {
        "instrument": "Dorothy · Rings",
        "center": center,
        "center_name": center_record["name"],
        "depth": max_depth,
        "sectors": len(sectors),
        "omitted": omitted,
        "subtree_mm3": round(total, 6),
        "children": [{
            "id": identifier,
            "acronym": by_id[identifier]["acronym"],
            "share": round(volumes[identifier] / volumes[center], 6),
            "mm3": round(volumes[identifier] * 25 ** 3 / 1e9, 6),
        } for identifier in shown],
        "scene_sha256": scene.digest(),
    }
    return scene, report


def default_rings_document(root=None, center=997, max_depth=3):
    graph = load_graph(root)
    volumes = subtree_volumes(graph, load_volumes(root))
    return rings_scene(graph, volumes, center=center, max_depth=max_depth)
