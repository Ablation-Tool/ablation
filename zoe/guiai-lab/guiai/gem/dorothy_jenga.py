"""Dorothy Jenga: the brain as a familiar block tower, one region per layer.

Layers are sorted by true CCF voxel volume, largest at the bottom. Three
blocks per layer alternate orientation like a real Jenga set. The exploded
layout separates every layer; the pull layout slides one block out along
its long axis so a single region can be inspected from every side.
"""

from __future__ import annotations

from .dorothy import CANVAS_HEIGHT, CANVAS_WIDTH, LEGEND_LEFT, VIEWPORT_WIDTH, _text
from .dorothy_data import load_structures, load_volumes
from .model import Scene
from .spatial3d import Camera, Mesh, render_triangles

LAYOUTS = ("tower", "exploded", "pull")
BLOCK_LENGTH = 3.0
BLOCK_WIDTH = 1.0
BLOCK_HEIGHT = 0.55
BLOCK_GAP = 0.04


def _box(center, length, width, height, axis):
    cx, cy, cz = center
    hx = length / 2 if axis == "x" else width / 2
    hz = width / 2 if axis == "x" else length / 2
    hy = height / 2
    vertices = [
        (cx + sx * hx, cy + sy * hy, cz + sz * hz)
        for sx, sy, sz in (
            (-1, -1, -1), (1, -1, -1), (1, 1, -1), (-1, 1, -1),
            (-1, -1, 1), (1, -1, 1), (1, 1, 1), (-1, 1, 1),
        )
    ]
    quads = [(0, 1, 2, 3), (4, 5, 6, 7), (0, 1, 5, 4), (2, 3, 7, 6), (0, 3, 7, 4), (1, 2, 6, 5)]
    faces = []
    for quad in quads:
        faces.append((quad[0], quad[1], quad[2]))
        faces.append((quad[0], quad[2], quad[3]))
    return Mesh(vertices, faces)


def jenga_blocks(structures, volumes, layout="tower", selected=None):
    if layout not in LAYOUTS:
        raise ValueError(f"Jenga layout must be one of {', '.join(LAYOUTS)}")
    layers = []
    for record in structures:
        count = volumes.get(record["id"])
        if not count:
            raise ValueError(f"structure {record['id']} has no annotation volume; run `gem dorothy --fetch`")
        layers.append({"record": record, "voxels": count, "mm3": count * 25 ** 3 / 1e9})
    layers.sort(key=lambda layer: (-layer["voxels"], layer["record"]["id"]))
    maximum = layers[0]["voxels"]
    if layout == "pull":
        identifiers = [layer["record"]["id"] for layer in layers]
        if selected is None:
            selected = 549 if 549 in identifiers else identifiers[len(identifiers) // 2]
        if selected not in identifiers:
            raise ValueError(f"structure {selected} is not part of this Jenga set")
    items = []
    y = 0.0
    previous_height = 0.0
    for index, layer in enumerate(layers):
        scale = (layer["voxels"] / maximum) ** (1 / 3)
        axis = "x" if index % 2 == 0 else "z"
        gap = 0.02 * BLOCK_HEIGHT if layout == "tower" else BLOCK_HEIGHT * 1.4 if layout == "exploded" else BLOCK_HEIGHT * 0.25
        height = BLOCK_HEIGHT * scale
        if index:
            y -= previous_height / 2 + height / 2 + gap
        previous_height = height
        layer["scale"] = scale
        layer["level"] = index + 1
        layer["y"] = y
        layer["blocks"] = []
        for position in range(3):
            offset = (position - 1) * (BLOCK_WIDTH * scale + BLOCK_GAP)
            center = [0.0, y, offset] if axis == "x" else [offset, y, 0.0]
            pulled = layout == "pull" and layer["record"]["id"] == selected and position == 1
            if pulled:
                slide = 1.15 * BLOCK_LENGTH * scale
                center[0 if axis == "x" else 2] += slide
            block = _box(
                center,
                BLOCK_LENGTH * scale, BLOCK_WIDTH * scale, BLOCK_HEIGHT * scale, axis,
            )
            layer["blocks"].append({"position": position, "pulled": pulled})
            items.append((f"{layer['record']['id']}-{position}", block, layer["record"]["color"]))
    return items, layers, selected


def jenga_scene(structures, volumes, layout="tower", selected=None, yaw=None, pitch=None, fov=32.0):
    yaw = 35.0 if yaw is None else yaw
    pitch = -22.0 if pitch is None else pitch
    items, layers, selected = jenga_blocks(structures, volumes, layout=layout, selected=selected)
    vertices = [vertex for _identifier, block, _color in items for vertex in block.vertices]
    camera = Camera.fit(vertices, yaw=yaw, pitch=pitch, fov=fov)
    rendered = render_triangles(items, camera, VIEWPORT_WIDTH, CANVAS_HEIGHT)
    objects = [{
        "id": "jenga-mesh", "type": "mesh", "role": "jenga_blocks",
        "points": rendered["points"], "fills": rendered["fills"],
        "fill": "none", "stroke": "none", "width": 0,
    }]
    objects.append(_text("jenga-title", [LEGEND_LEFT, 56], "Dorothy · Jenga", 30))
    subtitle = {"tower": "12 regions · 36 blocks", "exploded": "exploded · every layer visible", "pull": "one block pulled out"}[layout]
    objects.append(_text("jenga-subtitle", [LEGEND_LEFT, 88], subtitle, 20))
    top = 130
    for layer in reversed(layers):
        y = top + (len(layers) - layer["level"]) * 66
        record = layer["record"]
        objects.append({
            "id": f"swatch-{record['id']}", "type": "rectangle",
            "bounds": [LEGEND_LEFT, y, LEGEND_LEFT + 26, y + 26],
            "fill": record["color"], "stroke": "black", "width": 1,
        })
        label = f"{layer['level']:2} {record['acronym']}"
        if layout == "pull" and record["id"] == selected:
            label += " ← pulled"
        objects.append(_text(f"legend-{record['id']}", [LEGEND_LEFT + 38, y + 22], label, 24))
        objects.append(_text(f"volume-{record['id']}", [LEGEND_LEFT + 38, y + 46], f"{layer['mm3']:.1f} mm³ · scale {layer['scale']:.2f}", 18))
    footer = top + len(layers) * 66 + 26
    objects.append(_text("order", [LEGEND_LEFT, footer], "Bottom → top: largest → smallest", 18))
    objects.append(_text("volumes", [LEGEND_LEFT, footer + 28], "Layer scale = CCF voxel volume^1/3", 18))
    objects.append(_text("renderer", [LEGEND_LEFT, footer + 62], "Deterministic software render", 18))
    objects.append(_text("renderer-detail", [LEGEND_LEFT, footer + 86], "painter's algorithm · flat shading", 18))
    objects.append(_text("credit", [LEGEND_LEFT, footer + 120], "Data: Allen Institute · CCFv3", 18))
    objects.append(_text("scope", [LEGEND_LEFT, footer + 154], "Volumes from annotation_25.nrrd", 16))
    objects.append(_text("scope-2", [LEGEND_LEFT, footer + 176], "block geometry is illustrative", 16))
    scene = Scene.from_dict({
        "schema_version": 1,
        "id": f"dorothy-jenga-{layout}",
        "title": f"Dorothy · Jenga {layout} brain atlas",
        "canvas": {"width": CANVAS_WIDTH, "height": CANVAS_HEIGHT},
        "objects": objects,
        "constraints": [{"type": "inside_canvas", "object": "*"}],
    })
    report = {
        "instrument": "Dorothy · Jenga",
        "layout": layout,
        "selected_structure": selected,
        "blocks": len(items),
        "triangles": rendered["total"],
        "layers": [{
            "level": layer["level"],
            "id": layer["record"]["id"],
            "acronym": layer["record"]["acronym"],
            "volume_mm3": round(layer["mm3"], 6),
            "voxels": layer["voxels"],
            "scale": round(layer["scale"], 6),
            "pulled_blocks": sum(block["pulled"] for block in layer["blocks"]),
        } for layer in layers],
        "camera": camera.state(),
        "scene_sha256": scene.digest(),
    }
    return scene, report


def default_jenga_document(root=None, layout="tower", selected=None, **options):
    from .dorothy_data import load_graph, subtree_volumes
    volumes = subtree_volumes(load_graph(root), load_volumes(root))
    return jenga_scene(load_structures(root), volumes, layout=layout, selected=selected, **options)
