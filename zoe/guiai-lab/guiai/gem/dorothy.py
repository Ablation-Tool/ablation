"""Dorothy: Allen CCFv3 structure meshes as a native GEM brain atlas scene."""

from __future__ import annotations

from .model import Scene
from .dorothy_data import ATLAS_CITATION, ATLAS_NAME, load_structures
from .spatial3d import Camera, parse_ply, render_triangles

CANVAS_WIDTH = 1600
CANVAS_HEIGHT = 1200
VIEWPORT_WIDTH = 1180
LEGEND_LEFT = 1210


def _text(identifier, position, text, size=22, stroke="black"):
    return {"id": identifier, "type": "text", "position": position, "text": text, "size": size, "stroke": stroke, "fill": "none", "width": 0}


def dorothy_scene(structures, yaw=215.0, pitch=-18.0, distance=None, fov=35.0, shade_levels=16):
    if not structures:
        raise ValueError("Dorothy requires at least one structure")
    items = [(record["id"], parse_ply(record["data"]), record["color"]) for record in structures]
    vertices = [vertex for _identifier, mesh, _color in items for vertex in mesh.vertices]
    fitted = Camera.fit(vertices, yaw=yaw, pitch=pitch, fov=fov)
    camera = fitted if distance is None else Camera(fitted.target, distance, yaw=yaw, pitch=pitch, fov=fov)
    rendered = render_triangles(items, camera, VIEWPORT_WIDTH, CANVAS_HEIGHT, shade_levels=shade_levels)
    objects = [{
        "id": "ccf-mesh", "type": "mesh", "role": "ccf_structures",
        "points": rendered["points"], "fills": rendered["fills"],
        "fill": "none", "stroke": "none", "width": 0,
    }]
    objects.append(_text("atlas-title", [LEGEND_LEFT, 56], "Dorothy", 30))
    objects.append(_text("atlas-subtitle", [LEGEND_LEFT, 88], "Allen Mouse CCFv3 · 2017 meshes", 20))
    top = 130
    for index, record in enumerate(structures):
        y = top + index * 66
        objects.append({
            "id": f"swatch-{record['id']}", "type": "rectangle",
            "bounds": [LEGEND_LEFT, y, LEGEND_LEFT + 26, y + 26],
            "fill": record["color"], "stroke": "black", "width": 1,
        })
        objects.append(_text(f"legend-{record['id']}", [LEGEND_LEFT + 38, y + 22], f"{record['acronym']} · {record['id']}", 24))
        objects.append(_text(f"name-{record['id']}", [LEGEND_LEFT + 38, y + 46], record["name"], 20))
    footer = top + len(structures) * 66 + 26
    camera_state = camera.state()
    objects.append(_text("camera", [LEGEND_LEFT, footer], f"yaw={camera_state['yaw']:g}° pitch={camera_state['pitch']:g}° fov={camera_state['fov']:g}°", 18))
    objects.append(_text("counts", [LEGEND_LEFT, footer + 30], f"{rendered['total']:,} triangles · {len(structures)} structures", 18))
    objects.append(_text("renderer", [LEGEND_LEFT, footer + 58], "Deterministic software render", 18))
    objects.append(_text("renderer-detail", [LEGEND_LEFT, footer + 82], "painter's algorithm · flat shading", 18))
    objects.append(_text("credit", [LEGEND_LEFT, footer + 116], "Data: Allen Institute", 18))
    objects.append(_text("citation", [LEGEND_LEFT, footer + 140], "Wang et al. 2020, Cell 180(5)", 18))
    objects.append(_text("scope", [LEGEND_LEFT, footer + 174], "Atlas geometry only; no registration,", 16))
    objects.append(_text("scope-2", [LEGEND_LEFT, footer + 196], "connectivity, or inference claim", 16))
    scene = Scene.from_dict({
        "schema_version": 1,
        "id": "dorothy-ccf2017",
        "title": "Dorothy · CCFv3 3D brain atlas",
        "canvas": {"width": CANVAS_WIDTH, "height": CANVAS_HEIGHT},
        "objects": objects,
        "constraints": [{"type": "inside_canvas", "object": "*"}],
    })
    report = {
        "instrument": "Dorothy",
        "atlas": ATLAS_NAME,
        "citation": ATLAS_CITATION,
        "structures": [{
            "id": record["id"],
            "acronym": record["acronym"],
            "name": record["name"],
            "color": record["color"],
            "triangles": rendered["counts"][record["id"]],
            "sha256": record["sha256"],
        } for record in structures],
        "vertices": len(vertices),
        "triangles": rendered["total"],
        "camera": camera_state,
        "shade_levels": shade_levels,
        "renderer": "deterministic software projection, two-sided flat shading, painter's algorithm",
        "scene_sha256": scene.digest(),
    }
    return scene, report


def default_dorothy_document(root=None, **options):
    return dorothy_scene(load_structures(root), **options)
