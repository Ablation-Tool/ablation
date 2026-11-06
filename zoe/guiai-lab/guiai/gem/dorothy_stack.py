"""Dorothy Stack: real CCF meshes cut into coronal slabs and exploded apart.

Instead of one fully framed brain, the long axis is sliced into slabs that
are separated along the same axis, so interior layers become visible.
"""

from __future__ import annotations

from .dorothy import CANVAS_HEIGHT, CANVAS_WIDTH, LEGEND_LEFT, VIEWPORT_WIDTH, _text
from .dorothy_data import load_structures
from .model import Scene
from .spatial3d import Camera, Mesh, parse_ply, render_triangles


def stack_meshes(items, slices=8, gap_ratio=0.22):
    if not 2 <= slices <= 32:
        raise ValueError("stack slices must be 2-32")
    vertices = [vertex for _identifier, mesh, _color in items for vertex in mesh.vertices]
    extents = []
    for axis in range(3):
        values = [vertex[axis] for vertex in vertices]
        extents.append(max(values) - min(values))
    axis = extents.index(max(extents))
    minimum = min(vertex[axis] for vertex in vertices)
    extent = extents[axis]
    gap = extent * gap_ratio
    slabs = []
    for index in range(slices):
        slabs.append({"index": index, "triangles": 0})
    exploded = []
    for identifier, mesh, color in items:
        grouped = [[] for _ in range(slices)]
        for face in mesh.faces:
            center = sum(mesh.vertices[corner][axis] for corner in face) / 3
            index = min(slices - 1, max(0, int((center - minimum) / extent * slices)))
            grouped[index].append(face)
        for index, faces in enumerate(grouped):
            if not faces:
                continue
            used = sorted({corner for face in faces for corner in face})
            remap = {corner: position for position, corner in enumerate(used)}
            offset = index * gap
            shifted = []
            for corner in used:
                vertex = list(mesh.vertices[corner])
                vertex[axis] += offset
                shifted.append(tuple(vertex))
            remapped = [(remap[a], remap[b], remap[c]) for a, b, c in faces]
            exploded.append(((identifier, index), Mesh(shifted, remapped), color))
            slabs[index]["triangles"] += len(faces)
    return exploded, slabs, axis, gap


def stack_scene(structures, slices=8, yaw=None, pitch=None, fov=35.0):
    yaw = 215.0 if yaw is None else yaw
    pitch = -18.0 if pitch is None else pitch
    items = [(record["id"], __import__("guiai.gem.spatial3d", fromlist=["parse_ply"]).parse_ply(record["data"]), record["color"]) for record in structures]
    exploded, slabs, axis, gap = stack_meshes(items, slices=slices)
    vertices = [vertex for _identifier, mesh, _color in exploded for vertex in mesh.vertices]
    camera = Camera.fit(vertices, yaw=yaw, pitch=pitch, fov=fov)
    rendered = render_triangles(exploded, camera, VIEWPORT_WIDTH, CANVAS_HEIGHT)
    objects = [{
        "id": "stack-mesh", "type": "mesh", "role": "stacked_slabs",
        "points": rendered["points"], "fills": rendered["fills"],
        "fill": "none", "stroke": "none", "width": 0,
    }]
    objects.append(_text("stack-title", [LEGEND_LEFT, 56], "Dorothy · Stack", 30))
    objects.append(_text("stack-subtitle", [LEGEND_LEFT, 88], f"{slices} coronal slabs · exploded", 20))
    top = 130
    for index, record in enumerate(structures):
        y = top + index * 66
        objects.append({
            "id": f"swatch-{record['id']}", "type": "rectangle",
            "bounds": [LEGEND_LEFT, y, LEGEND_LEFT + 26, y + 26],
            "fill": record["color"], "stroke": "black", "width": 1,
        })
        objects.append(_text(f"legend-{record['id']}", [LEGEND_LEFT + 38, y + 22], record["acronym"], 24))
        objects.append(_text(f"name-{record['id']}", [LEGEND_LEFT + 38, y + 46], record["name"], 20))
    footer = top + len(structures) * 66 + 26
    objects.append(_text("axis", [LEGEND_LEFT, footer], f"Long axis: {'xyz'[axis]} · gap {gap:.0f} CCF units", 18))
    objects.append(_text("counts", [LEGEND_LEFT, footer + 28], f"{rendered['total']:,} triangles in {len(exploded)} slab meshes", 18))
    objects.append(_text("renderer", [LEGEND_LEFT, footer + 62], "Deterministic software render", 18))
    objects.append(_text("renderer-detail", [LEGEND_LEFT, footer + 86], "painter's algorithm · flat shading", 18))
    objects.append(_text("credit", [LEGEND_LEFT, footer + 120], "Data: Allen Institute · CCFv3", 18))
    objects.append(_text("scope", [LEGEND_LEFT, footer + 154], "Slabs are open meshes, not capped", 16))
    objects.append(_text("scope-2", [LEGEND_LEFT, footer + 176], "sections; anatomy is illustrative", 16))
    scene = Scene.from_dict({
        "schema_version": 1,
        "id": "dorothy-stack",
        "title": "Dorothy · Stack exploded coronal slabs",
        "canvas": {"width": CANVAS_WIDTH, "height": CANVAS_HEIGHT},
        "objects": objects,
        "constraints": [{"type": "inside_canvas", "object": "*"}],
    })
    report = {
        "instrument": "Dorothy · Stack",
        "slices": slices,
        "axis": "xyz"[axis],
        "gap": gap,
        "slabs": slabs,
        "triangles": rendered["total"],
        "camera": camera.state(),
        "scene_sha256": scene.digest(),
    }
    return scene, report


def default_stack_document(root=None, **options):
    return stack_scene(load_structures(root), **options)
