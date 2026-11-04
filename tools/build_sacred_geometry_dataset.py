from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys
from xml.etree import ElementTree

import numpy as np
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gem-lab"))
from gem.events import atomic_write, sha256
from gem.model import Scene
from gem.render import draw_cairo, write_svg
from gem.runner import export_run, replay

ARCHIVE_SHA256 = "9f511506d8566e4a6744daa2eb8d03c6debcbc9749cdc39447b21005611bbff2"
SOURCE = ROOT / "experiments" / "sacred-geometry" / "source"
DIST = ROOT / "experiments" / "sacred-geometry" / "dist"

CURATED = {
    "Screenshot_20261104-142508.png": {
        "title": "Set Theory",
        "math": [
            "Sets, elements, subsets, union and intersection with Venn diagrams, power sets and infinite sets.",
        ],
        "region": [0.0, 0.0, 1.0, 1.0],
    },
    "Screenshot_20261104-142605.png": {
        "title": "Function mapping",
        "math": [
            "f(x) = x²",
            "A = {-1, 1, 2}; B = {1, 4, 7}",
            "-1 ↦ 1; 1 ↦ 4; 2 ↦ 7",
            "Each element of domain A has exactly one arrow. 7 is in B but is not an output, so the range is {1, 4}.",
        ],
        "region": [0.03, 0.02, 0.96, 0.80],
    },
    "Screenshot_20261104-142622.png": {
        "title": "Piecewise functions",
        "math": [
            "A large left brace lists different rules for different inputs:",
            "f(x) = { x + 1, x < 0; x², x ≥ 0 }",
            "So f(−3) = −2 and f(3) = 9.",
        ],
        "region": [0.0, 0.0, 1.0, 1.0],
    },
    "Screenshot_20261104-142637.png": {
        "title": "Summation and product notation",
        "math": [
            "Read aloud: “the sum from i equals 1 to n of a sub i”.",
            "∑ U+2211 — summation sign: add the terms for every value of the index.",
            "Π U+220F — product sign: multiply the terms for every value of the index.",
            "∑i∈S — sum over a set: add the terms for every element of set S. U+2211 U+2208.",
            "∑∞ U+2211 U+221E — infinite series: the sum of infinitely many terms, defined as a limit.",
            "Unicode has separate characters for the operators ∑ (U+2211) and Π (U+220F) and for the Greek letters Σ (U+03A3) and Π (U+03A0). Use the operator characters for sums and products.",
        ],
        "region": [0.0, 0.0, 1.0, 1.0],
    },
    "Screenshot_20261104-142703.png": {
        "title": "Modular arithmetic",
        "math": [
            "15 mod 12 = 3",
            "15 ≡ 3 (mod 12)",
            "Count 15 steps from 0: one full turn, then 3.",
            "Modular arithmetic works like a clock: after 11 the count starts again at 0.",
        ],
        "region": [0.03, 0.02, 0.55, 0.80],
    },
    "Screenshot_20261104-142802.png": {
        "title": "Circle and centre",
        "math": [
            "circle — the circle with the given centre (in some textbooks).",
            "U+2299.",
        ],
        "region": [0.0, 0.0, 1.0, 1.0],
    },
    "Screenshot_20261104-142821.png": {
        "title": "Angle units",
        "math": [
            "′ U+2032 — prime (minute of arc): one 60th of a degree.",
            "″ U+2033 — double prime (second of arc): one 60th of a minute.",
            "rad — radian: the SI unit of angle, arc length divided by radius.",
        ],
        "region": [0.0, 0.0, 1.0, 1.0],
    },
    "Screenshot_20261104-142841.png": {
        "title": "Circle formulas",
        "math": [
            "arc AB (orange)",
            "d = 2r",
            "C = 2πr = πd",
            "A = πr²",
            "The arc AB is the part of the circle between A and B.",
            "Circle formulas: C = 2πr; A = πr²; s = rθ.",
            "r — radius; C — circumference (distance around the circle); A — area; s — arc length for an angle θ at the centre, in radians.",
        ],
        "region": [0.03, 0.02, 0.96, 0.45],
    },
    "hub-loop.png": {
        "title": "Hub loop",
        "math": [
            "A central hub with h1 through h8 and v1, v2, v4, v5 arranged around it.",
            "h1 has no loop label; h2 through h8 are marked [loop].",
            "The 12 positions correspond to a modular clock while preserving the hub-loop topology.",
        ],
        "region": [0.0, 0.0, 1.0, 1.0],
    },
}


def polar(cx, cy, radius, degrees):
    angle = math.radians(degrees)
    return [round(cx + radius * math.cos(angle)), round(cy + radius * math.sin(angle))]


def font(size):
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", size)
    except OSError:
        return ImageFont.load_default()


def make_hub_loop_assets():
    SOURCE.mkdir(parents=True, exist_ok=True)
    svg = ElementTree.Element("svg", {"width": "1200", "height": "900", "viewBox": "0 0 1200 900", "xmlns": "http://www.w3.org/2000/svg"})
    image = Image.new("RGBA", (1200, 900), "#101010")
    draw = ImageDraw.Draw(image)
    center = [600, 450]
    h_positions = [(600, 130), (826, 224), (920, 450), (826, 676), (600, 770), (374, 676), (280, 450), (374, 224)]
    v_positions = [(770, 330), (770, 570), (430, 570), (430, 330)]
    v_names = ["v2", "v1", "v4", "v5"]
    for index, position in enumerate(h_positions, 1):
        x, y = position
        draw.line((center[0], center[1], x, y), fill="#00b000", width=3)
        ElementTree.SubElement(svg, "line", {"x1": str(center[0]), "y1": str(center[1]), "x2": str(x), "y2": str(y), "stroke": "#00b000", "stroke-width": "3"})
        draw.text((x - 24, y - 12), f"h{index}", font=font(30), fill="#00e000")
        label = ElementTree.SubElement(svg, "text", {"x": str(x - 24), "y": str(y), "fill": "#00e000", "font-family": "monospace", "font-size": "30"})
        label.text = f"h{index}"
        if index > 1:
            draw.text((x - 40, y + 32), "[loop]", font=font(22), fill="#00e000")
            loop = ElementTree.SubElement(svg, "text", {"x": str(x - 40), "y": str(y + 32), "fill": "#00e000", "font-family": "monospace", "font-size": "22"})
            loop.text = "[loop]"
    for position, name in zip(v_positions, v_names):
        x, y = position
        draw.line((center[0], center[1], x, y), fill="#00b000", width=3)
        ElementTree.SubElement(svg, "line", {"x1": str(center[0]), "y1": str(center[1]), "x2": str(x), "y2": str(y), "stroke": "#00b000", "stroke-width": "3"})
        draw.text((x - 20, y - 10), name, font=font(28), fill="#00e000")
        label = ElementTree.SubElement(svg, "text", {"x": str(x - 20), "y": str(y), "fill": "#00e000", "font-family": "monospace", "font-size": "28"})
        label.text = name
    draw.text((545, 438), "( hub )", font=font(32), fill="#00e000")
    ElementTree.SubElement(svg, "text", {"x": "545", "y": "450", "fill": "#00e000", "font-family": "monospace", "font-size": "32"}).text = "( hub )"
    image.save(SOURCE / "hub-loop.png")
    (SOURCE / "hub-loop.svg").write_text(ElementTree.tostring(svg, encoding="unicode") + "\n", encoding="utf-8")


def components(mask):
    visited = np.zeros(mask.shape, dtype=bool)
    found = []
    height, width = mask.shape
    for y, x in zip(*np.nonzero(mask)):
        if visited[y, x]:
            continue
        queue = deque([(y, x)])
        points = []
        while queue:
            cy, cx = queue.popleft()
            if cy < 0 or cy >= height or cx < 0 or cx >= width or visited[cy, cx] or not mask[cy, cx]:
                continue
            visited[cy, cx] = True
            points.append((cx, cy))
            for dy in (-1, 0, 1):
                for dx in (-1, 0, 1):
                    if dx or dy:
                        queue.append((cy + dy, cx + dx))
        if len(points) >= 8:
            xs, ys = zip(*points)
            found.append((min(xs), min(ys), max(xs) + 1, max(ys) + 1, len(points)))
    found.sort(key=lambda item: item[4], reverse=True)
    return found[:32]


def measure(image, region):
    width, height = image.size
    x0, y0 = round(region[0] * width), round(region[1] * height)
    x1, y1 = round(region[2] * width), round(region[3] * height)
    crop = np.asarray(image.crop((x0, y0, x1, y1)), dtype=np.uint8)
    corners = np.concatenate((crop[:16, :16], crop[:16, -16:], crop[-16:, :16], crop[-16:, -16:]))
    background = np.median(corners.reshape(-1, 4), axis=0).astype(np.uint8).tolist()
    delta = np.abs(crop.astype(np.int16) - np.asarray(background, dtype=np.int16)).max(axis=2)
    mask = delta > 32
    entries = []
    for left, top, right, bottom, area in components(mask):
        component = crop[top:bottom, left:right]
        entries.append({
            "bounds": [int(left + x0), int(top + y0), int(right + x0), int(bottom + y0)],
            "area": int(area),
            "sha256": hashlib.sha256(component.tobytes()).hexdigest(),
        })
    packed = (crop[:, :, 0].astype(np.uint32) << 24 | crop[:, :, 1].astype(np.uint32) << 16 | crop[:, :, 2].astype(np.uint32) << 8 | crop[:, :, 3].astype(np.uint32))
    values, counts = np.unique(packed, return_counts=True)
    order = np.argsort(-counts)[:8]
    palette = [{"rgba": [int(values[index] >> 24 & 255), int(values[index] >> 16 & 255), int(values[index] >> 8 & 255), int(values[index] & 255)], "count": int(counts[index])} for index in order]
    return {
        "background_rgba": background,
        "foreground_pixels": int(mask.sum()),
        "palette": palette,
        "components": entries,
    }


def write_preview_png(scene, path):
    import cairo

    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, 1200, 840)
    context = cairo.Context(surface)
    draw_cairo(context, scene, 1200, 840)
    surface.write_to_png(str(path))


def write_json(path, document):
    atomic_write(path, json.dumps(document, indent=2, ensure_ascii=False) + "\n")


def scene_document():
    objects = []
    constraints = [{"type": "inside_canvas", "object": "*"}]
    center = [5000, 3500]
    for radius, width in ((3000, 40), (2300, 35), (1600, 30)):
        objects.append({"id": f"ring-{radius}", "type": "ellipse", "role": "ring", "center": center, "radii": [radius, radius], "fill": "none", "stroke": "#000080", "width": width})
    objects.extend([
        {"id": "left-circle", "type": "ellipse", "role": "circle", "center": [3500, 3500], "radii": [1200, 1200], "fill": "none", "stroke": "#000080", "width": 30},
        {"id": "right-circle", "type": "ellipse", "role": "circle", "center": [6500, 3500], "radii": [1200, 1200], "fill": "none", "stroke": "#000080", "width": 30},
        {"id": "woven-diamond", "type": "polygon", "role": "diamond", "points": [[5000, 1900], [6600, 3500], [5000, 5100], [3400, 3500]], "fill": "none", "stroke": "#000080", "width": 50},
        {"id": "inner-diamond", "type": "polygon", "role": "diamond", "points": [[5000, 2700], [5800, 3500], [5000, 4300], [4200, 3500]], "fill": "#000080", "stroke": "white", "width": 20},
    ])
    constraints.append({"type": "symmetric", "a": "left-circle", "b": "right-circle", "axis": "x", "value": 5000})
    h_names = [f"h{index}" for index in range(1, 9)]
    h_angles = [-90, -45, 0, 45, 90, 135, 180, 225]
    for name, angle in zip(h_names, h_angles):
        endpoint = polar(5000, 3500, 3000, angle)
        objects.append({"id": f"spoke-{name}", "type": "line", "role": "spoke", "points": [center, endpoint], "fill": "none", "stroke": "#000080", "width": 15})
        objects.append({"id": f"label-{name}", "type": "text", "role": "label", "position": [endpoint[0] - 80, endpoint[1] + 30], "text": name, "size": 180, "fill": "none", "stroke": "#000080"})
        if name != "h1":
            loop_position = polar(5000, 3500, 3300, angle)
            objects.append({"id": f"loop-{name}", "type": "text", "role": "loop-label", "position": [loop_position[0] - 140, loop_position[1] + 30], "text": "[loop]", "size": 140, "fill": "none", "stroke": "#000080"})
    for name, angle in zip(("v2", "v1", "v4", "v5"), (-45, 45, 135, 225)):
        endpoint = polar(5000, 3500, 1900, angle)
        objects.append({"id": f"spoke-{name}", "type": "line", "role": "spoke", "points": [center, endpoint], "fill": "none", "stroke": "#000080", "width": 15})
        objects.append({"id": f"label-{name}", "type": "text", "role": "label", "position": [endpoint[0] - 70, endpoint[1] + 30], "text": name, "size": 180, "fill": "none", "stroke": "#000080"})
    arc_points = [polar(5000, 3500, 3000, angle) for angle in range(-90, 1, 10)]
    objects.extend([
        {"id": "arc-ab", "type": "polyline", "role": "arc", "points": arc_points, "fill": "none", "stroke": "orange", "width": 60},
        {"id": "arc-label", "type": "text", "role": "label", "position": [7200, 1800], "text": "arc AB", "size": 180, "fill": "none", "stroke": "orange"},
        {"id": "hub-label", "type": "text", "role": "hub", "position": [4700, 3600], "text": "( hub )", "size": 300, "fill": "none", "stroke": "#000080"},
        {"id": "formulas", "type": "text", "role": "formula", "position": [500, 6300], "text": "C = 2πr · A = πr² · s = rθ · 15 mod 12 = 3", "size": 200, "fill": "none", "stroke": "#000080"},
        {"id": "measurement", "type": "text", "role": "measurement", "position": [500, 6600], "text": "Aτ = 3 · Aᶜ = 50254 · M = 0 · advisory only", "size": 180, "fill": "none", "stroke": "#000080"},
        {"id": "scope", "type": "text", "role": "scope", "position": [2200, 6850], "text": "Measured geometry · forecast breadth only, not correctness or safety", "size": 180, "fill": "none", "stroke": "#000080"},
    ])
    return Scene.from_dict({
        "schema_version": 1,
        "id": "sacred-geometry-volume",
        "title": "Sacred geometry: accessible volume, complement, momentum, and the hub loop",
        "prompt": "Nested circles, symmetric circles, a woven diamond, 12 hub-loop positions, modular arithmetic, and circle formulas.",
        "canvas": {"width": 10000, "height": 7000},
        "objects": objects,
        "constraints": constraints,
    })


def main():
    make_hub_loop_assets()
    if DIST.exists():
        shutil.rmtree(DIST)
    (DIST / "ocr").mkdir(parents=True)
    arrays = {}
    images = []
    measurements = {}
    source_manifest = {"schema_version": 1, "archive_sha256": ARCHIVE_SHA256, "files": []}
    for index, (filename, curated) in enumerate(CURATED.items(), 1):
        source_path = SOURCE / filename
        image = Image.open(source_path).convert("RGBA")
        key = f"image_{index:02d}"
        arrays[key] = np.asarray(image, dtype=np.uint8)
        source_sha256 = sha256(source_path)
        ocr_path = DIST / "ocr" / f"{key}.txt"
        result = subprocess.run(["tesseract", str(source_path), "stdout"], capture_output=True, text=True, check=True)
        ocr_path.write_text(result.stdout, encoding="utf-8")
        measurement = measure(image, curated["region"])
        measurements[key] = measurement
        source_manifest["files"].append({"name": filename, "sha256": source_sha256})
        images.append({
            "key": key,
            "source": f"source/{filename}",
            "title": curated["title"],
            "sha256": source_sha256,
            "mode": image.mode,
            "width": image.width,
            "height": image.height,
            "diagram_region": curated["region"],
            "math": curated["math"],
            "ocr": f"ocr/{key}.txt",
            "measurement": f"measurements.json#{key}",
            "pixel_vector": {
                "key": key,
                "dtype": str(arrays[key].dtype),
                "shape": list(arrays[key].shape),
                "strides": list(arrays[key].strides),
                "sha256": hashlib.sha256(arrays[key].tobytes()).hexdigest(),
            },
        })
    np.savez_compressed(DIST / "pixel-vectors.npz", **arrays)
    write_json(DIST / "math-content.json", {"schema_version": 1, "images": images})
    write_json(DIST / "measurements.json", measurements)
    write_json(DIST / "source-manifest.json", source_manifest)
    scene = scene_document()
    run = export_run(scene, DIST / "run")
    write_preview_png(scene, DIST / "preview.png")
    replayed = replay(run.path)
    if not replayed.matches_recorded or not replayed.passed:
        raise RuntimeError("sacred-geometry VDI replay failed")
    alignment_path = DIST / "alignment" / "landmark-alignment-analysis.json"
    alignment = json.loads(alignment_path.read_text(encoding="utf-8")) if alignment_path.exists() else None
    write_json(DIST / "verification.json", {
        "schema_version": 1,
        "dataset_images": len(images),
        "ocr_files": len(images),
        "pixel_vectors": len(arrays),
        "component_images": len(measurements),
        "vdi_replay": replayed.to_dict(),
        "landmark_alignment": alignment["checks"] if alignment else None,
    })
    manifest = {
        "schema_version": 1,
        "dataset": "sacred-geometry",
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "archive_sha256": ARCHIVE_SHA256,
        "images": images,
        "run": str(run.path.relative_to(ROOT)),
        "scene_digest": run.manifest["scene_digest"],
        "passed": run.passed,
        "landmark_alignment": {
            "analysis": "alignment/landmark-alignment-analysis.json",
            "model": "alignment/landmark-alignment-model.svg",
            "preview": "alignment/alignment-preview.png",
        } if alignment else None,
    }
    write_json(DIST / "manifest.json", manifest)
    files = sorted(path for path in DIST.rglob("*") if path.is_file() and path.name != "SHA256SUMS.txt")
    lines = [f"{sha256(path)}  {path.relative_to(DIST)}" for path in files]
    (DIST / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    for line in lines:
        expected, name = line.split("  ", 1)
        assert sha256(DIST / name) == expected, name
    print(json.dumps({"images": len(images), "scene_digest": run.manifest["scene_digest"], "passed": run.passed, "dist": str(DIST)}, indent=2))


if __name__ == "__main__":
    main()
