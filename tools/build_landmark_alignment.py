import hashlib
import json
import math
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gem-lab"))
from gem.events import atomic_write
SOURCE = ROOT / "experiments" / "sacred-geometry" / "source" / "Untitled drawing (1).png"
DIST = ROOT / "experiments" / "sacred-geometry" / "dist" / "alignment"

P = np.array([[101.0, 114.0], [285.0, 159.0]])
Q = np.array([[345.0, 35.0], [500.0, 205.0]])
REFERENCE_A = np.array([[1.0080544021, -0.6773779995], [0.6773779995, 1.0080544021]])
REFERENCE_T = np.array([320.40759734, -148.33337978])


def similarity_procrustes(source, target):
    source_center = source.mean(axis=0)
    target_center = target.mean(axis=0)
    centered_source = source - source_center
    centered_target = target - target_center
    u, singular, vt = np.linalg.svd(centered_source.T @ centered_target)
    rotation = vt.T @ u.T
    if np.linalg.det(rotation) < 0:
        u[:, -1] *= -1
        rotation = vt.T @ u.T
    scale = singular.sum() / np.square(centered_source).sum()
    matrix = scale * rotation
    translation = target_center - matrix @ source_center
    return matrix, translation, rotation, scale, singular


def affine_least_squares(source, target):
    design = np.zeros((4, 6))
    for index, (x, y) in enumerate(source):
        design[2 * index] = [x, y, 1, 0, 0, 0]
        design[2 * index + 1] = [0, 0, 0, x, y, 1]
    coefficients, _residuals, rank, _ = np.linalg.lstsq(design, target.reshape(-1), rcond=None)
    matrix = np.array([
        [coefficients[0], coefficients[1], coefficients[2]],
        [coefficients[3], coefficients[4], coefficients[5]],
    ])
    return matrix, rank


def error(source, target, matrix, translation):
    if matrix.shape == (2, 3):
        predicted = source @ matrix[:, :2].T + matrix[:, 2]
    else:
        predicted = source @ matrix.T + translation
    errors = np.linalg.norm(predicted - target, axis=1)
    return predicted, {
        "rms": float(np.sqrt(np.mean(np.square(errors)))),
        "max": float(errors.max()),
    }


def text(draw, xy, value, size=20, fill="#202020"):
    try:
        face = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", size)
    except OSError:
        face = ImageFont.load_default()
    draw.text(xy, value, fill=fill, font=face)


def preview(similarity, affine, source, target, checks):
    DIST.mkdir(parents=True, exist_ok=True)
    original = Image.open(SOURCE).convert("RGBA")
    original.thumbnail((640, 480))
    image = Image.new("RGBA", (1280, 600), "white")
    image.paste(original, (0, 60))
    draw = ImageDraw.Draw(image)
    text(draw, (20, 20), "Source landmarks", 24)
    text(draw, (680, 20), "Procrustes alignment", 24)
    scale = 0.55
    for index, (point, color) in enumerate(zip(source, ("#e03030", "#e03030"))):
        x, y = 640 + point[0] * scale, 60 + point[1] * scale
        draw.ellipse((x - 7, y - 7, x + 7, y + 7), fill=color)
        text(draw, (x + 10, y - 10), f"p{index + 1}", 18)
    for index, point in enumerate(target):
        x, y = 640 + point[0] * scale, 60 + point[1] * scale
        draw.ellipse((x - 7, y - 7, x + 7, y + 7), fill="#2030c0")
        text(draw, (x + 10, y - 10), f"q{index + 1}", 18)
    transformed = source @ similarity[0].T + similarity[1]
    for index, point in enumerate(transformed):
        x, y = 640 + point[0] * scale, 60 + point[1] * scale
        draw.ellipse((x - 5, y - 5, x + 5, y + 5), outline="#109030", width=3)
    draw.line((690, 450, 930, 450), fill="#606060", width=2)
    draw.line((690, 450, 690, 470), fill="#606060", width=2)
    draw.line((930, 450, 930, 470), fill="#606060", width=2)
    text(draw, (680, 490), f"scale={checks['scale']:.10f}  rotation={checks['rotation_degrees']:.10f} deg", 18)
    text(draw, (680, 520), f"det(A)={checks['area_scale']:.10f}  max error={checks['max_error']:.2e}px", 18)
    text(draw, (680, 550), "Affine fit: least-norm, nullity=2 (not unique)", 18)
    image.save(DIST / "alignment-preview.png")


def svg_preview(matrix, translation, checks):
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="430" viewBox="0 0 1100 430">
<rect width="1100" height="430" fill="white"/>
<text x="35" y="45" font-family="monospace" font-size="24">Similarity / affine landmark alignment</text>
<text x="35" y="85" font-family="monospace" font-size="20">p1 = (101,114) → q1 = (345,35)    p2 = (285,159) → q2 = (500,205)</text>
<text x="35" y="120" font-family="monospace" font-size="20">q = A p + t</text>
<text x="35" y="155" font-family="monospace" font-size="20">A = [{matrix[0,0]:.10f}, {matrix[0,1]:.10f}; {matrix[1,0]:.10f}, {matrix[1,1]:.10f}]</text>
<text x="35" y="190" font-family="monospace" font-size="20">t = ({translation[0]:.8f}, {translation[1]:.8f})</text>
<text x="35" y="225" font-family="monospace" font-size="20">scale = {checks['scale']:.10f}; rotation = {checks['rotation_degrees']:.10f}°; det A = {checks['area_scale']:.10f}</text>
<text x="35" y="260" font-family="monospace" font-size="20">SVD Procrustes: centered P,Q → H = PᵀQ = UΣVᵀ → R = VUᵀ</text>
<text x="35" y="295" font-family="monospace" font-size="20">s = Σσᵢ / Σ‖pᵢ‖²; t = q̄ − sRp̄</text>
<text x="35" y="330" font-family="monospace" font-size="20">General affine: six unknowns, four equations, nullity = 2 → no unique solution</text>
<text x="35" y="365" font-family="monospace" font-size="20">Least-norm affine fit included separately. Landmark alignment ≠ outline coincidence.</text>
</svg>
'''
    (DIST / "landmark-alignment-model.svg").write_text(svg, encoding="utf-8")


def main():
    DIST.mkdir(parents=True, exist_ok=True)
    matrix, translation, rotation, scale, singular = similarity_procrustes(P, Q)
    predicted, similarity_error = error(P, Q, matrix, translation)
    affine_matrix, rank = affine_least_squares(P, Q)
    _, affine_error = error(P, Q, affine_matrix, np.zeros(2))
    assert np.max(np.abs(predicted - Q)) < 1e-8
    assert np.max(np.abs(matrix - REFERENCE_A)) < 1e-8
    assert np.max(np.abs(translation - REFERENCE_T)) < 1e-8
    assert rank == 4
    area_scale = float(np.linalg.det(matrix))
    rotation_degrees = float(np.degrees(np.arctan2(matrix[1, 0], matrix[0, 0])))
    checks = {
        "scale": float(scale),
        "rotation_degrees": rotation_degrees,
        "area_scale": area_scale,
        "max_error": similarity_error["max"],
    }
    report = {
        "schema_version": 1,
        "source": {
            "path": f"source/{SOURCE.name}",
            "sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            "composite": True,
        },
        "correspondences": [
            {"source": P[0].tolist(), "target": Q[0].tolist()},
            {"source": P[1].tolist(), "target": Q[1].tolist()},
        ],
        "similarity_procrustes": {
            "equation": "q = sRp + t, with H = PᵀQ = UΣVᵀ, R = VUᵀ, s = Σσᵢ/Σ‖pᵢ‖², t = q̄ − sRp̄",
            "matrix": matrix.tolist(),
            "translation": translation.tolist(),
            "rotation_matrix": rotation.tolist(),
            "singular_values": singular.tolist(),
            "scale": float(scale),
            "rotation_degrees": rotation_degrees,
            "area_scale": area_scale,
            "prediction": predicted.tolist(),
            "errors": similarity_error,
        },
        "affine_least_squares": {
            "equation": "q = Ap + t solved by least squares for [a b tx; c d ty]",
            "matrix": affine_matrix.tolist(),
            "rank": int(rank),
            "nullity": int(6 - rank),
            "degrees_of_freedom": 2,
            "errors": affine_error,
            "note": "Two point pairs provide four equations for six affine unknowns. The least-norm solution is not unique.",
        },
        "checks": checks,
        "limitations": "Exact landmark alignment does not imply the different animal outlines coincide. A rigid transform cannot align different-length segments exactly.",
    }
    atomic_write(DIST / "landmark-alignment-analysis.json", json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    preview((matrix, translation), affine_matrix, P, Q, checks)
    svg_preview(matrix, translation, checks)
    geometry = f'''# Landmark alignment geometry

Measured correspondences:

- p1 = (101,114) → q1 = (345,35)
- p2 = (285,159) → q2 = (500,205)

## Similarity Procrustes solution

q = sRp + t

A = [{matrix[0,0]:.10f}, {matrix[0,1]:.10f}; {matrix[1,0]:.10f}, {matrix[1,1]:.10f}]

t = ({translation[0]:.8f}, {translation[1]:.8f})

- scale: {scale:.10f}
- rotation: {rotation_degrees:.10f}° in screen coordinates
- area scaling: det A = {area_scale:.10f}
- landmark error after alignment: zero, verified numerically to 1e-8 pixel

The centered covariance H = PᵀQ is decomposed with SVD. R = VUᵀ, s = Σσᵢ/Σ‖pᵢ‖², and t = q̄ − sRp̄.

## General affine fit

The six affine unknowns have only four equations, so the solution is not unique. The included least-norm affine fit has rank {rank} and nullity {6 - rank}. It is included to contrast full affine fitting with the unique two-point similarity Procrustes solution.

A rigid transform cannot align different-length segments exactly. Exact landmark alignment does not imply that the two different animal outlines would coincide.
'''
    (DIST / "geometry-report.md").write_text(geometry, encoding="utf-8")
    manifest_path = DIST.parent / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["landmark_alignment"] = {
        "analysis": "alignment/landmark-alignment-analysis.json",
        "model": "alignment/landmark-alignment-model.svg",
        "preview": "alignment/alignment-preview.png",
    }
    atomic_write(manifest_path, json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    verification_path = DIST.parent / "verification.json"
    if verification_path.exists():
        verification = json.loads(verification_path.read_text(encoding="utf-8"))
        verification["landmark_alignment"] = checks
        atomic_write(verification_path, json.dumps(verification, indent=2, ensure_ascii=False) + "\n")
    parent_files = sorted(path for path in DIST.parent.rglob("*") if path.is_file() and path.name != "SHA256SUMS.txt")
    parent_lines = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(DIST.parent)}" for path in parent_files]
    (DIST.parent / "SHA256SUMS.txt").write_text("\n".join(parent_lines) + "\n", encoding="utf-8")
    (DIST / "SHA256SUMS.txt").write_text("", encoding="utf-8")
    files = sorted(path for path in DIST.rglob("*") if path.is_file() and path.name != "SHA256SUMS.txt")
    lines = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(DIST)}" for path in files]
    (DIST / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(checks, indent=2))


if __name__ == "__main__":
    main()
