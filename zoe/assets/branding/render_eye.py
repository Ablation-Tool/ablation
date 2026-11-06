from __future__ import annotations

import math
from pathlib import Path
import random
import shutil
import subprocess


WIDTH = 1200
HEIGHT = 760
ROOT = Path(__file__).resolve().parent
COLORS = ("#67e8f9", "#c4b5fd", "#fde68a", "#86efac", "#f0abfc", "#93c5fd")


def eye_path(cx, cy, width, height, angle, color, opacity):
    return f'<path d="M{-width/2} 0 C{-width*.28} {-height*.7} {width*.28} {-height*.7} {width/2} 0 C{width*.28} {height*.7} {-width*.28} {height*.7} {-width/2} 0 Z" transform="translate({cx} {cy}) rotate({angle})" fill="none" stroke="{color}" stroke-width="1.2" opacity="{opacity}"/>'


def build():
    rng = random.Random(260306)
    parts = [
        '<defs><radialGradient id="night"><stop stop-color="#152039"/><stop offset=".58" stop-color="#080f20"/><stop offset="1" stop-color="#160d2d"/></radialGradient><linearGradient id="floor" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#6948b8" stop-opacity="0"/><stop offset="1" stop-color="#9365e3" stop-opacity=".45"/></linearGradient></defs>',
        '<rect width="1200" height="760" fill="url(#night)"/>',
        '<rect y="540" width="1200" height="220" fill="url(#floor)"/>',
    ]
    for _ in range(250):
        x, y = rng.uniform(30, 1170), rng.uniform(35, 665)
        radius = rng.choice((.55, .8, 1.0, 1.4, 1.9))
        color = rng.choice(("#67e8f9", "#c4b5fd", "#fde68a"))
        parts.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{radius}" fill="{color}" opacity="{rng.uniform(.1, .45):.3f}"/>')
    for index in range(9):
        angle = -32 + index * 8
        parts.append(f'<ellipse cx="600" cy="385" rx="{390 + index * 27}" ry="{110 + index * 10}" transform="rotate({angle} 600 385)" fill="none" stroke="{COLORS[index % len(COLORS)]}" stroke-width=".65" opacity=".2"/>')
    for index in range(30):
        width = 1040 - index * 21
        height = 570 - index * 11
        angle = (index - 15) * 1.1
        parts.append(eye_path(600, 382, width, height, angle, COLORS[index % len(COLORS)], .76))
    for index, color in enumerate(COLORS):
        parts.append(eye_path(600, 382, 560 - index * 38, 285 - index * 17, (index - 2.5) * 12, color, .85))
    nodes = [(120, 73, "10", "#86efac"), (1080, 75, "2", "#f0abfc"), (148, 680, "7", "#67e8f9"), (1050, 680, "5", "#fde68a"), (600, 716, "6", "#c4b5fd")]
    for x, y, label, color in nodes:
        parts.append(f'<circle cx="{x}" cy="{y}" r="21" fill="#0b1424" stroke="{color}" stroke-width="1.5"/>')
        parts.append(f'<text x="{x}" y="{y+6}" fill="{color}" font-family="Lato, sans-serif" font-size="19" text-anchor="middle">{label}</text>')
    parts.extend([
        '<circle cx="600" cy="382" r="48" fill="#0a1627" stroke="#67e8f9" stroke-width="2"/>',
        '<text x="600" y="397" fill="#d8f8ff" font-family="Lato, sans-serif" font-size="42" text-anchor="middle">Z</text>',
        '<text x="600" y="752" fill="#b7cce3" font-family="Lato, sans-serif" font-size="11" letter-spacing="3" text-anchor="middle">ZOE · ALLGEMS</text>',
    ])
    return "".join(parts)


def render():
    svg_path = ROOT / "zoe-eye.svg"
    png_path = ROOT / "zoe-eye.png"
    if svg_path.exists() or png_path.exists():
        raise FileExistsError("ZOE emblem exports will not overwrite existing files")
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-label="ZOE allgems orbital eye emblem"><title>ZOE allgems orbital eye emblem</title>{build()}</svg>\n'
    with svg_path.open("x", encoding="utf-8") as stream:
        stream.write(svg)
    converter = shutil.which("rsvg-convert")
    if converter is None:
        raise RuntimeError("rsvg-convert is required for PNG output")
    subprocess.run([converter, "-w", str(WIDTH), "-h", str(HEIGHT), "-o", str(png_path), str(svg_path)], check=True)
    print(svg_path)
    print(png_path)


if __name__ == "__main__":
    render()
