from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
from xml.sax.saxutils import escape


WIDTH = 1920
HEIGHT = 1080
ROOT = Path(__file__).resolve().parents[2]


def text(x, y, value, size=18, color="#dce8f5", anchor="start", spacing=0):
    return f'<text x="{x}" y="{y}" fill="{color}" font-family="Lato, sans-serif" font-size="{size}" letter-spacing="{spacing}" text-anchor="{anchor}">{escape(value)}</text>'


def slab(x, y, width, color):
    points = f"{x},{y+14} {x+width-20},{y} {x+width},{y+14} {x+20},{y+28}"
    return f'<polygon points="{points}" fill="{color}" stroke="#d7f3ff" stroke-width="1"/>'


def flow(x1, y1, x2, y2, color="#67e8f9"):
    return f'<path d="M{x1} {y1} L{x2} {y2}" fill="none" stroke="{color}" stroke-width="2"/>'


def cognitive_panel():
    parts = [
        '<rect x="1000" y="236" width="750" height="545" rx="24" fill="#0b1626" stroke="#67e8f9" stroke-width="1.5"/>',
        text(1040, 286, "Z.O.E. / GENERAL SYMBOL PROCESSOR", 24, "#67e8f9"),
        text(1040, 315, "explicit symbols · bounded state · inspectable memory", 16, "#9fb1c8"),
        '<rect x="1040" y="355" width="220" height="138" rx="10" fill="#132337" stroke="#67e8f9"/>',
        text(1060, 386, "DECLARATIVE", 17, "#67e8f9"),
        text(1060, 414, "store / retrieve", 15),
        text(1060, 440, "source + revision", 14, "#9fb1c8"),
        text(1060, 466, "mismatch preserved", 14, "#9fb1c8"),
        '<rect x="1488" y="355" width="220" height="138" rx="10" fill="#251a36" stroke="#f0abfc"/>',
        text(1508, 386, "PROCEDURAL", 17, "#f0abfc"),
        text(1508, 414, "tags / match", 15),
        text(1508, 440, "descriptions, not code", 14, "#d6bde0"),
        text(1508, 466, "negative results kept", 14, "#d6bde0"),
        '<rect x="1252" y="360" width="205" height="282" rx="10" fill="#282819" stroke="#fde68a" stroke-width="2"/>',
        text(1270, 390, "WORKING", 18, "#fde68a"),
        text(1270, 414, "bounded FIFO", 14, "#d8cda6"),
    ]
    for index, color in enumerate(("#4e9fb0", "#b486bf", "#8aab62", "#c37d8d")):
        parts.append(slab(1280 + index * 3, 442 + index * 39, 125, color))
    parts.extend([
        text(1270, 618, "active representations", 12, "#fde68a"),
        '<rect x="1040" y="556" width="220" height="138" rx="10" fill="#251a36" stroke="#f0abfc"/>',
        text(1060, 588, "SENSORY", 17, "#f0abfc"),
        text(1060, 616, "information / source", 15),
        text(1060, 642, "encoding / event ID", 14, "#d6bde0"),
        text(1060, 668, "eviction stays visible", 14, "#d6bde0"),
        '<rect x="1488" y="556" width="220" height="138" rx="10" fill="#142a24" stroke="#86efac"/>',
        text(1508, 588, "PERFORMANCE", 17, "#86efac"),
        text(1508, 616, "proposal for review", 15),
        text(1508, 642, "not motor output", 14, "#afd3bd"),
        text(1508, 668, "executed = False", 14, "#afd3bd"),
        flow(1260, 424, 1252, 424),
        flow(1488, 424, 1457, 424, "#f0abfc"),
        flow(1260, 625, 1290, 642, "#f0abfc"),
        flow(1457, 578, 1488, 625, "#86efac"),
        text(1375, 731, "event-linked memory / SHA-256 / replay", 14, "#fde68a", "middle"),
        text(1375, 758, "measurement != evidence != belief update != action", 13, "#fda4af", "middle"),
    ])
    return "".join(parts)


def composition(definitions, background, human_brain):
    parts = [background]
    parts.extend([
        text(80, 88, "Z.O.E. / COGNITIVE FIELD / GSP", 39, "#e6f4fa", spacing=1),
        text(80, 126, "An anatomical dialogue about representation, not a claim of anatomical equivalence.", 21, "#a9bfd3"),
        text(1838, 88, "GENERAL SYMBOL PROCESSOR", 16, "#67e8f9", "end", 2),
        text(1838, 118, "illustrative anatomy + executable memory", 16, "#a9bfd3", "end"),
        text(100, 208, "ANATOMICAL REFERENCE", 19, "#e5d0a4", spacing=2),
        text(100, 232, "Organic forms inspire the question; they do not localize software.", 15, "#b8b5c5"),
        human_brain(128, 292, .84),
        text(445, 795, "Illustrative anatomy · not a brain scan · not a map of Zoe", 15, "#d9c7b3", "middle"),
        '<path d="M920 190 V808" stroke="#71859d" stroke-width="1" stroke-dasharray="5 10" opacity=".48"/>',
        text(920, 454, "!=", 42, "#a9bfd3", "middle"),
        text(920, 485, "REFERENCE", 12, "#a9bfd3", "middle", 2),
        text(920, 505, "NOT EQUIVALENCE", 12, "#a9bfd3", "middle", 2),
        cognitive_panel(),
        '<rect x="80" y="850" width="1760" height="160" rx="18" fill="#0b1423" stroke="#465b73"/>',
        text(110, 885, "SOFTWARE PIPELINE / EXPLICIT BOUNDARIES", 15, "#a9bfd3", spacing=2),
    ])
    stages = [
        (110, "SOURCE", "text + provenance", "#f0abfc"),
        (455, "ENCODE", "bounded active state", "#67e8f9"),
        (800, "TRANSFORM", "store / retrieve / match", "#fde68a"),
        (1145, "DECODE", "inspect provenance", "#b486bf"),
        (1490, "REVIEW", "proposal, not action", "#86efac"),
    ]
    for index, (x, title, subtitle, color) in enumerate(stages):
        parts.extend([
            f'<rect x="{x}" y="907" width="260" height="66" rx="8" fill="#142238" stroke="{color}"/>',
            text(x + 16, 935, title, 15, color),
            text(x + 16, 959, subtitle, 13, "#c0cfdd"),
        ])
        if index + 1 < len(stages):
            parts.append(text(x + 282, 946, "->", 21, "#71859d"))
    parts.extend([
        text(960, 1041, "No cortical localization · no reward estimate · no motor control · no consciousness measurement", 15, "#c5b4c5", "middle"),
        text(960, 1066, "Organic artwork is illustrative. GSP memory is explicit software state. Human review remains the action boundary.", 12, "#879db4", "middle"),
    ])
    return definitions + "".join(parts)


def render(output=ROOT / "guiai-lab/docs/images"):
    source = ROOT / "assets/brain-dialogue/render.py"
    specification = importlib.util.spec_from_file_location("cognitive_dialogue_brain", source)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    svg_path = output / "zoe-cognitive-anatomy.svg"
    png_path = output / "zoe-cognitive-anatomy.png"
    if svg_path.exists() or png_path.exists():
        raise FileExistsError("Cognitive anatomy artwork will not overwrite an existing file")
    output.mkdir(parents=True, exist_ok=True)
    document = composition(module.definitions(), module.background(), module.human_brain)
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-label="Zoe Cognitive Field anatomical dialogue; illustrative anatomy is not equivalent to software memory"><title>Z.O.E. Cognitive Field anatomical dialogue</title>{document}</svg>\n'
    with svg_path.open("x", encoding="utf-8") as handle:
        handle.write(svg)
    converter = shutil.which("rsvg-convert")
    if converter is None:
        raise RuntimeError("rsvg-convert is required for PNG output")
    subprocess.run([converter, "-w", str(WIDTH), "-h", str(HEIGHT), "-o", str(png_path), str(svg_path)], check=True)
    print(svg_path)
    print(png_path)
    print("SVG SHA-256:", hashlib.sha256(svg_path.read_bytes()).hexdigest())


if __name__ == "__main__":
    render()
