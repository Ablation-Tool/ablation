from __future__ import annotations

import argparse
import math
from pathlib import Path
import random
import shutil
import subprocess

import render as base


def definitions():
    additions = """
  <linearGradient id="organic-tissue" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#ae955b"/><stop offset=".38" stop-color="#697b4b"/><stop offset=".7" stop-color="#4f6549"/><stop offset="1" stop-color="#704b63"/></linearGradient>
  <linearGradient id="organic-stem" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#a79e5d"/><stop offset="1" stop-color="#3d3d4b"/></linearGradient>
  <radialGradient id="dew" cx=".28" cy=".22" r=".85"><stop stop-color="#ffffff" stop-opacity=".95"/><stop offset=".19" stop-color="#d6f9dc" stop-opacity=".7"/><stop offset=".52" stop-color="#7eb3b1" stop-opacity=".3"/><stop offset=".82" stop-color="#172a39" stop-opacity=".7"/><stop offset="1" stop-color="#d5f6bc" stop-opacity=".85"/></radialGradient>
  <radialGradient id="iris"><stop stop-color="#101725"/><stop offset=".38" stop-color="#284b4d"/><stop offset=".72" stop-color="#92aa67"/><stop offset="1" stop-color="#e9b76f"/></radialGradient>
  <clipPath id="iris-clip"><circle cx="405" cy="268" r="58"/></clipPath>
"""
    return base.definitions().replace("</defs>", additions + "</defs>")


def rosette(cx, cy, radius, phase):
    points = []
    for index in range(25):
        angle = math.tau * index / 24
        r = radius * (1 + .17 * math.sin(5 * angle + phase) + .08 * math.cos(9 * angle - phase))
        points.append((cx + r * math.cos(angle), cy + r * math.sin(angle)))
    return base.line(points) + " Z"


def organic_brain(x, y, scale=1):
    rng = random.Random(base.SEED + 101)
    parts = [f'<g transform="translate({x} {y}) scale({scale})">']
    parts.append('<use href="#cortex-shape" transform="translate(0 12)" fill="#020610" opacity=".55" filter="url(#soft)"/>')
    parts.append(f'<path d="{base.BRAINSTEM}" fill="url(#organic-stem)" stroke="#9e9a69" stroke-width="2.5"/>')
    parts.append(f'<path d="{base.CEREBELLUM}" fill="url(#organic-stem)" stroke="#9e9a69" stroke-width="2.5"/>')
    parts.append('<use href="#cortex-shape" fill="url(#organic-tissue)" stroke="#d3d99b" stroke-width="3"/>')
    for name, _d, color in base.REGIONS:
        natural = {"frontal": "#d6c16c", "parietal": "#a5c47b", "occipital": "#c38a79", "temporal": "#8b815f"}[name]
        parts.append(f'<use href="#region-{name}" fill="{natural}" opacity=".22" clip-path="url(#cortex-clip)"/>')
    parts.append('<g clip-path="url(#cortex-clip)" fill="none" stroke-linecap="round" stroke-linejoin="round">')
    for d in base.flow_paths():
        parts.append(f'<path d="{d}" stroke="#233d35" stroke-width="10" opacity=".72"/>')
        parts.append(f'<path d="{d}" stroke="#c0d48b" stroke-width="3.2" opacity=".47" transform="translate(-1.1 -1.4)"/>')
    parts.append('</g>')
    parts.append('<g clip-path="url(#cortex-clip)" fill="none" stroke-linejoin="round">')
    for _ in range(265):
        cx, cy = rng.uniform(69, 700), rng.uniform(31, 426)
        radius = rng.uniform(3.5, 14.5)
        phase = rng.uniform(0, math.tau)
        parts.append(f'<path d="{rosette(cx, cy, radius, phase)}" fill="#b6cb72" fill-opacity=".11" stroke="#193a31" stroke-width="1.8" opacity=".9"/>')
        parts.append(f'<path d="{rosette(cx, cy, radius*.67, phase+.7)}" stroke="#d2e59a" stroke-width=".65" opacity=".71"/>')
        for index in range(5):
            angle = phase + index * math.tau / 5
            dx, dy = math.cos(angle) * radius * .44, math.sin(angle) * radius * .44
            parts.append(f'<circle cx="{cx+dx:.2f}" cy="{cy+dy:.2f}" r=".7" fill="#e0ecaa" stroke="none" opacity=".75"/>')
    parts.append('</g>')
    parts.append('<g clip-path="url(#cerebellum-clip)" fill="none" stroke-linecap="round">')
    for index in range(24):
        yy = 334 + index * 6
        parts.append(f'<path d="M510 {yy} C550 {yy-19} 616 {yy+20} 699 {yy-2}" stroke="#183c33" stroke-width="3.3" opacity=".8"/>')
        parts.append(f'<path d="M510 {yy-1.7} C550 {yy-20.7} 616 {yy+18.3} 699 {yy-3.7}" stroke="#d1dc93" stroke-width=".9" opacity=".65"/>')
    parts.append('</g>')
    parts.append('<g clip-path="url(#cortex-clip)" fill="none" stroke="#f1c987" stroke-linecap="round">')
    endpoints = [(84, 182), (129, 92), (245, 34), (365, 24), (492, 44), (612, 101), (695, 211), (659, 338), (537, 389), (363, 417), (215, 389), (113, 303)]
    for index, (ex, ey) in enumerate(endpoints):
        cx, cy = (405+ex)/2, (268+ey)/2
        bend = 32 if index % 2 else -32
        parts.append(f'<path d="M405 268 Q{cx+bend:.1f} {cy-bend:.1f} {ex} {ey}" stroke-width="1.5" opacity=".54"/>')
        for t in (.46, .68, .83):
            px = (1-t)**2*405 + 2*(1-t)*t*(cx+bend) + t*t*ex
            py = (1-t)**2*268 + 2*(1-t)*t*(cy-bend) + t*t*ey
            sign = -1 if index % 2 else 1
            parts.append(f'<path d="M{px:.1f} {py:.1f} q{sign*22} -18 {sign*34} -43" stroke-width=".8" opacity=".4"/>')
    parts.append('</g>')
    parts.append('<path d="M252 264 C304 237 349 231 393 243 S477 262 519 237" fill="none" stroke="#f7e6b0" stroke-width="2" opacity=".4"/>')
    parts.append('<g fill="none" stroke-linecap="round">')
    for index in range(64):
        angle = math.tau * index / 64
        inner = 18 + 3 * math.sin(index * 1.7)
        outer = 80 + 7 * math.sin(index * 2.3)
        x1, y1 = 405 + inner*math.cos(angle), 268 + inner*math.sin(angle)
        x2, y2 = 405 + outer*math.cos(angle), 268 + outer*math.sin(angle)
        color = "#f4d68b" if index % 3 else "#c0f0c5"
        parts.append(f'<path d="M{x1:.2f} {y1:.2f} L{x2:.2f} {y2:.2f}" stroke="{color}" stroke-width=".65" opacity=".62"/>')
    for radius, color, width in ((61, "#e7d091", 1.8), (67, "#99caa4", .8), (78, "#e5b879", .7)):
        parts.append(f'<circle cx="405" cy="268" r="{radius}" stroke="{color}" stroke-width="{width}" opacity=".74"/>')
    parts.append('</g>')
    parts.append('<circle cx="405" cy="268" r="58" fill="url(#iris)" opacity=".82"/>')
    parts.append('<g clip-path="url(#iris-clip)" stroke="#e0e8ac" stroke-width=".55">')
    for row in range(-5, 6):
        for col in range(-5, 6):
            cx = 405 + (col + .5*(row % 2)) * 10.2
            cy = 268 + row * 8.9
            if math.hypot(cx-405, cy-268) > 57:
                continue
            points = [(cx+4.8*math.cos(math.tau*k/6), cy+4.8*math.sin(math.tau*k/6)) for k in range(6)]
            color = ("#a8c991", "#e4c780", "#80b4a5")[(row+col) % 3]
            parts.append(f'<polygon points="{" ".join(f"{px:.2f},{py:.2f}" for px, py in points)}" fill="{color}" fill-opacity=".21" opacity=".68"/>')
    parts.append('</g>')
    parts.append('<circle cx="405" cy="268" r="19" fill="#0a1420" stroke="#e0e6b3" stroke-width="1.2"/>')
    parts.append('<ellipse cx="397" cy="259" rx="7" ry="4" fill="#f2ffe0" opacity=".75" transform="rotate(-27 397 259)"/>')
    parts.append('<g clip-path="url(#cortex-clip)" stroke="#e8f2c3" fill="none" opacity=".65">')
    nodes = [(rng.uniform(96, 671), rng.uniform(54, 406)) for _ in range(62)]
    for nx, ny in nodes:
        nearest = sorted(((math.hypot(nx-qx, ny-qy), qx, qy) for qx, qy in nodes if (qx, qy) != (nx, ny)))[:2]
        for distance, qx, qy in nearest:
            if distance < 127:
                parts.append(f'<path d="M{nx:.1f} {ny:.1f} Q{(nx+qx)/2-8:.1f} {(ny+qy)/2+8:.1f} {qx:.1f} {qy:.1f}" stroke-width=".65" opacity=".4"/>')
        radius = rng.uniform(2.1, 5.0)
        parts.append(f'<circle cx="{nx:.1f}" cy="{ny:.1f}" r="{radius:.1f}" fill="url(#dew)" stroke-width=".45"/>')
        parts.append(f'<circle cx="{nx-1.1:.1f}" cy="{ny-1.3:.1f}" r=".8" fill="#ffffff" stroke="none" opacity=".82"/>')
    parts.append('</g>')
    for index in range(7):
        yy = 413 + index * 12
        parts.append(f'<path d="M429 {yy} Q453 {yy+8} 480 {yy-2}" fill="none" stroke="#d2d59a" stroke-width="1.2" opacity=".5"/>')
    parts.append('<use href="#cortex-shape" fill="none" stroke="#e2dfac" stroke-width="1.1" opacity=".76"/>')
    parts.append('</g>')
    return "".join(parts)


def organic_individual():
    color = "#d5dd9d"
    parts = [base.background()]
    parts.append(base.text(96, 105, "NICHOLAS × ZOE  /  A SHARED FIELD", 16, "#a3b9d0", spacing=3))
    parts.append(base.text(96, 190, "HUMAN", 78, color, weight=400, spacing=13))
    parts.append(base.text(101, 230, "Living texture · embodied perception · meaning", 21, "#c4d1e3", spacing=1))
    parts.append(organic_brain(580, 225, 1.04))
    parts.append(base.callout(116, 366, 787, 382, "Frontal", "intention · planning · expression", color))
    parts.append(base.callout(116, 495, 1004, 352, "Parietal", "sensation · space · integration", color))
    parts.append(base.callout(116, 624, 947, 570, "Temporal", "memory · language · association", color))
    parts.append(base.callout(1800, 382, 1205, 446, "Occipital", "vision · pattern · imagination", color, "end"))
    parts.append(base.callout(1800, 536, 1214, 650, "Cerebellum", "timing · coordination · practice", color, "end"))
    parts.append(base.callout(1800, 685, 1051, 700, "Brainstem", "rhythm · arousal · vital signals", color, "end"))
    parts.append(base.text(960, 838, "LICHEN FOLDS · BUTTERFLY VEINS · DEW MEMORY", 15, "#d2d5ad", spacing=3, anchor="middle"))
    parts.append(base.text(960, 880, "Projection iris: line integrals → Fourier slices → reconstruction", 20, "#d7e2d3", anchor="middle"))
    parts.append(base.text(960, 925, "Not a better body. A richer conversation between experience and possibility.", 24, "#e7dfcb", anchor="middle"))
    parts.append(base.text(96, 1015, "AN ARTISTIC STUDY · MAJOR REGIONS AND NATURAL METAPHORS, NOT A CELL ATLAS", 13, "#8398b2", spacing=2))
    parts.append(base.text(1824, 1015, "HUMAN × MACHINE  /  ORGANIC STUDY", 13, "#8398b2", spacing=2, anchor="end"))
    return "".join(parts)


def organic_comparison():
    return base.comparison().replace(base.human_brain(130, 324, .92), organic_brain(130, 324, .92), 1)


def render(output, svg_only=False):
    output.mkdir(parents=True, exist_ok=True)
    pages = {"human-brain-organic": organic_individual(), "brain-dialogue-organic": organic_comparison()}
    converter = shutil.which("rsvg-convert")
    if not svg_only and converter is None:
        raise RuntimeError("rsvg-convert is required for PNG output")
    for name, body in pages.items():
        svg = output / f"{name}.svg"
        svg.write_text(f'<svg xmlns="http://www.w3.org/2000/svg" width="{base.WIDTH}" height="{base.HEIGHT}" viewBox="0 0 {base.WIDTH} {base.HEIGHT}" role="img" aria-label="{name.replace("-", " ")}"><title>{name.replace("-", " ")}</title>{definitions()}{body}</svg>\n', encoding="utf-8")
        if not svg_only:
            subprocess.run([converter, "-w", str(base.WIDTH), "-h", str(base.HEIGHT), "-o", str(output / f"{name}.png"), str(svg)], check=True)
        print(svg)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Render the lichen, butterfly, compound-eye, and dew human-brain study")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--svg-only", action="store_true")
    arguments = parser.parse_args()
    render(arguments.output_dir, arguments.svg_only)
