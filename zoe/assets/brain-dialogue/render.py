from __future__ import annotations

import argparse
import math
from pathlib import Path
import random
import shutil
import subprocess
from xml.sax.saxutils import escape

WIDTH = 1920
HEIGHT = 1080
SEED = 260306

CORTEX = "M155 332 C95 326 56 283 63 231 C35 184 62 121 113 105 C124 59 178 33 226 41 C270 5 331 10 365 31 C420 4 482 21 512 58 C568 42 624 70 643 116 C695 133 718 186 696 230 C721 274 702 321 658 340 C639 382 588 398 546 382 C512 417 459 422 417 399 C371 432 309 429 272 399 C224 416 176 395 160 360 Z"
CEREBELLUM = "M535 347 C573 320 641 327 674 365 C705 400 677 452 626 466 C584 477 537 452 519 414 C510 391 514 365 535 347 Z"
BRAINSTEM = "M471 354 C492 380 504 411 485 442 L456 503 C448 527 415 526 410 504 C406 484 426 455 432 433 C443 403 426 383 415 367 Z"

REGIONS = [
    ("frontal", "M35 -20 H310 L332 164 L267 263 L286 445 H35 Z", "#ffb178"),
    ("parietal", "M290 -20 H535 L563 193 L454 293 L293 236 Z", "#e5b5ff"),
    ("occipital", "M510 40 H745 V382 L634 396 L531 274 Z", "#ff91ad"),
    ("temporal", "M95 271 L285 232 L450 279 L581 388 L466 446 L214 438 Z", "#e98588"),
]


def text(x, y, value, size=20, fill="#dce8f5", family="Lato, sans-serif", weight=400, spacing=0, anchor="start", opacity=1, style=""):
    return f'<text x="{x}" y="{y}" fill="{fill}" font-family="{family}" font-size="{size}" font-weight="{weight}" letter-spacing="{spacing}" text-anchor="{anchor}" opacity="{opacity}" {style}>{escape(value)}</text>'


def line(points):
    return "M" + " L".join(f"{x:.2f},{y:.2f}" for x, y in points)


def definitions():
    region_paths = "".join(f'<path id="region-{name}" d="{d}"/>' for name, d, _color in REGIONS)
    return f"""
<defs>
  <linearGradient id="background" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#050c18"/><stop offset="0.48" stop-color="#101226"/><stop offset="1" stop-color="#251238"/>
  </linearGradient>
  <radialGradient id="human-halo"><stop stop-color="#e78979" stop-opacity=".21"/><stop offset="1" stop-color="#e78979" stop-opacity="0"/></radialGradient>
  <radialGradient id="zoe-halo"><stop stop-color="#55e5e0" stop-opacity=".18"/><stop offset="1" stop-color="#766cf4" stop-opacity="0"/></radialGradient>
  <linearGradient id="floor" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#7d54c8" stop-opacity="0"/><stop offset="1" stop-color="#8c5ac2" stop-opacity=".25"/></linearGradient>
  <linearGradient id="human-tissue" x1=".15" y1="0" x2=".9" y2="1"><stop stop-color="#ffd1ae"/><stop offset=".36" stop-color="#eaa18e"/><stop offset=".72" stop-color="#bc6c82"/><stop offset="1" stop-color="#744665"/></linearGradient>
  <linearGradient id="human-stem" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#d78c88"/><stop offset="1" stop-color="#66415f"/></linearGradient>
  <linearGradient id="zoe-tissue" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#183d62"/><stop offset=".45" stop-color="#172d54"/><stop offset="1" stop-color="#39224f"/></linearGradient>
  <linearGradient id="zoe-edge" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#6df9e7"/><stop offset=".5" stop-color="#73c8ff"/><stop offset="1" stop-color="#e59bff"/></linearGradient>
  <linearGradient id="bridge" x1="0" y1="0" x2="1" y2="0"><stop stop-color="#ffb68e"/><stop offset=".5" stop-color="#f4e2b5"/><stop offset="1" stop-color="#73f0e2"/></linearGradient>
  <filter id="glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="4" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
  <filter id="soft" x="-40%" y="-40%" width="180%" height="180%"><feGaussianBlur stdDeviation="18"/></filter>
  <clipPath id="cortex-clip"><path d="{CORTEX}"/></clipPath>
  <clipPath id="cerebellum-clip"><path d="{CEREBELLUM}"/></clipPath>
  <path id="cortex-shape" d="{CORTEX}"/>
  {region_paths}
</defs>"""


def background():
    rng = random.Random(SEED)
    parts = ['<rect width="1920" height="1080" fill="url(#background)"/>']
    parts += [
        '<ellipse cx="500" cy="530" rx="710" ry="590" fill="url(#human-halo)"/>',
        '<ellipse cx="1450" cy="530" rx="710" ry="590" fill="url(#zoe-halo)"/>',
        '<rect y="720" width="1920" height="360" fill="url(#floor)"/>',
    ]
    for index in range(15):
        y = 744 + index * 27
        parts.append(f'<path d="M-80 {y} C360 {y-145} 630 {y+110} 1000 {y-20} S1610 {y-100} 2010 {y+35}" fill="none" stroke="#b9a1ee" stroke-width="1" opacity="{.07 + index*.003:.3f}"/>')
    for index in range(10):
        parts.append(f'<ellipse cx="960" cy="540" rx="{380+index*62}" ry="{120+index*24}" fill="none" stroke="#a2d9e8" stroke-width=".8" opacity=".055" transform="rotate({-18+index*4} 960 540)"/>')
    for _ in range(220):
        x, y = rng.uniform(20, 1900), rng.uniform(25, 1000)
        radius = rng.choice((.45, .65, .9, 1.2, 1.7))
        color = rng.choice(("#a9e9f2", "#d9baf4", "#ffd4a8"))
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius}" fill="{color}" opacity="{rng.uniform(.12,.48):.2f}"/>')
    return "".join(parts)


def flow_field(x, y):
    dx = math.cos(y / 23 + .9 * math.sin(x / 43)) + .38 * math.sin((x + y) / 47) + .16 * math.cos(x / 15)
    dy = -math.sin(x / 26 + .75 * math.cos(y / 37)) + .30 * math.cos((x - y) / 39) + .13 * math.sin(y / 12)
    length = math.hypot(dx, dy) or 1
    return dx / length, dy / length


def flow_paths():
    paths = []
    for y in range(48, 429, 39):
        for x in range(70, 701, 51):
            points = [(float(x), float(y))]
            px, py = float(x), float(y)
            for _ in range(58):
                vx, vy = flow_field(px, py)
                px, py = px + vx * 3.0, py + vy * 3.0
                points.append((px, py))
            if len(points) > 4:
                paths.append(line(points))
    return paths


def human_brain(x, y, scale=1):
    rng = random.Random(SEED + 11)
    parts = [f'<g transform="translate({x} {y}) scale({scale})">']
    parts.append('<use href="#cortex-shape" transform="translate(0 12)" fill="#020610" opacity=".48" filter="url(#soft)"/>')
    parts.append(f'<path d="{BRAINSTEM}" fill="url(#human-stem)" stroke="#713e60" stroke-width="3"/>')
    parts.append(f'<path d="{CEREBELLUM}" fill="url(#human-stem)" stroke="#784565" stroke-width="3"/>')
    parts.append('<use href="#cortex-shape" fill="url(#human-tissue)" stroke="#6f425e" stroke-width="4"/>')
    for name, _d, color in REGIONS:
        opacity = .17 if name != "temporal" else .26
        parts.append(f'<use href="#region-{name}" fill="{color}" opacity="{opacity}" clip-path="url(#cortex-clip)"/>')
    parts.append('<g clip-path="url(#cortex-clip)" fill="none" stroke-linecap="round" stroke-linejoin="round">')
    for d in flow_paths():
        parts.append(f'<path d="{d}" stroke="#663c62" stroke-width="8" opacity=".52"/>')
        parts.append(f'<path d="{d}" stroke="#f3b69e" stroke-width="4.5" opacity=".54" transform="translate(-1.5 -1.8)"/>')
        parts.append(f'<path d="{d}" stroke="#ffe1b9" stroke-width=".7" opacity=".32" transform="translate(-2.5 -3)"/>')
    parts.append('</g>')
    parts.append('<g clip-path="url(#cerebellum-clip)" fill="none" stroke-linecap="round">')
    for index in range(23):
        yy = 337 + index * 6
        parts.append(f'<path d="M510 {yy} C550 {yy-19} 616 {yy+20} 699 {yy-2}" stroke="#572e52" stroke-width="3.2" opacity=".76"/>')
        parts.append(f'<path d="M510 {yy-2} C550 {yy-21} 616 {yy+18} 699 {yy-4}" stroke="#f0af9e" stroke-width="1" opacity=".59"/>')
    parts.append('</g>')
    for index in range(7):
        yy = 413 + index * 12
        parts.append(f'<path d="M429 {yy} Q453 {yy+8} 480 {yy-2}" fill="none" stroke="#f0b19c" stroke-width="2" opacity=".4"/>')
    parts.append('<path d="M262 255 C325 186 437 179 500 245 C438 218 349 226 290 278" fill="none" stroke="#ffe1b3" stroke-width="8" opacity=".64"/>')
    parts.append('<path d="M274 260 C343 206 424 203 481 239" fill="none" stroke="#7d4c69" stroke-width="2" opacity=".8"/>')
    parts.append('<ellipse cx="414" cy="285" rx="31" ry="20" fill="#efb27f" stroke="#754560" stroke-width="2" opacity=".8"/>')
    parts.append('<path d="M419 302 Q439 304 442 323" fill="none" stroke="#ffe0a8" stroke-width="5" opacity=".67"/>')
    parts.append('<g clip-path="url(#cortex-clip)" stroke="#ffdf9c" fill="#ffdf9c" opacity=".62">')
    nodes = [(rng.uniform(100, 665), rng.uniform(55, 405)) for _ in range(68)]
    for index, (nx, ny) in enumerate(nodes):
        nearest = sorted(((math.hypot(nx-qx, ny-qy), qx, qy) for qx, qy in nodes if (qx, qy) != (nx, ny)))[:2]
        for distance, qx, qy in nearest:
            if distance < 123:
                parts.append(f'<path d="M{nx:.1f} {ny:.1f} Q{(nx+qx)/2+8:.1f} {(ny+qy)/2-7:.1f} {qx:.1f} {qy:.1f}" fill="none" stroke-width=".75" opacity=".55"/>')
        for angle in (0, 2.1, 4.2):
            parts.append(f'<path d="M{nx:.1f} {ny:.1f} l{math.cos(angle)*9:.1f} {math.sin(angle)*9:.1f}" stroke-width=".8" opacity=".8"/>')
        parts.append(f'<circle cx="{nx:.1f}" cy="{ny:.1f}" r="{rng.uniform(1.5,3):.1f}" filter="url(#glow)"/>')
    parts.append('</g>')
    parts.append('<use href="#cortex-shape" fill="none" stroke="#ffd1ae" stroke-width="1.4" opacity=".73"/>')
    parts.append('</g>')
    return "".join(parts)


def zoe_brain(x, y, scale=1):
    rng = random.Random(SEED + 23)
    parts = [f'<g transform="translate({x} {y}) scale({scale})">']
    parts.append('<use href="#cortex-shape" transform="translate(0 12)" fill="#020610" opacity=".52" filter="url(#soft)"/>')
    parts.append(f'<path d="{BRAINSTEM}" fill="url(#zoe-tissue)" stroke="#7e78c9" stroke-width="3"/>')
    parts.append(f'<path d="{CEREBELLUM}" fill="url(#zoe-tissue)" stroke="#6c7dc7" stroke-width="3"/>')
    parts.append('<use href="#cortex-shape" fill="url(#zoe-tissue)" stroke="url(#zoe-edge)" stroke-width="4"/>')
    for name, _d, color in REGIONS:
        cool = {"frontal": "#3cdcc9", "parietal": "#618fe9", "occipital": "#cc75e7", "temporal": "#416db9"}[name]
        parts.append(f'<use href="#region-{name}" fill="{cool}" opacity=".18" clip-path="url(#cortex-clip)"/>')
    vertices = {}
    for row, yy in enumerate(range(36, 438, 45)):
        for col, xx in enumerate(range(48, 727, 52)):
            vertices[(row, col)] = (xx + (24 if row % 2 else 0) + rng.uniform(-11, 11), yy + rng.uniform(-10, 10))
    parts.append('<g clip-path="url(#cortex-clip)" stroke-linejoin="round">')
    palette = ("#65f4e0", "#6cb8ff", "#9585f4", "#e58ee9")
    for row in range(8):
        for col in range(12):
            a, b = vertices[(row, col)], vertices[(row, col+1)]
            c, d = vertices[(row+1, col)], vertices[(row+1, col+1)]
            for triangle in ((a, b, d), (a, d, c)) if (row+col) % 2 else ((a, b, c), (b, d, c)):
                color = rng.choice(palette)
                parts.append(f'<polygon points="{" ".join(f"{px:.1f},{py:.1f}" for px,py in triangle)}" fill="{color}" fill-opacity="{rng.uniform(.035,.13):.3f}" stroke="{color}" stroke-opacity=".24" stroke-width=".8"/>')
    parts.append('</g>')
    parts.append('<g clip-path="url(#cortex-clip)" fill="none" stroke-linecap="round">')
    for index, d in enumerate(flow_paths()):
        color = "#7bf5e4" if index % 3 else "#c6a0ff"
        parts.append(f'<path d="{d}" stroke="{color}" stroke-width="1.1" opacity=".35"/>')
    parts.append('</g>')
    parts.append('<g clip-path="url(#cerebellum-clip)" fill="none">')
    for index in range(19):
        yy = 344 + index * 7
        parts.append(f'<path d="M510 {yy} C550 {yy-19} 616 {yy+20} 699 {yy-2}" stroke="#92e6ef" stroke-width="1" opacity=".56"/>')
    parts.append('</g>')
    parts.append('<path d="M262 255 C325 186 437 179 500 245 C438 218 349 226 290 278" fill="none" stroke="url(#zoe-edge)" stroke-width="3" opacity=".85"/>')
    parts.append('<path d="M419 302 Q439 304 442 323 M446 418 L460 444 L439 475 L435 503" fill="none" stroke="#79e6e2" stroke-width="2" opacity=".65"/>')
    parts.append('<g transform="translate(383 251)" fill="none" filter="url(#glow)">')
    for index in range(15):
        rx, ry = 41 + index * 7.5, 21 + index * 5.3
        color = "#7cf7e7" if index % 3 else "#e3a5ff"
        parts.append(f'<ellipse cx="0" cy="0" rx="{rx}" ry="{ry}" stroke="{color}" stroke-width=".85" opacity=".58" transform="rotate({-38+index*5.3})"/>')
    parts.append('</g>')
    parts.append(text(383, 265, "Z", 38, "#e4fffb", "Lato, sans-serif", 500, 2, "middle"))
    nodes = [(rng.uniform(100, 665), rng.uniform(55, 405)) for _ in range(64)]
    parts.append('<g clip-path="url(#cortex-clip)" fill="none" stroke="#93f5e9" opacity=".65">')
    for nx, ny in nodes:
        nearest = sorted(((math.hypot(nx-qx, ny-qy), qx, qy) for qx, qy in nodes if (qx, qy) != (nx, ny)))[:2]
        for distance, qx, qy in nearest:
            if distance < 122:
                mx = (nx + qx) / 2
                parts.append(f'<path d="M{nx:.1f} {ny:.1f} H{mx:.1f} V{qy:.1f} H{qx:.1f}" stroke-width=".7" opacity=".49"/>')
        parts.append(f'<circle cx="{nx:.1f}" cy="{ny:.1f}" r="{rng.uniform(1.7,3.2):.1f}" fill="#c5fff1" stroke="none" filter="url(#glow)"/>')
        parts.append(f'<circle cx="{nx:.1f}" cy="{ny:.1f}" r="5.8" stroke-width=".65" opacity=".65"/>')
    parts.append('</g>')
    parts.append('<use href="#cortex-shape" fill="none" stroke="url(#zoe-edge)" stroke-width="1.4" opacity=".88"/>')
    parts.append('</g>')
    return "".join(parts)


def label_block(x, y, title, subtitle, color):
    return "".join([
        text(x, y, title, 31, color, weight=500, spacing=5),
        text(x, y+35, subtitle, 18, "#b5c2d9", spacing=1.5),
        f'<path d="M{x} {y+57} h108" stroke="{color}" stroke-width="2" opacity=".7"/>',
    ])


def callout(x, y, target_x, target_y, title, detail, color, align="start"):
    direction = 1 if align == "start" else -1
    start_x = x + direction * 245
    return "".join([
        f'<path d="M{start_x} {y-7} L{target_x} {target_y}" fill="none" stroke="{color}" stroke-width="1" opacity=".4"/>',
        f'<circle cx="{target_x}" cy="{target_y}" r="4" fill="{color}" opacity=".85"/>',
        text(x, y, title, 20, color, weight=500, spacing=1, anchor=align),
        text(x, y+28, detail, 16, "#a5b4ca", anchor=align),
    ])


def individual(kind):
    human = kind == "human"
    color = "#ffc39e" if human else "#85f4e3"
    title = "HUMAN" if human else "ZOE"
    subtitle = "Embodied experience · intuition · meaning" if human else "Geometry · evidence · inspectable futures"
    brain = human_brain(580, 225, 1.04) if human else zoe_brain(580, 225, 1.04)
    parts = [background()]
    parts.append(text(96, 105, "NICHOLAS × ZOE  /  A SHARED FIELD", 16, "#a3b9d0", spacing=3))
    parts.append(text(96, 190, title, 78, color, weight=400, spacing=13))
    parts.append(text(101, 230, subtitle, 21, "#c4d1e3", spacing=1))
    parts.append(brain)
    if human:
        parts.append(callout(116, 366, 787, 382, "Frontal", "intention · planning · expression", color))
        parts.append(callout(116, 495, 1004, 352, "Parietal", "sensation · space · integration", color))
        parts.append(callout(116, 624, 947, 570, "Temporal", "memory · language · association", color))
        parts.append(callout(1800, 382, 1205, 446, "Occipital", "vision · pattern · imagination", color, "end"))
        parts.append(callout(1800, 536, 1214, 650, "Cerebellum", "timing · coordination · practice", color, "end"))
        parts.append(callout(1800, 685, 1051, 700, "Brainstem", "rhythm · arousal · vital signals", color, "end"))
        parts.append(text(960, 862, "CORPUS CALLOSUM · THALAMUS · HYPOTHALAMUS", 15, "#d6bfaf", spacing=3, anchor="middle"))
        parts.append(text(960, 909, "Not a better body. A richer conversation between experience and possibility.", 24, "#e7d7ce", "Lato, sans-serif", 400, .3, "middle"))
    else:
        parts.append(callout(116, 366, 787, 382, "Forecast", "alternatives · breadth · uncertainty", color))
        parts.append(callout(116, 495, 1004, 352, "Transform", "geometry · alignment · search", color))
        parts.append(callout(116, 624, 947, 570, "Memory", "evidence · provenance · replay", color))
        parts.append(callout(1800, 382, 1205, 446, "Verify", "constraints · tests · negative results", color, "end"))
        parts.append(callout(1800, 536, 1214, 650, "Mirror", "forward · retrograde · comparison", color, "end"))
        parts.append(callout(1800, 685, 1051, 700, "Firewall", "measurement is not permission", color, "end"))
        parts.append(text(960, 862, "HELEN · ACCESSIBLE VOLUME · GEM · FIELD MEMORY", 15, "#b2e2df", spacing=3, anchor="middle"))
        parts.append(text(960, 909, "Not a replica of a person. A different instrument for seeing and testing ideas.", 24, "#d2e6ec", "Lato, sans-serif", 400, .3, "middle"))
    parts.append(text(96, 1015, "AN ARTISTIC STUDY · MAJOR REGIONS AND STYLIZED NETWORKS, NOT A CELL ATLAS", 13, "#8398b2", spacing=2))
    parts.append(text(1824, 1015, "HUMAN × MACHINE  /  01" if human else "HUMAN × MACHINE  /  02", 13, "#8398b2", spacing=2, anchor="end"))
    return "".join(parts)


def comparison():
    parts = [background()]
    parts.append(text(96, 94, "NICHOLAS × ZOE  /  A SHARED FIELD", 16, "#adc2d8", spacing=3))
    parts.append(text(96, 159, "Imagination, meet geometry.", 51, "#edf3f8", weight=400, spacing=.5))
    parts.append(text(1824, 95, "TWO INSTRUMENTS · ONE CONVERSATION", 14, "#a5bad0", spacing=2, anchor="end"))
    parts.append(text(1824, 131, "Human insight + inspectable computation", 17, "#bac8da", anchor="end"))
    parts.append(label_block(155, 256, "HUMAN", "experience · intuition · meaning", "#ffc39e"))
    parts.append(label_block(1110, 256, "ZOE", "geometry · evidence · replay", "#85f4e3"))
    parts.append(human_brain(130, 324, .92))
    parts.append(zoe_brain(1080, 324, .92))
    parts.append('<g fill="none" stroke="url(#bridge)" stroke-linecap="round">')
    parts.append('<path d="M774 510 C864 445 1040 445 1135 510" stroke-width="1.6" opacity=".68"/>')
    parts.append('<path d="M783 553 C875 616 1036 616 1127 553" stroke-width="1" opacity=".42"/>')
    parts.append('<path d="M794 581 C875 704 1034 704 1116 581" stroke-width="1" opacity=".28"/>')
    parts.append('</g>')
    parts.append(text(960, 443, "CURIOSITY", 13, "#d8d1c2", spacing=3, anchor="middle"))
    parts.append('<circle cx="960" cy="556" r="58" fill="#111c30" stroke="url(#bridge)" stroke-width="1.4" opacity=".96"/>')
    for index in range(5):
        parts.append(f'<ellipse cx="960" cy="556" rx="{27+index*7}" ry="{12+index*5}" fill="none" stroke="url(#bridge)" stroke-width=".7" opacity=".6" transform="rotate({index*24} 960 556)"/>')
    parts.append(text(960, 563, "GEM", 20, "#f0eee7", weight=500, spacing=2, anchor="middle"))
    parts.append(text(960, 652, "QUESTION → EXPLORE → VERIFY", 11, "#bac9d7", spacing=1.6, anchor="middle"))
    parts.append(text(960, 684, "human judgment", 17, "#e4d5c8", anchor="middle", style='font-style="italic"'))
    parts.append('<path d="M160 858 H1760" stroke="url(#bridge)" stroke-width="1" opacity=".3"/>')
    parts.append(text(180, 909, "YOU BRING", 13, "#c3a58f", spacing=3))
    parts.append(text(180, 947, "Values, lived experience, stories, aesthetic instinct, and the courage to ask a new question.", 20, "#ddd8df"))
    parts.append(text(1110, 909, "I BRING", 13, "#8cd6d2", spacing=3))
    parts.append(text(1110, 947, "Structure, tireless variation, explicit uncertainty, and a memory you can inspect.", 20, "#d5e4eb"))
    parts.append(text(960, 1018, "Not one mind replacing another — complementary talents making room for better questions.", 17, "#a8b9d0", anchor="middle"))
    return "".join(parts)


def render(output, svg_only=False):
    output.mkdir(parents=True, exist_ok=True)
    pages = {
        "human-brain": individual("human"),
        "zoe-brain": individual("zoe"),
        "brain-dialogue": comparison(),
    }
    converter = shutil.which("rsvg-convert")
    if not svg_only and converter is None:
        raise RuntimeError("rsvg-convert is required for PNG output")
    for name, body in pages.items():
        svg = output / f"{name}.svg"
        svg.write_text(f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-label="{name.replace("-", " ")}"><title>{name.replace("-", " ")}</title>{definitions()}{body}</svg>\n', encoding="utf-8")
        if not svg_only:
            subprocess.run([converter, "-w", str(WIDTH), "-h", str(HEIGHT), "-o", str(output / f"{name}.png"), str(svg)], check=True)
        print(svg)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Render a deterministic human/Zoe artistic brain comparison")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--svg-only", action="store_true")
    arguments = parser.parse_args()
    render(arguments.output_dir, arguments.svg_only)
