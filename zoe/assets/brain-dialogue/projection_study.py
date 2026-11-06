from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import shutil
import subprocess

import numpy as np

import render as base

N = 256
SOURCE = "Gengsheng Lawrence Zeng, Medical Image Reconstruction, 2nd Edition, sections 2.2 and 2.6.3"
BOOK_URL = "https://learning.oreilly.com/library/view/medical-image-reconstruction/9783111055701/"


def sample2(field, x, y, x_min=-1.0, x_max=1.0, y_min=-1.0, y_max=1.0):
    nx, ny = field.shape[1], field.shape[0]
    ix = (np.asarray(x) - x_min) / (x_max - x_min) * (nx - 1)
    iy = (np.asarray(y) - y_min) / (y_max - y_min) * (ny - 1)
    valid = (ix >= 0) & (ix <= nx - 1) & (iy >= 0) & (iy <= ny - 1)
    ix = np.clip(ix, 0, nx - 1 - 1e-12)
    iy = np.clip(iy, 0, ny - 1 - 1e-12)
    x0, y0 = np.floor(ix).astype(int), np.floor(iy).astype(int)
    x1, y1 = np.minimum(x0 + 1, nx - 1), np.minimum(y0 + 1, ny - 1)
    ax, ay = ix - x0, iy - y0
    result = (
        field[y0, x0] * (1-ax) * (1-ay)
        + field[y0, x1] * ax * (1-ay)
        + field[y1, x0] * (1-ax) * ay
        + field[y1, x1] * ax * ay
    )
    return result * valid


def phantom():
    coordinates = np.linspace(-1, 1, N)
    x, y = np.meshgrid(coordinates, coordinates)
    left = np.exp(-((x + .29)**2 / .085 + y*y / .29))
    right = .88 * np.exp(-((x - .29)**2 / .085 + y*y / .29))
    ring = .45 * np.exp(-((np.hypot(x, y) - .51)**2 / .003))
    f = left + right + ring
    spectrum = np.fft.fftshift(np.fft.fft2(np.fft.ifftshift(f))) * (coordinates[1]-coordinates[0])**2
    return f, spectrum


def project(f, theta, detector):
    s, u = np.meshgrid(detector, detector)
    x = s * math.cos(theta) - u * math.sin(theta)
    y = s * math.sin(theta) + u * math.cos(theta)
    samples = sample2(f, x, y)
    return samples.sum(axis=0) * (detector[1] - detector[0])


def experiment():
    f, spectrum = phantom()
    detector = np.linspace(-1.5, 1.5, N)
    frequencies = np.fft.fftshift(np.fft.fftfreq(N, d=detector[1]-detector[0]))
    field_frequencies = np.fft.fftshift(np.fft.fftfreq(N, d=2/(N-1)))
    checks = []
    projections = []
    for theta in np.linspace(0, math.pi, 8, endpoint=False):
        projection = project(f, theta, detector)
        projections.append(projection)
        one_dimensional = np.fft.fftshift(np.fft.fft(np.fft.ifftshift(projection))) * (detector[1]-detector[0])
        kx = frequencies * math.cos(theta)
        ky = frequencies * math.sin(theta)
        central = sample2(spectrum.real, kx, ky, field_frequencies[0], field_frequencies[-1], field_frequencies[0], field_frequencies[-1])
        central = central + 1j * sample2(spectrum.imag, kx, ky, field_frequencies[0], field_frequencies[-1], field_frequencies[0], field_frequencies[-1])
        relative_error = float(np.linalg.norm(one_dimensional-central) / np.linalg.norm(one_dimensional))
        correlation = float(abs(np.vdot(one_dimensional, central)) / (np.linalg.norm(one_dimensional)*np.linalg.norm(central)))
        checks.append({"theta_degrees": math.degrees(theta), "relative_l2_error": relative_error, "complex_correlation": correlation})
    assert all(item["complex_correlation"] > .99 for item in checks), checks
    return f, spectrum, np.asarray(projections), checks


def spectral_profile(spectrum, count=128):
    frequencies = np.fft.fftshift(np.fft.fftfreq(N, d=2/(N-1)))
    radial = np.linspace(0, frequencies[-1], N//2)
    profile = []
    for theta in np.linspace(0, math.tau, count, endpoint=False):
        kx, ky = radial * math.cos(theta), radial * math.sin(theta)
        values = sample2(abs(spectrum), kx, ky, frequencies[0], frequencies[-1], frequencies[0], frequencies[-1])
        profile.append(float(np.sum(np.log1p(values[1:] * 100))))
    profile = np.asarray(profile)
    return profile / profile.max()


def mix(strength):
    warm = np.asarray((238, 188, 114))
    cool = np.asarray((112, 229, 220))
    rgb = np.round(warm * (1-strength) + cool * strength).astype(int)
    return "#" + "".join(f"{value:02x}" for value in rgb)


def eye_art(f, spectrum, projections):
    profile = spectral_profile(spectrum)
    parts = [base.background()]
    parts.append(base.text(96, 94, "MATHEMATICS AS A WARDROBE  /  CENTRAL-SLICE STUDY", 15, "#aac1d3", spacing=2.6))
    parts.append(base.text(96, 165, "A field learning to see.", 55, "#eef2f4", weight=400))
    parts.append(base.text(98, 208, "Projection becomes spectrum. Spectrum becomes form.", 22, "#bccbd9", spacing=.4))
    cx, cy = 1210, 560
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="272" fill="url(#zoe-halo)" opacity=".7"/>')
    for index in range(9):
        parts.append(f'<ellipse cx="{cx}" cy="{cy}" rx="{300+index*11}" ry="{185+index*7}" fill="none" stroke="#b5c8e1" stroke-width=".7" opacity=".12" transform="rotate({-25+index*7} {cx} {cy})"/>')
    for index, strength in enumerate(profile):
        theta = math.tau * index / len(profile)
        inner = 66 + 9 * math.sin(index * 1.9)
        outer = 218 + 35 * strength
        x1, y1 = cx + inner*math.cos(theta), cy + inner*math.sin(theta)
        x2, y2 = cx + outer*math.cos(theta), cy + outer*math.sin(theta)
        parts.append(f'<path d="M{x1:.2f} {y1:.2f} L{x2:.2f} {y2:.2f}" stroke="{mix(strength)}" stroke-width="{.6+2.4*strength:.2f}" opacity="{.28+.67*strength:.2f}" stroke-linecap="round"/>')
        if index % 2 == 0:
            parts.append(f'<circle cx="{x2:.2f}" cy="{y2:.2f}" r="{.8+2.2*strength:.2f}" fill="{mix(strength)}" opacity=".8"/>')
    for index in range(8):
        radius = 72 + index * 22
        parts.append(f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" stroke="{mix(index/8)}" stroke-width=".65" opacity=".3"/>')
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="57" fill="url(#iris)" stroke="#d7d8a5" stroke-width="1.2"/>')
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="34" fill="#08111e"/>')
    parts.append(f'<ellipse cx="{cx-12}" cy="{cy-14}" rx="11" ry="6" fill="#edffe4" opacity=".8" transform="rotate(-26 {cx-12} {cy-14})"/>')
    parts.append(base.text(138, 315, "01 / OBJECT", 16, "#d5d7ae", spacing=2.5))
    for index, scale in enumerate((1.0, .82, .64, .46)):
        for sign, strength in ((-1, .9), (1, .7)):
            parts.append(f'<ellipse cx="{315+sign*39.15}" cy="444" rx="{39.4*scale:.2f}" ry="{58.2*scale:.2f}" fill="{mix(index/4)}" fill-opacity=".07" stroke="{mix(index/4)}" stroke-width="1" opacity="{strength}"/>')
        parts.append(f'<ellipse cx="315" cy="444" rx="{68.85+index*2}" ry="{55.08+index*2}" fill="none" stroke="#c6d89f" stroke-width=".8" opacity=".52"/>')
    for index in range(3):
        theta = index * math.pi / 3 + .22
        dx, dy = 160*math.cos(theta), 160*math.sin(theta)
        parts.append(f'<path d="M{315-dx:.1f} {444-dy:.1f} L{315+dx:.1f} {444+dy:.1f}" stroke="#e2e9cd" stroke-width=".7" stroke-dasharray="4 6" opacity=".38"/>')
    parts.append(base.text(138, 592, "02 / PROJECT", 16, "#d5d7ae", spacing=2.5))
    parts.append(base.text(138, 624, "Integrate along each viewing direction", 17, "#9eb1c5"))
    maximum = max(float(np.max(np.abs(row))) for row in projections)
    for row_index, projection in enumerate(projections):
        points = []
        for index, value in enumerate(projection):
            x = 166 + index / (N-1) * 315
            y = 692 + row_index * 13 - 22 * value / maximum
            points.append((x, y))
        parts.append(f'<path d="{base.line(points)}" fill="none" stroke="{mix(row_index/len(projections))}" stroke-width="1" opacity=".72"/>')
    parts.append(base.text(138, 831, "03 / SLICE", 16, "#d5d7ae", spacing=2.5))
    parts.append(base.text(138, 863, "Read the spectrum radially; let energy become color", 17, "#9eb1c5"))
    points = [(166+index/(len(profile)-1)*315, 931-58*value) for index, value in enumerate(profile)]
    parts.append(f'<path d="{base.line(points)}" fill="none" stroke="url(#bridge)" stroke-width="1.6" opacity=".8"/>')
    parts.append(base.text(960, 998, "P(ω, θ) = F(ω cos θ, ω sin θ)", 29, "#e1e6dc", "Lato, sans-serif", 400, 1, "middle"))
    parts.append(base.text(96, 1040, "SYNTHETIC PHANTOM · DISCRETE APPROXIMATION · NO MEDICAL DATA", 12, "#8499b0", spacing=2))
    parts.append(base.text(1824, 1040, "ZENG · MEDICAL IMAGE RECONSTRUCTION · §2.2", 12, "#8499b0", spacing=1.5, anchor="end"))
    return "".join(parts)


def render(output, svg_only=False):
    output.mkdir(parents=True, exist_ok=True)
    f, spectrum, projections, checks = experiment()
    document = {
        "schema_version": 1,
        "source": SOURCE,
        "source_url": BOOK_URL,
        "equation": "P(omega,theta)=F(omega*cos(theta),omega*sin(theta))",
        "grid": [N, N],
        "phantom": "two elliptical Gaussian lobes and a narrow ring; synthetic, not medical data",
        "method": "bilinear parallel-beam sampling and centered DFT with physical sample spacing; compare projection FFT with interpolated central Fourier slices",
        "approximation_scope": "coarse discrete approximation; interpolation and finite-grid errors are retained, not a validated medical reconstruction",
        "correlation_minimum": min(item["complex_correlation"] for item in checks),
        "max_relative_l2_error": max(item["relative_l2_error"] for item in checks),
        "correlation_threshold": .99,
        "checks": checks,
        "medical_reconstruction": False,
        "book_content_included": False,
    }
    (output / "projection-verification.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    if not svg_only:
        converter = shutil.which("rsvg-convert")
        if converter is None:
            raise RuntimeError("rsvg-convert is required for PNG output")
    svg = output / "projection-iris.svg"
    svg.write_text(f'<svg xmlns="http://www.w3.org/2000/svg" width="1920" height="1080" viewBox="0 0 1920 1080" role="img" aria-label="Projection Fourier iris"><title>Projection Fourier iris</title>{base.definitions()}{eye_art(f, spectrum, projections)}</svg>\n')
    if not svg_only:
        subprocess.run([converter, "-w", "1920", "-h", "1080", "-o", str(output / "projection-iris.png"), str(svg)], check=True)
    print(json.dumps({"checks": checks, "output": str(svg)}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify a discrete central-slice toy and render its spectral iris")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--svg-only", action="store_true")
    arguments = parser.parse_args()
    render(arguments.output_dir, arguments.svg_only)
