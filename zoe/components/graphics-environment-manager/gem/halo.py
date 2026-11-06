from __future__ import annotations

from dataclasses import dataclass
import math

import numpy as np

from .scene_utils import _ellipse, _line, _rectangle, _scene, _text

POSE_NAMES = ("rx", "ry", "rz", "tx", "ty", "tz")


@dataclass(frozen=True)
class Pose:
    rx: float = 0.0
    ry: float = 0.0
    rz: float = 0.0
    tx: float = 0.0
    ty: float = 0.0
    tz: float = 0.0

    def vector(self):
        return np.asarray([self.rx, self.ry, self.rz, self.tx, self.ty, self.tz], dtype=float)

    def moved(self, axis, delta):
        values = list(self.vector())
        values[axis] += delta
        values[:3] = np.clip(values[:3], -75, 75)
        values[3:] = np.clip(values[3:], -.45, .45)
        return Pose(*values)

    def as_dict(self):
        return {name: float(value) for name, value in zip(POSE_NAMES, self.vector())}


def rotation(pose):
    rx, ry, rz = np.radians([pose.rx, pose.ry, pose.rz])
    cx, sx = np.cos(rx), np.sin(rx)
    cy, sy = np.cos(ry), np.sin(ry)
    cz, sz = np.cos(rz), np.sin(rz)
    x_rotation = np.array([[1, 0, 0], [0, cx, -sx], [0, sx, cx]])
    y_rotation = np.array([[cy, 0, sy], [0, 1, 0], [-sy, 0, cy]])
    z_rotation = np.array([[cz, -sz, 0], [sz, cz, 0], [0, 0, 1]])
    return z_rotation @ y_rotation @ x_rotation


def rotation_error(first, second):
    value = (np.trace(rotation(first).T @ rotation(second)) - 1) / 2
    return math.degrees(math.acos(float(np.clip(value, -1, 1))))


def ellipsoid(center, radii, count=72):
    center = np.asarray(center, dtype=float)
    radii = np.asarray(radii, dtype=float)
    points = []
    for index in range(count):
        z = 1 - 2 * (index + .5) / count
        angle = index * math.pi * (3 - math.sqrt(5))
        radius = math.sqrt(max(0, 1-z*z))
        points.append(center + radii * [radius*math.cos(angle), radius*math.sin(angle), z])
    return points


def synthetic_points():
    groups = [
        ((-.12, .02, -.62), (.18, .15, .24)),
        ((.05, -.02, -.12), (.18, .14, .31)),
        ((-.16, .06, .43), (.23, .17, .23)),
        ((.32, -.09, .18), (.17, .10, .12)),
        ((-.32, .08, .64), (.12, .10, .11)),
    ]
    points = []
    for center, radii in groups:
        points.extend(ellipsoid(center, radii))
    for index in range(90):
        t = index / 89
        points.append([-.12+.16*t, .035*math.sin(t*math.tau*1.5), -.58+1.05*t])
    return np.asarray(points)


def _smooth(image):
    kernel = np.asarray([.25, .5, .25])
    image = np.apply_along_axis(lambda row: np.convolve(row, kernel, mode="same"), 0, image)
    image = np.apply_along_axis(lambda row: np.convolve(row, kernel, mode="same"), 1, image)
    return image


def project(points, pose, view_degrees=0, noise=0.0, seed=7):
    transformed = points @ rotation(pose).T + pose.vector()[3:]
    theta = math.radians(view_degrees)
    u = transformed[:, 0]*math.cos(theta) - transformed[:, 1]*math.sin(theta)
    depth = transformed[:, 0]*math.sin(theta) + transformed[:, 1]*math.cos(theta)
    weights = np.exp(-.35*depth)
    image, _x, _y = np.histogram2d(transformed[:, 2], u, bins=48, range=((-1.25, 1.25), (-1.25, 1.25)), weights=weights)
    image = _smooth(image)
    if noise:
        image = np.clip(image + np.random.default_rng(seed).normal(0, noise, image.shape), 0, None)
    total = image.sum()
    return image / total if total else image


def moment_distance(first, second):
    first, second = first/first.sum(), second/second.sum()
    y, x = np.indices(first.shape)
    first_center = np.asarray([(first*x).sum(), (first*y).sum()])
    second_center = np.asarray([(second*x).sum(), (second*y).sum()])
    return float(np.linalg.norm(first_center-second_center) / first.shape[0])


def pixel_distance(first, second):
    first, second = first/first.sum(), second/second.sum()
    return float(np.mean((first-second)**2))


def pool(image, size=4):
    height, width = image.shape
    return image.reshape(size, height//size, size, width//size).mean(axis=(1, 3))


def walsh_spectrum(bits):
    bits = np.asarray(bits)
    if bits.size == 0 or bits.size & (bits.size-1):
        raise ValueError("Boolean vector length must be a positive power of two")
    if not np.all((bits == 0) | (bits == 1)):
        raise ValueError("Walsh spectrum input must contain only zero and one")
    spectrum = 1 - 2*bits.astype(np.int64).reshape(-1)
    width = 1
    while width < spectrum.size:
        blocks = spectrum.reshape(-1, 2*width)
        left = blocks[:, :width].copy()
        right = blocks[:, width:].copy()
        blocks[:, :width] = left + right
        blocks[:, width:] = left - right
        width *= 2
    return spectrum


def nonlinearity(bits):
    bits = np.asarray(bits, dtype=np.uint8)
    variables = int(math.log2(bits.size)) if bits.size else 0
    if variables == 0 or variables % 2:
        raise ValueError("nonlinearity requires an even number of Boolean variables")
    return 2**(variables-1) - int(np.max(np.abs(walsh_spectrum(bits)))) // 2


def is_bent(bits):
    bits = np.asarray(bits, dtype=np.uint8)
    variables = int(math.log2(bits.size)) if bits.size else 0
    maximum = 2**(variables-1) - 2**(variables//2-1) if variables >= 2 and not variables % 2 else 0
    return bool(variables >= 2 and not variables % 2 and nonlinearity(bits) == maximum)


def walsh_template(image):
    pooled = pool(image)
    threshold = pooled.max() * .35 if pooled.max() else 0
    spectrum = np.abs(walsh_spectrum(pooled > threshold)).astype(float)
    norm = np.linalg.norm(spectrum)
    if norm:
        spectrum /= norm
    return np.sort(spectrum)


def walsh_distance(first, second):
    return float(np.mean(np.abs(walsh_template(first) - walsh_template(second))))


def _evaluate(points, pose, target, view_angle, metric):
    first = project(points, pose, 0)
    second = project(points, pose, view_angle)
    if metric == "l2":
        return pixel_distance(first, target[0]) + pixel_distance(second, target[1])
    if metric == "walsh":
        return walsh_distance(first, target[0]) + walsh_distance(second, target[1])
    raise ValueError("metric must be l2 or walsh")


def optimize(points, target, view_angle, seed, metric):
    initial = [Pose()]
    rng = np.random.default_rng(seed)
    for _ in range(23):
        initial.append(Pose(*np.r_[rng.uniform(-35, 35, 3), rng.uniform(-.2, .2, 3)]))
    ranked = sorted(initial, key=lambda pose: moment_distance(project(points, pose, 0), target[0]) + moment_distance(project(points, pose, view_angle), target[1]))
    results = []
    for start in ranked[:3]:
        current = start
        score = _evaluate(points, current, target, view_angle, metric)
        for step in (12, 6, 3, 1.5, .75, .25):
            for _ in range(2):
                improved = False
                for axis in range(6):
                    delta = step if axis < 3 else step / 60
                    for direction in (-1, 1):
                        candidate = current.moved(axis, direction*delta)
                        candidate_score = _evaluate(points, candidate, target, view_angle, metric)
                        if candidate_score + 1e-12 < score:
                            current, score = candidate, candidate_score
                            improved = True
                if not improved:
                    break
        results.append({"pose": current, "score": score})
    results.sort(key=lambda item: item["score"])
    return results


def experiment(metric="both", view_angle=65, noise=0.0, seed=7):
    if metric not in {"l2", "walsh", "both"}:
        raise ValueError("metric must be l2, walsh, or both")
    if isinstance(view_angle, bool) or not isinstance(view_angle, (int, float)) or not 1 <= view_angle <= 89:
        raise ValueError("view angle must be between 1 and 89 degrees")
    if isinstance(noise, bool) or not isinstance(noise, (int, float)) or not 0 <= noise <= .05:
        raise ValueError("noise must be between 0 and 0.05")
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 999999:
        raise ValueError("seed must be an integer from 0 to 999999")
    points = synthetic_points()
    truth = Pose(17, -21, 27, .10, -.08, .09)
    target = (project(points, truth, 0, noise, seed), project(points, truth, view_angle, noise, seed+1))
    report = {
        "schema_version": 1,
        "instrument": "Halo Field",
        "source": "original synthetic point cloud and two orthographic projections",
        "point_count": len(points),
        "projection_shape": [48, 48],
        "medical_data": False,
        "anatomical_model": False,
        "physical_xray_simulation": False,
        "encryption": False,
        "view_angle_degrees": float(view_angle),
        "noise": float(noise),
        "seed": seed,
        "truth": truth.as_dict(),
        "projection_model": "orthographic projection with exponential depth attenuation and separable [1,2,1] smoothing",
        "representations": {
            "l2": "normalized 48x48 pixel intensities; mean squared difference summed over two views",
            "walsh_template": "mean-pool to a 4x4 grid; Boolean threshold at 0.35 times the grid maximum; 16 signed Walsh magnitudes; L2-normalized and sorted; mean absolute difference summed over two views",
        },
        "optimizer": "moment-ranked starts followed by bounded coordinate descent over rx, ry, rz, tx, ty, tz",
        "metrics": {},
        "boundary_exchange": "candidate summaries are exchanged for comparison; metric scores are never averaged",
        "uncertainty_scope": "score gaps and competing candidates are evidence of ambiguity, not posterior probabilities",
        "inspiration": ["Zeng medical-image projection geometry", "Tokareva bent functions and Walsh-Hadamard nonlinearity", "Warren framed observation channels", "PETSc distributed ownership and boundary exchange", "DR Draw circle construction and the circled Zoe mark as visual boundaries"],
        "original_code": True,
        "autonomous_action": False,
    }
    metrics = ("l2", "walsh") if metric == "both" else (metric,)
    for name in metrics:
        candidates = optimize(points, target, view_angle, seed, name)
        for candidate in candidates:
            candidate["pose"] = candidate["pose"].as_dict()
            candidate["translation_error"] = float(np.linalg.norm(np.asarray(tuple(candidate["pose"][key] for key in ("tx", "ty", "tz"))) - truth.vector()[3:]))
            candidate["rotation_error_degrees"] = rotation_error(Pose(**candidate["pose"]), truth)
        report["metrics"][name] = {
            "best": candidates[0],
            "alternatives": candidates[1:3],
            "score_gap": candidates[1]["score"] - candidates[0]["score"],
            "tied_with_next": math.isclose(candidates[0]["score"], candidates[1]["score"], abs_tol=1e-12),
            "truth_score": _evaluate(points, truth, target, view_angle, name),
        }
    if metric == "both":
        first = Pose(**report["metrics"]["l2"]["best"]["pose"])
        second = Pose(**report["metrics"]["walsh"]["best"]["pose"])
        report["disagreement"] = first != second
        report["metric_rotation_difference_degrees"] = rotation_error(first, second)
        report["metric_translation_difference"] = float(np.linalg.norm(first.vector()[3:] - second.vector()[3:]))
    else:
        report["disagreement"] = None
        report["metric_rotation_difference_degrees"] = None
        report["metric_translation_difference"] = None
    measurements = [
        f"{name.upper()}: translation={report['metrics'][name]['best']['translation_error']:.3f}, rotation={report['metrics'][name]['best']['rotation_error_degrees']:.2f}°"
        for name in metrics
    ]
    report["summary"] = " · ".join(measurements)
    if metric == "both":
        report["summary"] += f" · independent poses disagree={report['disagreement']}"
    return report


def _raster(objects, prefix, image, left, top, cell=18):
    pooled = pool(image, 24)
    maximum = pooled.max() or 1
    for row in range(24):
        for column in range(24):
            value = float(pooled[row, column] / maximum)
            color = "white" if value > .65 else "cyan" if value > .30 else "blue" if value > .08 else "black"
            objects.append(_rectangle(f"{prefix}-{row}-{column}", [left+column*cell, top+row*cell, left+(column+1)*cell, top+(row+1)*cell], "none", color, 0))


def _arc(objects, identifier, center, radii, start, stop, stroke):
    steps = max(4, int(abs(stop-start)/6))
    points = [
        [
            center[0] + radii[0]*math.cos(math.radians(start+(stop-start)*index/steps)),
            center[1] + radii[1]*math.sin(math.radians(start+(stop-start)*index/steps)),
        ]
        for index in range(steps+1)
    ]
    for index, (first, second) in enumerate(zip(points, points[1:])):
        objects.append(_line(f"{identifier}-{index}", first, second, stroke, 1))


def halo_scene(report):
    truth = report["truth"]
    image_a = project(synthetic_points(), Pose(**truth), 0, report["noise"], report["seed"])
    image_b = project(synthetic_points(), Pose(**truth), report["view_angle_degrees"], report["noise"], report["seed"]+1)
    objects = [
        _rectangle("background", [0, 0, 1920, 1080], "black", "black"),
        _text("title", [88, 91], "HALO FIELD", 28, "cyan"),
        _text("headline", [88, 151], "Two projections. Six pose parameters. No forced agreement.", 36, "white"),
        _text("subtitle", [91, 191], "Synthetic geometry · competing similarity metrics · bounded uncertainty", 18, "lightgray"),
        _text("settings", [1270, 91], f"view={report['view_angle_degrees']:g}° · noise={report['noise']:g} · seed={report['seed']}", 16, "cyan"),
        _text("view-a", [140, 270], "VIEW A / reference", 20, "cyan"),
        _text("view-b", [1080, 270], "VIEW B / parallax", 20, "cyan"),
        _rectangle("frame-a", [132, 292, 580, 748], "blue", "black", 2),
        _rectangle("frame-b", [1072, 292, 1520, 748], "blue", "black", 2),
        _text("node-left", [650, 414], "NODE L", 16, "yellow"),
        _text("node-right", [940, 414], "NODE R", 16, "cyan"),
        _ellipse("halo-left", [680, 520], [45, 65], "yellow", "black", 2),
        _ellipse("halo-right", [970, 520], [45, 65], "cyan", "black", 2),
        _ellipse("zoe-circle", [825, 520], [27, 27], "white", "black", 1),
        _text("zoe-mark", [816, 529], "Z", 20, "white"),
        _line("halo-forward", [725, 480], [925, 480], "yellow", 1.5),
        _line("halo-back", [925, 560], [725, 560], "cyan", 1.5),
        _text("halo-forward-text", [765, 458], "ghost boundary ->", 13, "yellow"),
        _text("halo-back-text", [787, 592], "<- ghost boundary", 13, "cyan"),
        _text("halo-core", [758, 650], "no hidden average", 14, "white"),
        _text("halo-negative-space", [727, 686], "negative space is a constraint", 13, "gray"),
    ]
    _arc(objects, "halo-upper", [825, 520], [200, 190], 200, 340, "blue")
    _arc(objects, "halo-lower", [825, 520], [200, 190], 20, 160, "blue")
    _raster(objects, "a", image_a, 140, 300)
    _raster(objects, "b", image_b, 1080, 300)
    primary = next(iter(report["metrics"]))
    secondary = next((name for name in report["metrics"] if name != primary), None)
    best = report["metrics"][primary]["best"]
    primary_result = report["metrics"][primary]
    objects.extend([
        _text("best-label", [140, 804], f"{primary.upper()} CANDIDATE / independent metric", 16, "cyan"),
        _text("best-pose", [140, 838], f"rx={best['pose']['rx']:.1f}  ry={best['pose']['ry']:.1f}  rz={best['pose']['rz']:.1f}", 19, "white"),
        _text("best-translation", [140, 872], f"tx={best['pose']['tx']:.2f}  ty={best['pose']['ty']:.2f}  tz={best['pose']['tz']:.2f}", 17, "lightgray"),
        _text("best-errors", [140, 910], f"translation error={best['translation_error']:.3f}  rotation error={best['rotation_error_degrees']:.2f}°", 17, "yellow"),
        _text("best-score", [140, 944], f"score={best['score']:.6g} · next-score gap={primary_result['score_gap']:.3g} · tied={primary_result['tied_with_next']}", 14, "cyan"),
        _text("truth-label", [730, 804], "SYNTHETIC TRUTH / evaluation only", 16, "cyan"),
        _text("truth-pose", [730, 838], f"rx={truth['rx']}  ry={truth['ry']}  rz={truth['rz']}", 19, "white"),
        _text("truth-translation", [730, 872], f"tx={truth['tx']}  ty={truth['ty']}  tz={truth['tz']}", 17, "lightgray"),
        _text("uncertainty", [730, 910], "Score gaps are ambiguity, not posteriors.", 15, "lightgray"),
        _text("candidate-scope", [730, 944], "Three local searches retained per metric.", 14, "gray"),
    ])
    if secondary:
        other = report["metrics"][secondary]["best"]
        other_result = report["metrics"][secondary]
        objects.extend([
            _text("other-label", [1270, 804], f"{secondary.upper()} {'TEMPLATE' if secondary == 'walsh' else 'CANDIDATE'} / independent metric", 16, "cyan"),
            _text("other-errors", [1270, 838], f"translation error={other['translation_error']:.3f}", 17, "yellow"),
            _text("other-rotation", [1270, 872], f"rotation error={other['rotation_error_degrees']:.2f}°", 17, "yellow"),
            _text("other-score", [1270, 910], f"score={other['score']:.6g} · gap={other_result['score_gap']:.3g} · tied={other_result['tied_with_next']}", 14, "cyan"),
            _text("disagreement", [1270, 944], f"independent poses disagree: {report['disagreement']}", 16, "yellow" if report["disagreement"] else "white"),
        ])
    else:
        objects.extend([
            _text("boundary-label", [1270, 804], "METRIC BOUNDARY", 16, "cyan"),
            _text("single-metric", [1270, 838], "One metric selected; no comparison made.", 16, "lightgray"),
            _text("no-average", [1270, 872], "No hidden average or universal winner.", 16, "lightgray"),
        ])
    objects.extend([
        _text("summary", [88, 1007], report["summary"], 16, "lightgray"),
        _text("scope", [88, 1040], "Synthetic 6D pose experiment · no medical data · no encryption claim · no forced agreement", 14, "gray"),
    ])
    return _scene("halo-field", 1920, 1080, objects, "Halo Field · two projections and six pose parameters"), report
