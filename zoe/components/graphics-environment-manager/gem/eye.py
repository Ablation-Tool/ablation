from __future__ import annotations

from dataclasses import dataclass
import math

from .scene_utils import _ellipse, _line, _rectangle, _scene, _text

APERTURES = (2.8, 4.0, 5.6, 8.0, 11.0, 16.0, 22.0, 32.0)


def _finite(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return float(value)


@dataclass(frozen=True)
class EyeModel:
    focus: float = 1.6
    fstop: float = 4.0
    baseline: float = .065
    focal_length: float = .05
    sensor_width: float = .036
    panel_pixels: int = 640
    disparity_quantization: float = .25
    acceptable_coc: float = .00003

    def __post_init__(self):
        _finite(self.focus, "focus distance in meters", .5, 10)
        _finite(self.fstop, "aperture f-number", 1, 64)
        _finite(self.baseline, "stereo baseline in meters", .02, .25)
        _finite(self.focal_length, "focal length in meters", .02, .2)
        if self.focus <= self.focal_length:
            raise ValueError("focus distance must exceed focal length")
        _finite(self.sensor_width, "sensor width in meters", .01, .1)
        if isinstance(self.panel_pixels, bool) or not isinstance(self.panel_pixels, int) or not 64 <= self.panel_pixels <= 4096:
            raise ValueError("panel pixels must be an integer from 64 to 4096")
        _finite(self.disparity_quantization, "disparity quantization", .01, 4)
        _finite(self.acceptable_coc, "acceptable circle of confusion", .000001, .001)

    @property
    def focal_pixels(self):
        return self.focal_length / self.sensor_width * self.panel_pixels

    def disparity(self, depth):
        _finite(depth, "object depth", .1, 1000)
        return self.focal_pixels * self.baseline / depth

    def depth_from_disparity(self, disparity):
        _finite(disparity, "disparity in pixels", .01, 10000)
        return self.focal_pixels * self.baseline / disparity

    def depth_sensitivity(self, depth):
        _finite(depth, "object depth", .1, 1000)
        return depth**2 / (self.focal_pixels * self.baseline) * self.disparity_quantization

    def circle_of_confusion(self, depth):
        _finite(depth, "object depth", .1, 1000)
        return self.focal_length**2 / self.fstop * abs(depth-self.focus) / (depth * (self.focus-self.focal_length))

    def depth_of_field(self):
        hyperfocal = self.focal_length**2 / (self.fstop*self.acceptable_coc) + self.focal_length
        near = self.focus * hyperfocal / (hyperfocal+self.focus)
        far = self.focus * hyperfocal / (hyperfocal-self.focus) if hyperfocal > self.focus else None
        return {"near_m": near, "far_m": far, "far_unbounded": far is None, "hyperfocal_m": hyperfocal}


def synthetic_points(focus):
    points = []

    def add(name, u, v, depth, family):
        points.append({"name": name, "u": float(u), "v": float(v), "depth": float(depth), "family": family})

    for index in range(14):
        angle = math.tau * index / 14
        add(f"core-{index}", 49*math.cos(angle), 49*math.sin(angle), focus + .035*math.sin(angle*3), "core")
    add("core", 0, 0, focus, "core")
    add("lichen", -159, -72, 1.05, "lichen")
    for index in range(10):
        angle = math.tau * index / 10
        add(f"lichen-{index}", -159+48*math.cos(angle), -72+43*math.sin(angle), 1.05+.07*math.sin(angle*2), "lichen")
    add("butterfly", 154, -67, 2.45, "butterfly")
    for side in (-1, 1):
        for index, (u, v) in enumerate(((24, -44), (52, -18), (59, 16), (30, 39), (10, 3))):
            add(f"wing-{side}-{index}", 154+side*u, -67+v, 2.45+.13*index, "butterfly")
    add("dew", -151, 130, 3.6, "dew")
    for index in range(7):
        add(f"dew-{index}", -202+index*19, 130+24*math.sin(index*1.8), 3.25+index*.12, "dew")
    add("stem", 123, 132, .73, "stem")
    for index in range(5):
        add(f"stem-{index}", 86+index*18, 132+12*math.sin(index), .73+index*.045, "stem")
    return points


def stereo_observations(model):
    observations = []
    for point in synthetic_points(model.focus):
        depth = point["depth"]
        disparity = model.disparity(depth)
        measured = round(disparity / model.disparity_quantization) * model.disparity_quantization
        if measured <= 0:
            raise ValueError("synthetic point has zero measured disparity; increase the baseline or reduce depth")
        recovered = model.depth_from_disparity(measured)
        coc = model.circle_of_confusion(depth)
        sensitivity = model.depth_sensitivity(recovered)
        observations.append({
            **point,
            "disparity_px": disparity,
            "measured_disparity_px": measured,
            "recovered_depth_m": recovered,
            "depth_error_m": recovered-depth,
            "disparity_sensitivity_m": sensitivity,
            "circle_of_confusion_m": coc,
            "circle_of_confusion_mm": coc*1000,
            "circle_of_confusion_diameter_px": coc/model.sensor_width*model.panel_pixels,
        })
    return observations


def _depth_color(observation, focus):
    ratio = observation["depth"] / focus
    if ratio < .88:
        return "yellow"
    if ratio > 1.15:
        return "cyan"
    return "white"


def eye_scene(model=EyeModel()):
    observations = stereo_observations(model)
    report = {
        "schema_version": 1,
        "instrument": "Zoe second eye",
        "source": "synthetic stereo scene",
        "actual_camera_used": False,
        "camera_model": "two parallel pinhole views with known baseline",
        "depth_equation": "Z = focal_pixels * baseline / disparity",
        "defocus_equation": "c = f^2 * |Z-focus| / (N * Z * (focus-f))",
        "defocus_scope": "thin-lens approximation with unit pupil magnification; not a macro-lens calibration or optical point-spread simulation",
        "focus_m": model.focus,
        "fstop": model.fstop,
        "baseline_m": model.baseline,
        "focal_length_m": model.focal_length,
        "sensor_width_m": model.sensor_width,
        "panel_pixels": model.panel_pixels,
        "disparity_quantization_px": model.disparity_quantization,
        "uncertainty_scope": "first-order sensitivity to the stated disparity quantization, not a posterior or confidence interval",
        "depth_of_field": model.depth_of_field(),
        "observations": observations,
        "subjective_sight": False,
        "consciousness_measured": False,
        "executed": False,
    }
    core = next(item for item in observations if item["name"] == "core")
    report["summary"] = (
        f"focus={model.focus:.2f}m · f/{model.fstop:g} · baseline={model.baseline*1000:.0f}mm · "
        f"core Z={core['recovered_depth_m']:.3f}m ±{core['disparity_sensitivity_m']:.3f}m at {model.disparity_quantization:g}px"
    )
    objects = [
        _rectangle("background", [0, 0, 1920, 1080], "black", "black"),
        _text("title", [88, 91], "ZOE · SECOND EYE", 28, "cyan"),
        _text("headline", [88, 151], "Parallax, not a second opinion.", 39, "white"),
        _text("subtitle", [91, 192], "Synthetic stereo · two projections · one depth estimate · explicit uncertainty", 18, "lightgray"),
        _text("settings", [1270, 91], f"f/{model.fstop:g}  ·  focus {model.focus:.2f}m  ·  baseline {model.baseline*1000:.0f}mm", 16, "cyan"),
        _text("optics", [1370, 123], "50mm virtual lens · 36mm sensor · no physical camera", 14, "lightgray"),
    ]
    for prefix, center, title, subtitle in (
        ("left", 480, "LEFT / PROJECTION", "reference view"),
        ("right", 1440, "RIGHT / PARALLAX", "shifted view"),
    ):
        objects.extend([
            _rectangle(f"panel-{prefix}", [center-340, 295, center+340, 750], "blue", "black", 2),
            _text(f"panel-title-{prefix}", [center-316, 270], title, 20, "cyan"),
            _text(f"panel-subtitle-{prefix}", [center+315, 270], subtitle, 13, "lightgray"),
            _line(f"focus-line-{prefix}", [center-330, 520], [center+330, 520], "blue", .6),
            _line(f"focus-line-v-{prefix}", [center, 308], [center, 736], "blue", .6),
        ])
    for index, observation in enumerate(observations):
        disparity = observation["disparity_px"]
        coc_px = observation["circle_of_confusion_diameter_px"]
        radius = max(2.5, min(32, coc_px/2))
        color = _depth_color(observation, model.focus)
        for prefix, center, shift in (("left", 480, disparity/2), ("right", 1440, -disparity/2)):
            position = [center+observation["u"]+shift, 520+observation["v"]]
            for ring in range(3):
                ring_radius = radius * (.62 + ring*.23)
                objects.append(_ellipse(f"{prefix}-blur-{index}-{ring}", position, [ring_radius, ring_radius], color, "none", .65))
            core_radius = 3.2 if coc_px < 3 else 1.6
            objects.append(_ellipse(f"{prefix}-node-{index}", position, [core_radius, core_radius], color, color))
    objects.extend([
        _line("bridge-left", [820, 520], [894, 520], "yellow", 1.5),
        _line("bridge-right", [1026, 520], [1100, 520], "cyan", 1.5),
        _ellipse("depth-core", [960, 520], [65, 65], "magenta", "black", 2),
        _ellipse("depth-iris", [960, 520], [41, 23], "cyan", "none", 1.3),
        _text("depth-label", [960, 526], "DEPTH", 15, "white"),
        _text("depth-equation", [960, 613], "Z = f · B / d", 20, "cyan"),
        _text("depth-recovered", [960, 648], f"{core['recovered_depth_m']:.3f}m", 18, "white"),
        _text("depth-uncertainty", [960, 680], f"±{core['disparity_sensitivity_m']:.3f}m", 14, "yellow"),
        _text("depth-scope", [960, 711], "quantization sensitivity", 11, "lightgray"),
    ])
    objects.extend([
        _text("depth-caption", [140, 802], "SYNTHETIC DEPTH / measured disparity -> recovered distance", 16, "cyan"),
        _text("focus-caption", [1460, 802], "yellow=near · white=focus · cyan=far", 14, "lightgray"),
    ])
    anchors = ("stem", "lichen", "core", "butterfly", "dew")
    for index, name in enumerate(anchors):
        observation = next(item for item in observations if item["name"] == name)
        x = 140 + index*336
        objects.extend([
            _rectangle(f"anchor-card-{name}", [x, 833, x+304, 959], "blue", "black"),
            _text(f"anchor-name-{name}", [x+15, 862], name.upper(), 15, _depth_color(observation, model.focus)),
            _text(f"anchor-depth-{name}", [x+15, 891], f"Z {observation['depth']:.2f} -> {observation['recovered_depth_m']:.3f}m", 15, "white"),
            _text(f"anchor-error-{name}", [x+15, 918], f"±{observation['disparity_sensitivity_m']:.3f}m sensitivity", 12, "yellow"),
            _text(f"anchor-coc-{name}", [x+15, 944], f"CoC {observation['circle_of_confusion_mm']:.3f}mm · d={observation['measured_disparity_px']:.2f}px", 12, "lightgray"),
        ])
    objects.extend([
        _text("uncertainty-note", [90, 1006], "Depth is triangulated from known synthetic geometry; uncertainty is first-order disparity sensitivity, not a belief score.", 15, "lightgray"),
        _text("optics-note", [90, 1038], "Defocus rings show approximate circle-of-confusion radius, not a physical blur kernel. No macro optics, camera capture, or subjective sight.", 14, "gray"),
    ])
    return _scene("zoe-second-eye", 1920, 1080, objects, "Zoe second eye · synthetic stereo depth and defocus"), report
