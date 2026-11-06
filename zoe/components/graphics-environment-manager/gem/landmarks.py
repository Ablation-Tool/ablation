from dataclasses import dataclass
import math


def _numpy():
    try:
        import numpy as np
    except ImportError as error:
        raise ValueError("Landmark alignment requires NumPy: python -m pip install numpy") from error
    return np


def _paired(source, target):
    np = _numpy()
    source = np.asarray(source, dtype=np.float64)
    target = np.asarray(target, dtype=np.float64)
    if source.ndim != 2 or source.shape[1] != 2 or source.shape != target.shape:
        raise ValueError("source and target must both be N-by-2 arrays with matching shapes")
    if len(source) < 2:
        raise ValueError("at least two landmark correspondences are required")
    if not np.all(np.isfinite(source)) or not np.all(np.isfinite(target)):
        raise ValueError("landmark coordinates must be finite")
    return source, target


def _rms(predicted, target):
    np = _numpy()
    return float(np.sqrt(np.sum((predicted - target) ** 2) / len(target)))


@dataclass(frozen=True)
class SimilarityAlignment:
    scale: float
    rotation: object
    translation: object
    predicted: object
    rms: float
    allow_reflection: bool

    @property
    def determinant(self):
        np = _numpy()
        return float(np.linalg.det(self.rotation))

    @property
    def angle_degrees(self):
        return math.degrees(math.atan2(self.rotation[1, 0], self.rotation[0, 0]))


@dataclass(frozen=True)
class AffineAlignment:
    matrix: object
    translation: object
    predicted: object
    rms: float
    rank: int
    unique: bool


def similarity_procrustes(source, target, allow_reflection=False):
    np = _numpy()
    source, target = _paired(source, target)
    if not isinstance(allow_reflection, bool):
        raise ValueError("allow_reflection must be a boolean")
    source_center = source.mean(axis=0)
    target_center = target.mean(axis=0)
    x = source - source_center
    y = target - target_center
    if np.linalg.matrix_rank(x) < 1 or np.linalg.matrix_rank(y) < 1:
        raise ValueError("each landmark set must contain at least two distinct points")
    u, singular, vt = np.linalg.svd(x.T @ y)
    natural_determinant = float(np.linalg.det(vt.T @ u.T))
    if allow_reflection:
        correction = np.diag([1.0, 1.0])
        adjusted_sum = float(singular.sum())
    else:
        correction = np.diag([1.0, natural_determinant])
        adjusted_sum = float(singular[0] + natural_determinant * singular[1])
    rotation = vt.T @ correction @ u.T
    scale = adjusted_sum / float(np.sum(x ** 2))
    if scale < 0:
        raise ValueError("the proper-rotation similarity scale is negative; enable reflection for this landmark set")
    translation = target_center - scale * rotation @ source_center
    predicted = scale * (rotation @ x.T).T + target_center
    return SimilarityAlignment(
        float(scale), rotation, translation, predicted,
        _rms(predicted, target), allow_reflection,
    )


def affine_design(source, target):
    np = _numpy()
    source, target = _paired(source, target)
    design = np.zeros((2 * len(source), 6), dtype=np.float64)
    design[0::2, 0:2] = source
    design[0::2, 2] = 1.0
    design[1::2, 3:5] = source
    design[1::2, 5] = 1.0
    return design, target.reshape(-1)


def affine_procrustes(source, target, allow_underdetermined=False):
    np = _numpy()
    source, target = _paired(source, target)
    if not isinstance(allow_underdetermined, bool):
        raise ValueError("allow_underdetermined must be a boolean")
    design, values = affine_design(source, target)
    rank = int(np.linalg.matrix_rank(design))
    unique = rank == 6
    if not unique and not allow_underdetermined:
        raise ValueError("full affine alignment requires at least three non-collinear correspondences (design rank 6)")
    parameters, *_ = np.linalg.lstsq(design, values, rcond=None)
    matrix = np.array([
        [parameters[0], parameters[1]],
        [parameters[3], parameters[4]],
    ])
    translation = np.array([parameters[2], parameters[5]])
    predicted = (matrix @ source.T).T + translation
    return AffineAlignment(matrix, translation, predicted, _rms(predicted, target), rank, unique)


def alignment_document(alignment):
    return {
        "scale": alignment.scale,
        "rotation": alignment.rotation.tolist(),
        "translation": alignment.translation.tolist(),
        "determinant": alignment.determinant,
        "angle_degrees": alignment.angle_degrees,
        "allow_reflection": alignment.allow_reflection,
        "predicted": alignment.predicted.tolist(),
        "rms": alignment.rms,
    }


def landmark_scene(source, target, alignment):
    from .model import Scene

    np = _numpy()
    source, target = _paired(source, target)
    predicted = np.asarray(alignment.predicted, dtype=np.float64)
    objects = []
    constraints = [{"type": "inside_canvas", "object": "*"}]
    for index, (source_point, target_point, fitted_point) in enumerate(zip(source, target, predicted)):
        source_id = f"source:{index}"
        target_id = f"target:{index}"
        fitted_id = f"fitted:{index}"
        connector_id = f"correspondence:{index}"
        objects.extend([
            {
                "id": source_id, "type": "ellipse", "role": "source_landmark",
                "center": (source_point * 10).tolist(), "radii": [35, 35],
                "fill": "red", "stroke": "black", "width": 10,
            },
            {
                "id": target_id, "type": "ellipse", "role": "target_landmark",
                "center": (target_point * 10).tolist(), "radii": [35, 35],
                "fill": "blue", "stroke": "black", "width": 10,
            },
            {
                "id": fitted_id, "type": "ellipse", "role": "fitted_landmark",
                "center": (fitted_point * 10).tolist(), "radii": [18, 18],
                "fill": "green", "stroke": "black", "width": 10,
            },
            {
                "id": connector_id, "type": "line", "role": "correspondence",
                "from": source_id, "to": target_id,
                "points": [(source_point * 10).tolist(), (target_point * 10).tolist()],
                "stroke": "gray", "width": 10,
            },
        ])
        constraints.extend([
            {"type": "connected", "a": connector_id, "b": source_id, "anchor": "center", "endpoint": 0},
            {"type": "connected", "a": connector_id, "b": target_id, "anchor": "center", "endpoint": 1},
            {"type": "aligned", "a": fitted_id, "b": target_id, "axis": "center_x"},
            {"type": "aligned", "a": fitted_id, "b": target_id, "axis": "center_y"},
        ])
    return Scene.from_dict({
        "schema_version": 1,
        "id": "landmark-procrustes",
        "title": "Landmark Procrustes alignment",
        "canvas": {"width": 6000, "height": 7000},
        "objects": objects,
        "constraints": constraints,
    })
