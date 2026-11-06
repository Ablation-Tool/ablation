from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math

from .scene_utils import _line, _rectangle, _scene, _text

PIECE_NAMES = ("I", "O", "T", "S", "Z", "J", "L")
PIECE_COLORS = {
    "I": "cyan", "O": "yellow", "T": "magenta", "S": "green",
    "Z": "red", "J": "blue", "L": "white",
}
BASE_SHAPES = {
    "I": ((0, 1), (1, 1), (2, 1), (3, 1)),
    "O": ((1, 0), (2, 0), (1, 1), (2, 1)),
    "T": ((1, 0), (0, 1), (1, 1), (2, 1)),
    "S": ((1, 0), (2, 0), (0, 1), (1, 1)),
    "Z": ((0, 0), (1, 0), (1, 1), (2, 1)),
    "J": ((0, 0), (0, 1), (1, 1), (2, 1)),
    "L": ((2, 0), (0, 1), (1, 1), (2, 1)),
}
DEFAULT_THRESHOLDS = (0.02, 0.05, 0.10, 0.15, 0.30, 0.50)
MASK64 = (1 << 64) - 1


def _normalize(cells):
    minimum_x = min(x for x, _ in cells)
    minimum_y = min(y for _, y in cells)
    return tuple(sorted((x-minimum_x, y-minimum_y) for x, y in cells))


def _rotation_states(cells):
    states = []
    current = cells
    for _ in range(4):
        states.append(current)
        current = _normalize([(2-y, x) for x, y in current])
    return tuple(states)


ROTATIONS = {name: _rotation_states(cells) for name, cells in BASE_SHAPES.items()}


class SplitMix64:
    def __init__(self, seed):
        self.state = seed & MASK64

    def next(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK64
        value = self.state
        value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9 & MASK64
        value = (value ^ (value >> 27)) * 0x94D049BB133111EB & MASK64
        return value ^ (value >> 31)

    def randbelow(self, bound):
        if bound <= 0:
            raise ValueError("bound must be positive")
        limit = (1 << 64) - ((1 << 64) % bound)
        while True:
            value = self.next()
            if value < limit:
                return value % bound


@dataclass(frozen=True)
class Piece:
    kind: str
    x: int
    y: int
    rotation: int = 0

    def cells(self):
        rotation = ROTATIONS[self.kind][self.rotation % 4]
        return tuple((self.x+x, self.y+y) for x, y in rotation)

    def moved(self, dx=0, dy=0, rotation=0):
        return Piece(self.kind, self.x+dx, self.y+dy, (self.rotation+rotation) % 4)

    def as_dict(self):
        return {"kind": self.kind, "x": self.x, "y": self.y, "rotation": self.rotation}


class TetrisGame:
    def __init__(self, seed=7, randomizer="bag", width=10, height=20):
        if randomizer not in {"bag", "uniform"}:
            raise ValueError("randomizer must be bag or uniform")
        if isinstance(width, bool) or not isinstance(width, int) or width < 4:
            raise ValueError("width must be at least 4")
        if isinstance(height, bool) or not isinstance(height, int) or height < 4:
            raise ValueError("height must be at least 4")
        if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= MASK64:
            raise ValueError("seed must be an unsigned 64-bit integer")
        self.width = width
        self.height = height
        self.seed = seed
        self.randomizer = randomizer
        self.rng = SplitMix64(seed)
        self.grid = [[None for _ in range(width)] for _ in range(height)]
        self.remaining = []
        self.lines = 0
        self.score = 0
        self.level = 1
        self.tick_count = 0
        self.gravity_interval = 30
        self.game_over = False
        self.current = self._spawn_piece(self._draw_kind())
        self.next_kind = self._draw_kind()
        if not self._valid(self.current):
            self.game_over = True

    def _spawn_piece(self, kind):
        return Piece(kind, self.width//2-2, 0)

    def _draw_kind(self):
        if self.randomizer == "uniform":
            return PIECE_NAMES[self.rng.randbelow(len(PIECE_NAMES))]
        if not self.remaining:
            self.remaining = list(PIECE_NAMES)
            for index in range(len(self.remaining)-1, 0, -1):
                other = self.rng.randbelow(index+1)
                self.remaining[index], self.remaining[other] = self.remaining[other], self.remaining[index]
        return self.remaining.pop(0)

    def _valid(self, piece):
        for x, y in piece.cells():
            if not 0 <= x < self.width or not 0 <= y < self.height or self.grid[y][x] is not None:
                return False
        return True

    def move(self, direction):
        candidate = self.current.moved(dx=direction)
        if self.game_over or not self._valid(candidate):
            return False
        self.current = candidate
        return True

    def rotate(self, direction=1):
        candidate = self.current.moved(rotation=direction)
        if self.game_over or not self._valid(candidate):
            return False
        self.current = candidate
        return True

    def soft_drop(self):
        if self.game_over:
            return False
        candidate = self.current.moved(dy=1)
        if self._valid(candidate):
            self.current = candidate
        else:
            self._lock()
        return True

    def hard_drop(self):
        if self.game_over:
            return False
        while self._valid(self.current.moved(dy=1)):
            self.current = self.current.moved(dy=1)
        self._lock()
        return True

    def tick(self, count=1):
        for _ in range(count):
            if self.game_over:
                break
            self.tick_count += 1
            if self.tick_count % self.gravity_interval == 0:
                self.soft_drop()

    def _lock(self):
        for x, y in self.current.cells():
            self.grid[y][x] = self.current.kind
        retained = [row for row in self.grid if not all(cell is not None for cell in row)]
        cleared = self.height - len(retained)
        if cleared:
            self.grid = retained + [[None for _ in range(self.width)] for _ in range(cleared)]
            self.lines += cleared
            self.score += 10 * cleared * cleared
            self.level = 1 + self.score // 500
            self.gravity_interval = max(1, 30 >> min(self.level-1, 29))
        self.current = self._spawn_piece(self.next_kind)
        self.next_kind = self._draw_kind()
        if not self._valid(self.current):
            self.game_over = True

    def next_probabilities(self):
        if self.randomizer == "uniform" or not self.remaining:
            return {name: 1/len(PIECE_NAMES) for name in PIECE_NAMES}
        probability = 1/len(self.remaining)
        return {name: probability if name in self.remaining else 0.0 for name in PIECE_NAMES}

    def joint_probabilities(self, horizon=1):
        if isinstance(horizon, bool) or not isinstance(horizon, int) or not 1 <= horizon <= 3:
            raise ValueError("horizon must be an integer from 1 to 3")

        def walk(remaining, depth):
            if depth == horizon:
                return {(): 1.0}
            outcomes = {}
            if self.randomizer == "uniform":
                for kind in PIECE_NAMES:
                    for sequence, probability in walk(remaining, depth+1).items():
                        key = (kind,) + sequence
                        outcomes[key] = outcomes.get(key, 0.0) + probability/len(PIECE_NAMES)
                return outcomes
            if not remaining:
                remaining = PIECE_NAMES
            probability = 1/len(remaining)
            for kind in remaining:
                next_remaining = tuple(other for other in remaining if other != kind)
                for sequence, value in walk(next_remaining, depth+1).items():
                    key = (kind,) + sequence
                    outcomes[key] = outcomes.get(key, 0.0) + probability*value
            return outcomes

        return walk(tuple(self.remaining), 0)

    def accessibility(self, horizon=1, thresholds=DEFAULT_THRESHOLDS):
        distribution = self.joint_probabilities(horizon)
        results = []
        for threshold in thresholds:
            if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
                raise ValueError("probability thresholds must be finite numbers from 0 to 1")
            accessible = sum(probability > threshold for probability in distribution.values())
            results.append({
                "tau": float(threshold),
                "accessible_volume": accessible,
                "complement_volume": len(distribution) - accessible,
                "outcome_space": len(distribution),
                "horizon": horizon,
                "approximate": False,
            })
        return results

    def snapshot(self):
        return {
            "schema_version": 1,
            "width": self.width,
            "height": self.height,
            "seed": self.seed,
            "randomizer": self.randomizer,
            "grid": [list(row) for row in self.grid],
            "current": self.current.as_dict(),
            "next_kind": self.next_kind,
            "remaining": list(self.remaining),
            "rng_state": self.rng.state,
            "lines": self.lines,
            "score": self.score,
            "level": self.level,
            "tick_count": self.tick_count,
            "gravity_interval": self.gravity_interval,
            "game_over": self.game_over,
        }

    @classmethod
    def from_snapshot(cls, document):
        game = cls(
            seed=document["seed"], randomizer=document["randomizer"],
            width=document["width"], height=document["height"],
        )
        if len(document["grid"]) != game.height or any(len(row) != game.width for row in document["grid"]):
            raise ValueError("snapshot grid dimensions do not match")
        game.grid = [list(row) for row in document["grid"]]
        current = document["current"]
        game.current = Piece(current["kind"], current["x"], current["y"], current["rotation"])
        game.next_kind = document["next_kind"]
        game.remaining = list(document["remaining"])
        game.rng.state = document["rng_state"]
        game.lines = document["lines"]
        game.score = document["score"]
        game.level = document["level"]
        game.tick_count = document["tick_count"]
        game.gravity_interval = document["gravity_interval"]
        game.game_over = document["game_over"]
        if not game.game_over and not game._valid(game.current):
            raise ValueError("snapshot current piece is invalid")
        return game

    def snapshot_hash(self):
        canonical = json.dumps(self.snapshot(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def randomizer_log_likelihood(observed, model, bag_position=0):
    if model not in {"bag", "uniform"}:
        raise ValueError("model must be bag or uniform")
    if isinstance(bag_position, bool) or not isinstance(bag_position, int) or not 0 <= bag_position <= 6:
        raise ValueError("bag_position must be an integer from 0 to 6")
    remaining = set(PIECE_NAMES)
    position = bag_position
    likelihood = 0.0
    for kind in observed:
        if kind not in PIECE_NAMES:
            raise ValueError("observed piece must be one of I, O, T, S, Z, J, L")
        if model == "uniform":
            likelihood += math.log(1/len(PIECE_NAMES))
            continue
        if position == 0:
            remaining = set(PIECE_NAMES)
        if kind not in remaining:
            return -math.inf
        likelihood += math.log(1/len(remaining))
        remaining.remove(kind)
        position = (position+1) % 7
    return likelihood


def randomizer_posterior(observed, bag_position=0):
    models = ("uniform", "bag")
    log_weights = {
        model: math.log(.5) + randomizer_log_likelihood(observed, model, bag_position)
        for model in models
    }
    if all(value == -math.inf for value in log_weights.values()):
        raise ValueError("observed sequence is incompatible with both randomizers")
    maximum = max(log_weights.values())
    weights = {model: math.exp(value-maximum) for model, value in log_weights.items()}
    total = sum(weights.values())
    return {model: weights[model]/total for model in models}


def tetris_report(game, horizon=1, thresholds=DEFAULT_THRESHOLDS):
    distribution = game.next_probabilities()
    accessible = game.accessibility(horizon, thresholds)
    example_sequence = list(PIECE_NAMES)
    report = {
        "schema_version": 1,
        "instrument": "Bounded Tetris probability field",
        "source": "original deterministic Tetris model with explicit bag and uniform randomizers",
        "official_tetris_implementation": False,
        "autonomous_action": False,
        "randomizer": game.randomizer,
        "next_piece_probabilities": distribution,
        "accessibility": accessible,
        "horizon": horizon,
        "joint_model": "independent uniform draws" if game.randomizer == "uniform" else "sampling without replacement within each shuffled seven-piece bag",
        "game": game.snapshot(),
        "state_sha256": game.snapshot_hash(),
        "bayesian_example": {
            "sequence": example_sequence,
            "posterior": randomizer_posterior(example_sequence),
            "scope": "candidate-model comparison, not evidence about the original implementation's unknown RNG",
        },
        "vr": {
            "active": False,
            "essential_interaction": "manual piece placement and spatial audio must justify a headset",
            "comfort": "the two-dimensional board remains readable; no virtual camera motion is required",
        },
        "uncertainty_scope": "exact probabilities under the declared randomizer, not posterior beliefs about an unknown implementation or probabilities of winning",
    }
    first = accessible[0]
    report["summary"] = (
        f"{game.randomizer}: A({first['tau']:g})={first['accessible_volume']} of {first['outcome_space']} · "
        f"horizon={horizon} · exact joint distribution · seed={game.seed}"
    )
    return report


def _piece_raster(objects, game, left, top, cell):
    for row in range(game.height):
        for column in range(game.width):
            kind = game.grid[row][column]
            color = PIECE_COLORS.get(kind, "black") if kind else "black"
            objects.append(_rectangle(
                f"board-{row}-{column}",
                [left+column*cell, top+row*cell, left+(column+1)*cell, top+(row+1)*cell],
                "gray", color, .5,
            ))
    for x, y in game.current.cells():
        objects.append(_rectangle(
            f"current-{x}-{y}", [left+x*cell, top+y*cell, left+(x+1)*cell, top+(y+1)*cell],
            "white", PIECE_COLORS[game.current.kind], 1,
        ))


def tetris_scene(report):
    game = TetrisGame.from_snapshot(report["game"])
    objects = [
        _rectangle("background", [0, 0, 1920, 1080], "black", "black"),
        _text("title", [70, 72], "BOUNDED TETRIS / PROBABILITY FIELD", 28, "cyan"),
        _text("headline", [70, 124], "Seven pieces. A finite board. Exact uncertainty.", 36, "white"),
        _text("subtitle", [70, 165], "Declared randomizer · deterministic replay · no hidden model or autonomous play", 18, "lightgray"),
        _text("board-label", [120, 218], "10 x 20 FUNCTIONAL SPACE", 18, "cyan"),
        _text("randomizer", [650, 218], f"RANDOMIZER / {game.randomizer.upper()}", 18, "cyan"),
        _text("score", [650, 264], f"score={game.score}  lines={game.lines}  level={game.level}", 20, "white"),
        _text("next", [650, 310], f"current={game.current.kind}  next={game.next_kind}", 22, "yellow"),
        _text("seed", [650, 350], f"seed={game.seed}  tick={game.tick_count}  gravity={game.gravity_interval}", 16, "lightgray"),
        _text("access-title", [650, 414], "ACCESSIBLE NEXT OUTCOMES / exact support", 18, "cyan"),
        _text("access-header", [650, 452], "tau       accessible    complement    support", 16, "lightgray"),
        _text("model-note", [1130, 414], "BAYESIAN MODEL COMPARISON", 18, "cyan"),
        _text("posterior-label", [1130, 452], "after seeing all seven types", 16, "lightgray"),
        _text("vr-label", [1130, 694], "TETRIS + VR / OPTIONAL ADAPTER", 18, "cyan"),
        _text("vr-essential", [1130, 738], "Only if hands or spatial audio add something essential.", 16, "white"),
        _text("vr-comfort", [1130, 774], "The 2D board stays readable; no camera motion is required.", 15, "lightgray"),
        _text("vr-inactive", [1130, 810], "VR active: False", 15, "yellow"),
        _text("scope", [70, 1032], "Exact probabilities under the declared randomizer, not a prediction of winning or TikTok's algorithm", 14, "gray"),
    ]
    _piece_raster(objects, game, 120, 248, 30)
    for index, measurement in enumerate(report["accessibility"]):
        objects.append(_text(
            f"access-{index}", [650, 490+index*36],
            f"{measurement['tau']:.2f}    {measurement['accessible_volume']:>3}          {measurement['complement_volume']:>3}          {measurement['outcome_space']:>3}",
            17, "white",
        ))
    posterior = report["bayesian_example"]["posterior"]
    objects.extend([
        _text("posterior-bag", [1130, 490], f"P(7-bag)={posterior['bag']:.6f}", 19, "yellow"),
        _text("posterior-uniform", [1130, 526], f"P(uniform)={posterior['uniform']:.6f}", 17, "lightgray"),
        _text("posterior-scope", [1130, 566], "Evidence updates a candidate model;", 15, "lightgray"),
        _text("posterior-scope-2", [1130, 592], "it does not identify an unknown RNG.", 15, "lightgray"),
        _text("summary", [650, 990], report["summary"], 16, "cyan"),
    ])
    return _scene("bounded-tetris", 1920, 1080, objects, "Bounded Tetris: exact probabilities over a finite game space"), report
