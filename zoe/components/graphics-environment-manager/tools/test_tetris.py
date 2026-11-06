from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from gem.cli import main as gem_main
from gem.geometry import verify
from gem.runner import verify_vdi
from gem.tetris import (
    PIECE_NAMES,
    ROTATIONS,
    Piece,
    TetrisGame,
    randomizer_posterior,
    tetris_report,
    tetris_scene,
)


class BoundedTetrisCase(unittest.TestCase):
    def test_piece_shapes_and_rotations(self):
        self.assertEqual(set(ROTATIONS), set(PIECE_NAMES))
        for name, states in ROTATIONS.items():
            self.assertEqual(len(states), 4, name)
            for cells in states:
                self.assertEqual(len(cells), 4, name)
                self.assertEqual(len(set(cells)), 4, name)
                self.assertTrue(all(0 <= x < 4 and 0 <= y < 4 for x, y in cells), name)
                remaining = set(cells)
                connected = {next(iter(remaining))}
                while True:
                    expanded = {cell for cell in remaining if any(abs(cell[0]-other[0])+abs(cell[1]-other[1]) == 1 for other in connected)}
                    if not expanded:
                        break
                    connected |= expanded
                    remaining -= expanded
                self.assertFalse(remaining, name)
        square = Piece("O", 0, 0)
        self.assertEqual(Piece("O", 0, 0).cells(), square.cells())
        for _ in range(4):
            square = square.moved(rotation=1)
        self.assertEqual(square.cells(), Piece("O", 0, 0).cells())

    def test_bag_and_uniform_probability_spaces(self):
        game = TetrisGame(seed=7)
        self.assertEqual(len(game.remaining), 5)
        self.assertEqual(sum(game.next_probabilities().values()), 1)
        self.assertEqual([value for value in game.next_probabilities().values() if value], [1/5]*5)
        first = game.accessibility()[0]
        self.assertEqual(first["accessible_volume"], 5)
        self.assertEqual(first["complement_volume"], 0)
        self.assertEqual(first["outcome_space"], 5)
        self.assertEqual(game.accessibility(thresholds=(.2,))[0]["accessible_volume"], 0)
        game.remaining = list(PIECE_NAMES)
        joint = game.joint_probabilities(2)
        self.assertEqual(len(joint), 42)
        self.assertTrue(all(abs(value-1/42) < 1e-12 for value in joint.values()))
        seven = game.joint_probabilities(3)
        self.assertEqual(len(seven), 210)
        game.remaining = list(PIECE_NAMES)
        full = game.joint_probabilities(3)
        self.assertEqual(len(full), 210)
        self.assertTrue(all(abs(value-1/210) < 1e-12 for value in full.values()))
        independent = TetrisGame(seed=7, randomizer="uniform")
        independent_joint = independent.joint_probabilities(2)
        self.assertEqual(len(independent_joint), 49)
        self.assertTrue(all(abs(value-1/49) < 1e-12 for value in independent_joint.values()))

    def test_hard_drop_line_clear_level_and_replay(self):
        game = TetrisGame(seed=7)
        game.grid[19] = ["J"]*4 + [None]*4 + ["J"]*2
        game.current = Piece("I", 4, 18)
        game.score = 490
        game.hard_drop()
        self.assertEqual(game.lines, 1)
        self.assertEqual(game.score, 500)
        self.assertEqual(game.level, 2)
        self.assertEqual(game.gravity_interval, 15)
        self.assertEqual(game.grid[19], [None]*10)
        self.assertEqual(game.grid[0], [None]*10)
        restored = TetrisGame.from_snapshot(game.snapshot())
        self.assertEqual(restored.snapshot_hash(), game.snapshot_hash())
        self.assertEqual(restored.next_probabilities(), game.next_probabilities())
        restored.hard_drop()
        game.hard_drop()
        self.assertEqual(restored.snapshot_hash(), game.snapshot_hash())

    def test_game_over_snapshot_and_threshold_boundaries(self):
        game = TetrisGame(seed=7)
        game.grid[0][3] = "J"
        game.game_over = not game._valid(game.current)
        self.assertTrue(game.game_over)
        restored = TetrisGame.from_snapshot(game.snapshot())
        self.assertTrue(restored.game_over)
        self.assertEqual(restored.snapshot_hash(), game.snapshot_hash())
        with self.assertRaises(ValueError):
            game.accessibility(thresholds=(-.01,))
        with self.assertRaises(ValueError):
            game.accessibility(thresholds=(float("nan"),))

    def test_collision_and_deterministic_bag(self):
        first = TetrisGame(seed=11)
        second = TetrisGame(seed=11)
        self.assertEqual(first.snapshot_hash(), second.snapshot_hash())
        first.current = second.current = Piece("O", 3, 0)
        for _ in range(4):
            self.assertTrue(first.move(-1))
        self.assertFalse(first.move(-1))
        first.current = second.current = Piece("O", 3, 0)
        first.hard_drop()
        second.hard_drop()
        self.assertEqual(first.snapshot_hash(), second.snapshot_hash())
        self.assertEqual(first.current.kind, second.current.kind)
        self.assertEqual(first.next_kind, second.next_kind)
        game = TetrisGame(seed=7)
        game.current = Piece("O", 0, 0)
        for _ in range(3):
            self.assertTrue(game.rotate())
        self.assertTrue(game.rotate())

    def test_posterior_and_scene(self):
        posterior = randomizer_posterior(list(PIECE_NAMES))
        self.assertGreater(posterior["bag"], .99)
        repeated = randomizer_posterior(["I", "I"], bag_position=1)
        self.assertEqual(repeated["bag"], 0)
        self.assertEqual(repeated["uniform"], 1)
        report = tetris_report(TetrisGame(seed=7), horizon=2)
        self.assertFalse(report["official_tetris_implementation"])
        self.assertFalse(report["autonomous_action"])
        self.assertFalse(report["vr"]["active"])
        self.assertIn("exact joint distribution", report["summary"])
        scene, _ = tetris_scene(report)
        self.assertTrue(verify(scene).passed, verify(scene).text())
        self.assertTrue(verify_vdi(scene).passed)

    def test_cli_exports_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for suffix in ("json", "svg", "png", "gem"):
                output = root / f"tetris.{suffix}"
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(gem_main(["tetris", "--horizon", "2", "--output", str(output)]), 0)
                self.assertGreater(output.stat().st_size, 100)
            document = json.loads((root / "tetris.json").read_text())
            self.assertEqual(document["horizon"], 2)
            self.assertFalse(document["autonomous_action"])
            self.assertIn("BOUNDED TETRIS", (root / "tetris.svg").read_text())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(gem_main(["tetris", "--output", str(root / "tetris.json")]), 2)

    def test_feed_cli(self):
        events = [bool(index % 2) for index in range(48)]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "feed.json"
            source.write_text(json.dumps(events))
            output = Path(directory) / "report.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main(["feed", str(source), "--output", str(output)]), 0)
            report = json.loads(output.read_text())
            self.assertIn("model_scope", report)
            self.assertFalse(report["autonomous_action"])


try:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_foreign("cairo")
    HAS_GTK = bool(os.environ.get("DISPLAY"))
except (ImportError, ValueError):
    HAS_GTK = False


@unittest.skipUnless(HAS_GTK, "native Tetris tests require GTK, Cairo, and an X11 display")
class NativeTetrisCase(unittest.TestCase):
    def test_controls_and_exports(self):
        from gem.tetris_view import TetrisWindow

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            window = TetrisWindow(seed=7)
            try:
                self.assertTrue(window.move("Left"))
                self.assertTrue(window.rotate())
                self.assertTrue(window.hard_drop())
                window.tick()
                self.assertGreater(window.game.tick_count, 0)
                output = window.export_current(root / "tetris.json")
                self.assertEqual(json.loads(output.read_text())["game"]["seed"], 7)
                self.assertIn("BOUNDED TETRIS", window.export_current(root / "tetris.svg").read_text())
                self.assertGreater(window.export_current(root / "tetris.gem").stat().st_size, 1000)
            finally:
                window.destroy()


if __name__ == "__main__":
    unittest.main()
