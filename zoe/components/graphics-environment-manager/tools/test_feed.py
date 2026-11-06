from __future__ import annotations

import unittest

from gem.feed import evaluate_feed


class BinaryFeedCase(unittest.TestCase):
    def test_alternating_sequence_favors_first_order(self):
        report = evaluate_feed([bool(index % 2) for index in range(48)])
        self.assertTrue(report["previous_observation_helps"])
        self.assertFalse(report["second_order_helps_beyond_first"])
        self.assertEqual(report["best_by_held_out_log_loss"], "order_1")
        self.assertLess(report["summary"]["order_1"]["log_loss"], report["summary"]["order_0"]["log_loss"])
        self.assertEqual(report["observations"], 48)
        self.assertEqual(report["likes"], 24)
        self.assertFalse(report["autonomous_action"])
        self.assertIn("not recovery", report["model_scope"])

    def test_constant_sequence_does_not_require_history(self):
        report = evaluate_feed([True]*40)
        self.assertFalse(report["previous_observation_helps"])
        self.assertEqual(report["best_by_held_out_log_loss"], "order_0")
        self.assertEqual(report["summary"]["order_0"]["accuracy"], 1)

    def test_trials_are_chronological_and_bounded(self):
        report = evaluate_feed([bool(index % 2) for index in range(48)])
        self.assertEqual(len(report["trials"]), 3)
        expected_train = 24
        for trial in report["trials"]:
            self.assertEqual(trial["train_observations"], expected_train)
            self.assertEqual(trial["test_observations"], 8)
            self.assertEqual(set(trial["models"]), {"order_0", "order_1", "order_2"})
            expected_train += 8
        with self.assertRaises(ValueError):
            evaluate_feed([True]*39)
        with self.assertRaises(ValueError):
            evaluate_feed([True]*40, alpha=0)
        with self.assertRaises(ValueError):
            evaluate_feed([{"outcome": "unknown"}]*40)


if __name__ == "__main__":
    unittest.main()
