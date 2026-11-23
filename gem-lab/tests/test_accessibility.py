from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from gem.accessibility import (
    DEFAULT_PALETTE,
    DEFAULT_SETTINGS,
    FONT_SCALE_MAX,
    FONT_SCALE_MIN,
    LINE_SPACING_MAX,
    LINE_SPACING_MIN,
    MAX_SETTINGS_BYTES,
    PALETTE_MODES,
    WCAG_AA_CONTRAST,
    WCAG_AAA_CONTRAST,
    apply_atk_metadata,
    best_text_color,
    build_gtk_accessibility_css,
    contrast_ratio,
    detect_system_accessibility,
    evaluate_accessibility,
    line_spacing_pixels,
    load_accessibility,
    load_accessibility_settings,
    recommended_settings_from_system,
    save_accessibility,
    save_accessibility_settings,
    step_font_scale,
    validate_accessibility_settings,
)
from gem.safety import safety_colors


class AccessibilitySettingsCase(unittest.TestCase):
    def test_legacy_palette_file_loads_with_defaults_and_round_trips(self):
        with tempfile.TemporaryDirectory(prefix="gem-a11y-legacy-") as temporary:
            root = Path(temporary)
            self.assertEqual(load_accessibility(root), (DEFAULT_PALETTE, None))
            self.assertEqual(load_accessibility_settings(root), (DEFAULT_SETTINGS, None))

            (root / "accessibility.json").write_text('{"palette": "colorblind"}\n', encoding="utf-8")
            settings, error = load_accessibility_settings(root)
            self.assertIsNone(error)
            self.assertEqual(settings["palette"], "colorblind")
            self.assertEqual(settings["font_scale"], 1.0)
            self.assertEqual(settings["line_spacing"], 1.2)
            self.assertFalse(settings["reduced_motion"])
            self.assertTrue(settings["focus_ring"])
            self.assertFalse(settings["dyslexia_spacing"])
            self.assertEqual(load_accessibility(root), ("colorblind", None))

    def test_full_settings_round_trip_and_palette_update_preserves_other_fields(self):
        with tempfile.TemporaryDirectory(prefix="gem-a11y-full-") as temporary:
            root = Path(temporary)
            custom = {
                "palette": "high-contrast",
                "font_scale": 1.5,
                "line_spacing": 1.6,
                "reduced_motion": True,
                "focus_ring": True,
                "dyslexia_spacing": True,
            }
            saved = save_accessibility_settings(root, custom)
            self.assertEqual(saved, custom)
            loaded, error = load_accessibility_settings(root)
            self.assertIsNone(error)
            self.assertEqual(loaded, custom)

            # Legacy save_accessibility should preserve non-palette settings.
            save_accessibility(root, "colorblind")
            after, error = load_accessibility_settings(root)
            self.assertIsNone(error)
            self.assertEqual(after["palette"], "colorblind")
            self.assertEqual(after["font_scale"], 1.5)
            self.assertEqual(after["line_spacing"], 1.6)
            self.assertTrue(after["reduced_motion"])
            self.assertTrue(after["dyslexia_spacing"])

    def test_strict_schema_validation_rejects_invalid_payloads(self):
        invalid_records = [
            ("not a dict", "JSON object"),
            ({}, "palette"),
            ({"palette": "neon"}, "Unknown accessibility palette"),
            ({"palette": "system", "rogue": True}, "Unexpected accessibility keys"),
            ({"palette": "system", "font_scale": True}, "must be a number"),
            ({"palette": "system", "font_scale": FONT_SCALE_MIN - 0.1}, "must be between"),
            ({"palette": "system", "font_scale": FONT_SCALE_MAX + 0.1}, "must be between"),
            ({"palette": "system", "font_scale": float("nan")}, "must be between"),
            ({"palette": "system", "line_spacing": LINE_SPACING_MIN - 0.1}, "must be between"),
            ({"palette": "system", "line_spacing": LINE_SPACING_MAX + 0.1}, "must be between"),
            ({"palette": "system", "reduced_motion": "yes"}, "must be a boolean"),
            ({"palette": "system", "focus_ring": 1}, "must be a boolean"),
            ({"palette": "system", "dyslexia_spacing": None}, "must be a boolean"),
        ]
        for payload, expected_fragment in invalid_records:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError) as ctx:
                    validate_accessibility_settings(payload)
                self.assertIn(expected_fragment, str(ctx.exception))

    def test_size_limit_and_corrupt_json_fall_back_safely(self):
        with tempfile.TemporaryDirectory(prefix="gem-a11y-cap-") as temporary:
            root = Path(temporary)
            path = root / "accessibility.json"
            path.write_text(" " * (MAX_SETTINGS_BYTES + 1), encoding="utf-8")
            settings, error = load_accessibility_settings(root)
            self.assertEqual(settings, DEFAULT_SETTINGS)
            self.assertIn("16 KiB", error)

            path.write_text("{corrupt", encoding="utf-8")
            settings, error = load_accessibility_settings(root)
            self.assertEqual(settings, DEFAULT_SETTINGS)
            self.assertIsNotNone(error)


class ContrastAndEvaluationCase(unittest.TestCase):
    def test_wcag_aa_and_high_contrast_aaa_ratios(self):
        self.assertAlmostEqual(contrast_ratio("#000000", "#ffffff"), 21.0)
        self.assertEqual(best_text_color("#000000"), "#ffffff")
        self.assertEqual(best_text_color("#ffffff"), "#000000")

        light_backgrounds = ("#ffffff", "#f6f5f4")
        dark_backgrounds = ("#0d1117", "#1e1e1e", "#2d2d2d")
        for palette in PALETTE_MODES:
            target = WCAG_AAA_CONTRAST if palette == "high-contrast" else WCAG_AA_CONTRAST
            for light, backgrounds in ((True, light_backgrounds), (False, dark_backgrounds)):
                colors = safety_colors(light, palette)
                for background in backgrounds:
                    for name in ("pass", "review", "accent"):
                        with self.subTest(palette=palette, bg=background, color=name):
                            self.assertGreaterEqual(contrast_ratio(colors[name], background), target)

    def test_evaluate_accessibility_supports_settings_and_aaa_target(self):
        features = {"Keyboard navigation": True, "Descriptive control labels": True}
        settings = dict(DEFAULT_SETTINGS, palette="high-contrast", font_scale=1.5, reduced_motion=True)
        report = evaluate_accessibility("high-contrast", False, "#0d1117", features, settings=settings)
        self.assertTrue(report["ready"])
        self.assertEqual(report["contrast_target"], WCAG_AAA_CONTRAST)
        self.assertIn("7.0:1", report["details"])
        self.assertIn("150% text scale", report["details"])
        self.assertIn("Reduced motion enabled", report["details"])
        self.assertIn("Orca", report["details"])

        # Legacy 4-argument signature remains unchanged.
        legacy = evaluate_accessibility("colorblind", True, "#ffffff", features)
        self.assertTrue(legacy["ready"])
        self.assertEqual(legacy["contrast_target"], WCAG_AA_CONTRAST)


class SystemDetectionAndCssCase(unittest.TestCase):
    def test_recommended_settings_from_system_preferences(self):
        recommended = recommended_settings_from_system({
            "high_contrast": True,
            "reduced_motion": True,
            "font_scale": 1.4,
        })
        self.assertEqual(recommended["palette"], "high-contrast")
        self.assertTrue(recommended["reduced_motion"])
        self.assertEqual(recommended["font_scale"], 1.4)
        self.assertTrue(recommended["focus_ring"])

        # Clamps extreme OS scales safely within bounds.
        clamped = recommended_settings_from_system({"font_scale": 5.0})
        self.assertEqual(clamped["font_scale"], FONT_SCALE_MAX)

    def test_detect_system_accessibility_is_safe_across_platforms(self):
        with mock.patch("gem.accessibility._gnome_settings", return_value=None):
            detected = detect_system_accessibility()
        self.assertIn("platform", detected)
        self.assertIn("high_contrast", detected)
        self.assertIn("reduced_motion", detected)
        self.assertIn("font_scale", detected)

    def test_gtk_css_generation_and_valid_gtk_parse(self):
        settings = {
            "palette": "high-contrast",
            "font_scale": 1.3,
            "line_spacing": 1.6,
            "reduced_motion": True,
            "focus_ring": True,
            "dyslexia_spacing": True,
        }
        css = build_gtk_accessibility_css(settings, accent="#000080", base_font_pt=10.5)
        self.assertIn("font-size: 13.65pt;", css)
        self.assertIn("letter-spacing: 1px;", css)
        self.assertIn("outline-color: #000080;", css)
        self.assertIn("transition-duration: 0ms;", css)
        self.assertNotIn("line-height", css)

        # Verify GTK 3 parses the generated CSS with zero errors if GTK is available.
        try:
            import gi
            gi.require_version("Gtk", "3.0")
            from gi.repository import Gtk
        except (ImportError, ValueError):
            return
        provider = Gtk.CssProvider()
        parse_errors = []
        provider.connect("parsing-error", lambda _p, _section, err: parse_errors.append(str(err)))
        provider.load_from_data(css.encode("utf-8"))
        self.assertEqual(parse_errors, [])
        self.assertIn("font-size", provider.to_string())

        # Verify invalid accent strings cannot inject arbitrary CSS.
        injected = build_gtk_accessibility_css(settings, accent="red; } * { color: pink", base_font_pt=10.5)
        self.assertNotIn("pink", injected)
        self.assertIn("outline-color: #1867c0;", injected)

    def test_helpers_step_scale_spacing_and_atk_metadata(self):
        self.assertEqual(step_font_scale(1.0, 1), 1.15)
        self.assertEqual(step_font_scale(1.0, -1), 0.85)
        self.assertEqual(step_font_scale(1.75, 0), 1.0)
        self.assertEqual(step_font_scale(2.0, 1), 2.0)

        above, below, wrap = line_spacing_pixels(1.5, 10.0)
        self.assertEqual(wrap, 5)
        self.assertEqual(above + below, 5)

        fake_atk = mock.Mock()
        fake_widget = mock.Mock()
        fake_widget.get_accessible.return_value = fake_atk
        self.assertTrue(apply_atk_metadata(fake_widget, name="Label", description="Desc", role="role"))
        fake_atk.set_name.assert_called_once_with("Label")
        fake_atk.set_description.assert_called_once_with("Desc")
        fake_atk.set_role.assert_called_once_with("role")
        self.assertFalse(apply_atk_metadata(object(), name="Ignored"))


class TkAccessibilityIntegrationCase(unittest.TestCase):
    def test_tk_app_persists_and_applies_full_accessibility_controls(self):
        import tkinter as tk
        from gem.app import InvestigationApp
        from gem.events import Session

        with tempfile.TemporaryDirectory(prefix="gem-tk-a11y-") as temporary:
            root_path = Path(temporary)
            session = Session(root_path, "/bin/true")
            try:
                tk_root = tk.Tk()
            except tk.TclError:
                self.skipTest("No Tk display available")
            tk_root.withdraw()
            app = InvestigationApp(tk_root, session)
            try:
                app.show_accessibility()
                app.accessibility_font_scale_var.set("150%")
                app.accessibility_line_spacing_var.set("1.6x")
                app.accessibility_reduced_motion_var.set(True)
                app.accessibility_dyslexia_spacing_var.set(True)
                app.on_accessibility_setting_changed()

                saved = json.loads((root_path / "accessibility.json").read_text(encoding="utf-8"))
                self.assertEqual(saved["font_scale"], 1.5)
                self.assertEqual(saved["line_spacing"], 1.6)
                self.assertTrue(saved["reduced_motion"])
                self.assertTrue(saved["dyslexia_spacing"])
                self.assertGreater(int(app.details.cget("spacing2")), 0)

                app._adjust_font_scale(0)
                self.assertEqual(app.accessibility_settings["font_scale"], 1.0)
                self.assertEqual(app.accessibility_font_scale_var.get(), "100%")
            finally:
                app.close()


class GtkAccessibilityIntegrationCase(unittest.TestCase):
    def test_gtk_window_applies_and_persists_accessibility_controls(self):
        try:
            import gi
            gi.require_version("Gdk", "3.0")
            gi.require_version("Gtk", "3.0")
            gi.require_version("Vte", "2.91")
            from gi.repository import Gdk, Gtk
        except (ImportError, ValueError):
            self.skipTest("GTK/VTE not available")
        if Gdk.Display.get_default() is None:
            self.skipTest("No GTK display available")

        from gem.events import Session
        from gem.gtk_app import AblationWindow

        with tempfile.TemporaryDirectory(prefix="gem-gtk-a11y-") as temporary:
            root_path = Path(temporary)
            session = Session(root_path, "/bin/true")
            window = AblationWindow(None, session, None, root_path, export_actions=False)
            try:
                window.show_accessibility()
                self.assertTrue(window.accessibility_panel.get_visible())
                self.assertTrue(
                    window.accessibility_palette_combo.get_accessible().get_name().startswith("Contrast, pass")
                )
                window.accessibility_palette_combo.set_active_id("high-contrast")
                window.accessibility_font_scale_combo.set_active_id("1.50")
                window.accessibility_line_spacing_combo.set_active_id("1.60")
                window.accessibility_reduced_motion_check.set_active(True)
                window.accessibility_dyslexia_spacing_check.set_active(True)

                saved = json.loads((root_path / "accessibility.json").read_text(encoding="utf-8"))
                self.assertEqual(saved["palette"], "high-contrast")
                self.assertEqual(saved["font_scale"], 1.5)
                self.assertEqual(saved["line_spacing"], 1.6)
                self.assertTrue(saved["reduced_motion"])
                self.assertTrue(saved["dyslexia_spacing"])
                self.assertAlmostEqual(window.current_workspace().terminal.get_font_scale(), 1.5, places=2)
                self.assertGreater(window.accessibility_details.get_pixels_inside_wrap(), 0)

                window._adjust_font_scale(0)
                self.assertEqual(window.accessibility_settings["font_scale"], 1.0)
                self.assertAlmostEqual(window.current_workspace().terminal.get_font_scale(), 1.0, places=2)
            finally:
                window.close()
                window.destroy()


if __name__ == "__main__":
    unittest.main()
