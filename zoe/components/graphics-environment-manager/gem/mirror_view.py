from __future__ import annotations

import os
from pathlib import Path

import gi
gi.require_version("Gtk", "3.0")
gi.require_foreign("cairo")
from gi.repository import Gtk

from .authorization import launch_explicit
from .field import FieldNotebook, field_scene
from .library import ManualLibrary, library_scene
from .mirror import MirroredBrain, mirror_scene
from .render import write_png, write_svg
from .vdi import write_metafile
from .view import GemView


class MirrorWindow(Gtk.Window):
    def __init__(self, module="mirror"):
        super().__init__(title="Zoe OS · mirrored brain and GEM workbench")
        self.set_default_size(1240, 820)
        self.module = module
        self.mirror = MirroredBrain()
        self.library = ManualLibrary(os.environ.get("GEM_LIBRARY"))
        self.library_results = None
        self.field = FieldNotebook.demo() if module == "field" else FieldNotebook()
        self.controls = {}
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, border_width=10)
        self.add(outer)
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)
        for label, suffix in (("Export SVG", "svg"), ("Export PNG", "png"), ("Export GEM VDI", "gem")):
            button = Gtk.Button(label=label)
            button.connect("clicked", self.choose_export, suffix)
            toolbar.pack_start(button, False, False, 0)
        for label, module_name in (("Mirrored brain", "mirror"), ("Library", "library"), ("Field notebook", "field")):
            button = Gtk.Button(label=label)
            button.connect("clicked", self.show_module, module_name)
            toolbar.pack_end(button, False, False, 0)
        outer.pack_start(toolbar, False, False, 0)
        self.paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        outer.pack_start(self.paned, True, True, 0)
        self.canvas = GemView(lambda *_args: False)
        self.paned.pack1(self.canvas, True)
        self.control_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7, border_width=8)
        self.paned.pack2(self.control_box, False)
        self.paned.set_position(830)
        self.summary = Gtk.Label(xalign=0)
        self.summary.set_line_wrap(True)
        self.summary.set_selectable(True)
        outer.pack_start(self.summary, False, False, 0)
        self.observations = Gtk.Label(xalign=0)
        outer.pack_start(self.observations, False, False, 0)
        self.build_controls()
        self.connect("destroy", self.on_destroy)

    def on_destroy(self, *_args):
        if Gtk.main_level() > 0:
            Gtk.main_quit()

    def add_text(self, text):
        label = Gtk.Label(label=text, xalign=0)
        label.set_line_wrap(True)
        self.control_box.pack_start(label, False, False, 0)
        return label

    def add_entry(self, key, label, initial=""):
        self.add_text(label)
        entry = Gtk.Entry()
        entry.set_text(initial)
        self.control_box.pack_start(entry, False, False, 0)
        self.controls[key] = entry

    def add_spin(self, key, label, minimum, maximum, step, initial):
        self.add_text(label)
        widget = Gtk.SpinButton.new_with_range(minimum, maximum, step)
        widget.set_value(initial)
        self.control_box.pack_start(widget, False, False, 0)
        self.controls[key] = widget

    def add_scale(self, key, label, minimum, maximum, step, initial):
        self.add_text(label)
        widget = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, minimum, maximum, step)
        widget.set_value(initial)
        widget.set_digits(3)
        widget.set_draw_value(True)
        self.control_box.pack_start(widget, False, False, 0)
        self.controls[key] = widget

    def add_combo(self, key, label, choices, initial):
        self.add_text(label)
        widget = Gtk.ComboBoxText()
        for identifier, title in choices:
            widget.append(identifier, title)
        widget.set_active_id(initial)
        self.control_box.pack_start(widget, False, False, 0)
        self.controls[key] = widget

    def add_button(self, label, callback, *args):
        button = Gtk.Button(label=label)
        button.connect("clicked", callback, *args)
        self.control_box.pack_start(button, False, False, 0)
        return button

    def value(self, key):
        return self.controls[key].get_value()

    def integer(self, key):
        return self.controls[key].get_value_as_int()

    def text(self, key):
        return self.controls[key].get_text()

    def choice(self, key):
        return self.controls[key].get_active_id()

    def build_controls(self):
        for child in self.control_box.get_children():
            self.control_box.remove(child)
        if self.module == "mirror":
            self.add_spin("index", "Matched forward/retrograde index", 0, 1919, 1, 0)
            self.add_scale("tau", "Probability threshold τ", 0, .5, .001, .05)
            self.add_scale("temperature", "Experimental temperature", .25, 4, .01, 1)
            self.add_button("Observe mirrored pair", self.observe_mirror)
            self.add_button("Observe next mirrored pair", self.observe_mirror_next)
            self.add_text("Both distributions remain separate. Agreement and volume differences are inspected, never averaged into truth.")
        elif self.module == "library":
            self.add_entry("library_query", "Search local GEM manuals")
            self.add_button("Search manual index", self.search_library)
            self.add_button("Open first source document", self.open_library_result)
            self.add_text("Read-only search. Original manuals and document text are never treated as commands.")
        else:
            self.add_button("Load worked GEM example", self.load_field_demo)
            self.add_entry("new_question", "New question")
            self.add_button("Add question", self.add_field_question)
            if self.field.questions:
                choices = tuple((question["id"], question["text"][:65]) for question in self.field.questions)
                self.add_combo("field_question", "Question", choices, choices[-1][0])
                self.add_entry("new_claim", "New competing claim")
                self.add_scale("prior", "Prior probability", .001, .999, .001, .5)
                self.add_entry("falsifier", "What would change your mind?")
                self.add_button("Add competing claim", self.add_field_claim)
            if self.field.claims:
                choices = tuple((claim["id"], claim["statement"][:65]) for claim in self.field.claims)
                self.add_combo("field_claim", "Claim", choices, choices[-1][0])
                self.add_entry("evidence", "Evidence or counterevidence")
                self.add_entry("source", "Source / locator", "human assessment")
                self.add_entry("family", "Evidence family (prevents double counting)")
                self.add_scale("likelihood_true", "P(evidence | claim)", .001, 1, .001, .8)
                self.add_scale("likelihood_false", "P(evidence | not claim)", .001, 1, .001, .2)
                self.add_button("Apply explicit Bayesian update", self.add_field_evidence)
            self.add_scale("tau", "Baseline probability threshold τ", 0, .5, .001, .05)
            self.add_spin("seed", "Stochastic chamber seed", 0, 999999, 1, 7)
            self.add_button("Measure deterministic baseline", self.measure_field)
            self.add_button("Sample stochastic baseline", self.sample_field)
            self.add_button("Save unified memory JSON", self.save_field)
            self.add_button("Replace memory from JSON", self.load_field)
        self.observations.set_text(f"{self.mirror.observation_count} mirrored observations · {len(self.field.observations)} preserved observations · {len(self.field.events)} memory events")
        self.refresh()
        self.control_box.show_all()

    def refresh(self):
        if self.module == "mirror":
            self.scene, self.report = mirror_scene(self.mirror)
        elif self.module == "library":
            query = self.text("library_query") if "library_query" in self.controls else ""
            self.scene, self.report = library_scene(self.library, query, self.library_results)
        else:
            self.scene, self.report = field_scene(self.field)
        self.canvas.set_model(self.scene, None, None)
        self.summary.set_text(self.report["summary"])

    def show_module(self, _widget, module):
        self.module = module
        self.build_controls()

    def observe_mirror(self, *_args):
        try:
            state = self.mirror.observe(index=self.integer("index"), tau=self.value("tau"), temperature=self.value("temperature"))
            self.field.record_brain_observation(state["current"])
            self.controls["index"].set_value(self.mirror.forward.onset_positions["forward"])
            self.observations.set_text(f"{self.mirror.observation_count} mirrored observations · {len(self.field.observations)} preserved observations · {len(self.field.events)} memory events")
            self.refresh()
        except (OSError, ImportError, RuntimeError, ValueError) as error:
            self.summary.set_text(f"Mirrored observation failed: {error}")

    def observe_mirror_next(self, *_args):
        try:
            state = self.mirror.observe(tau=self.value("tau"), temperature=self.value("temperature"))
            self.field.record_brain_observation(state["current"])
            self.controls["index"].set_value(self.mirror.forward.onset_positions["forward"])
            self.observations.set_text(f"{self.mirror.observation_count} mirrored observations · {len(self.field.observations)} preserved observations · {len(self.field.events)} memory events")
            self.refresh()
        except (OSError, ImportError, RuntimeError, ValueError) as error:
            self.summary.set_text(f"Mirrored observation failed: {error}")

    def search_library(self, *_args):
        try:
            self.library_results = self.library.search(self.text("library_query"))
            self.refresh()
        except (OSError, ValueError) as error:
            self.summary.set_text(f"Manual search failed: {error}")

    def open_library_result(self, *_args):
        if not self.library_results:
            self.summary.set_text("Search for a source document first.")
            return
        try:
            with open(os.devnull, "wb") as output:
                launch_explicit(["/usr/bin/xdg-open", self.library_results[0]["path"]], approved=True, stdout=output, stderr=output, start_new_session=True)
            self.summary.set_text(f"Opening source: {self.library_results[0]['title']}, page {self.library_results[0]['page']}")
        except (OSError, PermissionError, ValueError) as error:
            self.summary.set_text(f"Open source failed: {error}")

    def export_current(self, path):
        path = Path(path)
        if path.suffix.lower() == ".json" and self.module == "field":
            self.field.save(path)
            return path
        self.refresh()
        if path.suffix.lower() == ".svg":
            write_svg(self.scene, path)
        elif path.suffix.lower() == ".png":
            write_png(self.scene, path)
        elif path.suffix.lower() == ".gem":
            write_metafile(self.scene, path)
        else:
            raise ValueError("export must use .svg, .png, .gem, or field-only .json")
        if self.module == "mirror":
            self.mirror.mark_exported()
            self.refresh()
        return path

    def choose_export(self, _widget, suffix):
        dialog = Gtk.FileChooserDialog(title=f"Export {suffix.upper()}", transient_for=self, action=Gtk.FileChooserAction.SAVE)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Export", Gtk.ResponseType.OK)
        dialog.set_current_name(f"zoe-{self.module}.{suffix}")
        dialog.set_do_overwrite_confirmation(True)
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                self.export_current(dialog.get_filename())
        except (OSError, ValueError, RuntimeError) as error:
            self.summary.set_text(f"Export failed: {error}")
        finally:
            dialog.destroy()

    def field_error(self, operation, error):
        self.summary.set_text(f"{operation} failed: {error}")

    def load_field_demo(self, *_args):
        self.field = FieldNotebook.demo()
        self.build_controls()

    def add_field_question(self, *_args):
        try:
            self.field.add_question(self.text("new_question"))
            self.build_controls()
        except ValueError as error:
            self.field_error("Add question", error)

    def add_field_claim(self, *_args):
        try:
            self.field.add_claim(self.choice("field_question"), self.text("new_claim"), prior=self.value("prior"), falsifier=self.text("falsifier"))
            self.build_controls()
        except ValueError as error:
            self.field_error("Add claim", error)

    def add_field_evidence(self, *_args):
        try:
            self.field.add_evidence(
                self.choice("field_claim"), self.text("evidence"),
                likelihood_true=self.value("likelihood_true"), likelihood_false=self.value("likelihood_false"),
                source=self.text("source"), family=self.text("family") or None,
            )
            self.build_controls()
        except ValueError as error:
            self.field_error("Bayesian update", error)

    def field_chambers(self):
        result = {}
        for name, mode, equation in (("Strict baseline", "deterministic", "volume/strict@v1"), ("Seeded baseline", "stochastic", "sample/categorical@v1")):
            chamber = next((item for item in self.field.chambers if item["name"] == name), None)
            if chamber is None:
                chamber = self.field.add_chamber(name, mode, equation, disposition="active" if mode == "deterministic" else "experimental")
            result[mode] = chamber["id"]
        return result

    def measure_field(self, *_args):
        try:
            chambers = self.field_chambers()
            self.field.run_chamber(chambers["deterministic"], probabilities=[.70, .20, .08, .02], tau=self.value("tau"))
            self.build_controls()
        except ValueError as error:
            self.field_error("Deterministic measurement", error)

    def sample_field(self, *_args):
        try:
            chambers = self.field_chambers()
            self.field.run_chamber(chambers["stochastic"], probabilities=[.70, .20, .08, .02], seed=self.integer("seed"))
            self.build_controls()
        except ValueError as error:
            self.field_error("Stochastic sample", error)

    def save_field(self, *_args):
        dialog = Gtk.FileChooserDialog(title="Save unified memory", transient_for=self, action=Gtk.FileChooserAction.SAVE)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Save", Gtk.ResponseType.OK)
        dialog.set_current_name("gem-field.json")
        dialog.set_do_overwrite_confirmation(True)
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                self.field.save(dialog.get_filename())
                self.build_controls()
        except (OSError, ValueError) as error:
            self.field_error("Save memory", error)
        finally:
            dialog.destroy()

    def load_field(self, *_args):
        dialog = Gtk.FileChooserDialog(title="Load unified memory", transient_for=self, action=Gtk.FileChooserAction.OPEN)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Load", Gtk.ResponseType.OK)
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                self.field = FieldNotebook.load(dialog.get_filename())
                self.build_controls()
        except (OSError, ValueError) as error:
            self.field_error("Load memory", error)
        finally:
            dialog.destroy()


def launch_os(module="mirror"):
    from .mirror import os_document

    os_document(module, os.environ.get("GEM_LIBRARY"))
    Gtk.init([])
    window = MirrorWindow(module)
    window.show_all()
    Gtk.main()
