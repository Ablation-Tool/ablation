from __future__ import annotations

from copy import deepcopy
import json
import math
import os
from pathlib import Path

import gi
gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
gi.require_foreign("cairo")
from gi.repository import Gdk, Gtk, Pango

from .._callbacks import weak_callback
from .atlas import (
    ATLAS_MODULES, DEFAULT_SOURCE, DEFAULT_TARGET,
    circle_scene, clock_scene, ellipses_scene, graph_scene,
    landmark_scene, onset_scene, parabola_geometry, procrustes, volume_scene,
)
from .brain import BrainKernel, brain_scene, horizon_scene
from .field import FieldNotebook, field_scene
from .onset import run_synthetic_experiment
from .qualia import LENSES, qualia_scene
from .render import draw_cairo, write_png, write_svg
from .research import ResearchPack, research_scene
from .vdi import write_metafile
from .view import scene_layout
from .volume import VolumeBridge

VOLUME_PRESETS = {
    "baseline": [.70, .20, .08, .02],
    "metadata": [.55, .35, .08, .02],
    "concentrated": [1.0, 0.0, 0.0, 0.0],
    "broad": [.25, .25, .25, .25],
}


class AtlasCanvas(Gtk.DrawingArea):
    def __init__(self, on_landmark):
        super().__init__()
        self.on_landmark = on_landmark
        self.scene = None
        self.source = None
        self.target = None
        self.layout = None
        self.layout_size = None
        self.dragging = None
        self.selected = None
        self.set_size_request(560, 420)
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_can_focus(True)
        self.add_events(
            Gdk.EventMask.BUTTON_PRESS_MASK | Gdk.EventMask.BUTTON_RELEASE_MASK
            | Gdk.EventMask.POINTER_MOTION_MASK | Gdk.EventMask.LEAVE_NOTIFY_MASK
        )
        self.get_accessible().set_description(
            "Interactive geometry atlas. In Procrustes mode, drag landmarks or focus one and use arrow keys. "
            "Other modules expose their parameters in the adjacent controls."
        )
        for signal, callback in (
            ("button-press-event", self.on_button),
            ("button-release-event", self.on_release),
            ("motion-notify-event", self.on_motion),
            ("leave-notify-event", self.on_leave),
            ("key-press-event", self.on_key),
        ):
            self.connect(signal, weak_callback(callback))
        for signal in ("focus-in-event", "focus-out-event"):
            self.connect(signal, lambda *_args: self.queue_draw())

    def set_model(self, scene, source=None, target=None):
        self.scene = scene
        self.source = source
        self.target = target
        self.layout_size = None
        if source is None or target is None:
            self.dragging = None
            self.selected = None
        else:
            for attribute in ("dragging", "selected"):
                selection = getattr(self, attribute)
                if selection is not None:
                    prefix, index = selection
                    points = source if prefix == "p" else target
                    if index >= len(points):
                        setattr(self, attribute, None)
        self.queue_draw()

    def update_layout(self):
        size = (max(1, self.get_allocated_width()), max(1, self.get_allocated_height()))
        if self.scene is not None and size != self.layout_size:
            self.layout = scene_layout(self.scene, *size)
            self.layout_size = size
        return self.layout

    def landmark_at(self, x, y):
        if self.source is None or self.target is None:
            return None
        layout = self.update_layout()
        for prefix, points in (("p", self.source), ("q", self.target)):
            for index, point in enumerate(points):
                screen_x = layout.offset_x + point[0] * layout.scale
                screen_y = layout.offset_y + point[1] * layout.scale
                if math.hypot(x - screen_x, y - screen_y) <= 14:
                    return prefix, index
        return None

    def on_button(self, _widget, event):
        if event.button != 1:
            return False
        self.grab_focus()
        self.selected = self.landmark_at(event.x, event.y)
        self.dragging = self.selected
        self.queue_draw()
        return self.selected is not None

    def on_release(self, _widget, _event):
        self.dragging = None
        return False

    def on_motion(self, _widget, event):
        if self.dragging is None:
            return False
        layout = self.update_layout()
        scene_x, scene_y = layout.to_scene(event.x, event.y)
        point = [
            min(self.scene.canvas["width"], max(0, scene_x)),
            min(self.scene.canvas["height"], max(0, scene_y)),
        ]
        self.on_landmark(self.dragging[0], self.dragging[1], point)
        return True

    def on_leave(self, *_args):
        self.dragging = None
        return False

    def on_key(self, _widget, event):
        if self.selected is None:
            return False
        key = Gdk.keyval_name(event.keyval)
        if key == "Escape":
            self.selected = None
            self.queue_draw()
            return True
        movements = {"Left": (-1, 0), "Right": (1, 0), "Up": (0, -1), "Down": (0, 1)}
        if key not in movements:
            return False
        prefix, index = self.selected
        points = self.source if prefix == "p" else self.target
        step = 10 if event.state & Gdk.ModifierType.SHIFT_MASK else 1
        dx, dy = movements[key]
        point = [
            min(self.scene.canvas["width"], max(0, points[index][0] + step * dx)),
            min(self.scene.canvas["height"], max(0, points[index][1] + step * dy)),
        ]
        self.on_landmark(prefix, index, point)
        return True

    def do_draw(self, context):
        if self.scene is None:
            return False
        layout = self.update_layout()
        draw_cairo(context, self.scene, self.get_allocated_width(), self.get_allocated_height())
        if self.selected is not None:
            prefix, index = self.selected
            points = self.source if prefix == "p" else self.target
            point = points[index]
            x = layout.offset_x + point[0] * layout.scale
            y = layout.offset_y + point[1] * layout.scale
            context.set_source_rgb(.95, .35, .05)
            context.set_line_width(2)
            context.arc(x, y, 11, 0, math.tau)
            context.stroke()
        return False


class AtlasWindow(Gtk.Window):
    def __init__(self, module="procrustes", experiment_factory=run_synthetic_experiment, research_root=None):
        super().__init__(title="Zoe · living geometry, inspectable futures")
        self.set_default_size(1200, 780)
        self.module = module if module in ATLAS_MODULES else "procrustes"
        self.experiment_factory = experiment_factory
        self.experiment = None
        self.scene = None
        self.report = {}
        self.controls = {}
        self.updating = False
        self.source = deepcopy(DEFAULT_SOURCE)
        self.target = deepcopy(DEFAULT_TARGET)
        self.brain = BrainKernel()
        self.field = FieldNotebook()
        from .cognitive import CognitiveField
        self.cognitive = CognitiveField()
        from .unified import ComponentRegistry
        self.unified_registry = ComponentRegistry()
        self.research_pack = ResearchPack.load(research_root) if research_root else ResearchPack()
        self.volume_bridge = VolumeBridge(minimum=1, maximum=4)
        self.volume_current = VOLUME_PRESETS["baseline"]
        self.volume_previous = None
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, border_width=10)
        self.add(outer)
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        outer.pack_start(toolbar, False, False, 0)
        self.module_selector = Gtk.ComboBoxText()
        for identifier, title in ATLAS_MODULES.items():
            self.module_selector.append(identifier, title)
        self.module_selector.set_active_id(self.module)
        self.module_selector.connect("changed", self.on_module_changed)
        toolbar.pack_start(self.module_selector, False, False, 0)
        svg_button = Gtk.Button(label="Export SVG")
        svg_button.connect("clicked", self.on_export_svg)
        toolbar.pack_start(svg_button, False, False, 0)
        png_button = Gtk.Button(label="Export PNG")
        png_button.connect("clicked", self.on_export_png)
        toolbar.pack_start(png_button, False, False, 0)
        gem_button = Gtk.Button(label="Export GEM + VDI")
        gem_button.connect("clicked", self.on_export_gem)
        toolbar.pack_start(gem_button, False, False, 0)
        toolbar.pack_start(Gtk.Label(label="Native Spatial IR · no server", xalign=1), True, True, 0)
        self.panes = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL, wide_handle=True)
        outer.pack_start(self.panes, True, True, 0)
        self.canvas = AtlasCanvas(self.move_landmark)
        self.panes.pack1(self.canvas, True, True)
        right = Gtk.ScrolledWindow()
        right.set_size_request(350, -1)
        right.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.control_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, border_width=8)
        right.add(self.control_box)
        self.panes.pack2(right, False, True)
        self.summary = Gtk.Label(xalign=0, selectable=True)
        self.summary.set_line_wrap(True)
        self.summary.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
        outer.pack_end(self.summary, False, False, 0)
        self.build_controls()

    def clear_controls(self):
        for child in self.control_box.get_children():
            self.control_box.remove(child)
        self.controls = {}

    def add_text(self, text):
        label = Gtk.Label(label=text, xalign=0)
        label.set_line_wrap(True)
        label.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
        self.control_box.pack_start(label, False, False, 0)
        return label

    def add_entry(self, key, label, initial=""):
        self.add_text(label)
        widget = Gtk.Entry()
        widget.set_text(initial)
        self.control_box.pack_start(widget, False, False, 0)
        self.controls[key] = widget
        return widget

    def add_spin(self, key, label, minimum, maximum, step, initial):
        self.add_text(label)
        adjustment = Gtk.Adjustment(value=initial, lower=minimum, upper=maximum, step_increment=step, page_increment=step*10)
        widget = Gtk.SpinButton(adjustment=adjustment, numeric=True)
        widget.set_digits(0 if step >= 1 else 3)
        widget.connect("value-changed", self.on_control_changed)
        self.control_box.pack_start(widget, False, False, 0)
        self.controls[key] = widget
        return widget

    def add_scale(self, key, label, minimum, maximum, step, initial):
        self.add_text(label)
        adjustment = Gtk.Adjustment(value=initial, lower=minimum, upper=maximum, step_increment=step, page_increment=step*10)
        widget = Gtk.Scale(orientation=Gtk.Orientation.HORIZONTAL, adjustment=adjustment)
        widget.set_digits(3)
        widget.set_value_pos(Gtk.PositionType.RIGHT)
        widget.connect("value-changed", self.on_control_changed)
        self.control_box.pack_start(widget, False, False, 0)
        self.controls[key] = widget
        return widget

    def add_combo(self, key, label, choices, initial):
        self.add_text(label)
        widget = Gtk.ComboBoxText()
        for identifier, title in choices:
            widget.append(identifier, title)
        widget.set_active_id(initial)
        widget.connect("changed", self.on_control_changed)
        self.control_box.pack_start(widget, False, False, 0)
        self.controls[key] = widget
        return widget

    def add_action(self, label, callback):
        button = Gtk.Button(label=label)
        button.connect("clicked", callback)
        self.control_box.pack_start(button, False, False, 0)
        return button

    def build_controls(self):
        self.updating = True
        self.clear_controls()
        self.add_text(ATLAS_MODULES[self.module])
        if self.module == "unified":
            from .unified import COMPONENTS
            self.add_action("Open Zoe Cognitive Field", self.open_cognitive)
            for component in COMPONENTS:
                if component.identifier in {"zoe", "cerotto"}:
                    continue
                if component.inspect_only:
                    self.add_action(f"Inspect {component.title}", self.make_unified_inspect(component.identifier))
                else:
                    self.add_action(f"Launch {component.title}", self.make_unified_launch(component.identifier))
                self.add_action(f"Link {component.title} source context", self.make_unified_source_record(component.identifier))
                self.add_text(f"{component.summary}. Source: {component.checkout}.")
            self.add_entry("cerotto_case", "Cerotto case ID", os.environ.get("CEROTTO_CASE", "incident-7"))
            self.add_entry("cerotto_conversation", "Cerotto conversation ID", os.environ.get("CEROTTO_CONVERSATION", "conv-7"))
            self.add_action("Choose Cerotto case DB and launch", self.choose_cerotto)
            self.add_action("Export unified component manifest", self.save_unified_manifest)
            self.add_action("Save unified knowledge graph", self.save_unified_knowledge)
            self.add_text("The hub launches nothing automatically. Link buttons record source context, not runtime proof or evidence transfer. Cerotto requires a user-selected case. Component processes retain their dependencies, evidence models, and authorization rules.")
        elif self.module == "brain":
            self.add_combo("condition", "HELEN held-out condition", (("forward", "Forward"), ("retrograde", "Retrograde")), "forward")
            self.add_spin("index", "Held-out onset index", 0, 1919, 1, 0)
            self.add_scale("tau", "Probability threshold τ", 0, .5, .001, .05)
            self.add_scale("temperature", "Experimental temperature", .25, 4, .01, 1)
            self.add_spin("minimum", "Target band minimum", 0, 8, 1, 1)
            self.add_spin("maximum", "Target band maximum", 0, 8, 1, 4)
            self.add_action("Observe selected HELEN onset", self.observe_brain)
            self.add_action("Observe next in sequence", self.observe_brain_next)
            self.add_action("Open recommended module", self.open_recommended)
            self.add_action("Reset BRAIN", self.reset_brain)
            self.add_text("Real stored categorical predictions load lazily from HELEN. Zoe computes correctness, breadth, momentum, and recommendations; no action is executed.")
        elif self.module == "field":
            self.add_action("Load worked GEM example", self.load_field_demo)
            self.add_entry("new_question", "New question")
            self.add_action("Add question", self.add_field_question)
            if self.field.questions:
                choices = tuple((question["id"], question["text"][:70]) for question in self.field.questions)
                self.add_combo("field_question", "Question", choices, choices[-1][0])
                self.add_entry("new_claim", "New claim")
                self.add_scale("prior", "Prior probability", .001, .999, .001, .5)
                self.add_entry("falsifier", "What would change your mind?")
                self.add_action("Add competing claim", self.add_field_claim)
            if self.field.claims:
                choices = tuple((claim["id"], claim["statement"][:70]) for claim in self.field.claims)
                self.add_combo("field_claim", "Claim", choices, choices[-1][0])
                self.add_entry("evidence", "Evidence or counterevidence")
                self.add_entry("source", "Source / locator", "human assessment")
                self.add_entry("family", "Evidence family (prevents double counting)")
                self.add_scale("likelihood_true", "P(evidence | claim)", .001, 1, .001, .8)
                self.add_scale("likelihood_false", "P(evidence | not claim)", .001, 1, .001, .2)
                self.add_action("Apply explicit Bayesian update", self.add_field_evidence)
            self.add_scale("tau", "Baseline probability threshold τ", 0, .5, .001, .05)
            self.add_spin("seed", "Stochastic chamber seed", 0, 999999, 1, 7)
            self.add_action("Measure baseline in deterministic chamber", self.measure_field)
            self.add_action("Sample baseline in stochastic chamber", self.sample_field)
            self.add_action("Save unified memory JSON", self.save_field)
            self.add_action("Replace memory from JSON", self.load_field)
            self.add_text(f"Unified memory: {len(self.field.events)} events. BRAIN observations are preserved automatically. Chamber measurements never update beliefs automatically.")
        elif self.module == "cognitive":
            self.add_action("Load worked Cognitive Field", self.load_cognitive_demo)
            self.add_spin("capacity", "Capacity for a new empty field", 1, 16, 1, self.cognitive.working_capacity)
            self.add_action("Start empty with this capacity", self.new_cognitive)
            self.add_entry("sensory_text", "Information to encode", "Observe the explicit memory boundary.")
            self.add_entry("sensory_source", "Observation source", "native Cognitive Field")
            self.add_entry("sensory_tags", "Tags (comma-separated)", "information, review")
            self.add_action("Encode into working memory", self.encode_cognitive)
            if self.cognitive.working:
                choices = tuple((item["id"], f"{item['id']} · {item['text'][:52]}") for item in self.cognitive.working)
                self.add_combo("active_representation", "Active representation", choices, choices[0][0])
                self.add_action("Store active representation", self.store_cognitive)
            if self.cognitive.declarative:
                choices = tuple((item["id"], f"{item['id']} revision {item['revision']} · {item['text'][:40]}") for item in self.cognitive.declarative)
                self.add_combo("declarative_record", "Declarative record", choices, choices[0][0])
                self.add_spin("expected_revision", "Expected revision", 0, 1000000, 1, 1)
                self.add_action("Retrieve with provenance check", self.retrieve_cognitive)
            self.add_entry("rule_name", "New procedural rule", "Inspect explicit memory")
            self.add_entry("rule_tags", "Required tags", "information, review")
            self.add_entry("rule_description", "Performance description (not code)", "Review this matched memory operation; do not execute it.")
            self.add_action("Register procedural description", self.add_cognitive_rule)
            self.add_action("Match rules against active tags", self.match_cognitive)
            if self.cognitive.matches:
                choices = tuple((item["id"], f"{item['id']} · {item['status']} · {', '.join(item['matched_rule_ids']) or 'none'}") for item in self.cognitive.matches)
                self.add_combo("procedural_match", "Procedural match", choices, choices[-1][0])
                self.add_entry("performance_rationale", "Review rationale", "Review this proposal; no execution requested.")
                self.add_action("Prepare performance for review", self.propose_cognitive)
            self.add_scale("tau", "Baseline probability threshold τ", 0, .5, .001, .05)
            self.add_spin("seed", "Stochastic chamber seed", 0, 999999, 1, 7)
            self.add_action("Measure baseline breadth", self.measure_cognitive)
            self.add_action("Sample baseline with seed", self.sample_cognitive)
            self.add_action("Save Cognitive Field JSON", self.save_cognitive)
            self.add_action("Load Cognitive Field JSON", self.load_cognitive)
            self.add_text(f"{len(self.cognitive.working)}/{self.cognitive.working_capacity} active · {len(self.cognitive.evicted)} evicted · {len(self.cognitive.events)} events. Storage and retrieval are explicit. Matching cannot execute code. Every performance proposal requires review.")
        elif self.module == "qualia":
            self.add_combo("qualia_lens", "Field-guide lens", tuple((lens, lens.title()) for lens in LENSES), "overview")
            self.add_text("A conceptual guide to Balduzzi & Tononi's 2009 IIT geometry. The silent-AND number is one un-normalized whole-versus-product comparison, not a general Φ calculator.")
            self.add_text("Zoe is Quale. Zoe is Red. is a creative dedication, not a claim that Zoe is alive, conscious, or has subjective experience. No belief or action is updated.")
        elif self.module == "procrustes":
            self.add_text("Drag the red source and blue target landmarks. Similarity uses scale + rotation + translation; rigid fixes scale to one.")
            self.add_combo("mode", "Alignment model", (("similarity", "Similarity"), ("rigid", "Rigid"), ("affine", "Affine")), "similarity")
            self.add_action("Add landmark pair", self.add_landmark_pair)
            self.add_action("Remove landmark pair", self.remove_landmark_pair)
            self.add_action("Reset measured landmarks", self.reset_landmarks)
        elif self.module == "ellipses":
            self.add_spin("count", "Ellipse count", 2, 64, 1, 16)
            self.add_spin("selected", "Highlighted index", 0, 63, 1, 15)
            for key, label, initial in (("a0", "Horizontal radius at t=0", 99.5), ("a1", "Horizontal radius at t=1", 286.5), ("b0", "Vertical radius at t=0", 198), ("b1", "Vertical radius at t=1", 73)):
                self.add_scale(key, label, 1, 320, .5, initial)
        elif self.module == "parabola":
            self.add_spin("segments", "Ruled segments", 2, 128, 1, 32)
            self.add_scale("t", "Envelope parameter t", 0, 1, .001, .5)
        elif self.module == "circle":
            self.add_scale("radius", "Radius in pixels", 10, 207, .1, 207)
            self.add_scale("angle", "Central angle in degrees", 1, 360, .1, 100.1)
        elif self.module == "clock":
            self.add_spin("modulus", "Modulus", 2, 48, 1, 12)
            self.add_spin("value", "Integer value", 0, 999, 1, 15)
        elif self.module == "graph":
            self.add_combo("crossings", "Interpret six line crossings", (("no", "Crossings are not vertices"), ("yes", "Crossings are vertices")), "no")
            self.add_text("The image is ambiguous, so both graph invariants are available. Loops count twice in vertex degree.")
        elif self.module == "volume":
            self.add_combo("preset", "Next categorical observation", tuple((key, key) for key in VOLUME_PRESETS), "baseline")
            self.add_scale("tau", "Probability threshold τ", 0, .5, .001, .05)
            self.add_spin("minimum", "Target band minimum", 0, 8, 1, 1)
            self.add_spin("maximum", "Target band maximum", 0, 8, 1, 4)
            self.add_action("Observe distribution", self.observe_volume)
            self.add_action("Reset bridge", self.reset_volume)
            self.add_text("Observation updates the previous distribution and computes momentum. No action is executed.")
        elif self.module == "onset":
            self.add_scale("tau", "Probability threshold τ", .005, .5, .001, .05)
            self.add_scale("temperature", "Experimental distribution temperature", .25, 4, .01, 1)
            self.add_action("Recompute seeded synthetic experiment", self.recompute_onset)
            self.add_text("Eight motifs, forward training, held-out forward and retrograde tests. Temperature reshapes probabilities only; it does not generate music.")
            self.add_text("HOP negative baseline: top-1 11.3%, versus linear velocity 41.3% and the model 46.6%. HOP supplies no categorical distribution or accessible volume.")
        elif self.module == "horizon":
            self.add_spin("horizon", "Continuation horizon h", 1, 6, 1, 3)
            self.add_scale("tau", "Joint probability threshold τ", 0, .5, .001, .1)
            self.add_text("Exact enumeration over a defined two-state Markov toy. It is not a real language-model benchmark; full-vocabulary cost grows as |O|ʰ.")
        elif self.module == "research":
            cases = self.research_pack.cases()
            if cases:
                self.add_combo("case", "Verified evidence case", tuple((row["id"], row["label"]) for row in cases), cases[0]["id"])
                self.add_spin("index", "Groove prediction index", 0, 121391, 1, 0)
                self.add_scale("tau", "Probability threshold τ", 0, .5, .001, .05)
                self.add_action("Observe selected Groove distribution", self.observe_research)
                self.add_action("Verify all conformance vectors", self.verify_research)
                self.add_text("Groove predictions load on demand. Nightingale entries are aggregate-only and cannot supply individual observations.")
            else:
                self.add_text("Set MASTER_GEM_RESEARCH_ROOT or pass --research-root to the next-token-predictability checkout. No evidence is copied into the runtime.")
        self.updating = False
        self.refresh()
        self.control_box.show_all()

    def on_module_changed(self, widget):
        if self.updating:
            return
        self.module = widget.get_active_id()
        self.build_controls()

    def on_control_changed(self, *_args):
        if not self.updating:
            self.refresh()

    def value(self, key):
        return self.controls[key].get_value()

    def integer(self, key):
        return self.controls[key].get_value_as_int()

    def choice(self, key):
        return self.controls[key].get_active_id()

    def refresh(self):
        if self.module == "unified":
            from .unified import unified_scene
            self.scene, self.report = unified_scene(self.unified_registry, self.unified_registry.knowledge)
        elif self.module == "brain":
            self.scene, self.report = brain_scene(self.brain)
        elif self.module == "field":
            self.scene, self.report = field_scene(self.field)
        elif self.module == "cognitive":
            from .cognitive import cognitive_scene
            self.scene, self.report = cognitive_scene(self.cognitive)
        elif self.module == "qualia":
            self.scene, self.report = qualia_scene(self.choice("qualia_lens"))
        elif self.module == "procrustes":
            self.refresh_procrustes()
        elif self.module == "ellipses":
            self.scene, self.report = ellipses_scene(self.integer("count"), self.integer("selected"), *(self.value(key) for key in ("a0", "a1", "b0", "b1")))
        elif self.module == "parabola":
            self.scene, self.report = parabola_geometry(self.integer("segments"), self.value("t"))
        elif self.module == "circle":
            self.scene, self.report = circle_scene(self.value("radius"), self.value("angle"))
        elif self.module == "clock":
            self.scene, self.report = clock_scene(self.integer("modulus"), self.integer("value"))
        elif self.module == "graph":
            self.scene, self.report = graph_scene(self.choice("crossings") == "yes")
        elif self.module == "volume":
            self.refresh_volume()
        elif self.module == "onset":
            self.refresh_onset()
        elif self.module == "horizon":
            self.scene, self.report = horizon_scene(self.integer("horizon"), self.value("tau"))
        elif self.module == "research":
            identifier = self.choice("case") if self.controls else None
            self.scene, self.report = research_scene(self.research_pack, identifier)
        if self.scene is not None and self.module != "procrustes":
            self.canvas.set_model(self.scene)
        self.update_summary()
        return self.scene

    def refresh_procrustes(self):
        try:
            self.report = procrustes(self.source, self.target, self.choice("mode"))
            self.scene = landmark_scene(self.source, self.target, self.report)
        except ValueError as error:
            self.report = {"error": str(error)}
            self.scene = landmark_scene(self.source, self.target)
        self.canvas.set_model(self.scene, self.source, self.target)

    def move_landmark(self, prefix, index, point):
        points = self.source if prefix == "p" else self.target
        points[index] = point
        self.refresh_procrustes()
        self.canvas.selected = (prefix, index)
        self.update_summary()

    def add_landmark_pair(self, *_args):
        if len(self.source) >= 8:
            return
        index = len(self.source)
        self.source.append([180 + 25*index, 230 + 10*index])
        self.target.append([440 + 20*index, 250 + 12*index])
        self.refresh()

    def remove_landmark_pair(self, *_args):
        if len(self.source) > 2:
            self.source.pop()
            self.target.pop()
            self.refresh()

    def reset_landmarks(self, *_args):
        self.source = deepcopy(DEFAULT_SOURCE)
        self.target = deepcopy(DEFAULT_TARGET)
        self.refresh()

    def observe_volume(self, *_args):
        current = VOLUME_PRESETS[self.choice("preset")]
        previous = self.volume_current
        minimum, maximum = self.integer("minimum"), self.integer("maximum")
        if maximum < minimum:
            self.report = {"error": "Target maximum must be at least the minimum"}
            self.update_summary()
            return
        self.volume_bridge.minimum = minimum
        self.volume_bridge.maximum = maximum
        self.volume_bridge.observe(current, thresholds=[self.value("tau")])
        self.volume_previous = previous
        self.volume_current = current
        self.refresh()

    def reset_volume(self, *_args):
        self.volume_bridge = VolumeBridge(minimum=self.integer("minimum"), maximum=self.integer("maximum"))
        self.volume_previous = None
        self.refresh()

    def refresh_volume(self):
        self.scene, self.report = volume_scene(
            self.volume_current, self.volume_previous, self.value("tau"),
            self.integer("minimum"), self.integer("maximum"),
        )

    def field_error(self, operation, error):
        self.report = {"error": f"{operation}: {error}"}
        self.update_summary()

    def load_field_demo(self, *_args):
        self.field = FieldNotebook.demo()
        self.build_controls()

    def add_field_question(self, *_args):
        try:
            self.field.add_question(self.controls["new_question"].get_text())
            self.build_controls()
        except ValueError as error:
            self.field_error("Add question failed", error)

    def add_field_claim(self, *_args):
        try:
            self.field.add_claim(
                self.choice("field_question"), self.controls["new_claim"].get_text(),
                prior=self.value("prior"), falsifier=self.controls["falsifier"].get_text(),
            )
            self.build_controls()
        except ValueError as error:
            self.field_error("Add claim failed", error)

    def add_field_evidence(self, *_args):
        try:
            likelihood_true = self.value("likelihood_true")
            likelihood_false = self.value("likelihood_false")
            family = self.controls["family"].get_text().strip() or None
            self.field.add_evidence(
                self.choice("field_claim"), self.controls["evidence"].get_text(),
                likelihood_true, likelihood_false,
                source=self.controls["source"].get_text(), family=family,
                direction="supports" if likelihood_true >= likelihood_false else "challenges",
            )
            self.build_controls()
        except ValueError as error:
            self.field_error("Bayesian update failed", error)

    def ensure_field_chambers(self):
        identifiers = {}
        for name, mode, equation in (
            ("Strict threshold observatory", "deterministic", "volume/strict@v1"),
            ("Seeded categorical futures", "stochastic", "sample/categorical@v1"),
        ):
            chamber = next((item for item in self.field.chambers if item["name"] == name), None)
            if chamber is None:
                chamber = self.field.add_chamber(name, mode, equation, disposition="active" if mode == "deterministic" else "experimental")
            identifiers[mode] = chamber["id"]
        return identifiers

    def measure_field(self, *_args):
        try:
            chambers = self.ensure_field_chambers()
            self.field.run_chamber(chambers["deterministic"], probabilities=[.70, .20, .08, .02], tau=self.value("tau"))
            self.build_controls()
        except ValueError as error:
            self.field_error("Deterministic measurement failed", error)

    def sample_field(self, *_args):
        try:
            chambers = self.ensure_field_chambers()
            self.field.run_chamber(chambers["stochastic"], probabilities=[.70, .20, .08, .02], seed=self.integer("seed"))
            self.build_controls()
        except ValueError as error:
            self.field_error("Stochastic sample failed", error)

    def save_field(self, *_args):
        dialog = Gtk.FileChooserDialog(title="Save unified memory", transient_for=self, action=Gtk.FileChooserAction.SAVE)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Save", Gtk.ResponseType.OK)
        dialog.set_current_name("zoe-field.json")
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                self.field.save(dialog.get_filename())
                self.report = {"summary": f"Saved {len(self.field.events)} memory events to {dialog.get_filename()}"}
                self.update_summary()
        except (OSError, ValueError) as error:
            self.field_error("Save memory failed", error)
        finally:
            dialog.destroy()

    def load_field(self, *_args):
        dialog = Gtk.FileChooserDialog(title="Replace memory from JSON", transient_for=self, action=Gtk.FileChooserAction.OPEN)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Load", Gtk.ResponseType.OK)
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                self.field = FieldNotebook.load(dialog.get_filename())
                self.build_controls()
        except (OSError, ValueError, json.JSONDecodeError) as error:
            self.field_error("Load memory failed", error)
        finally:
            dialog.destroy()

    def open_cognitive(self, *_args):
        self.module_selector.set_active_id("cognitive")

    def make_unified_launch(self, identifier):
        return lambda *_args: self.launch_unified(identifier)

    def make_unified_inspect(self, identifier):
        return lambda *_args: self.show_unified(identifier)

    def make_unified_source_record(self, identifier):
        return lambda *_args: self.record_unified_source(identifier)

    def show_unified(self, identifier):
        component = self.unified_registry.component(identifier)
        source = self.unified_registry.source(identifier)
        self.report = {"summary": f"{component.title}: {component.summary}\nSource: {source['path']} · {source['mode']}\nContent inspection only; no process launched."}
        self.update_summary()

    def launch_unified(self, identifier, arguments=None):
        try:
            process = self.unified_registry.launch(identifier, arguments, detach=True)
            title = self.unified_registry.component(identifier).title
            self.report = {"summary": f"Started {title} as PID {process.pid}. Process creation does not verify readiness or authorize evidence actions."}
            self.update_summary()
        except (OSError, RuntimeError, ValueError) as error:
            self.field_error("Component launch failed", error)

    def record_unified_source(self, identifier):
        try:
            observation = self.unified_registry.record_source(identifier)
            if identifier != "zoe":
                self.unified_registry.knowledge.connect(
                    observation["id"], "zoe",
                    "Shared source and trust context; no evidence or permission transfer.",
                )
            self.refresh()
        except ValueError as error:
            self.field_error("Record source context failed", error)

    def choose_cerotto(self, *_args):
        dialog = Gtk.FileChooserDialog(title="Choose a Cerotto case database", transient_for=self, action=Gtk.FileChooserAction.OPEN)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Launch", Gtk.ResponseType.OK)
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                case = self.controls["cerotto_case"].get_text().strip()
                conversation = self.controls["cerotto_conversation"].get_text().strip()
                if not case or not conversation:
                    raise ValueError("Cerotto case and conversation IDs are required")
                self.launch_unified("cerotto", [
                    "--db", dialog.get_filename(), "--case", case, "--conversation", conversation,
                ])
        except (OSError, RuntimeError, ValueError) as error:
            self.field_error("Cerotto case selection failed", error)
        finally:
            dialog.destroy()

    def save_unified_manifest(self, *_args):
        dialog = Gtk.FileChooserDialog(title="Export unified component manifest", transient_for=self, action=Gtk.FileChooserAction.SAVE)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Export", Gtk.ResponseType.OK)
        dialog.set_current_name("gem-components.json")
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                output = self.unified_registry.write_manifest(dialog.get_filename())
                self.report = {"summary": f"Saved unified component manifest to {output}"}
                self.update_summary()
        except (OSError, ValueError) as error:
            self.field_error("Manifest export failed", error)
        finally:
            dialog.destroy()

    def save_unified_knowledge(self, *_args):
        dialog = Gtk.FileChooserDialog(title="Save unified knowledge graph", transient_for=self, action=Gtk.FileChooserAction.SAVE)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Save", Gtk.ResponseType.OK)
        dialog.set_current_name("gem-knowledge.json")
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                output = self.unified_registry.knowledge.save(dialog.get_filename())
                self.report = {"summary": f"Saved {len(self.unified_registry.knowledge.events)} knowledge events to {output}"}
                self.update_summary()
        except (OSError, ValueError) as error:
            self.field_error("Knowledge export failed", error)
        finally:
            dialog.destroy()

    def run_cognitive_operation(self, operation, *args):
        try:
            operation(*args)
            self.build_controls()
        except ValueError as error:
            self.field_error("Cognitive Field operation failed", error)

    def load_cognitive_demo(self, *_args):
        from .cognitive import CognitiveField
        self.cognitive = CognitiveField.demo()
        self.build_controls()

    def new_cognitive(self, *_args):
        from .cognitive import CognitiveField
        self.cognitive = CognitiveField(working_capacity=self.integer("capacity"))
        self.build_controls()

    def encode_cognitive(self, *_args):
        self.run_cognitive_operation(
            self.cognitive.encode, self.controls["sensory_text"].get_text(),
            self.controls["sensory_source"].get_text(), self.controls["sensory_tags"].get_text(),
        )

    def store_cognitive(self, *_args):
        self.run_cognitive_operation(self.cognitive.store_active, self.choice("active_representation"))

    def retrieve_cognitive(self, *_args):
        self.run_cognitive_operation(
            self.cognitive.retrieve, self.choice("declarative_record"), self.integer("expected_revision"),
        )

    def add_cognitive_rule(self, *_args):
        self.run_cognitive_operation(
            self.cognitive.add_rule, self.controls["rule_name"].get_text(),
            self.controls["rule_tags"].get_text(), self.controls["rule_description"].get_text(),
        )

    def match_cognitive(self, *_args):
        self.run_cognitive_operation(self.cognitive.match_rules)

    def propose_cognitive(self, *_args):
        self.run_cognitive_operation(
            self.cognitive.propose_performance, self.choice("procedural_match"),
            self.controls["performance_rationale"].get_text(),
        )

    def measure_cognitive(self, *_args):
        self.run_cognitive_operation(self.cognitive.measure, [.70, .20, .08, .02], self.value("tau"))

    def sample_cognitive(self, *_args):
        self.run_cognitive_operation(self.cognitive.measure, [.70, .20, .08, .02], self.value("tau"), self.integer("seed"))

    def save_cognitive(self, *_args):
        dialog = Gtk.FileChooserDialog(title="Save Cognitive Field memory", transient_for=self, action=Gtk.FileChooserAction.SAVE)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Save", Gtk.ResponseType.OK)
        dialog.set_current_name("zoe-cognitive-field.json")
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                self.export_current(dialog.get_filename())
                self.report = {"summary": f"Saved {len(self.cognitive.events)} Cognitive Field events; existing files are never overwritten."}
                self.update_summary()
        except (OSError, RuntimeError, ValueError) as error:
            self.field_error("Save Cognitive Field failed", error)
        finally:
            dialog.destroy()

    def load_cognitive(self, *_args):
        from .cognitive import CognitiveField
        dialog = Gtk.FileChooserDialog(title="Load Cognitive Field memory", transient_for=self, action=Gtk.FileChooserAction.OPEN)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Load", Gtk.ResponseType.OK)
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                self.cognitive = CognitiveField.load(dialog.get_filename())
                self.build_controls()
        except (OSError, ValueError, json.JSONDecodeError) as error:
            self.field_error("Load Cognitive Field failed", error)
        finally:
            dialog.destroy()

    def record_brain_field(self):
        if self.brain.current is not None:
            self.field.record_brain_observation(self.brain.current)

    def configure_brain_band(self):
        minimum, maximum = self.integer("minimum"), self.integer("maximum")
        if maximum < minimum:
            raise ValueError("target maximum must be at least the minimum")
        self.brain.minimum = minimum
        self.brain.maximum = maximum
        self.brain.volume_bridge.minimum = minimum
        self.brain.volume_bridge.maximum = maximum

    def observe_brain(self, *_args, next_in_sequence=False):
        try:
            self.configure_brain_band()
            index = None if next_in_sequence else self.integer("index")
            self.brain.observe_onset(
                condition=self.choice("condition"), index=index,
                tau=self.value("tau"), temperature=self.value("temperature"),
            )
            self.record_brain_field()
            self.updating = True
            self.controls["index"].set_value(self.brain.onset_positions[self.choice("condition")])
            self.updating = False
            self.refresh()
        except (OSError, ImportError, RuntimeError, ValueError) as error:
            self.updating = False
            self.report = {"error": f"Zoe observation failed: {error}"}
            self.update_summary()

    def observe_brain_next(self, *_args):
        self.observe_brain(next_in_sequence=True)

    def open_recommended(self, *_args):
        identifier = self.brain.recommend()["module"]
        if identifier in ATLAS_MODULES:
            self.module_selector.set_active_id(identifier)

    def reset_brain(self, *_args):
        self.brain = BrainKernel()
        self.refresh()

    def observe_research(self, *_args):
        try:
            identifier = self.choice("case")
            tau = self.value("tau")
            probabilities, target = self.research_pack.observe(identifier, self.integer("index"))
            self.brain.observe(
                probabilities, tau=tau, target=target, source=identifier,
                condition=self.research_pack.case(identifier)["condition"], index=self.integer("index"),
            )
            self.record_brain_field()
            self.module_selector.set_active_id("brain")
            self.updating = True
            self.controls["tau"].set_value(tau)
            self.updating = False
            self.refresh()
        except (OSError, ImportError, RuntimeError, ValueError) as error:
            self.updating = False
            self.report = {"error": f"Research observation failed: {error}"}
            self.update_summary()

    def verify_research(self, *_args):
        try:
            checks = self.research_pack.verify_conformance()
            passed = sum(check["passed"] for check in checks)
            self.report["summary"] = f"Conformance: {passed}/{len(checks)} checks passed · " + ", ".join(check["case"] for check in checks if not check["passed"])
        except (OSError, ImportError, RuntimeError, ValueError) as error:
            self.report = {"error": f"Conformance verification failed: {error}"}
        self.update_summary()

    def recompute_onset(self, *_args):
        self.experiment = None
        self.refresh()

    def refresh_onset(self):
        try:
            if self.experiment is None:
                self.experiment = self.experiment_factory()
            self.scene, self.report = onset_scene(self.experiment, self.value("tau"), self.value("temperature"))
        except (ImportError, RuntimeError, ValueError) as error:
            self.scene = None
            self.report = {"error": f"Onset experiment unavailable: {error}"}
            self.canvas.set_model(None)

    def update_summary(self):
        if not self.report:
            return
        if "error" in self.report:
            text = self.report["error"]
        elif self.module == "procrustes":
            matrix = self.report["matrix"]
            text = (
                f"A = [[{matrix[0][0]:.6f}, {matrix[0][1]:.6f}], [{matrix[1][0]:.6f}, {matrix[1][1]:.6f}]]\n"
                f"t = ({self.report['translation'][0]:.6f}, {self.report['translation'][1]:.6f})  ·  "
                f"scale={self.report['scale']:.6f}  angle={self.report['rotation_degrees']:.4f}°  "
                f"RMS/landmark={self.report['rmse_per_landmark']:.6f}"
            )
        elif self.module in {"brain", "field", "cognitive", "research", "qualia", "unified"}:
            text = self.report["summary"]
        elif self.module == "horizon":
            text = (
                f"h={self.report['horizon']} · τ={self.report['tau']:.3f} · "
                f"A={self.report['accessible_volume']} · complement={self.report['complement_volume']} · "
                f"universe={self.report['universe_size']} · exact toy Markov enumeration"
            )
        elif self.module == "volume":
            text = self.report["summary"]
        elif self.module == "onset":
            text = (
                f"Forward: top-1 {self.report['forward']['top1']:.1%}, log-loss {self.report['forward']['log_loss']:.3f}, "
                f"A(τ)={self.report['forward_at_tau']:.2f}. Retrograde: top-1 {self.report['retrograde']['top1']:.1%}, "
                f"log-loss {self.report['retrograde']['log_loss']:.3f}, A(τ)={self.report['retrograde_at_tau']:.2f}.\n"
                f"Temperature={self.report['temperature']:.2f}; synthetic held-out evidence only. "
                f"Deterministic HOP and linear extrapolation are separate baselines, not distributions."
            )
        else:
            text = " · ".join(f"{key}={value}" for key, value in self.report.items() if not isinstance(value, (dict, list)))
        self.summary.set_text(text)
        self.summary.set_tooltip_text(text)

    def export_current(self, path):
        if self.scene is None:
            self.refresh()
        path = Path(path)
        if self.module == "cognitive":
            from .cognitive import export_cognitive
            path, self.report = export_cognitive(self.cognitive, path)
            self.update_summary()
            return path
        if self.module == "unified" and path.suffix.lower() == ".json":
            self.unified_registry.knowledge.save(path)
            self.report["summary"] = f"Saved {len(self.unified_registry.knowledge.events)} unified knowledge events to {path}"
            self.update_summary()
            return path
        suffix = path.suffix.lower()
        if suffix == ".svg":
            write_svg(self.scene, path)
        elif suffix == ".png":
            write_png(self.scene, path)
        elif suffix == ".gem":
            write_metafile(self.scene, path)
        elif suffix == ".json" and self.module == "field":
            self.field.save(path)
        else:
            raise ValueError("atlas export must use .svg, .png, .gem, or field-only .json")
        if self.module == "brain":
            self.brain.mark_exported()
            self.refresh()
        return path

    def choose_export(self, suffix):
        dialog = Gtk.FileChooserDialog(
            title=f"Export {suffix.upper()}", transient_for=self,
            action=Gtk.FileChooserAction.SAVE,
        )
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Export", Gtk.ResponseType.OK)
        dialog.set_do_overwrite_confirmation(self.module != "cognitive")
        dialog.set_current_name(f"atlas-{self.module}.{suffix}")
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                self.export_current(dialog.get_filename())
        except (OSError, RuntimeError, ValueError) as error:
            if self.module != "cognitive":
                raise
            self.field_error("Cognitive Field export failed", error)
        finally:
            dialog.destroy()

    def on_export_svg(self, *_args):
        self.choose_export("svg")

    def on_export_png(self, *_args):
        self.choose_export("png")

    def on_export_gem(self, *_args):
        self.choose_export("gem")


def show_atlas(module="procrustes", research_root=None):
    research_root = research_root or os.environ.get("MASTER_GEM_RESEARCH_ROOT")
    window = AtlasWindow(module, research_root=research_root)
    window.show_all()
    return window


def launch_atlas(module="procrustes", research_root=None):
    if not os.environ.get("DISPLAY"):
        raise RuntimeError("the native geometry atlas requires a GTK display; use --output for headless export")
    window = show_atlas(module, research_root=research_root)
    window.connect("destroy", Gtk.main_quit)
    Gtk.main()
    return window
