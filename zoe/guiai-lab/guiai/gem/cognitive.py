from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from .field import FieldNotebook, _canonical, _fit, _text


MAX_COGNITIVE_EVENTS = 4096
COGNITIVE_OPERATIONS = {
    "sensory_encoded", "declarative_stored", "declarative_retrieved",
    "procedural_registered", "procedural_matched", "performance_proposed",
}


def _revision(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1000000:
        raise ValueError("expected_revision must be an integer from 0 to 1000000")
    return value


def _tags(values):
    if isinstance(values, str):
        values = values.split(",")
    if not isinstance(values, (list, tuple)):
        raise ValueError("tags must be a comma-separated string or a sequence")
    result = sorted(set(_text(value, "tag", 64) for value in values))
    if not 1 <= len(result) <= 16 or len(result) != len(values):
        raise ValueError("tags must contain 1–16 distinct nonempty values")
    return result


class CognitiveField(FieldNotebook):
    def __init__(self, registry=None, working_capacity=4):
        if isinstance(working_capacity, bool) or not isinstance(working_capacity, int) or not 1 <= working_capacity <= 16:
            raise ValueError("working_capacity must be an integer from 1 to 16")
        super().__init__(registry=registry)
        self.working_capacity = working_capacity
        self.sensory = []
        self.working = []
        self.evicted = []
        self.declarative = []
        self.procedural = []
        self.matches = []
        self.retrievals = []
        self.performance = []
        self.cognitive_log = []

    def _append(self, kind, payload):
        if len(self.events) >= MAX_COGNITIVE_EVENTS:
            raise ValueError("Cognitive Field event bound reached")
        return super()._append(kind, payload)

    def _record(self, record):
        if len(self.events) >= MAX_COGNITIVE_EVENTS:
            raise ValueError("Cognitive Field event bound reached")
        if record["operation"] not in COGNITIVE_OPERATIONS:
            raise ValueError("unsupported cognitive operation")
        return self._append("cognitive_operation_recorded", {"record": record})["record"]

    def _apply(self, event):
        if event["kind"] != "cognitive_operation_recorded":
            super()._apply(event)
            return
        record = event["payload"]["record"]
        operation = record["operation"]
        if operation not in COGNITIVE_OPERATIONS:
            raise ValueError(f"unsupported cognitive operation: {operation}")
        self.cognitive_log.append(deepcopy(record))
        if operation == "sensory_encoded":
            representation = deepcopy(record["representation"])
            self.sensory.append({**deepcopy(representation), "status": "active"})
            self.working.append(deepcopy(representation))
            if len(self.working) > self.working_capacity:
                evicted = self.working.pop(0)
                evicted["status"] = "evicted"
                evicted["eviction_event_sequence"] = record["event_sequence"]
                self.evicted.append(evicted)
                self._representation(evicted["id"])["status"] = "evicted"
        elif operation == "declarative_stored":
            self.declarative.append(deepcopy(record["record"]))
        elif operation == "declarative_retrieved":
            self.retrievals.append(deepcopy(record["retrieval"]))
        elif operation == "procedural_registered":
            self.procedural.append(deepcopy(record["rule"]))
        elif operation == "procedural_matched":
            self.matches.append(deepcopy(record["match"]))
        elif operation == "performance_proposed":
            self.performance.append(deepcopy(record["proposal"]))

    def _representation(self, identifier):
        for representation in self.sensory:
            if representation["id"] == identifier:
                return representation
        raise ValueError(f"unknown sensory representation: {identifier}")

    def _active(self, identifier):
        for representation in self.working:
            if representation["id"] == identifier:
                return representation
        raise ValueError("representation is not active in working memory; encode a new observation")

    def _rule(self, identifier):
        for rule in self.procedural:
            if rule["id"] == identifier:
                return rule
        raise ValueError(f"unknown procedural rule: {identifier}")

    def encode(self, text, source, tags):
        if len(self.sensory) >= 512:
            raise ValueError("sensory representation bound reached")
        representation = {
            "id": f"r-{len(self.sensory) + 1}",
            "text": _text(text, "sensory text", 1000),
            "source": _text(source, "sensory source", 500),
            "tags": _tags(tags),
            "revision": 0,
            "event_sequence": len(self.events) + 1,
            "status": "active",
        }
        self._record({"operation": "sensory_encoded", "event_sequence": len(self.events) + 1, "representation": representation})
        return deepcopy(self.working[-1])

    def store_active(self, representation_id, expected_revision=0):
        expected_revision = _revision(expected_revision)
        active = self._active(representation_id)
        if active["revision"] != expected_revision:
            raise ValueError(f"active representation revision is {active['revision']}, not {expected_revision}")
        if len(self.declarative) >= 128:
            raise ValueError("declarative memory bound reached")
        record = {
            "id": f"d-{len(self.declarative) + 1}",
            "text": active["text"],
            "source": active["source"],
            "tags": list(active["tags"]),
            "source_representation_id": active["id"],
            "source_event_sequence": active["event_sequence"],
            "revision": expected_revision + 1,
            "event_sequence": len(self.events) + 1,
        }
        self._record({"operation": "declarative_stored", "record": record})
        return deepcopy(record)

    def retrieve(self, record_id, expected_revision):
        expected_revision = _revision(expected_revision)
        record = next((item for item in self.declarative if item["id"] == record_id), None)
        if record is None:
            raise ValueError(f"unknown declarative record: {record_id}")
        matched = record["revision"] == expected_revision
        retrieval = {
            "id": f"q-{len(self.retrievals) + 1}",
            "record_id": record_id,
            "expected_revision": expected_revision,
            "actual_revision": record["revision"],
            "status": "matched" if matched else "revision_mismatch",
            "source_representation_id": record["source_representation_id"],
            "source_event_sequence": record["source_event_sequence"],
            "event_sequence": len(self.events) + 1,
            "belief_updated": False,
            "executed": False,
        }
        if matched:
            retrieval["record"] = deepcopy(record)
        self._record({"operation": "declarative_retrieved", "retrieval": retrieval})
        return deepcopy(retrieval)

    def add_rule(self, name, required_tags, description):
        if len(self.procedural) >= 64:
            raise ValueError("procedural memory bound reached")
        rule = {
            "id": f"p-{len(self.procedural) + 1}",
            "name": _text(name, "rule name", 128),
            "required_tags": _tags(required_tags),
            "description": _text(description, "rule description", 1000),
            "executable": False,
        }
        self._record({"operation": "procedural_registered", "rule": rule})
        return deepcopy(rule)

    def match_rules(self, rule_id=None):
        if len(self.matches) >= 256:
            raise ValueError("procedural match bound reached")
        rules = [self._rule(rule_id)] if rule_id is not None else self.procedural
        active_tags = sorted({tag for item in self.working for tag in item["tags"]})
        matches = [rule["id"] for rule in rules if set(rule["required_tags"]).issubset(active_tags)]
        result = {
            "id": f"x-{len(self.matches) + 1}",
            "active_representation_ids": [item["id"] for item in self.working],
            "active_tags": active_tags,
            "matched_rule_ids": matches,
            "status": "matched" if matches else "no_match",
            "event_sequence": len(self.events) + 1,
            "belief_updated": False,
            "executed": False,
        }
        self._record({"operation": "procedural_matched", "match": result})
        return deepcopy(result)

    def propose_performance(self, match_id, rationale, rule_id=None):
        match = next((item for item in self.matches if item["id"] == match_id), None)
        if match is None:
            raise ValueError(f"unknown procedural match: {match_id}")
        if not match["matched_rule_ids"]:
            raise ValueError("a no-match result cannot produce a performance proposal")
        rule_id = rule_id or match["matched_rule_ids"][0]
        if rule_id not in match["matched_rule_ids"]:
            raise ValueError("rule was not part of this procedural match")
        if len(self.performance) >= 128:
            raise ValueError("performance proposal bound reached")
        proposal = {
            "id": f"f-{len(self.performance) + 1}",
            "match_id": match_id,
            "rule_id": rule_id,
            "description": self._rule(rule_id)["description"],
            "rationale": _text(rationale, "performance rationale", 1000),
            "status": "review_required",
            "review_required": True,
            "event_sequence": len(self.events) + 1,
            "belief_updated": False,
            "executed": False,
        }
        self._record({"operation": "performance_proposed", "proposal": proposal})
        return deepcopy(proposal)

    def measure(self, probabilities, tau, seed=None):
        name = "Cognitive forecast sample" if seed is not None else "Cognitive forecast breadth"
        chamber = next((item for item in self.chambers if item["name"] == name), None)
        if chamber is None:
            chamber = self.add_chamber(
                name, "stochastic" if seed is not None else "deterministic",
                "sample/categorical@v1" if seed is not None else "volume/strict@v1",
                disposition="experimental" if seed is not None else "active",
                provenance="Nicholas Michael Kloster's accessible-volume equation" if seed is None else "Seeded categorical sample; outcome is not evidence",
            )
        inputs = {"probabilities": probabilities, "seed": seed} if seed is not None else {"probabilities": probabilities, "tau": tau}
        return self.run_chamber(chamber["id"], **inputs)

    def cognitive_state(self):
        return {
            "working_capacity": self.working_capacity,
            "sensory": deepcopy(self.sensory),
            "working": deepcopy(self.working),
            "evicted": deepcopy(self.evicted),
            "declarative": deepcopy(self.declarative),
            "procedural": deepcopy(self.procedural),
            "matches": deepcopy(self.matches),
            "retrievals": deepcopy(self.retrievals),
            "performance": deepcopy(self.performance),
            "event_clock": {"sequence": len(self.events), "meaning": "local event ordinal; not wall-clock time or a prediction of the future"},
            "executed": False,
        }

    def state(self):
        state = super().state()
        state["instrument"] = "Zoe Cognitive Field"
        state["cognitive"] = self.cognitive_state()
        return state

    def document(self):
        return {
            "schema_version": 1,
            "instrument": "zoe-cognitive-field",
            "configuration": {"working_capacity": self.working_capacity},
            "integrity": "canonical-json-sha256-chain; tamper evidence, not authentication",
            "events": deepcopy(self.events),
        }

    @classmethod
    def load(cls, path, registry=None):
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(document, dict) or document.get("schema_version") != 1 or document.get("instrument") != "zoe-cognitive-field":
            raise ValueError("unsupported Cognitive Field document")
        configuration = document.get("configuration")
        if not isinstance(configuration, dict) or set(configuration) != {"working_capacity"}:
            raise ValueError("Cognitive Field configuration must declare working_capacity")
        events = document.get("events")
        if not isinstance(events, list) or len(events) > MAX_COGNITIVE_EVENTS:
            raise ValueError(f"Cognitive Field requires a list of at most {MAX_COGNITIVE_EVENTS} events")
        field = cls(registry=registry, working_capacity=configuration["working_capacity"])
        for event in events:
            if not isinstance(event, dict) or not isinstance(event.get("kind"), str) or "payload" not in event:
                raise ValueError("invalid Cognitive Field event")
            if event["kind"] == "cognitive_operation_recorded":
                record = event["payload"].get("record") if isinstance(event["payload"], dict) else None
                if not isinstance(record, dict) or record.get("operation") not in COGNITIVE_OPERATIONS:
                    raise ValueError("invalid cognitive operation record")
            field._append(event["kind"], event["payload"])
            if field.events[-1] != event:
                raise ValueError(f"Cognitive Field hash-chain mismatch at event {len(field.events)}")
        _canonical(field.cognitive_state())
        return field

    @classmethod
    def demo(cls):
        field = cls(working_capacity=4)
        question = field.add_question("Can explicit memory operations remain inspectable?")
        field.add_claim(
            question["id"], "A measurement changes belief without an explicit evidence event.",
            prior=.5, falsifier="Inspect the event chain for a measurement that modifies a posterior.", status="rejected",
        )
        field.encode("Information enters as a sourced observation.", "Cognitive Field worked example", "information")
        field.encode("Keep the active set small enough to inspect.", "Cognitive Field worked example", "working")
        field.encode("Retention requires an explicit storage operation.", "Cognitive Field worked example", "declarative")
        field.encode("A matching rule describes performance; it does not perform.", "Cognitive Field worked example", ["procedural", "review"])
        field.encode("Overflow is retained as an eviction, not silently forgotten.", "Cognitive Field worked example", "eviction")
        field.store_active("r-3")
        field.retrieve("d-1", 1)
        field.retrieve("d-1", 0)
        field.add_rule("Review a memory boundary", ["procedural", "review"], "Inspect the matched rule and its provenance before deciding what to do.")
        field.add_rule("Require a missing tag", ["unavailable"], "This negative match remains available for inspection.")
        match = field.match_rules()
        field.propose_performance(match["id"], "Review the architecture demonstration; no execution requested.")
        field.measure([.70, .20, .08, .02], .05)
        return field


def _rectangle(identifier, bounds, stroke, fill, width=1):
    return {"id": identifier, "type": "rectangle", "bounds": bounds, "stroke": stroke, "fill": fill, "width": width}


def _arrow(objects, identifier, first, second, color):
    from .atlas import _line
    objects.append(_line(identifier, first, second, color, 2))
    direction = 1 if second[0] >= first[0] else -1
    objects.append({"id": f"{identifier}-head", "type": "polygon", "points": [second, [second[0] - direction * 10, second[1] - 5], [second[0] - direction * 10, second[1] + 5]], "stroke": color, "fill": color, "width": 1})


def _slab(identifier, x, y, color):
    return {
        "id": identifier, "type": "polygon", "role": "active_memory_layer",
        "points": [[x, y + 5], [x + 24, y], [x + 40, y + 5], [x + 16, y + 10]],
        "stroke": "#d7f3ff", "fill": color, "width": .5,
    }


def cognitive_scene(field):
    from .atlas import _line, _scene, _text
    state = field.cognitive_state()
    cyan, pink, yellow, green, muted = "#67e8f9", "#f0abfc", "#fde68a", "#86efac", "#94a3b8"
    objects = [_rectangle("background", [0, 0, 1400, 900], "#080d18", "#080d18")]
    objects.extend([
        _text("title", [32, 43], "Z.O.E. · COGNITIVE FIELD / GSP", 27, cyan),
        _text("subtitle", [32, 74], "Information changes form. Working memory stays explicit.", 17, "#e2e8f0"),
        _text("architecture", [32, 98], "GENERAL SYMBOL PROCESSOR · bounded software architecture · not ACT-R or consciousness", 12, muted),
        _text("clock", [1070, 42], f"EVENT CLOCK · {len(field.events)}", 14, yellow),
        _text("clock-note", [1070, 63], "ordinal sequence, not wall-clock time", 11, muted),
        _rectangle("logical-viewport", [1070, 82, 1368, 126], "#475569", "#111c2f"),
        _rectangle("logical-work-area", [1080, 90, 1358, 118], "#64748b", "#18263b"),
        _text("logical-label", [1090, 109], "work area · logical 1400 × 900", 11, "#cbd5e1"),
    ])
    panels = [
        ("declarative-panel", [32, 155, 435, 495], cyan, "DECLARATIVE MEMORY", "explicit store / provenance / revision checks"),
        ("working-panel", [480, 155, 940, 495], yellow, "WORKING MEMORY", f"active representations · bounded FIFO · capacity {field.working_capacity}"),
        ("procedural-panel", [985, 155, 1368, 495], pink, "PROCEDURAL MEMORY", "declared tags / match results · never executable code"),
        ("sensory-panel", [32, 545, 435, 710], pink, "SENSORY ENCODING", "information + source + tags -> active representation"),
        ("performance-panel", [985, 545, 1368, 710], green, "PERFORMANCE", "proposals remain review-required · executed=False"),
    ]
    for identifier, bounds, color, title, subtitle in panels:
        objects.append(_rectangle(identifier, bounds, color, "#0e1828", 2))
        objects.append(_text(f"{identifier}-title", [bounds[0] + 18, bounds[1] + 29], title, 17, color))
        objects.append(_text(f"{identifier}-subtitle", [bounds[0] + 18, bounds[1] + 51], subtitle, 11, muted))
    _arrow(objects, "sensory-to-working", [435, 625], [522, 495], pink)
    _arrow(objects, "declarative-to-working", [435, 310], [480, 310], cyan)
    _arrow(objects, "procedural-to-working", [985, 310], [940, 310], pink)
    _arrow(objects, "working-to-performance", [940, 450], [985, 575], green)
    objects.extend([
        _text("storage-flow", [374, 287], "store / retrieve", 11, cyan),
        _text("match-flow", [889, 287], "match", 11, pink),
        _text("review-flow", [908, 520], "review", 11, green),
    ])
    layer_colors = ["#4e9fb0", "#b486bf", "#8aab62", "#c37d8d"]
    for index in range(4):
        y = 230 + index * 53
        objects.append(_rectangle(f"working-slot-{index}", [500, y, 920, y + 42], "#3f4b61", "#17253a"))
        if index < len(state["working"]):
            item = state["working"][index]
            for layer in range(3):
                objects.append(_slab(f"working-layer-{index}-{layer}", 507 + layer * 3, y + 23 - layer * 5, layer_colors[index]))
            objects.append(_text(f"working-item-{index}", [562, y + 18], f"{item['id']} · {_fit(item['text'], 44)}", 12, "#f8fafc"))
            objects.append(_text(f"working-source-{index}", [562, y + 34], f"event {item['event_sequence']} · {_fit(', '.join(item['tags']), 49)}", 10, yellow))
        else:
            objects.append(_text(f"working-empty-{index}", [514, y + 26], "available · no implicit filler", 12, "#64748b"))
    objects.append(_text("working-overflow", [500, 466], f"{len(state['working'])} active · {len(state['evicted'])} evicted · overflow preserved below", 11, yellow))
    objects.append(_text("working-boundary", [500, 484], "Capacity limits display state, not the evidence chain.", 10, muted))
    objects.extend([
        _rectangle("context-panel", [480, 545, 940, 710], "#475569", "#0e1828"),
        _text("context-title", [500, 574], "PORTABLE CONTEXT · VISUAL KEY", 13, cyan),
        _rectangle("legend-record", [500, 589, 515, 601], cyan, "#163b49"),
        _text("legend-record-label", [526, 599], "bounded record / retained state", 11, "#e2e8f0"),
        {"id": "legend-observation", "type": "polygon", "points": [[507, 613], [515, 621], [507, 629], [499, 621]], "stroke": pink, "fill": pink, "width": 1},
        _text("legend-observation-label", [526, 625], "sourced input / explicit match", 11, "#e2e8f0"),
        _text("legend-provenance", [714, 599], "source + event + revision", 11, cyan),
        _text("legend-match", [714, 625], "required tags <= active tags", 11, pink),
        _text("legend-review", [714, 652], "match => proposal only", 11, green),
        _text("legend-event", [714, 679], "chain => inspectable past", 11, yellow),
        _text("legend-note", [500, 699], "Symbols compress the view; JSON retains the complete context.", 10, muted),
    ])
    for layer in range(3):
        objects.append(_slab(f"legend-layer-{layer}", 499 + layer * 3, 657 - layer * 5, layer_colors[layer]))
    objects.append(_text("legend-layer-label", [562, 654], "layered active memory", 11, "#e2e8f0"))
    objects.append(_text("legend-layer-note", [562, 670], "illustrative glyph only", 9, muted))
    for index, item in enumerate(state["declarative"][-4:]):
        y = 239 + index * 43
        objects.append(_text(f"declarative-item-{index}", [50, y], f"{item['id']} rev {item['revision']} · {_fit(item['text'], 41)}", 12, "#e2e8f0"))
        objects.append(_text(f"declarative-source-{index}", [50, y + 17], f"from {item['source_representation_id']} / event {item['source_event_sequence']} · {_fit(item['source'], 32)}", 10, cyan))
    if not state["declarative"]:
        objects.append(_text("declarative-empty", [50, 245], "Nothing is retained automatically.", 13, muted))
        objects.append(_text("declarative-empty-2", [50, 269], "Store an active representation explicitly.", 12, muted))
    if state["retrievals"]:
        result = state["retrievals"][-1]
        color = green if result["status"] == "matched" else "#fdba74"
        objects.append(_text("retrieval-status", [50, 432], f"retrieval: {result['status']}", 12, color))
        objects.append(_text("retrieval-revision", [50, 453], f"expected rev {result['expected_revision']} · actual rev {result['actual_revision']}", 11, color))
    objects.append(_text("declarative-rule", [50, 479], "Revision mismatch returns no stored record.", 11, muted))
    for index, rule in enumerate(state["procedural"][:5]):
        y = 235 + index * 38
        objects.append(_text(f"rule-{index}", [1003, y], f"{rule['id']} · {_fit(rule['name'], 35)}", 12, "#e2e8f0"))
        objects.append(_text(f"rule-tags-{index}", [1003, y + 16], _fit("requires " + ", ".join(rule["required_tags"]), 47), 10, pink))
    if not state["procedural"]:
        objects.append(_text("rules-empty", [1003, 245], "Declare rules and required tags.", 13, muted))
        objects.append(_text("rules-empty-2", [1003, 269], "Matching does not invoke a function.", 12, muted))
    if state["matches"]:
        result = state["matches"][-1]
        objects.append(_text("match-status", [1003, 425], f"{result['id']} · {result['status']} · {len(result['matched_rule_ids'])} matched", 12, pink))
        objects.append(_text("match-ids", [1003, 447], _fit("rules: " + (", ".join(result["matched_rule_ids"]) or "none"), 45), 11, muted))
    objects.append(_text("match-boundary", [1003, 479], "No match => no performance proposal.", 11, muted))
    for index, item in enumerate(state["sensory"][-3:]):
        y = 626 + index * 24
        objects.append(_text(f"sensory-item-{index}", [50, y], f"{item['id']} · {item['status']} · {_fit(item['text'], 33)}", 11, pink if item["status"] == "active" else muted))
    if not state["sensory"]:
        objects.append(_text("sensory-empty", [50, 638], "Encode an observation to begin.", 13, muted))
    objects.append(_text("sensory-count", [50, 700], f"{len(state['sensory'])} sourced inputs · {len(state['evicted'])} explicit evictions", 10, muted))
    for index, proposal in enumerate(state["performance"][-2:]):
        y = 626 + index * 35
        objects.append(_text(f"performance-item-{index}", [1003, y], f"{proposal['id']} · {proposal['status']}", 12, green))
        objects.append(_text(f"performance-description-{index}", [1003, y + 16], _fit(proposal["description"], 47), 10, muted))
    if not state["performance"]:
        objects.append(_text("performance-empty", [1003, 635], "No autonomous execution.", 14, green))
        objects.append(_text("performance-empty-2", [1003, 660], "A match is not an instruction.", 12, muted))
    objects.append(_text("performance-count", [1003, 700], f"{len(state['performance'])} review-required proposals · executed=False", 10, green))
    objects.append(_rectangle("memory-panel", [32, 746, 1368, 858], "#475569", "#0e1828"))
    objects.append(_text("memory-title", [50, 774], f"UNIFIED EVENT MEMORY · {len(field.events)} sequence-linked events", 13, yellow))
    objects.append(_text("memory-hash", [50, 795], f"SHA-256 head · {state['event_clock']['sequence']} · {field.events[-1]['hash'] if field.events else 'empty'}", 10, muted))
    recent = field.events[-24:]
    if recent:
        spacing = min(53, 1250 / max(1, len(recent) - 1))
        objects.append(_line("memory-chain", [60, 816], [60 + spacing * (len(recent) - 1), 816], "#475569", 2))
        for index, event in enumerate(recent):
            x = 60 + spacing * index
            color = pink if event["kind"] == "cognitive_operation_recorded" else cyan if event["kind"] == "evidence_added" else yellow
            objects.append(_rectangle(f"memory-event-{index}", [x - 4, 812, x + 4, 820], color, color))
    objects.append(_text("firewall", [50, 845], "measurement != evidence != belief update != action · no autonomous action · tamper evidence, not authentication", 12, "#fda4af"))
    objects.append(_text("scope", [32, 885], "A working memory instrument, not a mind · every representation and proposal remains inspectable and replayable", 11, muted))
    scene = _scene("zoe-cognitive-field", 1400, 900, objects, "Zoe Cognitive Field · bounded inspectable memory")
    report = {
        "summary": f"{len(state['working'])}/{field.working_capacity} active · {len(state['evicted'])} evicted · {len(state['declarative'])} declarative · {len(state['performance'])} review-required proposals · {len(field.events)} events · executed=False",
        "memory": field.document(),
        "state": field.state(),
        "working_count": len(state["working"]),
        "eviction_count": len(state["evicted"]),
        "declarative_count": len(state["declarative"]),
        "review_required_count": len(state["performance"]),
        "executed": False,
        "act_r_implementation": False,
        "consciousness_measured": False,
        "logical_canvas": {"width": 1400, "height": 900, "viewport": "aspect-preserving fit; logical work area is unchanged"},
        "recommended_module": "cognitive",
    }
    return scene, report


def export_cognitive(field, path, kind=None, width=1200):
    import os
    import tempfile
    from .geometry import verify
    from .render import write_png, write_svg
    from .runner import verify_vdi
    from .vdi import write_metafile

    path = Path(path)
    kind = kind or path.suffix.lower().lstrip(".")
    if kind not in {"json", "svg", "png", "gem"}:
        raise ValueError("Cognitive Field output format must be json, svg, png, or gem")
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "json":
        field.save(path)
        if CognitiveField.load(path).document() != field.document():
            raise RuntimeError("Cognitive Field memory round-trip did not reproduce the event chain")
        return path, {"summary": f"Saved {len(field.events)} Cognitive Field events; hash chain verified on reload.", "verification": {"memory_roundtrip": "passed"}}
    scene, report = cognitive_scene(field)
    source = verify(scene)
    vdi = verify_vdi(scene)
    if not source.passed or not vdi.passed:
        raise RuntimeError(f"Cognitive Field export verification failed: {source.text()} {vdi.text()}")
    report["verification"] = {"scene": source.to_dict(), "vdi": vdi.to_dict()}
    temporary = tempfile.NamedTemporaryFile(dir=path.parent, prefix=".cognitive-", suffix=f".{kind}", delete=False)
    temporary.close()
    temporary_path = Path(temporary.name)
    try:
        if kind == "svg":
            write_svg(scene, temporary_path, width)
        elif kind == "png":
            write_png(scene, temporary_path, width)
        else:
            write_metafile(scene, temporary_path)
        os.link(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return path, report
