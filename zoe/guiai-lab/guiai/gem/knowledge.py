from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from .field import FieldNotebook, _canonical, _text


MAX_KNOWLEDGE_EVENTS = 4096
MAX_OBSERVATION_BYTES = 65536


class KnowledgeField(FieldNotebook):
    def __init__(self, registry=None):
        super().__init__(registry=registry)
        self.knowledge_observations = []
        self.knowledge_links = []

    def _append(self, kind, payload):
        if len(self.events) >= MAX_KNOWLEDGE_EVENTS:
            raise ValueError("knowledge event bound reached")
        return super()._append(kind, payload)

    def _apply(self, event):
        if event["kind"] == "knowledge_observation_recorded":
            self.knowledge_observations.append(deepcopy(event["payload"]["observation"]))
        elif event["kind"] == "knowledge_link_recorded":
            self.knowledge_links.append(deepcopy(event["payload"]["link"]))
        else:
            super()._apply(event)

    def observation(self, identifier):
        for observation in self.knowledge_observations:
            if observation["id"] == identifier:
                return observation
        raise ValueError(f"unknown knowledge observation: {identifier}")

    def observe(self, component, observation, *, repository, revision, scope, source):
        if not isinstance(observation, dict):
            raise ValueError("knowledge observation must be a JSON object")
        encoded = _canonical(observation).encode("utf-8")
        if len(encoded) > MAX_OBSERVATION_BYTES:
            raise ValueError(f"knowledge observation exceeds {MAX_OBSERVATION_BYTES} canonical JSON bytes")
        repository = _text(repository, "component repository", 256)
        revision = _text(revision, "component revision", 64) if revision is not None else None
        scope = _text(scope, "knowledge scope", 2000)
        source = _text(source, "knowledge source", 1000)
        record = {
            "id": f"k-{len(self.knowledge_observations) + 1}",
            "component": _text(component, "knowledge component", 64),
            "observation": deepcopy(observation),
            "trust_context": {
                "repository": repository,
                "revision": revision,
                "source": source,
                "scope": scope,
            },
            "stability_context": {
                "process": "component-specific",
                "runtime_verified": False,
                "state": "recorded, not inferred",
                "replay": "canonical SHA-256 event chain",
            },
            "belief_updated": False,
            "executed": False,
        }
        return self._append("knowledge_observation_recorded", {"observation": record})["observation"]

    def observe_source(self, specification):
        source = specification["source"]
        return self.observe(
            specification["identifier"],
            {
                "summary": specification["summary"],
                "source_present": source["source_present"],
                "source_mode": source["mode"],
                "anchor": specification["anchor"],
            },
            repository=specification["repository"],
            revision=specification["revision"],
            source="component registry source inventory",
            scope="Source registration only; runtime behavior is not inferred or verified.",
        )

    def connect(self, observation_id, target_component, relation):
        self.observation(observation_id)
        record = {
            "id": f"l-{len(self.knowledge_links) + 1}",
            "source_observation_id": observation_id,
            "target_component": _text(target_component, "target component", 64),
            "relation": _text(relation, "knowledge relation", 2000),
            "kind": "declared_context_link",
            "evidence_transfer": False,
            "permission_transfer": False,
            "belief_updated": False,
            "executed": False,
        }
        return self._append("knowledge_link_recorded", {"link": record})["link"]

    def knowledge_state(self):
        return {
            "observations": deepcopy(self.knowledge_observations),
            "links": deepcopy(self.knowledge_links),
            "observation_count": len(self.knowledge_observations),
            "link_count": len(self.knowledge_links),
            "trust_context": "source, repository, revision, and explicit scope",
            "stability_context": "component-specific processes, replayable memory, and separately tested behavior",
            "executed": False,
        }

    def state(self):
        state = super().state()
        state["instrument"] = "GEM knowledge field"
        state["knowledge"] = self.knowledge_state()
        return state

    def document(self):
        return {
            "schema_version": 1,
            "instrument": "gem-knowledge-field",
            "knowledge_engineering": {
                "trust_context": "source, repository, revision, and explicit scope",
                "stability_context": "component-specific processes, replayable memory, and separately tested behavior",
            },
            "integrity": "canonical-json-sha256-chain; tamper evidence, not authentication",
            "events": deepcopy(self.events),
        }

    @classmethod
    def load(cls, path, registry=None):
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(document, dict) or document.get("schema_version") != 1 or document.get("instrument") != "gem-knowledge-field":
            raise ValueError("unsupported GEM knowledge document")
        events = document.get("events")
        if not isinstance(events, list) or len(events) > MAX_KNOWLEDGE_EVENTS:
            raise ValueError("knowledge events must be a bounded list")
        field = cls(registry=registry)
        for event in events:
            if not isinstance(event, dict) or not isinstance(event.get("kind"), str) or "payload" not in event:
                raise ValueError("invalid knowledge event")
            field._append(event["kind"], event["payload"])
            if field.events[-1] != event:
                raise ValueError(f"knowledge hash-chain mismatch at event {len(field.events)}")
        return field

    @classmethod
    def source_demo(cls, manifest):
        field = cls()
        for specification in manifest["components"]:
            observation = field.observe_source(specification)
            if specification["identifier"] != "zoe":
                field.connect(
                    observation["id"], "zoe",
                    "Shared source and trust context; no evidence or permission transfer.",
                )
        return field
