from dataclasses import dataclass

from .model import scene_from_events
from .runner import export_run, next_run_directory, replay


@dataclass(frozen=True)
class GemExport:
    run: object
    replay: object
    evidence: dict

    @property
    def passed(self):
        return (
            self.run.passed and self.replay.passed and self.replay.matches_recorded
            and self.evidence["status"] == "complete_scoped"
        )


class GemLabHost:
    def __init__(self, session):
        self.session = session

    @staticmethod
    def _chart_parent(events, selected_id, root_id):
        if any(event["parent_id"] == selected_id for event in events):
            return selected_id
        selected = next((event for event in events if event["id"] == selected_id), None)
        return selected["parent_id"] if selected and selected["parent_id"] else root_id

    def current_scene(self):
        state, events = self.session.investigation_snapshot()
        parent_id = self._chart_parent(events, state["selected_id"], self.session.root_id)
        scene = scene_from_events(events, parent_id, state["selected_id"])
        return state, parent_id, scene, events

    def _objects(self, state, parent_id, scene, events):
        investigation = [
            {
                "reference": f"investigation:{event['id']}",
                "kind": "investigation",
                "id": event["id"],
                "selected": event["id"] == state["selected_id"],
            }
            for event in events
        ]
        spatial = [
            {
                "reference": f"spatial:{scene.document['id']}:{item['id']}",
                "kind": "spatial",
                "id": item["id"],
                "scene_id": scene.document["id"],
                "event_id": item.get("event_id"),
                "chart_parent": parent_id,
            }
            for item in scene.objects
        ]
        return investigation + spatial

    def objects(self):
        state, parent_id, scene, events = self.current_scene()
        return self._objects(state, parent_id, scene, events)

    def resolve(self, reference):
        if not isinstance(reference, str):
            raise ValueError("object reference must be a string")
        if reference.startswith("investigation:"):
            node_id = reference.removeprefix("investigation:")
            event = self.session.events_by_id().get(node_id)
            if event is None:
                raise ValueError(f"unknown investigation object: {node_id}")
            return {"kind": "investigation", "object": event}
        if reference.startswith("spatial:"):
            _state, _parent_id, scene, _events = self.current_scene()
            prefix = f"spatial:{scene.document['id']}:"
            if not reference.startswith(prefix):
                raise ValueError("spatial object belongs to a stale or unknown scene")
            object_id = reference.removeprefix(prefix)
            try:
                item = scene.object(object_id)
            except KeyError as error:
                raise ValueError(f"unknown spatial object: {object_id}") from error
            return {"kind": "spatial", "object": item, "scene": scene}
        raise ValueError("object reference must use investigation: or spatial:")

    def snapshot(self):
        state, parent_id, scene, events = self.current_scene()
        return {
            "schema_version": 1,
            "environment": "gem",
            "application": "gem-lab",
            "session": str(self.session.root),
            "revision": state["revision"],
            "authoritative": {
                "target": self.session.target,
                "target_kind": self.session.target_kind,
                "selected_id": state["selected_id"],
                "chart_parent": parent_id,
                "events": events,
            },
            "derived": {
                "scene": scene.to_dict(),
                "objects": self._objects(state, parent_id, scene, events),
            },
        }

    def select(self, node_id, expected_revision=None):
        return self.session.select(node_id, expected_revision=expected_revision)

    def begin_selected_work(self, expected_id, expected_revision, note=None):
        return self.session.begin_selected_work(expected_id, expected_revision, note)

    def export_scene(self, scene, parent_id):
        if parent_id not in self.session.events_by_id():
            raise ValueError(f"GEM evidence parent does not exist: {parent_id}")
        path = next_run_directory(self.session.root / "gem-runs", scene)
        run = export_run(scene, path, trajectory=[{
            "sequence": 1,
            "kind": "gem_export",
            "parent_id": parent_id,
            "scene_digest": scene.digest(),
            "outcome": "exported",
        }])
        replayed = replay(path)
        passed = run.passed and replayed.passed and replayed.matches_recorded and bool(scene.constraints)
        relative = path.relative_to(self.session.root).as_posix()
        evidence_id = "evidence:gem:" + scene.digest()[:24]
        note = (
            "Deterministic Spatial IR, VDI-roundtrip, and device-profile checks; not human confirmation "
            f"or investigation coverage.\nRun: {relative}\n{run.scope()}\n"
            f"Replay matches recorded reports: {replayed.matches_recorded}"
        )
        evidence = self.session.emit(
            evidence_id,
            parent_id,
            "evidence",
            "GEM verified investigation geometry" if passed else "GEM geometry export with verification limits",
            "complete_scoped" if passed else "partial",
            "tool",
            relative,
            note,
            run.scope() if passed else None,
        )
        return GemExport(run, replayed, evidence)

    def export_current(self, expected_revision=None):
        state, parent_id, scene, _events = self.current_scene()
        if expected_revision is not None:
            if type(expected_revision) is not int or expected_revision < 1:
                raise ValueError("expected revision must be a positive integer")
            if state["revision"] != expected_revision:
                raise ValueError("stale selection revision; read state again before exporting")
        if not scene.objects:
            raise ValueError("No investigation nodes are available for GEM export")
        return self.export_scene(scene, parent_id)


class GemCommandBroker:
    COMMANDS = {"snapshot", "resolve", "select", "begin_selected_work", "export"}
    FIELDS = {
        "snapshot": {"command"},
        "resolve": {"command", "reference"},
        "select": {"command", "id", "expected_revision"},
        "begin_selected_work": {"command", "expected_id", "expected_revision", "note"},
        "export": {"command", "expected_revision"},
    }

    def __init__(self, host):
        self.host = host

    def execute(self, request):
        if not isinstance(request, dict):
            raise ValueError("GEM command must be an object")
        command = request.get("command")
        if command not in self.COMMANDS:
            raise ValueError(f"unsupported GEM command: {command}")
        unexpected = set(request) - self.FIELDS[command]
        if unexpected:
            raise ValueError(f"unsupported GEM command fields: {', '.join(sorted(unexpected))}")
        if command == "snapshot":
            return self.host.snapshot()
        if command == "resolve":
            return self.host.resolve(request.get("reference"))
        if command == "select":
            return self.host.select(request.get("id"), request.get("expected_revision"))
        if command == "begin_selected_work":
            return self.host.begin_selected_work(
                request.get("expected_id"), request.get("expected_revision"), request.get("note"),
            )
        return self.host.export_current(request.get("expected_revision"))
