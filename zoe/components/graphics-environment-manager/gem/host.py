from dataclasses import dataclass
import hashlib
import json

from .events import atomic_write
from .landmarks import alignment_document, affine_design, landmark_scene, similarity_procrustes
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


@dataclass(frozen=True)
class LandmarkRun:
    path: object
    report: dict
    evidence: dict
    export: GemExport
    alignment: object


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

    def align_landmarks(self, source, target, allow_reflection=False, parent_id=None):
        import numpy as np

        source = np.asarray(source, dtype=np.float64)
        target = np.asarray(target, dtype=np.float64)
        alignment = similarity_procrustes(source, target, allow_reflection=allow_reflection)
        scene = landmark_scene(source, target, alignment)
        parent_id = parent_id or self.session.current_state()["selected_id"]
        exported = self.export_scene(scene, parent_id)
        design, _ = affine_design(source, target)
        rank = int(np.linalg.matrix_rank(design))
        digest = hashlib.sha256(json.dumps({
            "source": source.tolist(), "target": target.tolist(),
            "allow_reflection": allow_reflection,
            "alignment": alignment_document(alignment),
        }, sort_keys=True).encode("utf-8")).hexdigest()
        report = {
            "schema_version": 1,
            "instrument": "least-squares Procrustes landmark alignment",
            "source": source.tolist(),
            "target": target.tolist(),
            "alignment": alignment_document(alignment),
            "affine_design_rank": rank,
            "affine_unique": rank == 6,
            "run_digest": digest,
            "geometry": {
                "scene_digest": scene.digest(),
                "run": str(exported.run.path),
                "evidence_event_id": exported.evidence["id"],
                "source_vdi_passed": exported.run.passed,
                "replay_passed": exported.replay.passed,
                "replay_matches_recorded": exported.replay.matches_recorded,
            },
            "scope": [
                "The transform is fitted only to the supplied landmark correspondences.",
                "Two pairs cannot uniquely determine a full affine transform; a third non-collinear pair is required.",
                "Exact landmark residuals do not establish whole-shape, anatomical, or semantic correctness.",
            ],
        }
        report_path = exported.run.path / "landmark-report.json"
        atomic_write(report_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        passed = exported.passed and alignment.rms <= 1e-6
        evidence = self.session.emit(
            f"evidence:landmark-procrustes:{digest[:24]}",
            exported.evidence["id"],
            "evidence",
            f"Landmark Procrustes alignment · RMS {alignment.rms:.3g}",
            "complete_scoped" if passed else "partial",
            "tool",
            report_path.relative_to(self.session.root).as_posix(),
            f"Least-squares similarity fit. Scale={alignment.scale:.9f}; det(R)={alignment.determinant:.1f}; RMS={alignment.rms:.6g}.\n"
            f"Geometry replay matches recorded reports: {exported.replay.matches_recorded}.\n"
            f"Affine design rank={rank}/6; underdetermined with two pairs.",
            f"Scoped to {len(source)} landmark pairs and the stated similarity/VDI checks; no whole-shape or unique-affine claim",
        )
        report["landmark_evidence_event_id"] = evidence["id"]
        atomic_write(report_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return LandmarkRun(exported.run.path, report, evidence, exported, alignment)

    def measure_prediction(self, model_dir=None, thresholds=None, predictor=None, actual_token_id=None):
        from .prediction import THRESHOLDS, measure_session

        return measure_session(
            self.session, model_dir=model_dir,
            thresholds=THRESHOLDS if thresholds is None else thresholds,
            predictor=predictor, actual_token_id=actual_token_id,
        )

    def advise_next_action(self, model_dir=None, thresholds=None, predictor=None):
        from .steering import advise_session

        return advise_session(
            self.session, model_dir=model_dir,
            thresholds=thresholds, predictor=predictor,
        )

    def run_equation_tournament(self, model_dir=None, thresholds=None, predictor=None):
        from .tournament import run_tournament

        return run_tournament(
            self.session, model_dir=model_dir,
            thresholds=thresholds, predictor=predictor,
        )

    def review_proposal(self, proposal, measurement, action_id, approve=False):
        import json

        from .cognition import (
            CognitiveGuard, CognitiveResult, bind_forecast, response_summary,
        )
        from .measurement import document_sha256
        from .prediction import PredictionRun, _next_run_directory

        broker = GemCommandBroker(self)
        snapshot = broker.execute({"command": "snapshot"})
        forecast = bind_forecast(
            measurement, snapshot, proposal,
            artifact_path=measurement.get("probability_artifact", ""),
        )
        evidence_id = f"evidence:cognition:{action_id}"
        if evidence_id in self.session.events_by_id():
            result = CognitiveResult("deny", "duplicate_action_id", False, False, [])
        else:
            result = CognitiveGuard(broker, approve=approve).execute(action_id, proposal, forecast)
        digest = document_sha256({
            "action_id": action_id, "forecast": forecast,
            "decision": result.decision, "reason": result.reason,
        })
        path = _next_run_directory(self.session.root / "cognition-runs", digest)
        path.mkdir(parents=True, exist_ok=False)
        report = {
            "schema_version": 1,
            "instrument": "context-bound cognitive action guard",
            "action_id": action_id,
            "proposal": proposal,
            "forecast": forecast,
            "decision": result.decision,
            "reason": result.reason,
            "executed": result.executed,
            "succeeded": result.succeeded,
            "approved": bool(approve),
            "events": result.events,
            "response": response_summary(result.response) if result.response is not None else None,
            "run_digest": digest,
            "scope": [
                "The guard binds one forecast to the exact target, selection, revision, and proposal.",
                "Accessible volume does not authorize execution or establish proposal correctness.",
                "Only snapshot, resolve, begin_selected_work, and export are supported; arbitrary commands are rejected.",
            ],
        }
        report_path = path / "cognition.json"
        atomic_write(report_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        if result.succeeded:
            status = "complete_scoped"
        elif result.decision == "deny":
            status = "rejected"
        elif result.executed:
            status = "blocked"
        else:
            status = "partial"
        evidence = self.session.emit(
            evidence_id,
            snapshot["authoritative"]["selected_id"],
            "evidence",
            f"Cognitive guard · {result.decision}",
            status,
            "tool",
            report_path.relative_to(self.session.root).as_posix(),
            f"Decision: {result.decision}; reason: {result.reason}; executed: {result.executed}; succeeded: {result.succeeded}.",
            "Forecast-bound proposal review with explicit approval and no arbitrary command path; not a correctness or consciousness claim",
        )
        report["evidence_event_id"] = evidence["id"]
        atomic_write(report_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return PredictionRun(path, report, evidence)

    def generate_proposals(self, measurement, count=4, generator=None):
        from .generation import baseline_candidates, generate_and_review

        if generator is None:
            candidates = baseline_candidates(self.snapshot(), count)
            metadata = {"mode": "deterministic-baseline", "prompt": ""}
        else:
            candidates, metadata = generator.generate(self.session, count)
        return generate_and_review(self, measurement, candidates, metadata)


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
