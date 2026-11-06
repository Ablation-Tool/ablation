"""Vault-event case view for the CEROTTO GEM workbench."""

from __future__ import annotations

from .model import CaseEvent


def vault_events(events) -> tuple[CaseEvent, ...]:
    return tuple(event for event in events if event.source_tool == "cerotto.vault")


def vault_summary(events) -> dict[str, int]:
    summary = {
        "events": 0,
        "contacts": 0,
        "modifications": 0,
        "denied_releases": 0,
        "health_alerts": 0,
        "responses": 0,
    }
    for event in vault_events(events):
        summary["events"] += 1
        if event.event_type in {"file.open", "file.read"}:
            summary["contacts"] += 1
        elif event.event_type in {"file.modify", "file.delete", "file.delete_self",
                                  "file.moved_from", "file.moved_to", "file.move_self"}:
            summary["modifications"] += 1
        elif event.event_type == "release.denied":
            summary["denied_releases"] += 1
        elif event.event_type in {"sensor.queue_overflow", "sensor.degraded", "sensor.clock_change"}:
            summary["health_alerts"] += 1
        elif event.event_type in {"response.suspended", "response.resumed"}:
            summary["responses"] += 1
    return summary

