"""Geometric Environment Manager for executable agent-generated scenes."""

from .model import Scene, demo_scene, scene_from_events
from .volume import VolumeBridge, accessible_volume

__all__ = ["Scene", "demo_scene", "scene_from_events", "VolumeBridge", "accessible_volume"]
__version__ = "0.1.0"
