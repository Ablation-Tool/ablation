"""Graphics Environment Manager for unified investigation and spatial execution."""

from .model import Scene, demo_scene, scene_from_events
from .volume import VolumeBridge

__all__ = ["Scene", "demo_scene", "scene_from_events", "VolumeBridge"]
__version__ = "0.1.0"
