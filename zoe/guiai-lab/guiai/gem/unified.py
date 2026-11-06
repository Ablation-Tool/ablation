from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import json
import math
import os
from pathlib import Path
import subprocess
import sys

from .field import _fit


IDENTITY = "ZOE is allgems"


@dataclass(frozen=True)
class Component:
    identifier: str
    title: str
    checkout: str
    repository: str
    revision: str | None
    summary: str
    anchor: str
    python_paths: tuple[str, ...]
    module: str
    default_args: tuple[str, ...] = ()
    runtime_checkout: str | None = None
    inspect_only: bool = False


COMPONENTS = (
    Component("zoe", "Zoe native shell", "guiai-lab", "https://github.com/Ablation-Tool/zoe", None, "Cognitive Field, Bayesian memory, geometry, and unified hub", "guiai/gem/cognitive.py", ("",), "guiai.gem", ("zoe", "--module", "unified")),
    Component("ablation", "Ablation core engine", "ablation", "https://github.com/Ablation-Tool/ablation", "b56f91e4c54cfd996bceea63a38d8136dc1e689f", "Complete AIARE framework, analyzers, parsers, modules, and core CLI", "ablation/analyzers/entropy_mapper.py", ("",), "ablation.cli", ("--help",)),
    Component("gem-lab", "Ablation GEM Lab", "ablation", "https://github.com/Ablation-Tool/ablation", "b56f91e4c54cfd996bceea63a38d8136dc1e689f", "Default native investigation GUI and shared Lab evidence protocol", "gem-lab/gem/gtk_app.py", ("gem-lab",), "gem", ("launch", "--no-agent")),
    Component("gem", "Canonical GEM", "graphics-environment-manager", "https://github.com/Ablation-Tool/graphics-environment-manager", "e63f6a7b84c2e8fffc0fcf01001986ae928f66b5", "Native workbench, mirrored brain, geometry, Spatial IR, and VDI", "gem/cli.py", ("",), "gem", ("os",)),
    Component("helen", "GEM HELEN", "gem-helen", "https://github.com/Ablation-Tool/gem-helen", "55fb1e494662e9b69e964ac2f9df41724cffeb0c", "Optimized geometry, rhythm, and forecast laboratory", "helen_gem/core.py", ("",), "helen_gem"),
    Component("brain", "BRAIN GEM", "brain-gem", "https://github.com/Ablation-Tool/brain-gem", "ed819c2824a55b019a532f4fa2cb440532030127", "Standalone Bayesian field notebook and chambered memory", "brain_gem/field.py", ("",), "brain_gem", ("field",)),
    Component("cerotto", "Cerotto GEM", "cerotto", "https://github.com/Ablation-Tool/cerotto", "5e2f0c06f1c9b6f6fe7d2489175ce89e7abb6ec4", "Guarded forensic cases, native C engine, timelines, and vault evidence", "cerotto_gem/cli.py", ("",), "cerotto_gem"),
    Component("research", "Research GEM", "next-token-predictability", "https://github.com/Ablation-Tool/next-token-predictability", "83b89a385aa4e67fb0c1b60ba30a21efcc0e50f9", "Accessible-volume research, evidence packs, and mirrored workbench", "evidence/master-gem/conformance.json", ("",), "gem", ("os",), "graphics-environment-manager"),
    Component("kevlar", "Kevlar MCP firewall", "kevlar", "https://github.com/Ablation-Tool/kevlar", "8ac3e0181e98572d6c41f964385393aa441a5f2a", "MCP proxy firewall, content disarm, policy enforcement, and audit evidence", "kevlar.py", ("",), "kevlar", ("--help",)),
    Component("pdf", "PDF Signature Toolkit", "pdf-signature-toolkit", "https://github.com/Ablation-Tool/pdf-signature-toolkit", "1198165962958c5132130f3854626ff39c333941", "Reproducible source integrity records and detached PDF signatures", "pdf_signature_toolkit/verify.py", ("",), "pdf_signature_toolkit.verify", ("--help",)),
    Component("chalkboard", "Chalkboard library", "Chalkboard", "https://github.com/Ablation-Tool/Chalkboard", "63646eb15737d822316073ba1f2114c608571c72", "Reusable ideas, templates, and prompts for knowledge engineering", "README.md", ("",), "", (), None, True),
)


def _python():
    if os.environ.get("ZOE_PYTHON"):
        return os.environ["ZOE_PYTHON"]
    system = Path("/usr/bin/python3")
    return str(system) if system.is_file() else sys.executable


class ComponentRegistry:
    def __init__(self, root=None):
        self.root = Path(root or os.environ.get("ZOE_ROOT") or Path(__file__).resolve().parents[3]).expanduser().resolve()
        self.components = {component.identifier: component for component in COMPONENTS}
        from .knowledge import KnowledgeField
        self.knowledge = KnowledgeField.source_demo(self.manifest())

    def component(self, identifier):
        if identifier not in self.components:
            raise ValueError(f"unknown unified component: {identifier}")
        return self.components[identifier]

    def source(self, identifier):
        component = self.component(identifier)
        checkout = component.checkout
        bundled = self.root / "components" / checkout
        external = self.root.parent / checkout
        host = Path(os.environ.get("ZOE_ABLATION_ROOT", self.root.parent)).expanduser().resolve()
        if component.identifier == "zoe":
            path = self.root / component.checkout
            mode = "zoe"
        elif (bundled / "README.md").is_file():
            path = bundled
            mode = "bundled"
        elif identifier in {"ablation", "gem-lab"} and (host / component.anchor).is_file():
            path = host
            mode = "host"
        elif (external / "README.md").is_file():
            path = external
            mode = "external"
        else:
            path = bundled
            mode = "missing"
        return {
            "path": path,
            "mode": mode,
            "available": mode != "missing" and (path / component.anchor).is_file(),
        }

    def environment(self, identifier):
        component = self.component(identifier)
        source = self.source("gem" if component.runtime_checkout else identifier)
        if not source["available"]:
            raise ValueError(f"component source is unavailable: {identifier} ({source['path']})")
        paths = [source["path"] / relative for relative in component.python_paths]
        dependencies = os.environ.get("ZOE_PYTHON_DEPENDENCIES", "")
        paths.extend(Path(item) for item in dependencies.split(os.pathsep) if item)
        distribution = Path("/usr/lib/python3/dist-packages")
        if distribution.is_dir():
            paths.append(distribution)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(str(path) for path in paths)
        environment["ZOE_ROOT"] = str(self.root)
        environment["ZOE_COMPONENT_ID"] = identifier
        environment["ZOE_UNIFIED"] = "1"
        research = self.source("research")["path"]
        if research.is_dir():
            environment["MASTER_GEM_RESEARCH_ROOT"] = str(research)
        if identifier == "cerotto":
            environment.setdefault("CEROTTO_BIN", str(source["path"] / "build" / "cerotto"))
        return environment

    def command(self, identifier, arguments=None):
        component = self.component(identifier)
        if arguments is not None and (len(arguments) > 128 or any(not isinstance(item, str) or not item or len(item) > 4096 for item in arguments)):
            raise ValueError("component arguments must contain at most 128 nonempty strings of at most 4096 characters")
        arguments = list(component.default_args if arguments is None else arguments)
        if component.inspect_only:
            raise ValueError(f"{identifier} is a content library; use `zoe show {identifier}` instead of launching a process")
        if identifier == "cerotto" and not arguments:
            raise ValueError("cerotto requires --db, --case, and --conversation; pass them after `--` or use the native case picker")
        source = self.source("gem" if component.runtime_checkout else identifier)
        cwd = source["path"] / component.python_paths[0] if component.python_paths and component.python_paths[0] else source["path"]
        return [_python(), "-m", component.module, *arguments], cwd

    def launch(self, identifier, arguments=None, detach=True):
        command, cwd = self.command(identifier, arguments)
        environment = self.environment(identifier)
        if detach:
            return subprocess.Popen(command, cwd=cwd, env=environment, start_new_session=True)
        return subprocess.run(command, cwd=cwd, env=environment, check=False)

    def manifest(self):
        rows = []
        for component in COMPONENTS:
            source = self.source(component.identifier)
            row = asdict(component)
            row["source"] = {"path": str(source["path"]), "mode": source["mode"], "source_present": source["available"], "runtime_verified": False}
            rows.append(row)
        return {
            "schema_version": 1,
            "identity": IDENTITY,
            "product": "ZOE allgems knowledge-engineering distribution",
            "root": str(self.root),
            "entrypoint_count": len(rows),
            "repository_count": 10,
            "upstream_repository_count": 9,
            "components": rows,
            "knowledge_engineering": {
                "trust_context": "source, repository, revision, evidence scope, and authorization boundary",
                "stability_context": "component-specific processes, version locks, replayable memory, and separately tested behavior; not an uptime guarantee",
            },
            "execution": "explicit component launch only; no process is started by inspecting this manifest",
            "boundaries": "One source distribution and identity; separate processes, dependencies, evidence, and authorization remain distinct.",
        }

    def observe(self, identifier, observation, **context):
        component = self.component(identifier)
        return self.knowledge.observe(
            identifier, observation, repository=component.repository,
            revision=component.revision, **context,
        )

    def record_source(self, identifier):
        row = next(item for item in self.manifest()["components"] if item["identifier"] == identifier)
        return self.knowledge.observe_source(row)

    def write_manifest(self, path):
        path = Path(path)
        if path.suffix.lower() != ".json":
            raise ValueError("unified component manifest must use a .json path")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            json.dump(self.manifest(), stream, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
            stream.write("\n")
        return path


def _rectangle(identifier, bounds, stroke, fill, width=1):
    return {"id": identifier, "type": "rectangle", "bounds": bounds, "stroke": stroke, "fill": fill, "width": width}


def _orbit(identifier, center, radii, angle, color):
    rotation = math.radians(angle)
    points = []
    for index in range(96):
        theta = math.tau * index / 96
        x = radii[0] * math.cos(theta)
        y = radii[1] * math.sin(theta)
        points.append([center[0] + x * math.cos(rotation) - y * math.sin(rotation), center[1] + x * math.sin(rotation) + y * math.cos(rotation)])
    return {"id": identifier, "type": "polygon", "points": points, "stroke": color, "fill": "none", "width": 1.2}


def unified_scene(registry=None, knowledge=None):
    from .atlas import _ellipse, _scene, _text

    registry = registry or ComponentRegistry()
    knowledge = knowledge or registry.knowledge
    manifest = registry.manifest()
    knowledge_state = knowledge.knowledge_state()
    cyan, yellow, pink, green, muted = "#67e8f9", "#fde68a", "#f0abfc", "#86efac", "#9fb1c8"
    colors = [cyan, yellow, pink, green, "#fda4af", "#93c5fd", "#fdba74", "#c4b5fd", "#a7f3d0", "#f9a8d4", "#d9f99d"]
    objects = [_rectangle("background", [0, 0, 1400, 1080], "#080d18", "#080d18")]
    objects.extend([
        _text("title", [40, 51], "ZOE · ALLGEMS", 29, cyan),
        _text("subtitle", [40, 83], "Trust Context / Stability Context", 17, "#e2e8f0"),
        _text("scope", [40, 109], f"{IDENTITY} · full source trees · one replayable knowledge field", 12, muted),
        _text("entrypoints", [45, 178], str(len(COMPONENTS)), 41, cyan),
        _text("entrypoint-label", [121, 175], "registered entrypoints", 15, muted),
        _text("repositories", [45, 222], "9", 32, yellow),
        _text("repository-label", [101, 220], "upstream repositories + Zoe", 14, muted),
        _text("engine", [355, 178], "FULL", 28, pink),
        _text("engine-label", [451, 176], "Ablation core and framework", 14, muted),
        _text("checkout", [355, 218], "ONE", 24, green),
        _text("checkout-label", [427, 216], "checkout · identity · manifest", 14, muted),
    ])
    for index, color in enumerate(colors[:10]):
        objects.append(_orbit(f"identity-orbit-{index}", [1150, 168], [120, 42], index * 18, color))
    objects.append(_ellipse("identity-center", [1150, 168], [43, 30], cyan, "#080d18", 2))
    objects.append(_text("identity-center-label", [1117, 175], "ZOE", 20, "#e2e8f0"))
    objects.append(_text("orbital-caption", [984, 254], "ZOE orbital eye · allgems · original vector interpretation", 11, muted))
    for index, component in enumerate(manifest["components"]):
        x = 40 + (index % 4) * 340
        y = 294 + (index // 4) * 202
        color = colors[index]
        source = component["source"]
        objects.append(_rectangle(f"component-{component['identifier']}", [x, y, x + 300, y + 181], color, "#101b2b", 2))
        objects.append(_ellipse(f"component-icon-{index}", [x + 29, y + 31], [8, 8], color, color))
        objects.append(_text(f"component-title-{index}", [x + 48, y + 37], component["title"], 18, color))
        objects.append(_text(f"component-summary-{index}", [x + 18, y + 72], _fit(component["summary"], 43), 11, "#d8e2ee"))
        objects.append(_text(f"component-summary-2-{index}", [x + 18, y + 91], _fit(component["summary"][43:], 43), 11, "#d8e2ee"))
        command = "show" if component["inspect_only"] else "launch"
        objects.append(_text(f"component-command-{index}", [x + 18, y + 125], f"zoe {command} {component['identifier']}", 12, muted))
        status = "source present" if source["source_present"] else "source unavailable"
        objects.append(_text(f"component-status-{index}", [x + 18, y + 151], f"{source['mode']} · {status}", 11, green if source["source_present"] else "#fdba74"))
        objects.append(_text(f"component-revision-{index}", [x + 18, y + 170], f"upstream {component['revision'][:12] if component['revision'] else 'Zoe baseline'}", 9, "#64748b"))
    objects.extend([
        _rectangle("knowledge-card", [1060, 698, 1360, 879], cyan, "#101b2b", 2),
        _text("knowledge-card-title", [1078, 735], "Shared knowledge field", 18, cyan),
        _text("knowledge-observations", [1078, 776], f"{knowledge_state['observation_count']} source observations", 13, "#e2e8f0"),
        _text("knowledge-links", [1078, 801], f"{knowledge_state['link_count']} declared context links", 13, "#e2e8f0"),
        _text("knowledge-hash", [1078, 827], f"SHA-256 {(knowledge.events[-1]['hash'][:24] if knowledge.events else 'empty')}", 10, yellow),
        _text("knowledge-scope", [1078, 852], "links do not transfer evidence", 11, muted),
        _text("knowledge-scope-2", [1078, 870], "or permission · executed=False", 11, green),
        _rectangle("unified-memory", [40, 915, 1360, 1048], "#475569", "#0e1828"),
    ])
    for index, symbol in enumerate(("G", "E", "M")):
        x = 62 + index * 50
        objects.append(_rectangle(f"symbol-cell-{index}", [x, 939, x + 48, 985], muted, "none"))
        objects.append(_text(f"symbol-{index}", [x + 16, 970], symbol, 20, colors[index]))
    objects.extend([
        _text("symbol-caption", [62, 1011], "source / trust / stability", 11, muted),
        _text("symbol-note", [62, 1033], "original symbol-grid references", 9, "#64748b"),
        _text("memory-title", [390, 949], "TEN REPOSITORIES · ONE KNOWLEDGE FIELD", 14, yellow),
        _text("memory-scope", [390, 980], "Source context is inspectable; observation does not transfer evidence or permission.", 12, "#fda4af"),
        _text("memory-detail", [390, 1006], "Trust: repository + revision + scope · Stability: process + replay + tests", 11, muted),
        _text("memory-boundary", [390, 1032], "No implicit agent launch · no runtime claim from source presence · executed=False", 11, green),
    ])
    scene = _scene("zoe-allgems", 1400, 1080, objects, IDENTITY)
    report = deepcopy(manifest)
    present = sum(row["source"]["source_present"] for row in manifest["components"])
    report.update({
        "summary": f"{present}/{len(COMPONENTS)} entrypoint sources present · {knowledge_state['observation_count']} observations · {knowledge_state['link_count']} context links · no process launched by this scene",
        "memory": knowledge.document(),
        "knowledge": knowledge_state,
        "scene_only": True,
        "executed": False,
        "recommended_module": "unified",
    })
    return scene, report
