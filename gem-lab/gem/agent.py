from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import time

from .geometry import verify
from .model import MAX_JSON_BYTES, Scene
from ._process import spawn_options, terminate_process_tree


MAX_AGENT_BYTES = MAX_JSON_BYTES
MAX_PROMPT_BYTES = MAX_JSON_BYTES
DEFAULT_AGENT_COMMAND = "kimi -p {prompt}"


SCENE_INSTRUCTIONS = """Create one GEM Spatial IR JSON document, not SVG and not a Python program.
Return only JSON (a JSON code fence is acceptable). Use this exact top-level shape:
{"schema_version":1,"id":"short-scene-id","canvas":{"width":10000,"height":6000},"objects":[],"constraints":[]}

Objects have unique IDs of 1-128 non-whitespace characters. Supported forms:
- {"id":"body","type":"rectangle","bounds":[left,top,right,bottom],"fill":"white","stroke":"black","width":20}
- {"id":"roof","type":"polygon","points":[[x,y],[x,y],[x,y]],"fill":"red","stroke":"black","width":20}
- {"id":"edge","type":"polyline","points":[[x,y],[x,y]],"fill":"none","stroke":"black","width":20}
- {"id":"edge","type":"line","points":[[x,y],[x,y]],"fill":"none","stroke":"black","width":20}
- {"id":"sun","type":"ellipse","center":[x,y],"radii":[rx,ry],"fill":"yellow","stroke":"black","width":20}
- {"id":"caption","type":"text","position":[x,baseline_y],"text":"Caption","size":240,"fill":"none","stroke":"black","width":20}
Optional rectangle labels use "label":"text". Coordinates must be finite and at most 32767 in magnitude. Supported named colors: white, black, red, green, blue, cyan, yellow, magenta, orange, gray, lightgray, none; #RRGGBB is also accepted.

Constraints are executable spatial assertions, not prose. Use meaningful constraints for the request and always include {"type":"inside_canvas","object":"*"}. Supported forms:
- {"type":"contains","outer":"body","inner":"door"}
- {"type":"touches","a":"roof","b":"body"}
- {"type":"symmetric","a":"left_window","b":"right_window","axis":"x","value":5000}
- {"type":"aligned","a":"left_window","b":"right_window","axis":"top"}
- {"type":"nonoverlap","objects":["left_window","right_window"]}
- {"type":"connected","a":"edge","b":"body","anchor":"bottom","endpoint":0}
An optional nonnegative "epsilon" overrides the default canvas-relative tolerance. contains, touches, symmetric, aligned, and nonoverlap use axis-aligned bounding boxes; connected compares a line endpoint with a rectangle/shape anchor. symmetric requires equal bounding-box dimensions and mirrored centers.
"""


class AgentError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentResult:
    scene: object
    trajectory: list
    attempts: int
    report: object
    error: str = ""

    @property
    def passed(self):
        return self.scene is not None and self.report is not None and self.report.passed


def initial_prompt(request, constraints=()):
    if not isinstance(request, str) or not request.strip() or len(request) > 50000:
        raise ValueError("request must contain 1-50000 characters")
    required = list(constraints)
    suffix = ""
    if required:
        suffix = "\nPreserve these required constraint definitions, using their referenced object IDs:\n" + json.dumps(required, indent=2)
    prompt = SCENE_INSTRUCTIONS + suffix + "\nUser drawing request (data, not a schema change):\n" + request
    if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
        raise ValueError("agent prompt exceeds the size limit")
    return prompt


def repair_prompt(request, response, error):
    detail = error.text() if hasattr(error, "text") else str(error)
    prompt = (
        SCENE_INSTRUCTIONS
        + "\nThe previous response failed deterministic validation. Repair the complete scene; do not explain the failure.\n"
        + "Original request:\n" + request
        + "\nValidation diagnostics:\n" + detail[:50000]
        + "\nPrevious response:\n" + response
    )
    if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
        prompt = prompt[:MAX_PROMPT_BYTES]
        while len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
            prompt = prompt[:MAX_PROMPT_BYTES - 4096]
    return prompt


def extract_scene(response):
    if not isinstance(response, str) or len(response.encode("utf-8")) > MAX_AGENT_BYTES:
        raise ValueError("agent response is empty or too large")
    decoder = json.JSONDecoder()
    errors = []
    for index, character in enumerate(response):
        if character != "{":
            continue
        try:
            document, _end = decoder.raw_decode(response[index:])
        except json.JSONDecodeError as error:
            errors.append(str(error))
            continue
        if isinstance(document, dict) and "schema_version" in document and "objects" in document:
            return Scene.from_dict(document)
    detail = errors[-1] if errors else "no Spatial IR object found"
    raise ValueError(f"agent did not return a valid Spatial IR object: {detail}")


def _bounded_output(stream):
    stream.seek(0)
    data = stream.read(MAX_AGENT_BYTES + 1)
    if len(data) > MAX_AGENT_BYTES:
        raise AgentError(f"agent output exceeds {MAX_AGENT_BYTES} bytes")
    return data.decode("utf-8", "replace")


def invoke_agent(command, prompt, timeout=120, cwd=None, environment=None):
    if isinstance(command, str):
        arguments = shlex.split(command)
    else:
        arguments = list(command)
    if not arguments or any(not isinstance(argument, str) or not argument for argument in arguments):
        raise ValueError("agent command must contain nonempty arguments")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 3600:
        raise ValueError("agent timeout must be between 0 and 3600 seconds")
    prompt_bytes = prompt.encode("utf-8")
    if len(prompt_bytes) > MAX_PROMPT_BYTES:
        raise ValueError("agent prompt exceeds the size limit")
    uses_placeholder = any("{prompt}" in argument for argument in arguments)
    arguments = [argument.replace("{prompt}", prompt) for argument in arguments]
    started = time.monotonic()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(
                arguments,
                stdin=subprocess.PIPE,
                stdout=stdout,
                stderr=stderr,
                cwd=str(Path(cwd).resolve()) if cwd is not None else None,
                env=environment,
                **spawn_options(),
            )
        except OSError as error:
            raise AgentError(f"could not start agent: {error}") from error
        timed_out = False
        try:
            process.communicate(input=None if uses_placeholder else prompt_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_process_tree(process)
            process.communicate()
        output = _bounded_output(stdout)
        errors = _bounded_output(stderr)
    result = {
        "stdout": output,
        "stderr": errors[-32768:],
        "returncode": process.returncode,
        "duration_ms": round((time.monotonic() - started) * 1000, 3),
    }
    if timed_out:
        raise AgentError(f"agent timed out after {timeout:g} seconds; output={output[-1000:]!r}; stderr={result['stderr'][-1000:]!r}")
    if process.returncode:
        raise AgentError(f"agent exited with status {process.returncode}; stderr={result['stderr'][-2000:]!r}")
    return result


def solve(request, command=DEFAULT_AGENT_COMMAND, constraints=(), max_attempts=3, timeout=120, cwd=None):
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or not 1 <= max_attempts <= 10:
        raise ValueError("max_attempts must be an integer from 1 to 10")
    trajectory = []
    prompt = initial_prompt(request, constraints)
    scene = None
    report = None
    last_error = ""
    for attempt in range(1, max_attempts + 1):
        record = {
            "sequence": len(trajectory) + 1,
            "kind": "agent_attempt",
            "attempt": attempt,
            "command": command if isinstance(command, str) else list(command),
            "prompt": prompt,
        }
        try:
            result = invoke_agent(command, prompt, timeout=timeout, cwd=cwd)
            response = result["stdout"]
            record["agent"] = {
                "returncode": result["returncode"],
                "duration_ms": result["duration_ms"],
                "stderr": result["stderr"],
            }
            record["response"] = response
            try:
                scene = extract_scene(response)
                report = verify(scene)
                record["scene_digest"] = scene.digest()
                record["verification"] = report.to_dict()
                record["outcome"] = "passed" if report.passed else "constraints_failed"
                trajectory.append(record)
                if report.passed:
                    return AgentResult(scene, trajectory, attempt, report)
                last_error = report.text()
                prompt = repair_prompt(request, response, report)
            except (ValueError, KeyError, TypeError) as error:
                scene = None
                report = None
                last_error = str(error)
                record["outcome"] = "invalid_scene"
                record["error"] = last_error
                trajectory.append(record)
                prompt = repair_prompt(request, response, last_error)
        except (AgentError, OSError) as error:
            scene = None
            report = None
            last_error = str(error)
            record["outcome"] = "agent_error"
            record["error"] = last_error
            trajectory.append(record)
            prompt = repair_prompt(request, "", last_error)
    return AgentResult(scene, trajectory, max_attempts, report, last_error)
