import json
from importlib import resources
from pathlib import Path

from .inventory import atomic_write, load_records


def load_summary(output):
    return json.loads((output / "summary.json").read_text(encoding="utf-8"))


def render(output):
    output = output.expanduser().resolve()
    summary = load_summary(output)
    records = list(load_records(output))
    document = {"summary": summary, "artifacts": records}
    embedded = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
    embedded = embedded.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    embedded = embedded.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    template = resources.files("metrix").joinpath("templates/matrix.html").read_text(encoding="utf-8")
    content = template.replace("__METRIX_DATA__", embedded)
    content = content.replace("__GENERATED__", summary["generated_utc"])
    content = content.replace("__ARTIFACT_COUNT__", str(summary["artifacts"]))
    if "__METRIX_DATA__" in content or "__GENERATED__" in content or "__ARTIFACT_COUNT__" in content:
        raise ValueError("HTML template substitution failed")
    destination = output / "matrix.html"
    atomic_write(destination, lambda stream: stream.write(content))
    return destination
