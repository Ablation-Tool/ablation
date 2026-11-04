import html
import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from urllib.parse import urlsplit

from .agent import AgentBridge, AgentError
from .inventory import load_records
from .render import load_summary


MAX_CHAT_BYTES = 1024 * 1024
MAX_MESSAGE_CHARACTERS = 8000
MAX_SELECTED = 25
MAX_HISTORY = 12
STATIC = {
    "/app.js": ("gui/app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("gui/style.css", "text/css; charset=utf-8"),
}


def resource(name):
    return resources.files("metrix").joinpath(name).read_bytes()


def validate_chat(document, records_by_id):
    if not isinstance(document, dict) or not isinstance(document.get("message"), str):
        raise ValueError("message must be a string")
    message = document["message"].strip()
    if not message or len(message) > MAX_MESSAGE_CHARACTERS:
        raise ValueError(f"message must contain 1–{MAX_MESSAGE_CHARACTERS} characters")
    selected_ids = document.get("selected_ids", [])
    if not isinstance(selected_ids, list) or len(selected_ids) > MAX_SELECTED or not all(isinstance(value, str) for value in selected_ids):
        raise ValueError(f"selected_ids must contain at most {MAX_SELECTED} strings")
    selected = [records_by_id[value] for value in selected_ids if value in records_by_id]
    filters = document.get("filters", {})
    if not isinstance(filters, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in filters.items()):
        raise ValueError("filters must be a string-to-string object")
    history = document.get("history", [])
    if not isinstance(history, list) or len(history) > MAX_HISTORY:
        raise ValueError(f"history must contain at most {MAX_HISTORY} messages")
    normalized_history = []
    for item in history:
        if not isinstance(item, dict) or item.get("role") not in {"user", "assistant"} or not isinstance(item.get("content"), str):
            raise ValueError("history entries require user/assistant roles and string content")
        normalized_history.append({"role": item["role"], "content": item["content"][:4000]})
    search = document.get("search", "")
    if not isinstance(search, str) or len(search) > 1000:
        raise ValueError("search must be a string of at most 1000 characters")
    filters = {**filters, "search": search}
    return message, selected, filters, normalized_history


class MetrixServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, output, bridge, token):
        self.output = output
        self.summary = load_summary(output)
        self.records = list(load_records(output))
        self.records_by_id = {record["id"]: record for record in self.records}
        self.bridge = bridge
        self.token = token
        super().__init__(address, MetrixHandler)

    @property
    def url(self):
        host, port = self.server_address[:2]
        display = "[::1]" if host == "::1" else host
        return f"http://{display}:{port}/?token={self.token}"


class MetrixHandler(BaseHTTPRequestHandler):
    server_version = "METRIX/0.1"
    sys_version = ""

    def log_message(self, format, *args):
        return

    def authorized_host(self):
        value = self.headers.get("Host", "").strip().casefold()
        host = value.split("]", 1)[0][1:] if value.startswith("[") else value.split(":", 1)[0]
        return host in {"127.0.0.1", "localhost", "::1"}

    def authorized_token(self):
        return secrets.compare_digest(self.headers.get("X-METRIX-Token", ""), self.server.token)

    def send_bytes(self, status, content, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, status, document):
        content = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_bytes(status, content, "application/json; charset=utf-8")

    def guard(self, token=True):
        if not self.authorized_host():
            self.send_json(403, {"error": "Host header is not allowed"})
            return False
        if token and not self.authorized_token():
            self.send_json(401, {"error": "Valid X-METRIX-Token header required"})
            return False
        return True

    def do_GET(self):
        path = urlsplit(self.path).path
        if not self.guard(token=path == "/api/state" or path == "/api/agent"):
            return
        if path == "/":
            template = resources.files("metrix").joinpath("gui/index.html").read_text(encoding="utf-8")
            content = template.replace("__METRIX_TOKEN__", html.escape(self.server.token, quote=True)).encode("utf-8")
            self.send_bytes(200, content, "text/html; charset=utf-8")
            return
        if path in STATIC:
            name, content_type = STATIC[path]
            self.send_bytes(200, resource(name), content_type)
            return
        if path == "/api/state":
            self.send_json(200, {
                "summary": self.server.summary,
                "artifacts": self.server.records,
                "agent": self.server.bridge.public_state(),
            })
            return
        if path == "/api/agent":
            self.send_json(200, self.server.bridge.public_state())
            return
        self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        if not self.guard():
            return
        if path != "/api/chat":
            self.send_json(404, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "Invalid Content-Length"})
            return
        if length < 1 or length > MAX_CHAT_BYTES:
            self.send_json(413, {"error": "Chat request is empty or too large"})
            return
        try:
            document = json.loads(self.rfile.read(length).decode("utf-8"))
            message, selected, filters, history = validate_chat(document, self.server.records_by_id)
            response = self.server.bridge.ask(message, selected, filters, history)
            response["selected_context_count"] = len(selected)
            self.send_json(200, response)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            self.send_json(400, {"error": str(error)})
        except AgentError as error:
            self.send_json(502, {"error": str(error)})
        except (BrokenPipeError, ConnectionResetError):
            return


def create_server(output, host="127.0.0.1", port=0, bridge=None):
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("METRIX GUI only binds to loopback addresses")
    output = Path(output).expanduser().resolve()
    bridge = bridge or AgentBridge(None, output, output)
    return MetrixServer((host, port), output, bridge, secrets.token_urlsafe(32))


def serve(output, host="127.0.0.1", port=0, bridge=None, open_browser=True):
    output = Path(output).expanduser().resolve()
    bridge = bridge or AgentBridge(None, output, output)
    server = create_server(output, host, port, bridge)
    state = bridge.public_state()
    print(json.dumps({"url": server.url, "output": str(server.output), "agent": state}, indent=2), flush=True)
    if open_browser:
        threading.Timer(0.2, lambda: webbrowser.open(server.url)).start()
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
