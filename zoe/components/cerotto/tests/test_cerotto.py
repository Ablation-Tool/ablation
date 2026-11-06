#!/usr/bin/env python3
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("CEROTTO_BIN", ROOT / "build/cerotto")).resolve()
EPOCH = 1793102400


def audit_lines():
    return [
        'node=agent-vm-1 type=SYSCALL arch=c000003e syscall=59 success=yes exit=0 ppid=100 pid=420 auid=1000 uid=1000 exe=2F62696E2F7368 msg=audit(1793102402.002:100):',
        'type=SYSCALL arch=c000003e syscall=257 success=yes exit=3 ppid=100 pid=420 auid=1000 uid=1000 exe="/bin/sh" msg=audit(1793102403.003:101):',
        'type=EXECVE msg=audit(1793102402.002:100): argc=2 a0=2F62696E2F7368 a1=2F746D702F6A6F622E7368',
        'type=PATH msg=audit(1793102403.003:101): item=0 name="/etc/canary secret" inode=123 nametype=NORMAL',
        'type=SYSCALL arch=c000003e syscall=42 success=yes exit=0 ppid=100 pid=420 auid=1000 uid=1000 exe="/bin/sh" msg=audit(1793102404.004:102):',
        'type=SOCKADDR msg=audit(1793102404.004:102): saddr="inet host:192.0.2.10 serv:443"',
        'type=SYSCALL arch=c000003e syscall=257 success=yes exit=4 ppid=100 pid=420 auid=1000 uid=1000 exe="/bin/sh" msg=audit(1793102403.500:103):',
        'type=PATH msg=audit(1793102403.500:103): item=0 name=2F746D702F6A6F622E7368 inode=124 nametype=CREATE',
        'type=SYSCALL arch=c000003e syscall=87 success=yes exit=0 ppid=100 pid=420 auid=1000 uid=1000 exe="/bin/sh" msg=audit(1793102404.500:104):',
        'type=PATH msg=audit(1793102404.500:104): item=0 name="/tmp/job.sh" inode=124 nametype=DELETE',
    ]


def agent_events():
    return [
        {"id": "evt-prompt", "observed_at": "2026-10-27T12:00:00Z", "host_id": "agent-vm-1", "source_tool": "agent_gateway", "event_type": "prompt", "conversation_id": "conv-7", "prompt_id": "prompt-9", "details": {"prompt": "CANARY_SECRET_DO_NOT_SEND"}},
        {"id": "evt-tool", "observed_at": "2026-10-27T12:00:01Z", "host_id": "agent-vm-1", "source_tool": "agent_gateway", "event_type": "tool_call", "conversation_id": "conv-7", "prompt_id": "prompt-9", "tool_call_id": "call-3", "process_id": 420, "parent_process_id": 100, "path": "/tmp/job.sh"},
        {"id": "evt-from", "observed_at": "2026-10-27T11:59:00Z", "host_id": "agent-vm-1", "source_tool": "agent_gateway", "event_type": "conversation_started", "conversation_id": "conv-7"},
        {"id": "evt-to", "observed_at": "2026-10-27T12:05:00Z", "host_id": "agent-vm-1", "source_tool": "agent_gateway", "event_type": "conversation_closed", "conversation_id": "conv-7"},
        {"id": "evt-other", "observed_at": "2026-10-27T12:00:03Z", "host_id": "agent-vm-2", "source_tool": "agent_gateway", "event_type": "prompt", "conversation_id": "other"},
    ]


class MockLLM:
    def __init__(self, modes, observation_ids=None):
        self.modes = list(modes)
        self.observation_ids = observation_ids
        self.requests = []
        self.lock = threading.Lock()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length))
                with outer.lock:
                    index = len(outer.requests)
                    outer.requests.append({"path": self.path, "payload": payload, "authorization": self.headers.get("Authorization")})
                    mode = outer.modes[min(index, len(outer.modes) - 1)]
                if mode == "error":
                    body = b'{"error":"controlled failure"}'
                    self.send_response(500)
                else:
                    timeline = json.loads(payload["messages"][1]["content"].split("\n", 1)[1])
                    available = [event["event_id"] for event in timeline["events"]]
                    if outer.observation_ids:
                        cited = [event_id for event_id in outer.observation_ids if event_id in available]
                    else:
                        cited = ["evt-tool"] if "evt-tool" in available else available[:1]
                    if mode == "invalid":
                        cited = ["invented-event"]
                    report = {
                        "summary": "Observed events are summarized without asserting causation.",
                        "observations": [{"description": "The supplied evidence contains the recorded activity.", "event_ids": cited}],
                        "hypotheses": [{"description": "The sequence may be related, but attribution and causation require verification.", "confidence": "low", "event_ids": cited}],
                        "limitations": ["Timing and correlation identifiers do not independently prove causation."],
                    }
                    body = json.dumps({"choices": [{"message": {"content": json.dumps(report)}}]}).encode()
                    self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}/v1"


class CerottoTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cerotto-test-")
        self.root = Path(self.temporary.name)
        self.db_path = self.root / "case.db"
        self.addCleanup(self.temporary.cleanup)
        self.assertTrue(BINARY.is_file(), f"missing CEROTTO binary: {BINARY}")

    def cli(self, *args, expected=0, env=None, timeout=20):
        command_env = os.environ.copy()
        command_env.pop("CEROTTO_BASE_URL", None)
        command_env.pop("CEROTTO_MODEL", None)
        command_env.pop("CEROTTO_API_KEY", None)
        if env:
            command_env.update(env)
        result = subprocess.run(
            [str(BINARY), *map(str, args)],
            cwd=self.root,
            env=command_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
        )
        if result.returncode != expected:
            self.fail(f"command returned {result.returncode}, expected {expected}: {args}\nstdout={result.stdout}\nstderr={result.stderr}")
        return result

    def database(self):
        connection = sqlite3.connect(self.db_path)
        self.addCleanup(connection.close)
        return connection

    def write_jsonl(self, name, events):
        path = self.root / name
        path.write_text("".join(json.dumps(event) + "\n" for event in events))
        return path

    def ingest_agents(self, events=None):
        source = self.write_jsonl("events.jsonl", events or agent_events())
        self.cli("ingest", "--db", self.db_path, "--case", "incident-7", "--input", source)
        return source

    def ingest_audit(self, lines=None, name="audit.log"):
        source = self.root / name
        source.write_text("\n".join(lines or audit_lines()) + "\n")
        self.cli("ingest-audit", "--db", self.db_path, "--case", "incident-7", "--input", source, "--host", "agent-vm-1")
        return source

    def timeline(self, *extra):
        output = self.root / "timeline.json"
        self.cli("timeline", "--db", self.db_path, "--case", "incident-7", "--conversation", "conv-7", "--from", "2026-10-27T11:59:00Z", "--to", "2026-10-27T12:05:00Z", "--output", output, *extra)
        return json.loads(output.read_text())

    def llm_environment(self, server):
        return {"CEROTTO_BASE_URL": server.base_url, "CEROTTO_MODEL": "local-mock", "CEROTTO_API_KEY": "local-test-key"}

    def analyze(self, server, expected=0):
        output = self.root / f"analysis-{len(server.requests)}.json"
        args = ("analyze", "--db", self.db_path, "--case", "incident-7", "--conversation", "conv-7", "--from", "2026-10-27T11:59:00Z", "--to", "2026-10-27T12:05:00Z", "--output", output)
        result = self.cli(*args, expected=expected, env=self.llm_environment(server), timeout=30)
        return output, result

    def make_image(self):
        image_root = self.root / "image-root"
        image_root.mkdir()
        (image_root / "allocated.txt").write_text("allocated evidence\n")
        (image_root / "deleted.txt").write_text("deleted evidence\n")
        os.utime(image_root / "allocated.txt", (EPOCH + 3, EPOCH + 3))
        os.utime(image_root / "deleted.txt", (EPOCH + 3, EPOCH + 3))
        image = self.root / "agent-disk.img"
        subprocess.run(["mke2fs", "-t", "ext2", "-F", "-q", "-d", str(image_root), str(image), "16M"], check=True, capture_output=True)
        subprocess.run(["debugfs", "-w", "-R", "rm /deleted.txt", str(image)], check=True, capture_output=True)
        return image

    def make_ewf(self, image):
        subprocess.run(["ewfacquire", "-u", "-q", "-d", "sha256", "-S", "1048576", "-t", str(self.root / "evidence"), str(image)], check=True, capture_output=True)
        return self.root / "evidence.E01"

    def collect_tsk(self, image, output_name="collected", env=None):
        output = self.root / output_name
        output.mkdir()
        before = hashlib.sha256(image.read_bytes()).hexdigest()
        self.cli("collect-tsk", "--db", self.db_path, "--case", "incident-7", "--image", image, "--output", output, "--host", "agent-vm-1", env=env)
        self.assertEqual(before, hashlib.sha256(image.read_bytes()).hexdigest())
        return output

    def collect_ewf(self, image, output_name="ewf-collected", expected=0, env=None):
        output = self.root / output_name
        output.mkdir()
        self.cli("collect-ewf", "--db", self.db_path, "--case", "incident-7", "--image", image, "--output", output, "--host", "agent-vm-1", expected=expected, env=env, timeout=60)
        return output

    def make_carve_image(self):
        png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=')
        gif = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'
        image = self.root / "carve-source.img"
        image.write_bytes(b'prefix' + png + b'middle' + gif + b'suffix')
        return image

    def collect_carve(self, image, output_name="recovered", carver="foremost", expected=0, env=None):
        output = self.root / output_name
        before = hashlib.sha256(image.read_bytes()).hexdigest()
        self.cli("carve", "--db", self.db_path, "--case", "incident-7", "--image", image, "--output", output, "--host", "agent-vm-1", "--carver", carver, expected=expected, env=env, timeout=60)
        self.assertEqual(before, hashlib.sha256(image.read_bytes()).hexdigest())
        return output

    def fake_scalpel(self):
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        fake = fake_bin / "scalpel"
        fake.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
if '-V' in sys.argv:
    print('scalpel test')
    raise SystemExit(0)
out = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])
out.mkdir()
(out / 'audit.txt').write_text('controlled audit')
(out.parent / f'{out.name}-args.json').write_text(json.dumps(sys.argv[1:]))
mode = os.environ.get('CARVER_MODE', 'normal')
if mode == 'normal':
    (out / 'nested').mkdir()
    (out / 'nested/artifact.bin').write_bytes(b'ARTIFACT_CONTENT_MUST_NOT_LEAK\\x00\\x01\\x02')
elif mode == 'symlink':
    (out / 'link').symlink_to(sys.argv[-1])
elif mode == 'many':
    for index in range(10001):
        (out / f'{index}.bin').write_bytes(b'')
elif mode == 'failed':
    raise SystemExit(1)
""")
        fake.chmod(0o755)
        return fake_bin

    def test_jsonl_parent_rollback_duplicates_and_ranges(self):
        self.cli("init", "--db", self.db_path)
        self.ingest_agents()
        connection = self.database()
        self.assertEqual(connection.execute("select count(*) from events").fetchone()[0], 5)
        self.ingest_agents_result = self.cli("ingest", "--db", self.db_path, "--case", "incident-7", "--input", self.root / "events.jsonl", expected=1)
        bad = self.root / "bad.jsonl"
        bad.write_text(json.dumps({**agent_events()[0], "id": "evt-rollback"}) + "\n{invalid}\n")
        self.cli("ingest", "--db", self.db_path, "--case", "incident-7", "--input", bad, expected=1)
        self.assertEqual(connection.execute("select count(*) from events").fetchone()[0], 5)
        self.assertEqual(connection.execute("select count(*) from evidence_sources where status='failed'").fetchone()[0], 2)
        timeline = self.timeline()
        ids = [event["event_id"] for event in timeline["events"]]
        self.assertIn("evt-from", ids)
        self.assertNotIn("evt-to", ids)
        self.assertNotIn("evt-other", ids)
        tool = next(event for event in timeline["events"] if event["event_id"] == "evt-tool")
        self.assertEqual((tool["process_id"], tool["parent_process_id"]), (420, 100))
        self.assertTrue(all("details" not in event for event in timeline["events"]))
        detailed = self.timeline("--include-details")
        prompt = next(event for event in detailed["events"] if event["event_id"] == "evt-prompt")
        self.assertEqual(prompt["details"]["prompt"], "CANARY_SECRET_DO_NOT_SEND")

    def test_schema_v1_migration_and_newer_rejection(self):
        connection = sqlite3.connect(self.db_path)
        connection.executescript("""
            PRAGMA user_version=1;
            CREATE TABLE cases(id TEXT PRIMARY KEY, created_at TEXT NOT NULL);
            CREATE TABLE evidence_sources(id INTEGER PRIMARY KEY, case_id TEXT NOT NULL, kind TEXT NOT NULL, origin_path TEXT NOT NULL, stored_path TEXT NOT NULL DEFAULT '', sha256 TEXT NOT NULL DEFAULT '', size_bytes INTEGER NOT NULL DEFAULT 0, tool_name TEXT NOT NULL DEFAULT '', tool_version TEXT NOT NULL DEFAULT '', command_json TEXT NOT NULL DEFAULT '[]', acquired_at TEXT NOT NULL, status TEXT NOT NULL, raw_sha256 TEXT NOT NULL DEFAULT '');
            CREATE TABLE events(id TEXT PRIMARY KEY, case_id TEXT NOT NULL, source_id INTEGER, observed_at TEXT NOT NULL, host_id TEXT NOT NULL, source_tool TEXT NOT NULL, event_type TEXT NOT NULL, conversation_id TEXT NOT NULL DEFAULT '', prompt_id TEXT NOT NULL DEFAULT '', tool_call_id TEXT NOT NULL DEFAULT '', process_id INTEGER, path TEXT NOT NULL DEFAULT '', deleted INTEGER, details_json TEXT NOT NULL DEFAULT '{}');
            INSERT INTO cases VALUES('incident-7','2026-10-27T00:00:00Z');
            INSERT INTO events(id,case_id,observed_at,host_id,source_tool,event_type,conversation_id) VALUES('legacy','incident-7','2026-10-27T12:00:00.000000Z','agent-vm-1','legacy','prompt','conv-7');
        """)
        connection.commit()
        connection.close()
        self.cli("init", "--db", self.db_path)
        connection = self.database()
        self.assertEqual(connection.execute("pragma user_version").fetchone()[0], 2)
        self.assertIsNone(connection.execute("select parent_process_id from events where id='legacy'").fetchone()[0])
        connection.execute("pragma user_version=99")
        connection.commit()
        self.cli("init", "--db", self.db_path, expected=1)

    def test_audit_interleaved_decoding_and_transaction_rollback(self):
        self.cli("init", "--db", self.db_path)
        source = self.ingest_audit()
        connection = self.database()
        rows = connection.execute("select event_type,process_id,parent_process_id,path,observed_at,host_id,details_json from events order by observed_at,id").fetchall()
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0][:6], ("process_started", 420, 100, "/bin/sh", "2026-10-27T12:00:02.002000Z", "agent-vm-1"))
        self.assertEqual(json.loads(rows[0][6])["arguments"], ["/bin/sh", "/tmp/job.sh"])
        by_type = {row[0]: row for row in rows}
        self.assertEqual(by_type["file_access"][3], "/etc/canary secret")
        self.assertEqual(by_type["file_created"][3], "/tmp/job.sh")
        self.assertEqual(by_type["file_deleted"][3], "/tmp/job.sh")
        self.assertIn("192.0.2.10", by_type["network_connection"][3])
        self.cli("ingest-audit", "--db", self.db_path, "--case", "incident-7", "--input", source, "--host", "agent-vm-1", expected=1)
        malformed = audit_lines() + ['type=SYSCALL arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=2 auid=0 uid=0 exe="/bin/true" msg=audit(1793102406.006:999):']
        bad = self.root / "bad-audit.log"
        bad.write_text("\n".join(malformed) + "\n")
        self.cli("ingest-audit", "--db", self.db_path, "--case", "incident-7", "--input", bad, "--host", "agent-vm-1", expected=1)
        self.assertEqual(connection.execute("select count(*) from events").fetchone()[0], 5)
        self.assertEqual(connection.execute("select count(*) from evidence_sources where status='failed'").fetchone()[0], 2)

    @unittest.skipUnless(shutil.which("mke2fs") and shutil.which("debugfs") and shutil.which("fls"), "TSK image tools unavailable")
    def test_real_tsk_allocated_deleted_and_provenance(self):
        self.cli("init", "--db", self.db_path)
        output = self.collect_tsk(self.make_image())
        connection = self.database()
        source = connection.execute("select id,sha256,raw_sha256,command_json from evidence_sources where kind='tsk_fls_body'").fetchone()
        self.assertEqual(source[2], hashlib.sha256((output / "fls.body").read_bytes()).hexdigest())
        commands = json.loads(source[3])
        self.assertEqual(commands["allocated"][:4], ["fls", "-i", "raw", "-r"])
        self.assertEqual(commands["deleted"][:6], ["fls", "-i", "raw", "-r", "-d", "-m"])
        rows = connection.execute("select path,deleted,observed_at from events where source_id=?", (source[0],)).fetchall()
        deleted = next(row for row in rows if row[0] == "/deleted.txt")
        self.assertEqual(deleted[1], 1)
        self.assertNotIn("(deleted)", deleted[0])
        allocated = next(row for row in rows if row[0] == "/allocated.txt")
        self.assertEqual(allocated[2], "2026-10-27T12:00:03.000000Z")

    def test_subprocess_stdout_stderr_regression(self):
        self.cli("init", "--db", self.db_path)
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        fake = fake_bin / "fls"
        fake.write_text("""#!/usr/bin/env python3
import sys
if '-V' in sys.argv:
    sys.stderr.write('v' * 16384)
    print('The Sleuth Kit ver test')
elif '-d' in sys.argv:
    sys.stderr.write('e' * 32768)
    print('0|/deleted.txt (deleted)|13|r/rrw-rw-r--|1000|1000|17|1793102403|1793102403|1793102403|0')
else:
    sys.stderr.write('o' * 32768)
    print('0|/allocated.txt|12|r/rrw-rw-r--|1000|1000|18|1793102403|1793102403|1793102403|0')
""")
        fake.chmod(0o755)
        image = self.root / "image.raw"
        image.write_bytes(b"controlled fake image")
        env = {"PATH": f"{fake_bin}:{os.environ['PATH']}"}
        self.collect_tsk(image, env=env)
        connection = self.database()
        self.assertEqual(connection.execute("select count(*) from events where source_tool like 'tsk_fls%'").fetchone()[0], 2)

    def test_llm_redaction_citation_validation_and_transport_error(self):
        self.cli("init", "--db", self.db_path)
        self.ingest_agents()
        with MockLLM(["valid", "invalid", "error"]) as server:
            output, _ = self.analyze(server)
            report = json.loads(output.read_text())
            self.assertEqual(report["analysis"]["observations"][0]["event_ids"], ["evt-tool"])
            self.analyze(server, expected=1)
            self.analyze(server, expected=1)
        self.assertEqual(len(server.requests), 3)
        serialized = json.dumps(server.requests[0]["payload"])
        self.assertNotIn("CANARY_SECRET_DO_NOT_SEND", serialized)
        self.assertEqual(server.requests[0]["authorization"], "Bearer local-test-key")
        self.assertTrue(all(request["path"] == "/v1/chat/completions" for request in server.requests))

    @unittest.skipUnless(shutil.which("mke2fs") and shutil.which("debugfs") and shutil.which("fls") and shutil.which("ewfacquire") and shutil.which("ewfinfo") and shutil.which("ewfverify"), "EWF tools unavailable")
    def test_real_ewf_manifest_verification_and_mismatch(self):
        self.cli("init", "--db", self.db_path)
        self.ingest_agents()
        image = self.make_image()
        ewf = self.make_ewf(image)
        first_hash = hashlib.sha256(ewf.read_bytes()).hexdigest()
        output = self.collect_ewf(ewf)
        self.assertEqual(first_hash, hashlib.sha256(ewf.read_bytes()).hexdigest())
        connection = self.database()
        self.assertGreaterEqual(connection.execute("select count(*) from evidence_sources where kind='ewf_segment'").fetchone()[0], 1)
        self.assertEqual(connection.execute("select count(*) from events where path='/deleted.txt' and deleted=1").fetchone()[0], 1)
        command = json.loads(connection.execute("select command_json from evidence_sources where kind='tsk_fls_body'").fetchone()[0])
        self.assertEqual(command["allocated"][:3], ["fls", "-i", "ewf"])
        self.assertTrue((output / "ewfinfo.txt").is_file())
        self.assertTrue((output / "ewfverify.txt").is_file())
        first = self.root / "manifest-first.json"
        second = self.root / "manifest-second.json"
        self.cli("manifest", "--db", self.db_path, "--case", "incident-7", "--output", first)
        self.cli("manifest", "--db", self.db_path, "--case", "incident-7", "--output", second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        manifest = json.loads(first.read_text())
        self.assertGreaterEqual(len(manifest["sources"]), 5)
        verified = self.root / "verified.json"
        self.cli("verify", "--db", self.db_path, "--case", "incident-7", "--output", verified)
        self.assertTrue(json.loads(verified.read_text())["verified"])
        second_segment = self.root / "evidence.E02"
        original = second_segment.read_bytes()
        second_segment.write_bytes(original + b"corruption")
        self.cli("verify", "--db", self.db_path, "--case", "incident-7", "--output", verified, expected=1)
        self.assertIn("mismatch", {check["status"] for check in json.loads(verified.read_text())["checks"]})
        second_segment.write_bytes(original)
        second_segment.rename(self.root / "evidence.E02.missing")
        self.cli("verify", "--db", self.db_path, "--case", "incident-7", "--output", verified, expected=1)
        self.assertIn("missing", {check["status"] for check in json.loads(verified.read_text())["checks"]})

    def test_failed_ewf_verification_never_runs_tsk(self):
        self.cli("init", "--db", self.db_path)
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        marker = self.root / "fls-called"
        (fake_bin / "ewfinfo").write_text("#!/bin/sh\n[ \"$1\" = \"-V\" ] && echo 'ewfinfo test' || echo 'metadata'\n")
        (fake_bin / "ewfverify").write_text("#!/bin/sh\nif [ \"$1\" = \"-V\" ]; then echo 'ewfverify test'; else echo 'verification failed' >&2; exit 1; fi\n")
        (fake_bin / "fls").write_text(f"#!/bin/sh\ntouch {marker}\n")
        for tool in fake_bin.iterdir():
            tool.chmod(0o755)
        image = self.root / "evidence.E01"
        image.write_bytes(b"not valid EWF")
        output = self.collect_ewf(image, expected=1, env={"PATH": f"{fake_bin}:{os.environ['PATH']}"})
        self.assertFalse(marker.exists())
        self.assertFalse((output / "fls.body").exists())
        connection = self.database()
        self.assertEqual(connection.execute("select count(*) from events").fetchone()[0], 0)
        self.assertEqual(connection.execute("select status from evidence_sources where kind='ewf_image'").fetchone()[0], "failed")
        self.assertTrue((output / "ewfverify.txt").is_file())

    def test_report_revalidation_review_and_markdown_escaping(self):
        self.cli("init", "--db", self.db_path)
        events = agent_events()
        events[1]["path"] = "/tmp/<script>alert(1)</script>|payload.sh"
        self.ingest_agents(events)
        with MockLLM(["valid"]) as server:
            analysis, _ = self.analyze(server)
        common = ("--db", self.db_path, "--case", "incident-7", "--conversation", "conv-7", "--from", "2026-10-27T11:59:00Z", "--to", "2026-10-27T12:05:00Z", "--analysis", analysis)
        json_report = self.root / "report.json"
        self.cli("report", *common, "--format", "json", "--output", json_report, "--reviewer", "Incident Reviewer", "--review-status", "reviewed")
        parsed = json.loads(json_report.read_text())
        self.assertEqual(parsed["review"]["status"], "reviewed")
        self.assertEqual(parsed["review"]["reviewer"], "Incident Reviewer")
        markdown_report = self.root / "report.md"
        self.cli("report", *common, "--format", "markdown", "--output", markdown_report, "--reviewer", "Incident Reviewer", "--review-status", "approved")
        rendered = markdown_report.read_text()
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("&#124;", rendered)
        self.assertIn("Incident Reviewer", rendered)
        tampered = self.root / "tampered-analysis.json"
        document = json.loads(analysis.read_text())
        document["analysis"]["observations"][0]["event_ids"] = ["invented-event"]
        tampered.write_text(json.dumps(document))
        self.cli("report", "--db", self.db_path, "--case", "incident-7", "--conversation", "conv-7", "--from", "2026-10-27T11:59:00Z", "--to", "2026-10-27T12:05:00Z", "--analysis", tampered, "--format", "json", expected=1)
        self.cli("report", *common, "--format", "json", "--review-status", "approved", expected=1)

    @unittest.skipUnless(shutil.which("foremost"), "Foremost unavailable")
    def test_foremost_carve_manifest_and_artifact_inspection(self):
        self.cli("init", "--db", self.db_path)
        self.ingest_agents()
        image = self.make_carve_image()
        output = self.collect_carve(image)
        connection = self.database()
        artifacts = connection.execute("select id,stored_path,raw_sha256 from evidence_sources where kind='carved_artifact'").fetchall()
        self.assertEqual(len(artifacts), 2)
        self.assertEqual(connection.execute("select count(*) from events where event_type='evidence_recovered'").fetchone()[0], 2)
        verified = self.root / "verify.json"
        self.cli("verify", "--db", self.db_path, "--case", "incident-7", "--output", verified)
        self.assertTrue(json.loads(verified.read_text())["verified"])
        artifact_id, path, expected_hash = artifacts[0]
        shown = self.root / "artifact.json"
        self.cli("artifact", "show", "--db", self.db_path, "--case", "incident-7", "--source-id", artifact_id, "--format", "json", "--max-bytes", 16, "--output", shown)
        document = json.loads(shown.read_text())
        content = Path(path).read_bytes()
        self.assertEqual(base64.b64decode(document["data"]), content[:16])
        self.assertEqual(document["sha256"], expected_hash)
        self.assertEqual(document["size_bytes"], len(content))
        self.assertTrue(document["truncated"])
        hexadecimal = self.cli("artifact", "show", "--db", self.db_path, "--case", "incident-7", "--source-id", artifact_id, "--max-bytes", 16).stdout
        self.assertIn("# truncated=true", hexadecimal)
        self.assertIn("00000000", hexadecimal)
        run_id = connection.execute("select id from evidence_sources where kind='carver_run'").fetchone()[0]
        self.cli("artifact", "show", "--db", self.db_path, "--case", "incident-7", "--source-id", run_id, expected=1)
        self.cli("artifact", "show", "--db", self.db_path, "--case", "other-case", "--source-id", artifact_id, expected=1)
        Path(path).write_bytes(content + b"tampered")
        self.cli("artifact", "show", "--db", self.db_path, "--case", "incident-7", "--source-id", artifact_id, expected=1)
        self.cli("verify", "--db", self.db_path, "--case", "incident-7", "--output", verified, expected=1)
        Path(path).write_bytes(content)
        Path(path).rename(str(path) + ".missing")
        self.cli("artifact", "show", "--db", self.db_path, "--case", "incident-7", "--source-id", artifact_id, expected=1)

    def test_scalpel_catalog_existing_output_and_llm_boundary(self):
        self.cli("init", "--db", self.db_path)
        self.ingest_agents()
        image = self.make_carve_image()
        fake_bin = self.fake_scalpel()
        env = {"PATH": f"{fake_bin}:{os.environ['PATH']}"}
        output = self.collect_carve(image, carver="scalpel", env=env)
        arguments = json.loads((self.root / f"{output.name}-args.json").read_text())
        self.assertEqual(arguments[:3], ["-b", "-o", str(output)])
        self.assertEqual(arguments[-1], str(image))
        connection = self.database()
        artifact_id, path = connection.execute("select id,stored_path from evidence_sources where kind='carved_artifact'").fetchone()
        shown = self.root / "artifact.json"
        self.cli("artifact", "show", "--db", self.db_path, "--case", "incident-7", "--source-id", artifact_id, "--format", "json", "--max-bytes", 8, "--output", shown)
        document = json.loads(shown.read_text())
        self.assertEqual(base64.b64decode(document["data"]), b"ARTIFACT")
        self.assertTrue(document["truncated"])
        with MockLLM(["valid"]) as server:
            self.analyze(server)
        self.assertNotIn("ARTIFACT_CONTENT_MUST_NOT_LEAK", json.dumps(server.requests[0]["payload"]))
        self.collect_carve(image, carver="scalpel", expected=1, env=env)
        self.assertEqual(connection.execute("select count(*) from evidence_sources where kind='carved_artifact'").fetchone()[0], 1)
        self.cli("artifact", "show", "--db", self.db_path, "--case", "incident-7", "--source-id", artifact_id, "--max-bytes", 1048577, expected=2)

    def test_carver_symlink_and_catalog_limit_rollback(self):
        self.cli("init", "--db", self.db_path)
        image = self.make_carve_image()
        fake_bin = self.fake_scalpel()
        env = {"PATH": f"{fake_bin}:{os.environ['PATH']}", "CARVER_MODE": "symlink"}
        self.collect_carve(image, output_name="symlink-output", carver="scalpel", expected=1, env=env)
        connection = self.database()
        self.assertEqual(connection.execute("select count(*) from evidence_sources").fetchone()[0], 0)
        env["CARVER_MODE"] = "many"
        self.collect_carve(image, output_name="many-output", carver="scalpel", expected=1, env=env)
        self.assertEqual(connection.execute("select count(*) from evidence_sources").fetchone()[0], 0)

    def test_carver_zero_file_and_failed_status(self):
        self.cli("init", "--db", self.db_path)
        image = self.make_carve_image()
        fake_bin = self.fake_scalpel()
        env = {"PATH": f"{fake_bin}:{os.environ['PATH']}", "CARVER_MODE": "zero"}
        self.collect_carve(image, output_name="zero-output", carver="scalpel", env=env)
        env["CARVER_MODE"] = "failed"
        self.collect_carve(image, output_name="failed-output", carver="scalpel", expected=1, env=env)
        connection = self.database()
        statuses = connection.execute("select status,count(*) from evidence_sources where kind='carver_run' group by status").fetchall()
        self.assertEqual(dict(statuses), {"completed": 1, "failed": 1})
        self.assertEqual(connection.execute("select count(*) from evidence_sources where kind='carved_artifact'").fetchone()[0], 0)

    @unittest.skipUnless(shutil.which("mke2fs") and shutil.which("debugfs") and shutil.which("fls"), "TSK image tools unavailable")
    def test_complete_synthetic_incident(self):
        self.cli("init", "--db", self.db_path)
        self.ingest_agents()
        self.ingest_audit()
        self.collect_tsk(self.make_image())
        timeline = self.timeline()
        ids = {event["event_id"] for event in timeline["events"]}
        self.assertIn("evt-prompt", ids)
        self.assertIn("evt-tool", ids)
        types = {event["event_type"] for event in timeline["events"]}
        self.assertLessEqual({"process_started", "file_access", "file_created", "file_deleted", "network_connection", "filesystem_metadata"}, types)
        process = next(event for event in timeline["events"] if event["event_type"] == "process_started")
        self.assertEqual((process["process_id"], process["parent_process_id"]), (420, 100))
        cited = ["evt-prompt", "evt-tool", process["event_id"]]
        with MockLLM(["valid"], observation_ids=cited) as server:
            output, _ = self.analyze(server)
            report = json.loads(output.read_text())
        self.assertEqual(report["analysis"]["observations"][0]["event_ids"], cited)
        self.assertEqual(report["analysis"]["hypotheses"][0]["confidence"], "low")
        self.assertIn("do not independently prove causation", report["analysis"]["limitations"][0])
        self.assertNotIn("CANARY_SECRET_DO_NOT_SEND", json.dumps(server.requests[0]["payload"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
