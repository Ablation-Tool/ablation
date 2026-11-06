#!/usr/bin/env python3
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest

from test_cerotto import agent_events, audit_lines


ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("CEROTTO_BIN", ROOT / "build" / "cerotto")).resolve()
REFERENCE = Path("/media/cowboy/research/GEM/analysis/gemseal")
VECTOR = "R0VNU0VBTDEBAAEAAQAwAAABAgMEBQYHCAkKCwwNDg8QERITFBUWFwAQAAAAAAAAAQABABMAAAAAAAMAAAAAAP3eBxRxm6eRP8nLh/BwOe63868CAAEAEAABAAAAAAAAAAAAQSBHysL8RkaySCG8VwtLCA=="
PROBABILITIES = [0.40, 0.20, 0.12, 0.06, 0.04] + [0.02] * 9


class CerottoCommand:
    def cli(self, *args, expected=0, env=None, timeout=30):
        environment = os.environ.copy()
        if env:
            environment.update(env)
        result = subprocess.run(
            [str(BINARY), *map(str, args)], capture_output=True, text=True,
            timeout=timeout, env=environment,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def database(self, path):
        connection = sqlite3.connect(path)
        self.addCleanup(connection.close)
        return connection

    def event_rows(self, database, event_type=None):
        if event_type:
            return database.execute("select id,event_type,details_json from events where event_type=? order by observed_at,id", (event_type,)).fetchall()
        return database.execute("select id,event_type,details_json from events order by observed_at,id").fetchall()


class GemsealTests(CerottoCommand, unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cerotto-gemseal-test-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.key = self.root / "key.bin"
        self.key.write_bytes(bytes(range(32)))
        self.key.chmod(0o600)
        self.plain = self.root / "plain.bin"
        self.plain.write_bytes(bytes((index * 37) % 256 for index in range(10000)))

    def encrypt(self, source, destination, chunk=1024, expected=0):
        self.cli("encrypt", "--key", self.key, "--input", source, "--output", destination,
                 "--chunk-size", chunk, expected=expected)

    def decrypt(self, container, destination, expected=0):
        return self.cli("decrypt", "--key", self.key, "--input", container, "--output", destination, expected=expected)

    def test_deterministic_vector_and_round_trips(self):
        vector = self.root / "vector.gemseal"
        vector.write_bytes(base64.b64decode(VECTOR))
        restored = self.root / "vector.out"
        self.decrypt(vector, restored)
        self.assertEqual(restored.read_bytes(), b"GEM")
        for name, size in (("empty", 0), ("exact", 8192), ("multi", 10000)):
            with self.subTest(name=name):
                source = self.root / f"{name}.bin"
                source.write_bytes(self.plain.read_bytes()[:size])
                container = self.root / f"{name}.gemseal"
                restored = self.root / f"{name}.out"
                self.encrypt(source, container)
                self.decrypt(container, restored)
                self.assertEqual(restored.read_bytes(), source.read_bytes())

    def test_randomized_ciphertext_and_key_generation(self):
        first = self.root / "first.gemseal"
        second = self.root / "second.gemseal"
        self.encrypt(self.plain, first)
        self.encrypt(self.plain, second)
        self.assertNotEqual(first.read_bytes(), second.read_bytes())
        generated = self.root / "generated.key"
        self.cli("keygen", "--output", generated)
        self.assertEqual(generated.stat().st_size, 32)
        self.assertEqual(stat.S_IMODE(generated.stat().st_mode), 0o600)
        self.assertNotEqual(generated.read_bytes(), bytes(32))

    def test_wrong_key_and_malformed_records_do_not_publish(self):
        container = self.root / "sealed.gemseal"
        self.encrypt(self.plain, container)
        original = container.read_bytes()
        variants = {
            "tampered": original[:80] + bytes([original[80] ^ 1]) + original[81:],
            "truncated": original[:-1],
            "trailing": original + b"X",
            "wrong-version": original[:8] + b"\x02\x00" + original[10:],
            "wrong-suite": original[:10] + b"\x02\x00" + original[12:],
            "reserved": original[:44] + b"\x01\x00\x00\x00" + original[48:],
            "invalid-index": original[:54] + b"\x01\x00\x00\x00" + original[58:],
            "empty-data": original[:48] + b"\x01\x00\x01\x00\x10\x00" + original[56:],
        }
        record_size = 16 + 1024 + 16
        variants["reordered"] = original[:48] + original[48 + record_size:48 + 2 * record_size] + original[48:48 + record_size] + original[48 + 2 * record_size:]
        for name, content in variants.items():
            with self.subTest(name=name):
                candidate = self.root / f"{name}.gemseal"
                candidate.write_bytes(content)
                destination = self.root / f"{name}.out"
                self.decrypt(candidate, destination, expected=1)
                self.assertFalse(destination.exists())
                self.assertEqual(list(self.root.glob(f".{name}.out.tmp.*")), [])
        wrong = self.root / "wrong.key"
        wrong.write_bytes(bytes(range(1, 33)))
        wrong.chmod(0o600)
        destination = self.root / "wrong.out"
        self.cli("decrypt", "--key", wrong, "--input", container, "--output", destination, expected=1)
        self.assertFalse(destination.exists())

    def test_atomic_publication_and_existing_output(self):
        destination = self.root / "published"
        destination.write_bytes(b"keep")
        self.encrypt(self.plain, destination, expected=1)
        self.assertEqual(destination.read_bytes(), b"keep")
        container = self.root / "valid.gemseal"
        self.encrypt(self.plain, container)
        restored = self.root / "restored"
        restored.write_bytes(b"keep")
        self.decrypt(container, restored, expected=1)
        self.assertEqual(restored.read_bytes(), b"keep")
        corrupted = self.root / "corrupted.gemseal"
        data = bytearray(container.read_bytes())
        data[-1] ^= 1
        corrupted.write_bytes(data)
        output = self.root / "interrupted.out"
        self.decrypt(corrupted, output, expected=1)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".interrupted.out.tmp.*")), [])

    @unittest.skipUnless(REFERENCE.is_dir(), "reference interoperability fixtures unavailable")
    def test_cross_compatibility_both_directions(self):
        native = self.root / "native.gemseal"
        self.encrypt(self.plain, native)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REFERENCE)
        code = (
            "import gemseal; from pathlib import Path; "
            "gemseal.decrypt_file(bytes(range(32)), Path(r'%s'), Path(r'%s')); "
            "gemseal.encrypt_file(bytes(range(32)), Path(r'%s'), Path(r'%s'), chunk_size=1024)"
            % (native, self.root / "python-native.out", self.plain, self.root / "python.gemseal")
        )
        result = subprocess.run([sys.executable, "-c", code], env=environment,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "python-native.out").read_bytes(), self.plain.read_bytes())
        restored = self.root / "native-python.out"
        self.decrypt(self.root / "python.gemseal", restored)
        self.assertEqual(restored.read_bytes(), self.plain.read_bytes())


class VaultTests(CerottoCommand, unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cerotto-vault-test-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.db = self.root / "case.db"
        self.vault = self.root / "vault"
        self.key = self.root / "private" / "vault.key"
        (self.root / "private").mkdir()
        self.release_root = self.root / "release"
        self.release_root.mkdir(mode=0o700)
        self.cli("init", "--db", self.db)

    def init_vault(self):
        self.cli("vault", "init", "--db", self.db, "--case", "incident-7",
                 "--vault", self.vault, "--key", self.key, "--host", "agent-vm-1")
        return self.vault / "project_notes.gemseal"

    def start_watch(self, *extra):
        process = subprocess.Popen([
            str(BINARY), "vault", "watch", "--db", str(self.db), "--case", "incident-7",
            "--vault", str(self.vault), "--host", "agent-vm-1", *map(str, extra),
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail(f"watcher exited early: {process.stderr.read()}")
            with sqlite3.connect(self.db) as connection:
                if connection.execute("select count(*) from events where event_type='sensor.ready'").fetchone()[0]:
                    return process
            time.sleep(0.02)
        process.kill()
        self.fail("watcher did not become ready")

    def finish_watch(self, process, expected):
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, expected, stdout + stderr)

    def release(self, name, approved, expiration=True):
        output = self.release_root / name
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        args = [
            "vault", "release", "--db", self.db, "--case", "incident-7",
            "--key", self.key, "--input", self.vault / "project_notes.gemseal",
            "--output", output, "--release-root", self.release_root,
            "--requester", "analyst", "--reason", "test release", "--identity", "agent-test",
            "--host", "agent-vm-1",
        ]
        if expiration:
            args.extend(["--expires", expires.strftime("%Y-%m-%dT%H:%M:%SZ")])
        if approved:
            args.append("--approve")
        result = self.cli(*args, expected=0 if approved else 2)
        document = json.loads(result.stdout)
        return output, document

    def test_native_vault_persistence_and_access_boundaries(self):
        canary = self.init_vault()
        connection = self.database(self.db)
        row = connection.execute("select source_tool,details_json from events where event_type='vault.initialized'").fetchone()
        self.assertEqual(row[0], "cerotto.vault")
        details = json.loads(row[1])
        self.assertEqual(details["source"], "cerotto.vault")
        self.assertIsNone(details["process"])
        self.assertIsNone(details["agent_session"])
        self.assertEqual(details["consent"], "unknown")
        self.assertNotIn(str(self.key), row[1])
        self.assertNotIn(self.key.read_bytes().hex(), row[1])
        self.assertEqual(canary.read_bytes()[:8], b"GEMSEAL1")
        self.assertNotIn(b"This Cerotto canary", canary.read_bytes())
        self.assertEqual(self.key.stat().st_size, 32)
        self.assertFalse((self.vault / "vault.key").exists())

    def test_real_inotify_repeated_open_and_negative_control(self):
        canary = self.init_vault()
        watcher = self.start_watch("--duration", 4)
        for _ in range(20):
            with canary.open("rb") as stream:
                stream.read(1)
            time.sleep(0.005)
        unrelated = self.root / "unrelated.txt"
        unrelated.write_text("unrelated")
        unrelated.read_bytes()
        watcher.send_signal(signal.SIGTERM)
        self.finish_watch(watcher, 0)
        connection = self.database(self.db)
        opens = self.event_rows(connection, "file.open")
        reads = self.event_rows(connection, "file.read")
        self.assertGreaterEqual(len(opens), 20)
        self.assertGreaterEqual(len(reads), 20)
        self.assertFalse(any(row[2] == str(unrelated) for row in self.event_rows(connection)))
        details = json.loads(opens[0][2])
        self.assertEqual(details["source"], "cerotto.vault")
        self.assertIsNone(details["process"])
        self.assertIsNone(details["agent_session"])
        self.assertEqual(details["attribution"], "unresolved")
        self.assertTrue(self.event_rows(connection, "sensor.stopped"))

    def test_watcher_health_restart_and_write_failure(self):
        canary = self.init_vault()
        watcher = self.start_watch("--duration", 4, "--inject-overflow", "--inject-clock-change")
        watcher.send_signal(signal.SIGTERM)
        self.finish_watch(watcher, 0)
        connection = self.database(self.db)
        self.assertTrue(self.event_rows(connection, "sensor.queue_overflow"))
        self.assertTrue(self.event_rows(connection, "sensor.clock_change"))
        first_session = json.loads(self.event_rows(connection, "sensor.ready")[0][2])["watcher_session"]
        watcher = self.start_watch("--duration", 2, "--fail-evidence-write")
        with canary.open("rb") as stream:
            stream.read(1)
        self.finish_watch(watcher, 1)
        self.assertTrue(self.event_rows(connection, "sensor.degraded"))
        second_session = json.loads(self.event_rows(connection, "sensor.ready")[-1][2])["watcher_session"]
        self.assertNotEqual(first_session, second_session)

    def test_approved_denied_release_and_cleanup(self):
        self.init_vault()
        denied, denial = self.release("denied.bin", approved=False)
        self.assertFalse(denied.exists())
        self.assertEqual(denial["decision"], "denied")
        approved, approval = self.release("approved.bin", approved=True)
        self.assertEqual(approved.read_text(), "This Cerotto canary contains no sensitive information.\n")
        self.assertEqual(approval["cleanup_result"], "residual_plaintext_present")
        self.cli("vault", "cleanup", "--db", self.db, "--case", "incident-7",
                 "--release-id", approval["release_id"], "--approve", "--host", "agent-vm-1")
        self.assertFalse(approved.exists())
        connection = self.database(self.db)
        self.assertTrue(self.event_rows(connection, "release.denied"))
        self.assertTrue(self.event_rows(connection, "release.approved"))
        self.assertTrue(self.event_rows(connection, "release.cleanup"))
        verification = self.cli("verify", "--db", self.db, "--case", "incident-7")
        self.assertTrue(json.loads(verification.stdout)["verified"])

    def test_modified_release_is_retained_and_recorded(self):
        self.init_vault()
        approved, approval = self.release("modified.bin", approved=True)
        approved.write_bytes(b"modified after release")
        self.cli("vault", "cleanup", "--db", self.db, "--case", "incident-7",
                 "--release-id", approval["release_id"], "--approve", "--host", "agent-vm-1", expected=1)
        self.assertTrue(approved.exists())
        rows = self.event_rows(self.database(self.db), "release.cleanup_failed")
        self.assertEqual(len(rows), 1)
        details = json.loads(rows[0][2])
        self.assertEqual(details["source_detail"]["cleanup_result"], "modified_retained")
        self.assertEqual(details["source_detail"]["residual_plaintext"], "true")

    def test_response_preserves_evidence_then_suspends_and_resumes(self):
        self.init_vault()
        target = self.database(self.db).execute(
            "select id from events where event_type='vault.initialized'").fetchone()[0]
        process = subprocess.Popen(["sleep", "300"])
        self.addCleanup(lambda: process.poll() is None and process.kill())
        export = self.root / "response-export"
        self.cli("vault", "respond", "--db", self.db, "--case", "incident-7",
                 "--event-id", target, "--pid", process.pid, "--output", export,
                 "--approve", "--host", "agent-vm-1")
        time.sleep(0.05)
        self.assertTrue(process.poll() is None)
        state = subprocess.run(["ps", "-o", "stat=", "-p", str(process.pid)],
                               capture_output=True, text=True, check=True).stdout.strip()
        self.assertTrue(state.startswith("T"), state)
        self.cli("vault", "resume", "--db", self.db, "--case", "incident-7",
                 "--event-id", target, "--pid", process.pid, "--approve", "--host", "agent-vm-1")
        time.sleep(0.05)
        state = subprocess.run(["ps", "-o", "stat=", "-p", str(process.pid)],
                               capture_output=True, text=True, check=True).stdout.strip()
        self.assertFalse(state.startswith("T"), state)
        process.kill()
        process.wait(timeout=5)
        self.assertTrue((export / "payload.json").is_file())
        self.assertTrue(self.event_rows(self.database(self.db), "response.suspended"))
        self.assertTrue(self.event_rows(self.database(self.db), "response.resumed"))

    def test_correlation_requires_independent_agent_evidence(self):
        self.init_vault()
        connection = self.database(self.db)
        target = connection.execute("select id,observed_at,path from events where event_type='vault.initialized'").fetchone()
        output = self.root / "correlation.json"
        self.cli("vault", "correlate", "--db", self.db, "--case", "incident-7",
                 "--event-id", target[0], "--output", output)
        result = json.loads(output.read_text())
        self.assertEqual(result["attribution"], "unresolved")
        self.assertEqual(result["intent"], "unresolved")
        output.unlink()
        related = self.root / "related.jsonl"
        records = [
            {"id": "process-independent", "observed_at": target[1], "host_id": "agent-vm-1",
             "source_tool": "linux_audit", "event_type": "process_started", "process_id": 420,
             "parent_process_id": 100, "path": target[2], "details": {"audit_event": "independent-1"}},
            {"id": "agent-independent", "observed_at": target[1], "host_id": "agent-vm-1",
             "source_tool": "agent_gateway", "event_type": "tool_call", "conversation_id": "conv-7",
             "tool_call_id": "call-1", "process_id": 420, "parent_process_id": 100,
             "path": target[2], "details": {"independent": True}},
        ]
        related.write_text("".join(json.dumps(record) + "\n" for record in records))
        self.cli("ingest", "--db", self.db, "--case", "incident-7", "--input", related)
        self.cli("vault", "correlate", "--db", self.db, "--case", "incident-7",
                 "--event-id", target[0], "--output", output)
        result = json.loads(output.read_text())
        self.assertEqual(result["attribution"], "agent_correlated")
        self.assertEqual(result["confidence"], "moderate")
        self.assertEqual(result["intent"], "unresolved")

    def test_export_reproducibility(self):
        self.init_vault()
        first = self.root / "export-one"
        second = self.root / "export-two"
        self.cli("vault", "export", "--db", self.db, "--case", "incident-7", "--output", first, "--retention-days", 30)
        self.cli("vault", "export", "--db", self.db, "--case", "incident-7", "--output", second, "--retention-days", 30)
        self.assertEqual((first / "payload.json").read_bytes(), (second / "payload.json").read_bytes())
        first_custody = json.loads((first / "custody.json").read_text())
        second_custody = json.loads((second / "custody.json").read_text())
        self.assertEqual(first_custody["payload_sha256"], second_custody["payload_sha256"])
        self.assertEqual(first_custody["retention_days"], 30)


class CrackTests(CerottoCommand, unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cerotto-crack-test-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.key = self.root / "key.bin"
        self.key.write_bytes(b"")
        self.key.chmod(0o600)
        self.counter = 0

    def make_container(self, key, plaintext=b"controlled plaintext"):
        self.key.write_bytes(key)
        source = self.root / "plain.bin"
        source.write_bytes(plaintext)
        self.counter += 1
        container = self.root / f"container-{self.counter}.gemseal"
        self.cli("encrypt", "--key", self.key, "--input", source, "--output", container, "--chunk-size", 16)
        return container

    def test_wordlist_pin_and_reduced_raw_space(self):
        password = b"correct horse"
        container = self.make_container(hashlib.sha256(password).digest())
        wordlist = self.root / "words.txt"
        wordlist.write_bytes(b"first\r\ncorrect horse\nlast\n")
        result = self.cli("crack", "wordlist", "--input", container, "--wordlist", wordlist)
        report = json.loads(result.stdout)
        self.assertTrue(report["found"])
        self.assertEqual(report["tested"], 2)
        self.assertGreater(report["candidates_per_second"], 0)
        container = self.make_container(hashlib.sha256(b"0042").digest())
        result = self.cli("crack", "pin", "--input", container, "--digits", 4)
        report = json.loads(result.stdout)
        self.assertTrue(report["found"])
        self.assertEqual(report["tested"], 43)
        container = self.make_container(b"\x2a" + bytes(31))
        result = self.cli("crack", "raw-prefix", "--input", container, "--variable-bytes", 1)
        report = json.loads(result.stdout)
        self.assertTrue(report["found"])
        self.assertEqual(report["tested"], 43)
        result = self.cli("crack", "raw-prefix", "--input", container, "--variable-bytes", 1,
                          "--candidate-limit", 16, expected=1)
        report = json.loads(result.stdout)
        self.assertFalse(report["found"])
        self.assertEqual(report["tested"], 16)
        container = self.make_container(b"gem".ljust(32, b"\0"))
        wordlist = self.root / "padded.txt"
        wordlist.write_bytes(b"first\n" + b"x" * 33 + b"\ngem\n")
        result = self.cli("crack", "wordlist", "--input", container, "--wordlist", wordlist,
                          "--mode", "zero-padded")
        report = json.loads(result.stdout)
        self.assertTrue(report["found"])
        self.assertEqual(report["tested"], 2)
        self.assertEqual(report["skipped"], 1)
        container = self.make_container(hashlib.sha256(b"key").digest())
        result = self.cli("crack", "wordlist", "--input", container, "--wordlist", wordlist,
                          "--mode", "raw", expected=1)
        report = json.loads(result.stdout)
        self.assertFalse(report["found"])
        self.assertEqual(report["tested"], 0)
        self.assertEqual(report["skipped"], 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
