# Streaming Pipeline & Observability Enumeration

**File:** `modules/streaming_enum.py`

## Why this exists

Three gaps existed before this module:

1. **Streaming infrastructure Kafka, Flink, NiFi, NATS, RabbitMQ, and Pulsar was not enumerated.** These components expose significant attack surface, unauthenticated topic listing, binary wire protocol probing, management APIs. None were covered by any prior Ablation network module.

2. **Observability stack exposure Prometheus, Grafana, Jaeger, Loki, Thanos was unprobed.** These components ship with no authentication by default and expose full internal telemetry, trace data, service topology, and alert routing configurations.

3. **Modern orchestration APIs Temporal, Argo Workflows, HashiCorp Vault/Nomad/Boundary, Cisco NSO, and Ansible Tower/AWX were not covered.** These surfaces expose workflow DAGs, credential stores, network device inventories, and live secret material.

---

## Scope

4214-line pure network I/O module. No filesystem reads. No subprocess calls. No lief usage. All probes are active send + receive. Covers:

**Streaming:**
- Kafka binary protocol ApiVersions and Metadata, REST Proxy 8082/8080, Schema Registry (8081), TLS port (9093)
- Apache Flink REST API (8081), RCE via JAR submit
- Apache NiFi REST API 8080/8443
- Confluent Schema Registry subjects and config
- EventStoreDB HTTP API (2113)
- NATS binary protocol, monitoring HTTP (8222), WebSocket (8080)
- RabbitMQ AMQP (5672), AMQPS (5671), Management API (15672), STOMP (61613), default creds
- Apache Pulsar binary protocol (6650), Admin REST API (8080), WebSocket producer
- Dead-letter queue detection on Kafka, RabbitMQ, NATS

**DNS:**
- Zone transfer AXFR/IXFR over TCP/UDP
- Open resolver detection
- DNSSEC misconfiguration
- Dynamic DNS UPDATE acceptance RFC 2136, unauthenticated
- DNS-over-TLS (DoT port 853) and DNS-over-HTTPS (DoH port 443/8443)

**gRPC:**
- HTTP/2 client preface probe plain TCP 50051
- gRPC-over-TLS port 443, ALPN h2
- Server reflection detection

**Observability:**
- Prometheus metrics, targets, PromQL, Alertmanager config (9090)
- Prometheus PushGateway metrics, metric names, DELETE tamper (9091)
- Prometheus Alertmanager alerts, receivers, silences (9093)
- Thanos Querier stores, PromQL, Ruler 10902/19192
- Jaeger services, traces, dependency graph, collector ingest 16686/14268
- Loki labels, log streams, series, unauthenticated push (3100)
- Grafana dashboards, datasources, user list (3000)
- InfluxDB databases, queries, v2 buckets (8086)

**Orchestration/Infrastructure:**
- Temporal gRPC frontend (7233), HTTP API namespaces/workflows (8233)
- Argo Workflows workflow list, template scripts, credential scanning (2746)
- Elasticsearch cluster info, index list, node topology; Kibana 9200/5601
- MinIO health, bucket listing, object listing, Console UI 9000/9001
- HashiCorp Vault health, seal status, root token check, KV secrets (8200)
- HashiCorp Boundary health, auth methods, hosts, sessions (9200)
- HashiCorp Nomad leader, jobs, nodes, ACL tokens (4646)
- Cisco NSO RESTCONF device list, packages, YANG modules, rollbacks, sync-from RPC 8080/8443
- Ansible Tower/AWX API root, ping, credentials, inventories, job templates, users, config, LDAP leak, default creds (443)

---

## Key API

```python
from modules.streaming_enum import (
    # Kafka
    kafka_list_topics,
    kafka_consume_sample,
    probe_kafka_exposure,
    # Flink
    flink_enumerate,
    flink_submit_jar_rce,
    # NiFi / Schema Registry
    nifi_enumerate,
    schema_registry_enumerate,
    # RabbitMQ / NATS / Pulsar
    probe_rabbitmq_exposure,
    probe_nats_messaging_exposure,
    probe_pulsar_messaging_exposure,
    check_dead_letter_queue,
    # DNS
    probe_dns_zone_transfer,
    probe_dns_recursion,
    probe_ddns_abuse,
    probe_dns_dot_doh,
    # gRPC
    probe_grpc_reflection,
    # Prometheus / Observability
    probe_prometheus_metrics_endpoint,
    probe_prometheus_pushgateway,
    probe_alertmanager_exposure,
    probe_thanos_querier,
    probe_jaeger_tracing,
    probe_loki_log_aggregation,
    probe_grafana_dashboard,
    probe_influxdb_exposure,
    # Orchestration
    probe_temporal_workflow,
    probe_argo_workflows,
    probe_elasticsearch_exposure,
    probe_minio_exposure,
    probe_vault_secrets_manager,
    probe_hashicorp_boundary,
    probe_nomad_orchestrator,
    probe_cisco_nso_exposure,
    probe_ansible_tower_awx_exposure,
    # Aggregate
    enumerate_all,
    enumerate_streaming_surface,
)
```

All probe functions return `list[dict]` with keys: `severity`, `title`, `detail`, `host`, `port`.

---

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_HTTP_BYTES` | 4 MB | Kafka/Flink/NiFi/EventStoreDB/NATS module-level `_http_get()` |

Note: Inner probe functions `probe_jaeger_tracing`, `probe_loki_log_aggregation`, `probe_temporal_workflow`, `probe_argo_workflows`, `probe_elasticsearch_exposure`, and `probe_minio_exposure` use local `_get()` helpers with `r.read(131072)` 128 KB cap. `probe_prometheus_metrics_endpoint` uses `r.read(65536)` (64 KB). `probe_ansible_tower_awx_exposure` uses `r.read(8192)`.

---

## FORGE audit

Gate: **PASSED**. No code changes needed.

**Security checks:**
- No file I/O anywhere in the module: no CWE-770 file read concerns.
- No `lief.parse()`: no CWE-755 lief null return concerns.
- No bare `except:`: all handlers use `except Exception:`, `except urllib.error.HTTPError:`, `except socket.timeout:`, or `except struct.error:`.
- All HTTP reads bounded: `_MAX_HTTP_BYTES` (4 MB) for Kafka-tier helpers; 128 KB, 64 KB, or 8 KB caps in per-probe inner functions; 512/256 byte preview reads in binary protocol probes.
- All `recv()` calls use fixed buffer sizes 256–4096 bytes: network socket buffers, not file reads.
- All sockets `settimeout()` bounded or use `timeout=` in `create_connection`.
- No subprocess calls.
- `ssl.CERT_NONE` intentional: probe mode against self-signed management TLS.

**Known residual:**
- `probe_ddns_abuse` sends a real DNS UPDATE RFC 2136: active write probe, not read-only. Injects `ablation-test.<zone> A 1.2.3.4`. Accepted by servers with unauthenticated DDNS enabled.
- `probe_cisco_nso_exposure` can trigger a `sync-from` RPC that causes NSO to actively poll all managed network devices: use with caution in production environments.
- `probe_ansible_tower_awx_exposure` attempts three default credential pairs `admin:password`, `admin:Tower`, and `admin:admin`: generates authentication log entries.

---

## How it works

All functions are standalone. Newer probe functions DNS, gRPC, and observability tools return `{severity, title, detail, host, port}` finding lists. Older enumeration functions Kafka, Flink, and NiFi return plain data dicts. `enumerate_all(host)` returns a keyed dict with per-service results. `enumerate_streaming_surface(hosts)` sweeps a host list.

---

## Usage

```python
from modules.streaming_enum import (
    enumerate_all,
    probe_prometheus_metrics_endpoint,
    probe_grafana_dashboard,
    probe_elasticsearch_exposure,
)

# Full single-host sweep
result = enumerate_all('10.0.0.1')
# result keys: kafka, flink, nifi, schema_registry, event_store, nats, dead_letter

# Newer finding-list probes — [{severity, title, detail, host, port}]
for f in probe_prometheus_metrics_endpoint('10.0.0.1', port=9090):
    print(f"  [{f['severity']}] {f['title']}: {f['detail'][:80]}")
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
enumerate_all: 10.0.0.1

  nats: [{severity: 'MEDIUM', title: 'NATS server client port exposed', detail: '...'}]
  kafka: {host: '10.0.0.1', port: 9092, reachable: True, topics: ['payments', 'events']}

probe_prometheus_metrics_endpoint:
  [HIGH]    Prometheus metrics exposed unauthenticated
            GET /metrics returned full metric dump without authentication
  [MEDIUM]  Prometheus target credentials in metrics
            service_account_token found in metric labels
```

---

## False positives

**`probe_prometheus_metrics_endpoint()` on internal-only Prometheus**: Prometheus is commonly deployed with no authentication on internal networks where access control is at the network boundary. Confirm whether the endpoint is accessible from outside the trusted network before treating this as an exposure finding.

**`kafka: {topics: [...]}` including internal `__consumer_offsets` topics**: Kafka always has internal topics prefixed with `__`. Report only non-internal topics as data exposure candidates.

---

## Pipeline position

Run `enumerate_all()` after identifying open ports on Kafka (9092), Flink (8081), NiFi 8080/8443, RabbitMQ (15672), or NATS (4222). Run observability probes `probe_prometheus_metrics_endpoint` and `probe_grafana_dashboard` when port 9090 or 3000 are confirmed open.

---

## Reading findings

Newer probe functions return `{severity, title, detail, host, port}`. Older enumeration functions return plain data dicts.

| Function | Return type |
|:---|:---|
| `probe_prometheus_metrics_endpoint()` | `List[{severity, title, detail, host, port}]` |
| `probe_grafana_dashboard()` | `List[{severity, title, detail, host, port}]` |
| `kafka_list_topics()` | `{host, port, reachable, topics: List[str], error}` |
| `flink_enumerate()` | `{jobs, taskmanagers, jars, config}` |
| `check_nats_exposure()` | `List[{severity, title, detail, host, port}]` |

---

## See also

- [Messaging/Streaming Enumeration](messaging-streaming-enumeration.md): probe-style findings from the same `streaming_enum.py` module in `{severity, title, detail, host, port}` format
- [Internal Network Reconnaissance](internal-network-reconnaissance.md): host discovery and port scanning to identify streaming infrastructure before enumeration
- [Evidence Scoring and Probe Ranking](evidence-scoring-and-probe-ranking.md): rank streaming findings by confidence before escalating to active exploitation
