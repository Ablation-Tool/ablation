# Streaming Operational Helpers

Consume a sample of messages from a Kafka topic, submit a JAR file to a Flink cluster for remote code execution, probe NATS connection and subscription surface, and enumerate Confluent Schema Registry schemas: the active operational layer that follows passive streaming enumeration: via `modules/streaming_enum.py`.

---

## Why this exists

1. `kafka_consume_sample()` retrieves actual messages from a Kafka topic: after `kafka_list_topics()` identifies topic names, `kafka_consume_sample()` fetches the first N messages from partition 0 using a raw `Fetch(v1)` API request. No consumer group offset tracking is used; the fetch starts at offset 0 the beginning of the retained log. This provides the actual message content: JSON payloads, Avro-encoded data, or plaintext: for topics identified as potentially sensitive during enumeration.

2. **`flink_submit_jar_rce()` executes arbitrary code on a Flink cluster**, it uploads a JAR to the Flink JobManager's `/jars/upload` endpoint and triggers execution via `/jars/<id>/run`. The JAR's entry class is called with the Flink TaskManager's JVM process identity and network access. This is the operational execution step that follows `flink_enumerate()` confirming that the upload and run endpoints are accessible. The function returns the Flink job ID and status, which can be monitored via `/jobs/<id>/exceptions` for execution confirmation.

3. `schema_registry_enumerate()` provides schema definitions for Avro/JSON schema-encoded Kafka topics: Confluent Schema Registry stores the Avro or JSON schema for each Kafka topic's value type. Retrieving schemas via `/subjects/<topic-value>/versions/latest` reveals field names, types, and whether sensitive fields SSN, credit card number, password are part of the schema, even before consuming actual messages. This is the schema-level reconnaissance step.

---

## How it works

```mermaid
flowchart TD
    A(["kafka_consume_sample(host, topic, port=9092, count=10) → List[dict]\n  Fetch(v1) request:\n    api_key=1, api_version=1\n    topic_name, partition=0, fetch_offset=0\n    max_bytes=1048576\n  Parse FetchResponse: message_set → records\n  Per record: key_bytes, value_bytes, offset, timestamp\n  → [{offset, key, value_raw, value_decoded_if_json}]"]):::input --> B["flink_submit_jar_rce(host, jar_bytes, entryClass, programArgs=None) → dict\n  POST /jars/upload multipart/form-data\n    jar_bytes → /tmp/uploaded.jar on JobManager\n    response: {filename: '<uuid>_uploaded.jar'}\n  POST /jars/<uuid>_uploaded.jar/run\n    body: {entryClass, programArgs, parallelism: 1}\n  Poll /jobs/<job_id>/exceptions for execution confirmation\n  → {job_id, status: RUNNING|FAILED, exceptions: List[str]}"]:::primary
    B:::primary --> C["schema_registry_enumerate(host, port=8081) → List[dict]\n  GET /subjects → subject name list\n  Per subject:\n    GET /subjects/<name>/versions/latest → {schema, id}\n    Parse Avro schema: fields → [{name, type}]\n  Flag fields: ssn|credit_card|password|token|key|secret\n  → [{subject, schema_type, fields, sensitive_fields}]"]:::secondary
    C:::secondary --> D(["check_nats_exposure(host, port=4222) → dict\n  TCP + INFO message (JSON): {version, auth_required, tls_required}\n  CONNECT {} → PONG (unauthenticated)\n  PUB test.subject 0\\r\\n\\r\\n → delivery confirmation\n  SUB > (all subjects) → subscription test\n  → {version, auth_required, pub_sub_accessible: bool}"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
```

---

## Usage

```python
from modules.streaming_enum import (
    kafka_consume_sample,
    flink_submit_jar_rce,
    schema_registry_enumerate
)

# Sample 5 messages from a sensitive topic
messages = kafka_consume_sample(kafka_host, topic='iam-credentials', count=5)
for m in messages:
    print(f"  offset={m['offset']}  value={m.get('value_raw', b'')[:100]}")

# Schema registry inspection
schemas = schema_registry_enumerate(schema_host)
for s in schemas:
    if s['sensitive_fields']:
        print(f"  {s['subject']}: SENSITIVE FIELDS = {s['sensitive_fields']}")

# Flink RCE (requires prepared JAR)
# result = flink_submit_jar_rce(flink_host, jar_bytes=open('payload.jar','rb').read(),
#                               entryClass='com.example.Main')
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
kafka_consume_sample: <kafka-host>:9092  topic=iam-credentials  count=5

  offset=0   {"user_id": "<id>", "api_key": "<api-key>", "role": "admin"}
  offset=1   {"user_id": "<id>", "api_key": "<api-key>", "role": "viewer"}

schema_registry_enumerate: <kafka-host>:8081

  payments-value: Avro  SENSITIVE: credit_card_number, cvv, billing_address
  user-events-value: Avro  SENSITIVE: email, phone, ssn

flink_submit_jar_rce: <flink-host>:8081

  job_id: <job-id>  status: RUNNING
  (payload executing as flink TaskManager process)
```

---

## False positives

**`kafka_consume_sample()` message encoding**: Kafka messages may be Avro-serialized with a 5-byte magic prefix (`\x00` + 4-byte schema ID). Messages that are not plain JSON will appear as binary in `value_raw`. Use `schema_registry_enumerate()` to obtain the Avro schema and deserialize before reporting on message content.

**`flink_submit_jar_rce()` FAILED status**: a `FAILED` job status may indicate the JAR's main class was not found, the JAR has a dependency that Flink's classpath does not include, or the TaskManager ran out of memory. A failed execution is not a false positive for the vulnerability JAR upload was accepted; it means the payload requires adjustment.

---

## Pipeline position

Run streaming operational helpers after `messaging-streaming-enumeration` confirms which topics and endpoints are accessible. Consume samples from sensitive-named topics first; run Flink JAR submission only after explicitly confirming the target cluster is in scope.

---

## Reading findings

Streaming operational probe functions return `List[{severity, title, detail, host, port}]`:

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` credential exposure in messages / `HIGH` schema registry / `MEDIUM` topic accessible |
| `title` | Finding code such as `KAFKA_SENSITIVE_SCHEMA_FIELD`, `KAFKA_CREDENTIAL_IN_TOPIC`, and `SCHEMA_REGISTRY_SENSITIVE` |
| `detail` | Topic name, schema name, or credential field names found in sampled messages |
| `host` | Broker or schema registry host |
| `port` | Service port |

---

## See also

- [Messaging/Streaming Enumeration](messaging-streaming-enumeration.md): passive enumeration that identifies accessible topics and endpoints
- [Observability Exposure](observability-exposure.md): Kafka schema registry as an observability component in data pipeline architectures
