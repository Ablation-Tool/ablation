# Streaming Pipeline Enumeration

**File:** `modules/streaming_enum.py`

## Why this exists

Three gaps existed before this module:

1. **Kafka, Flink, NiFi, and Confluent Schema Registry were not enumerated.** These streaming infrastructure components expose significant attack surface (unauthenticated topic listing, JMX, REST APIs with default credentials) that was not covered by any existing Ablation network module.

2. **Kafka binary protocol probing required manual frame construction.** The Kafka ApiVersions, Metadata, and ListOffsets requests use a custom binary framing. This module implements the framing correctly per the Kafka protocol spec, enabling unauthenticated topic enumeration against Kafka brokers.

3. **Confluent Schema Registry REST API exposure was not checked.** The Schema Registry (port 8081) exposes `/subjects`, `/config`, and `/schemas` without authentication by default. This module enumerates the full schema registry surface.

## Key functions

| Function | Description |
|---|---|
| `kafka_list_topics(host, port)` | Kafka topic enumeration via ApiVersions + Metadata |
| `flink_enum(host, port)` | Apache Flink REST API surface |
| `nifi_enum(host, port)` | Apache NiFi REST API surface |
| `schema_registry_enum(host, port)` | Confluent Schema Registry subjects and config |
| `enumerate_streaming(host)` | All streaming surfaces in one call |

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_HTTP_BYTES` | 4 MB | HTTP response body reads |

## FORGE audit

Gate: **PASSED**. One CWE-770 fix applied:
- Kafka `resp_len` server-controlled 4-byte big-endian length field: `struct.unpack(">i", raw_len)[0]` → `min(..., _MAX_HTTP_BYTES)`. Without the cap, a malicious Kafka endpoint could return a 2 GiB length value forcing the client to buffer 2 GiB before processing.

All HTTP reads use `r.read(_MAX_HTTP_BYTES)` or smaller bounds. All socket recv() loops are bounded by explicit byte limits or CRLF terminators. No file reads. No lief.parse().
