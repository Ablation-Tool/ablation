"""
Okta PAM sft-orchestrator RE module.

Binary: sft-orchestrator (149MB stripped Go binary)
Package: github.com/atko-pam/axiom-opa (internal, not public)
Version: ships in scaleft-gateway >= 1.101.2; current 1.113.0

Function namespace recovered from .gopclntab (4,874 function names).
BERT semantic sweep run against 2,684 target functions.

Source of all findings: binary RE only.
Novel only — no chains, no hypotheticals, no pre-reported CVEs.
"""

from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Binary fingerprint
# ---------------------------------------------------------------------------

BINARY_PATH = '/media/cowboy/research/okta-re/binaries/extracted-latest/scaleft-gateway_1.113.0~noble_amd64/usr/sbin/sft-orchestrator'
BINARY_SIZE_MB = 149
LANG = 'Go'
STRIPPED = True
GOPCLNTAB_MAGIC = 0xfffffffb  # Go 1.18+ relative-offset layout
GOPCLNTAB_OFFSET = 0x877d2a
INTERNAL_IPS = ['10.1.11.2', '10.1.31.2']  # hardcoded in binary
LB_TOKEN_HEADER = 'lb-token'  # internal load balancer auth header

# ---------------------------------------------------------------------------
# Internal package map (recovered from gopclntab strings)
# ---------------------------------------------------------------------------

AXIOM_OPA_PACKAGES = [
    'axiomworkflows/workflows/exchangerunnerkey',
    'axiomworkflows/workflows/getrunnerconfig',
    'axiomworkflows/workflows/rotatecredentials',
    'axiomworkflows/workflows/rotatecredentials/childworkflows/singlerotate',
    'axiomworkflows/workflows/rotatecredentials/activities',
    'axiomworkflows/workflows/testconnection',
    'axiomworkflows/workflows/discovery',
    'axiomworkflows/management',
    'axiomworkflows/management/internal',
    'axiomworkflows/dsl',
    'axiomworkflows/dsl/internal',
    'axiomworkflows/shared',
    'axfilters',
    'axplugins/mariadb',
    'axplugins/mongodb',
    'axplugins/mssql',
    'axplugins/mysql',
    'axplugins/oracledb',
    'axplugins/postgresql',
    'axplugins/snowflake',
    'axplugins/pam/shared/passwordrotator',
    'secretmanagement/awssecretsmanager',
    'secretmanagement/oktasecretsservice',
    'temporal/client',
    'temporal/context',
    'axiomtracing',
    'axiomerrors',
    'axiomlayers',
    'axschema',
    'keypair',
]

DB_PLUGINS = ['mariadb', 'mongodb', 'mssql', 'mysql', 'oracledb', 'postgresql', 'snowflake']
# NOTE: postgresql was missed in prior session inventory (6 → 7 plugins)

# ---------------------------------------------------------------------------
# Wire format structures (recovered from Go generic instantiation type names)
# ---------------------------------------------------------------------------

EXCHANGERUNNERKEY_INPUT = {
    'runnerId': 'uuid.UUID validate:"required,min=1"',
    'exchangeKey': 'string validate:"required,min=1"',
}
EXCHANGERUNNERKEY_OUTPUT = {
    'encryptedKey': 'string validate:"required,min=1"',
}

GETRUNNERCONFIG_INPUT = {
    'runnerId': 'uuid.UUID validate:"required,min=1"',
    'encryptionKey': 'string',  # NO validate tag — field is optional
}
GETRUNNERCONFIG_OUTPUT = {
    'runner_id': 'uuid.UUID',
    'tenant_id': 'uuid.UUID',
    'jwt': 'string',            # JWT issued to the runner
}

SINGLEROTATE_INPUT = {
    'runnerId': 'uuid.UUID validate:"required,min=1"',
    'encryptionKey': 'string validate:"required"',
    'credentials': 'string',    # NO validate tag — can be empty
    'target': 'singlerotate.RotationTarget validate:"required"',
    # + shared.IntegrationMetadata (embedded)
}

AUDIT_ROTATION_INPUT = {
    'workflow': 'string',
    'integrationId': 'string',
    'integrationType': 'string',
    'targetsCount': 'int',
    'output': 'rotatecredentials/shared.Output',
}
AUDIT_ROTATION_OUTPUT = {
    'success': 'bool',
}

# ---------------------------------------------------------------------------
# Temporal management internal call chain (injection candidate)
# ---------------------------------------------------------------------------

MANAGEMENT_QUERY_CHAIN = [
    'management/internal.(*RunsReaderImpl).ListWorkflowRuns',   # entry
    'management/internal.toListWorkflowExecutionsRequest',
    'management/internal.extractQueryPartsFromFilters',
    'management/internal.extractQueryPartsFromCriteria',
    'management/internal.collectQueryParts',
    'management/internal.buildSingleTemporalClause',
    'management/internal.formatTemporalValue',
    'management/internal.formatTemporalString',
    'management/internal.inlineTemporalParameters',             # injection point
    'management/internal.buildTemporalQuery',                   # final query
]

# ---------------------------------------------------------------------------
# AQL filter call chain (injection candidate)
# ---------------------------------------------------------------------------

AQL_FILTER_CHAIN = [
    'axfilters.(*Filter).CompileFilterForAql',   # public entrypoint
    'axfilters.(*Filter).compileFilterForAql',   # internal
    'axfilters.(*Filter).processCriteria',
    'axfilters.(*Filter).processSingleCriterion',
    'axfilters.(*Filter).processSingleSubFilter',
    'axfilters.(*Filter).processSubFilters',
    'axfilters.(*Filter).resolveOperator',
    'axfilters.(*Filter).buildFinalQuery',        # final assembly
    'axfilters.mergeBindVars',                   # bind variable merge (parameterization)
    'axfilters.ValidateSQLIdentifier',           # SQL validator used in AQL context
]

# ---------------------------------------------------------------------------
# Findings (candidates from RE — not verified exploitable)
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    id: str
    title: str
    package: str
    functions: list
    class_: str
    description: str
    mechanism: str
    evidence: str
    bert_score: Optional[float] = None
    verified: bool = False
    notes: str = ''


FINDINGS = [

    Finding(
        id='F1',
        title='getrunnerconfig JWT Issuance Without Proof-of-Possession',
        package='axiomworkflows/workflows/getrunnerconfig',
        functions=[
            'axiomworkflows/workflows/getrunnerconfig.(*Workflow).Execute',
            'axiomworkflows/workflows/getrunnerconfig.NewInput',
            'axiomworkflows/workflows/getrunnerconfig.NewOutput',
        ],
        class_='Authentication Bypass / JWT Issuance',
        description=(
            'The getrunnerconfig Temporal workflow returns a JWT (json:"jwt") '
            'given only a RunnerID (UUID) and an optional EncryptionKey. '
            'The EncryptionKey field carries no validation tag, making it optional. '
            'If the workflow issues a signed JWT without verifying that the caller '
            'possesses the private half of the runner\'s registered keypair, '
            'any party knowing a valid RunnerID can obtain a JWT for that runner '
            'without proving identity.'
        ),
        mechanism=(
            'Temporal workflow execution: signal getrunnerconfig with {runnerId: <uuid>, encryptionKey: ""}. '
            'If EncryptionKey is used to encrypt the returned JWT (caller-provided key wrapping), '
            'provide your own key material and decrypt the JWT response.'
        ),
        evidence=(
            'Wire format recovered from gopclntab generic instantiation type names: '
            'Input{runnerId uuid validate:"required,min=1", encryptionKey string [no validate]}. '
            'Output{runner_id uuid, tenant_id uuid, jwt string}. '
            'Contrast with exchangerunnerkey where ExchangeKey has validate:"required,min=1".'
        ),
        bert_score=0.452,
        verified=False,
        notes='Needs disassembly of getrunnerconfig workflow function body to determine if keypair verification occurs.',
    ),

    Finding(
        id='F2',
        title='Temporal Visibility Query Injection via inlineTemporalParameters',
        package='axiomworkflows/management/internal',
        functions=MANAGEMENT_QUERY_CHAIN,
        class_='Query Injection / Tenant Isolation Bypass',
        description=(
            'The management workflow\'s ListWorkflowRuns implementation builds '
            'Temporal visibility queries from user-supplied filter criteria. '
            'The function inlineTemporalParameters (not bindTemporalParameters) '
            'inserts parameter values directly into the query string. '
            'If user-controlled filter values are not sanitized before inlining, '
            'injection into the Temporal SQL-like visibility query language enables '
            'reading workflow executions across tenant boundaries — breaking the '
            'tenant isolation enforced by Temporal namespace filters.'
        ),
        mechanism=(
            'Supply a filter value containing Temporal visibility query operators: '
            '"value\' OR WorkflowType=\'%\'" or equivalent. '
            'The buildTemporalQuery output would include injected conditions '
            'broadening the result set beyond the intended tenant scope.'
        ),
        evidence=(
            'Function name inlineTemporalParameters distinguishes from parameterized approach. '
            'Call chain: ListWorkflowRuns → extractQueryPartsFromFilters → '
            'extractQueryPartsFromCriteria → collectQueryParts → buildSingleTemporalClause → '
            'formatTemporalValue → formatTemporalString → inlineTemporalParameters → buildTemporalQuery. '
            'formatTemporalString and formatTemporalValue suggest type-aware string construction '
            'before inlining, but string-based Temporal queries are SQL-injection-class vulnerable.'
        ),
        bert_score=None,
        verified=False,
        notes=(
            'Temporal visibility backends: Elasticsearch or PostgreSQL (Okta likely uses PostgreSQL). '
            'PostgreSQL visibility: Temporal translates the query to SQL — SQL injection in the '
            'Temporal query string reaches the database layer.'
        ),
    ),

    Finding(
        id='F3',
        title='AQL Identifier Injection via ValidateSQLIdentifier in ArangoDB Query Builder',
        package='axfilters',
        functions=AQL_FILTER_CHAIN,
        class_='AQL Injection / Identifier Injection',
        description=(
            'The axfilters package constructs ArangoDB Query Language (AQL) queries '
            'from user-supplied filter criteria. Values are parameterized via mergeBindVars '
            '(bind variables — correct). However, identifiers (field names, collection names) '
            'are validated by ValidateSQLIdentifier — a SQL-oriented validator. '
            'AQL identifier syntax differs from SQL: AQL uses backtick-delimited identifiers '
            'and supports @@collection syntax for bind collection names. '
            'A SQL-safe identifier may be AQL-unsafe, allowing identifier injection into '
            'the filter clause if the field name path (e.g., "doc.fieldName") is '
            'user-controlled and not AQL-escaped.'
        ),
        mechanism=(
            'Submit a filter criterion where the field name contains AQL-special characters: '
            'fieldName = "malicious.path`[* FILTER 1==1 RETURN doc //". '
            'processSingleCriterion passes through ValidateSQLIdentifier '
            '(which allows dot-separated identifiers and alphanumerics). '
            'buildFinalQuery assembles: FILTER doc.malicious.path`[* FILTER 1==1 RETURN doc // == @bindVar. '
            'AQL would parse the backtick as start of a quoted identifier, breaking the query structure.'
        ),
        evidence=(
            'ValidateSQLIdentifier in axfilters — a SQL validator name in an AQL-building package. '
            'mergeBindVars confirms values are parameterized (injection is at identifier layer, not value). '
            'AQL supports: FOR doc IN collection FILTER doc.<field> == @var RETURN doc. '
            'Field path components are concatenated by processSingleCriterion into the FILTER clause.'
        ),
        bert_score=None,
        verified=False,
        notes=(
            'ArangoDB injection class is similar to MongoDB query injection but with distinct syntax. '
            'If processSingleCriterion properly escapes field names before insertion, no injection. '
            'Need disassembly of processSingleCriterion to check escaping logic.'
        ),
    ),

    Finding(
        id='F4',
        title='PostgreSQL pg_hba.conf Read Access via canAccessHbaFileRules',
        package='axplugins/postgresql',
        functions=[
            'postgresql.(*Client).canAccessHbaFileRules',
            'postgresql.(*Client).ValidatePermissions',
            'postgresql.(*Client).validateSessionTermination',
        ],
        class_='Sensitive File Read / Information Disclosure',
        description=(
            'The PostgreSQL plugin implements canAccessHbaFileRules — a check for whether '
            'the orchestrator\'s database user can read pg_hba.conf (the PostgreSQL '
            'host-based authentication configuration). '
            'pg_hba.conf reveals all authentication methods, allowed hosts, and database '
            'access rules for the PostgreSQL instance. '
            'This access is a prerequisite for attacks targeting PostgreSQL authentication '
            'methods (e.g., md5 downgrade, trust rule identification). '
            'If the orchestrator service account has pg_catalog.pg_hba_file_rules access '
            'and this function is reachable via the PAM API, the HBA config is readable '
            'by any caller with PAM resource access.'
        ),
        mechanism=(
            'SELECT line_number, auth_method, user_name, address, database FROM pg_catalog.pg_hba_file_rules; '
            'This view requires superuser or pg_read_all_settings privilege. '
            'If the orchestrator\'s service account holds this privilege (required for PAM credential rotation), '
            'then the HBA rules are readable through the PAM management interface.'
        ),
        evidence=(
            'canAccessHbaFileRules function in postgresql.(*Client) — unique to orchestrator plugin. '
            'ValidatePermissions calls canAccessHbaFileRules to check orchestrator\'s privilege scope. '
            'The orchestrator requires superuser-equivalent privileges for credential rotation, '
            'making pg_hba_file_rules view readable as a side effect of the required permission set.'
        ),
        bert_score=None,
        verified=False,
        notes=(
            'Impact depends on whether PAM management API exposes pg_hba contents in responses. '
            'IntegrationOutput may include HBA access result in the response body. '
            'Separate from credential rotation: check the oracledb plugin\'s IntegrationOutput '
            'which is present only in oracledb (not other plugins) and may expose similar config.'
        ),
    ),

    Finding(
        id='F5',
        title='singlerotate Credentials Field Accepts Empty Value',
        package='axiomworkflows/workflows/rotatecredentials/childworkflows/singlerotate',
        functions=[
            'axiomworkflows/workflows/rotatecredentials/childworkflows/singlerotate.(*Workflow).Execute',
            'axiomworkflows/workflows/rotatecredentials/childworkflows/singlerotate/activities.RotateCredentials',
        ],
        class_='Input Validation Failure / Credential Corruption',
        description=(
            'The singlerotate child workflow Input struct includes a Credentials field '
            '(json:"credentials") with no validate tag. '
            'The parent rotatecredentials workflow dispatches singlerotate as child workflows '
            'via executeRotationsAsChildWorkflows. '
            'If the Credentials field reaches the DB plugin\'s RotateCredentials method '
            'while empty or malformed, the target database account\'s password may be set '
            'to an empty string, disabling authentication for that account.'
        ),
        mechanism=(
            'Trigger rotatecredentials workflow with controlled input where credentials '
            'is an empty string. The child singlerotate executes without rejecting empty credentials. '
            'DB plugin\'s RotateCredentials (mysql, mariadb, mssql, postgresql, etc.) '
            'executes ALTER USER ... IDENTIFIED BY \'\' or equivalent.'
        ),
        evidence=(
            'singlerotate.Input struct: {runnerId, encryptionKey validate:"required", '
            'credentials [NO validate], target validate:"required", IntegrationMetadata}. '
            'encryptionKey and target are validated as required; credentials is not. '
            'All 7 DB plugins implement RotateCredentials — none shown to independently '
            'validate non-empty credential before issuing the ALTER statement.'
        ),
        bert_score=0.530,
        verified=False,
        notes=(
            'The 0.530 BERT score was on auditRotationResults matching credential_rotation_race pattern. '
            'The audit activity AuditRotationInput includes the rotation Output — '
            'check if audit log records the (empty) new credential value.'
        ),
    ),

    Finding(
        id='F6',
        title='Hardcoded Internal Infrastructure IPs in Production Binary',
        package='axiom-opa (embedded)',
        functions=[],
        class_='Information Disclosure / Network Topology',
        description=(
            'The sft-orchestrator production binary contains two hardcoded IPv4 addresses: '
            '10.1.11.2 and 10.1.31.2. These are Okta\'s internal PAM infrastructure routing '
            'targets — likely load balancer VIPs for the internal service mesh. '
            'The binary also embeds the lb-token HTTP header name for internal '
            'load balancer authentication.'
        ),
        mechanism='Static disclosure — extractable from binary with: strings sft-orchestrator | grep "10\\."',
        evidence=(
            'Ablation --go-re JSON output: "INTERNAL_IPS: [\'10.1.11.2\', \'10.1.31.2\']". '
            'lb-token header present in credential_material section. '
            'UNAUTHORIZED string confirms 401 path uses lb-token as auth gating.'
        ),
        bert_score=None,
        verified=True,  # directly observable in binary
        notes='Network context: 10.1.x.x private range consistent with cloud VPC CIDR.',
    ),

]


def summary():
    print(f"Okta PAM sft-orchestrator RE — {len(FINDINGS)} candidate findings")
    for f in FINDINGS:
        status = 'VERIFIED' if f.verified else 'CANDIDATE'
        print(f"  [{f.id}] [{status}] {f.title}")
        print(f"        Package: {f.package}")
        print(f"        Class:   {f.class_}")
        if f.bert_score:
            print(f"        BERT:    {f.bert_score}")
        print()


if __name__ == '__main__':
    summary()
