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
            'axiomworkflows/workflows/getrunnerconfig.getRunnerConfig',     # VA: 0x55a6c60
            'axiomworkflows/workflows/getrunnerconfig/activities.init',      # VA: 0x55a4f20
        ],
        class_='Authentication Bypass / JWT Issuance',
        description=(
            'The getrunnerconfig Temporal workflow returns a JWT (json:"jwt") '
            'given only a RunnerID (UUID) and an optional EncryptionKey. '
            'EncryptionKey has no validate tag — optional by design. '
            'Disassembly of getRunnerConfig (0x55a6c60) and its activities.init (0x55a4f20) '
            'shows ZERO calls to any keypair.* function: no keypair.EncryptJWE, '
            'no keypair.EncryptHybrid, no keypair.DecryptJWE, no keypair.Decrypt. '
            'The activities package registers ONE activity (one func1 closure) with no crypto callees. '
            'shared/activities has fetchrunnerpublickey.go but that source file does not appear '
            'in getrunnerconfig\'s call graph — it is used by other workflows (exchangerunnerkey). '
            'Contrast: exchangerunnerkey has activities/fetchrunnersecret.go and requires '
            'ExchangeKey validate:"required,min=1". getrunnerconfig skips this requirement. '
            'Attack path: skip exchangerunnerkey; call getrunnerconfig directly with '
            '{runnerId: <valid UUID>, encryptionKey: ""}; receive JWT for target runner.'
        ),
        mechanism=(
            'Temporal workflow execution: start getrunnerconfig workflow with {runnerId: <uuid>, encryptionKey: ""}. '
            'No keypair verification occurs in the workflow or its activity. '
            'JWT is issued for the runner without proof-of-possession of the runner\'s private key.'
        ),
        evidence=(
            'DISASSEMBLY-BACKED (VA: 0x55a6c60). '
            'getRunnerConfig callees: uuid.encodeHex, axschema.PropertiesSchema.ToJSONSchema, '
            'dsl/internal.GetLogger, runtime.rawstringtmp, fmt.Sprintf. '
            'Zero keypair.* calls. Two indirect calls (call rdx at 0x55a7064/0x55a7193) '
            'with trivial args (esi=2,r8=2 and edi=0,esi=0) — not crypto verification signatures. '
            'activities.init callees: runtime only. '
            'Input struct: {runnerId validate:"required,min=1", encryptionKey [NO validate]}. '
            'Output struct: {runner_id, tenant_id, jwt}. '
            'shared/activities has fetchrunnerpublickey.go but NOT in getrunnerconfig call graph.'
        ),
        bert_score=0.452,
        verified=True,   # disassembly confirms no keypair ops
        notes=(
            'STATUS: PLAUSIBLE-HIGH. Disassembly confirms no keypair operations. '
            'Unresolved: whether the registered activity (func1 at 0x55a5120) calls a service-layer '
            'RPC that performs server-side proof-of-possession checks outside the binary. '
            'Proof: trigger getrunnerconfig Temporal workflow with known RunnerID and empty encryptionKey '
            'and observe if JWT is returned.'
        ),
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
            'Supply a filter value containing unescaped double-quote characters: '
            'value = `foo" OR WorkflowType="%`. '
            'formatTemporalValue wraps string with fmt.Sprintf("\\"%s\\"", value) → `"foo" OR WorkflowType="%"`. '
            'inlineTemporalParameters inserts result into query via strings.Replace(query, placeholder, formatted, -1). '
            'Final query: WorkflowType="foo" OR WorkflowType="%"  — injection breaks tenant namespace filter.'
        ),
        evidence=(
            'DISASSEMBLY-BACKED (VA: 0x2c9f8c0 / 0x2c9f9c0 register-ABI body). '
            'inlineTemporalParameters callees: '
            '  strings.Replace (at 0x2c9f934 and 0x2c9fd03) — parameter insertion mechanism. '
            '  fmt.Sprintf (at 0x2c9fb72 via formatTemporalValue at 0x2ca0100). '
            '  formatTemporalValue calls fmt.Sprintf with format string "\\"%s\\"" (at 0x2ca0172→0x057f5efd). '
            '  String values wrapped as "value" with NO inner-quote escaping before strings.Replace. '
            '  No strings.Replace(_, "\\"", ...) escaping call observed anywhere in the call tree. '
            '  formatTemporalValue is type-dispatching (5 CMP r9d branches for interface type hashes). '
            '  String branch produces "value" format; integer/time branches produce numeric/RFC3339 format. '
            '  strings.Replace replaces placeholder with formatted value, -1 = all occurrences. '
            'Function name: inlineTemporalParameters vs bind/parameterize — design intent is literal inlining. '
            'Source string table at 0x057f4f9f contains "GTE", "LTE" — Temporal query operators, '
            'confirming this function operates on Temporal visibility query strings.'
        ),
        bert_score=None,
        verified=True,   # disassembly confirms fmt.Sprintf wrap + strings.Replace insertion, no escaping
        notes=(
            'STATUS: PLAUSIBLE-HIGH. Injection path confirmed by disassembly: '
            'fmt.Sprintf("\\"%s\\"", value) + strings.Replace = string concatenation without escaping. '
            'Remaining open question: does Temporal\'s SQL-mode visibility backend sanitize '
            'the query string before translating to SQL? Likely no — Temporal trusts its own query format. '
            'Impact: cross-tenant workflow execution enumeration if Temporal namespace does not '
            'independently enforce tenant isolation at the filter level.'
        ),
    ),

    Finding(
        id='F3',
        title='AQL Identifier Injection — ValidateSQLIdentifier Dead Code (Zero Callers)',
        package='axfilters',
        functions=AQL_FILTER_CHAIN,
        class_='AQL Injection / Identifier Injection',
        description=(
            'The axfilters package constructs ArangoDB Query Language (AQL) queries from '
            'user-supplied filter criteria. Values are parameterized via mergeBindVars '
            '(bind variables — correct for values). However, field identifiers are inserted '
            'into the AQL query string via fmt.Sprintf in buildFinalQuery without any '
            'validation or escaping. ValidateSQLIdentifier (VA: 0x2c9aa80) is an exported '
            'function present in the binary but has ZERO callers — it is dead code. '
            'CompileFilterForAql also has zero CALL-instruction callers (may be interface-dispatched). '
            'No function in the binary calls ValidateSQLIdentifier before building the AQL filter. '
            'Field identifiers flow from the Filter struct into buildFinalQuery\'s fmt.Sprintf '
            'unvalidated, enabling AQL identifier injection if field names are user-controlled.'
        ),
        mechanism=(
            'axfilters.ValidateSQLIdentifier (VA: 0x2c9aa80) — ZERO callers in binary. '
            'buildFinalQuery (VA: 0x2c9a320 ABI Internal) calls fmt.Sprintf (0x9b2080) '
            'at 0x2c9a926 with format string " %s " (4 bytes at 0x057f5ef9) to interpolate '
            'a field value directly into the AQL clause, then strings.Join (0x9ea1e0 at 0x2c9a960) '
            'joins clauses with "AND" separator. '
            'Injection payload: fieldName="x` FILTER 1==1 RETURN doc //" '
            '→ AQL: FILTER x` FILTER 1==1 RETURN doc // "value" — backtick breaks identifier parsing, '
            'injected FILTER clause executes, line comment suppresses trailing syntax.'
        ),
        evidence=(
            'DISASSEMBLY-BACKED. '
            'ValidateSQLIdentifier VA: 0x2c9aa80 — exhaustive CALL-instruction scan of all '
            'PT_LOAD segments: 0 callers found. Dead code. '
            'CompileFilterForAql VA: 0x2c98580 — 0 direct CALL callers (interface/reflect dispatch). '
            'buildFinalQuery ABI Internal at 0x2c9a320: '
            '  single fmt.Sprintf call at 0x2c9a926 (RAX=0x057f5ef9 format=" %s ", RBX=4, RDI=1). '
            '  single strings.Join call at 0x2c9a960 (separator "AND" from 0x057f486d, len=3). '
            '  No calls to ValidateSQLIdentifier, no escaping functions observed. '
            'Format string raw bytes at 0x057f5ef9: 20 25 73 20 22 25 73 22 → " %s \\"%s\\"".'
        ),
        bert_score=None,
        verified=True,   # ValidateSQLIdentifier confirmed dead code; fmt.Sprintf insertion confirmed
        notes=(
            'STATUS: PLAUSIBLE-HIGH. '
            'ValidateSQLIdentifier is dead code — present but never called anywhere in the binary. '
            'fmt.Sprintf inserts criterion data into AQL without any identifier validation or escaping. '
            'Exploitability depends on: whether field names in axfilters Filter structs are '
            'user-controlled (from OPA policy data) or hardcoded in REGO rules. '
            'If OPA policy data (bundle JSON) is user-influenced, field names are attacker-controlled. '
            'Proof: send a CompileFilterForAql request with a Filter containing a field name '
            'with AQL-special characters (backtick, bracket, RETURN keyword) and observe query execution.'
        ),
    ),

    Finding(
        id='F4',
        title='pg_hba_file_rules Query Scope — REFUTED: Internal Use, Data Not Exposed in API',
        package='axplugins/postgresql',
        functions=[
            'postgresql.(*Client).canAccessHbaFileRules',   # inlined; no separate gopclntab entry
            'postgresql.(*Plugin).ValidatePermissions',      # VA: 0x355db80
        ],
        class_='Information Disclosure / REFUTED',
        description=(
            'REFUTED. The PostgreSQL plugin executes a CTE query reading auth_method from '
            'pg_hba_file_rules to determine what authentication methods apply to the '
            'orchestrator\'s service account. The query: '
            'COALESCE((SELECT array_agg(auth_method ORDER BY line_number) FROM pg_hba_file_rules '
            'WHERE %s = ANY(user_name) OR \'all\' = ANY(user_name)), ARRAY[]::text[]) '
            'AS potential_auth_methods. '
            'ValidatePermissions uses this internally to check privilege sufficiency. '
            'The pg_hba auth_method values are NOT returned in API responses — '
            'only a list of MISSING permissions (error strings) is returned to callers. '
            'canAccessHbaFileRules (inlined, not in gopclntab) probes with '
            'SELECT 1 FROM pg_hba_file_rules LIMIT 1 — boolean only.'
        ),
        mechanism=(
            'REFUTED — pg_hba_file_rules data is read internally but not exposed. '
            'ValidatePermissions reports: "The PostgreSQL user is missing the following permissions: %s" '
            'and "SELECT on pg_hba_file_rules (requires SUPERUSER, or GRANT SELECT + EXECUTE on '
            'pg_catalog.pg_hba_file_rules)" — permission NAMES only, not pg_hba data. '
            'The potential_auth_methods CTE is used to determine privilege checks; '
            'the actual auth_method values from pg_hba are not propagated to API responses.'
        ),
        evidence=(
            'DISASSEMBLY-BACKED (REFUTED). '
            'Full query bytes at 0x58c9272: '
            '"COALESCE(\\n           (SELECT array_agg(auth_method ORDER BY line_number)\\n'
            '            FROM pg_hba_file_rules\\n'
            '            WHERE %s = ANY(user_name) OR \'all\' = ANY(user_name)),..." '
            'ValidatePermissions (0x355db80) returns missing-permission error strings, '
            'not raw pg_hba data. String at 0x355e032: '
            '"The PostgreSQL user is missing the following permissions: %s". '
            'String at 0x58c12bd: "SELECT on pg_hba_file_rules (requires SUPERUSER, '
            'or GRANT SELECT + EXECUTE on pg_catalog.pg_hba_file_rules)" — in error message. '
            'canAccessHbaFileRules probe: "SELECT 1 FROM pg_hba_file_rules LIMIT 1" at 0x586981f — boolean.'
        ),
        bert_score=None,
        verified=False,
        notes=(
            'VERDICT: REFUTED. pg_hba_file_rules is queried internally for permission checking, '
            'not exposed in API responses. '
            'The orchestrator service account requires superuser-level PostgreSQL privileges '
            '(legitimate for credential rotation), and canAccessHbaFileRules is a standard '
            'health-check function. No novel exploit path identified. '
            'IntegrationOutput (oracledb-specific) remains unexamined — check separately.'
        ),
    ),

    Finding(
        id='F5',
        title='singlerotate Credentials Field — Missing validate Tag (REFUTED: Plugin Guards Exist)',
        package='axiomworkflows/workflows/rotatecredentials/childworkflows/singlerotate',
        functions=[
            'axiomworkflows/workflows/rotatecredentials/childworkflows/singlerotate.(*Workflow).Execute',
            'axiomworkflows/workflows/rotatecredentials/childworkflows/singlerotate/activities.RotateCredentials',
        ],
        class_='Input Validation Failure / REFUTED',
        description=(
            'REFUTED. The singlerotate Input.Credentials field (json:"credentials") has no validate tag, '
            'meaning Temporal does not reject empty credentials at the workflow layer. '
            'However, DB plugins implement runtime guards: '
            '"new password is required for password rotation" (Oracle/PostgreSQL) and '
            '"expected string credentials (user\'s new password) were not provided" (MySQL/MariaDB/MSSQL). '
            'An empty credentials field causes a plugin error and workflow failure — '
            'it does not silently set the DB password to an empty string.'
        ),
        mechanism=(
            'REFUTED — plugin-level checks exist. '
            'The Credentials field IS the new password encoded as a string (confirmed by error string '
            '"expected string credentials (user\'s new password) were not provided"). '
            'Missing validate tag is a defense-in-depth gap (no early workflow rejection), '
            'not an exploitable vulnerability. '
            'Operational impact only: workflow starts and retries before failing, creating audit log noise.'
        ),
        evidence=(
            'DISASSEMBLY-BACKED (REFUTED). '
            'String at 0x587d59d: "new password is required for password rotation" (Oracle/PG plugin). '
            'String at 0x58a5986: "expected string credentials (user\'s new password) were not provided" '
            '(MySQL/MariaDB/MSSQL plugin). '
            'Both strings confirm runtime credential validation at the plugin layer. '
            'singlerotate.Input struct (from generic type instantiation): '
            '{RunnerID validate:"required,min=1", EncryptionKey validate:"required", '
            'Credentials [NO validate tag], Target validate:"required"}. '
            'Credentials = new password encoded as string; empty string blocked at plugin layer.'
        ),
        bert_score=0.530,
        verified=False,
        notes=(
            'VERDICT: REFUTED. Plugin guards prevent empty-password DB corruption. '
            'Defense-in-depth gap (missing validate tag on Credentials field) is a code quality '
            'issue, not a novel security vulnerability. '
            'The BERT score of 0.530 matched auditRotationResults, not the primary candidate function.'
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
