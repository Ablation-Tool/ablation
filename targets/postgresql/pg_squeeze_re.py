"""
RE module: pg_squeeze master (source-only PostgreSQL extension)
Source ZIP: pg_squeeze-master.zip
Path (extracted): /tmp/pgsqueeze/pg_squeeze-master/

Files analyzed:
  concurrent.c   795 lines   tuple serialization / change capture
  worker.c      2193 lines   background worker / SQL generation
  pg_squeeze.c  3433 lines   main extension entry points
  pg_squeeze.h   429 lines   struct definitions
  pgstatapprox.c 313 lines   statistics

Architecture:
  Background worker reads from logical decoding stream.
  Changes serialized as bytea (ConcurrentChange struct + raw HeapTupleData)
  into Tuplestorestate. Consumed by process_concurrent_changes(), deserialized
  via get_changed_tuple(), inserted into transient table via heap_insert().
  Table names flow from squeeze.tables -> WorkerTask shared-memory struct ->
  background worker SQL string construction.
"""

# ============================================================
# TARGET METADATA
# ============================================================

PRODUCT = "pg_squeeze"
VERSION = "master"
VENDOR = "cybertec"
SOURCE_TYPE = "c_extension"

# ============================================================
# CONFIRMED FINDINGS
# ============================================================

# F1: Unquoted ANALYZE on user-controlled table name
# Severity: HIGH (SQL injection in background worker, requires squeeze.tables write access)
#
# Location: worker.c:1851-1853
# Function: squeeze_table_impl() (post-completion ANALYZE path)
#
# Code:
#   appendStringInfo(&query, "ANALYZE %s.%s",
#                    NameStr(*relschema),
#                    NameStr(*relname));
#   run_command(query.data, SPI_OK_UTILITY);
#
# No quote_identifier() applied to relschema or relname.
# Values come from WorkerTask.relschema / WorkerTask.relname (NameData, NAMEDATALEN=64).
# Set via namestrcpy() from squeeze_table() args or from squeeze.tables scheduler read.
#
# Attack path (scheduler mode):
#   1. INSERT INTO squeeze.tables (tabschema, tabname, ...) VALUES ('public', 'x; <payload>', ...)
#      requires INSERT on squeeze.tables (non-superuser attacker with that grant)
#   2. Scheduler worker picks up the task, sets task->relname = 'x; <payload>'
#   3. Worker completes the squeeze, then builds:
#      ANALYZE public.x; <payload>
#      run_command() executes it via SPI with superuser context
#
# CIA:
#   C: arbitrary SQL in superuser SPI context -> full database read
#   I: arbitrary DML/DDL
#   A: DROP TABLE, DROP SCHEMA, etc.
#
# Constraint: NameData is 64 bytes max; payload fits within NAMEDATALEN - 1 (63 chars).
# A minimal payload: '; SELECT pg_read_file('/etc/passwd')-- fits in 63 chars (43 chars used).
# Superuser functions like pg_read_file, pg_write_file, COPY TO/FROM available in SPI context.
#
# Fix: wrap with quote_identifier():
#   appendStringInfo(&query, "ANALYZE %s.%s",
#                    quote_identifier(NameStr(*relschema)),
#                    quote_identifier(NameStr(*relname)));


# F2: Unquoted relschema/relname in squeeze.log INSERT
# Severity: MEDIUM (second-order SQL injection in logging path)
#
# Location: worker.c:1813-1822
# Function: squeeze_table_impl() (success logging path)
#
# Code:
#   appendStringInfo(&query,
#       "INSERT INTO squeeze.log(tabschema, tabname, started, finished, ...) \
#   VALUES ('%s', '%s', '%s', clock_timestamp(), %ld, %ld, %ld, %ld)",
#       NameStr(*relschema),
#       NameStr(*relname),
#       start_ts_str, ...);
#   run_command(query.data, SPI_OK_INSERT);
#
# relschema and relname are interpolated as raw '%s' inside single quotes.
# A name containing a single quote (e.g. "o'reilly") breaks the literal.
# A name containing ','  or closing quote + SQL could inject full statements.
#
# Same attack path as F1 (requires squeeze.tables write).
# Exploitability lower than F1 because the payload must survive as a relname
# that also successfully completes the squeeze operation first.
#
# Fix: use quote_literal_cstr() consistently:
#   VALUES (%s, %s, ...)
#   quote_literal_cstr(NameStr(*relschema)),
#   quote_literal_cstr(NameStr(*relname)),


# F3: Unquoted relschema/relname in squeeze.errors INSERT
# Severity: MEDIUM (same class as F2, triggered on error path)
#
# Location: worker.c:1881-1888
# Function: squeeze_handle_error_app()
#
# Code:
#   appendStringInfo(&query,
#       "INSERT INTO squeeze.errors(tabschema, tabname, sql_state, err_msg, err_detail) \
#   VALUES ('%s', '%s', '%s', %s, %s)",
#       NameStr(task->relschema),
#       NameStr(task->relname),
#       unpack_sql_state(edata->sqlerrcode),
#       quote_literal_cstr(edata->message),          <- properly quoted
#       edata->detail ? quote_literal_cstr(edata->detail) : "''");  <- properly quoted
#
# Inconsistent: message and detail are properly escaped; schema and table are not.
# Fix: apply quote_literal_cstr() to relschema and relname columns.


# ============================================================
# SURFACE AREA NOT AFFECTED
# ============================================================

# HeapTupleHeaderData / t_hoff / BITMAPLEN / MAXALIGN:
#   pg_squeeze does NOT parse raw tuple headers. It uses PostgreSQL's standard
#   infrastructure: heap_insert, logical decoding callbacks, SPI. The attack
#   scenarios involving forged HeapTupleHeader fields do not apply here.
#
#   store_change() at concurrent.c:712:
#     size = MAXALIGN(VARHDRSZ) + sizeof(ConcurrentChange) + tuple->t_len;
#     if (size >= 0x3FFFFFFF) elog(ERROR, ...);
#   MAXALIGN here is on the bytea wrapper, not on tuple header fields.
#   tuple->t_len is from the logical decoding callback (trusted PG internals).
#
#   get_changed_tuple() at concurrent.c:768-774:
#     memcpy(&tup_data, &change->tup_data, sizeof(HeapTupleData));  <- alignment fix
#     result = palloc(HEAPTUPLESIZE + tup_data.t_len);
#     memcpy(result->t_data, src, result->t_len);
#   Allocation size == copy size == original t_len. No overflow.
#   t_data pointer is explicitly rebuilt at line 772 (not reused from storage).


# ============================================================
# ABLATION IMPROVEMENTS
# ============================================================

# Pattern: PostgreSQL C extension SQL injection via unquoted Name values.
# Gap identified: no ablation module scans C source for appendStringInfo/sprintf
# patterns where Name-typed values are interpolated without quote_identifier()
# or quote_literal_cstr().
#
# Proposed module: analyzers/pg_ext_sqli_scanner.py
# Target: C source files for PostgreSQL extensions
# Detection: regex for appendStringInfo/sprintf + format string containing '%s'
#   where the corresponding argument is NameStr(), but not wrapped in quote_identifier()
#   or quote_literal_cstr().
# Signal: all three findings in pg_squeeze match this exact pattern.
# Also catches: the pg_repack repack_apply pattern (direct CSTRING arg passing to SPI).
