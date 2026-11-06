#ifndef AF_AUDIT_H
#define AF_AUDIT_H

#include "db.h"

#include <stddef.h>

int af_ingest_audit(af_db *db, const char *case_id, const char *input_path,
                    const char *host_id, int64_t source_id, size_t *count);

#endif
