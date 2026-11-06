#ifndef AF_EVENT_H
#define AF_EVENT_H

#include "db.h"

#include <stddef.h>

int af_ingest_jsonl(af_db *db, const char *case_id, const char *input_path,
                    int64_t source_id, size_t *count);

#endif
