#ifndef AF_ARTIFACT_H
#define AF_ARTIFACT_H

#include "db.h"

#include <stddef.h>
#include <stdio.h>

int af_artifact_show(af_db *db, const char *case_id, int64_t source_id,
                     const char *format, size_t max_bytes, const char *base_path,
                     FILE *output);

#endif
