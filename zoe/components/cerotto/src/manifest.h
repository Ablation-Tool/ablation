#ifndef AF_MANIFEST_H
#define AF_MANIFEST_H

#include "db.h"
#include "util.h"

#include <cJSON.h>
#include <stdio.h>

cJSON *af_manifest_create(af_db *db, const char *case_id);
int af_manifest_write(af_db *db, const char *case_id, FILE *output);
int af_verify_case(af_db *db, const char *case_id, const char *base_path, FILE *output);

#endif
