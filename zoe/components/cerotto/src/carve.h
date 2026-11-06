#ifndef AF_CARVE_H
#define AF_CARVE_H

#include "db.h"

#include <stddef.h>

int af_carve(af_db *db, const char *case_id, const char *image_path,
             const char *output_dir, const char *host_id, const char *carver,
             size_t *count);

#endif
