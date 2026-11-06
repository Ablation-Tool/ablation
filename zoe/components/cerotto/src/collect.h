#ifndef AF_COLLECT_H
#define AF_COLLECT_H

#include "db.h"

#include <stddef.h>

int af_collect_tsk(af_db *db, const char *case_id, const char *image_path,
                   const char *output_dir, const char *host_id, size_t *count);
int af_collect_ewf(af_db *db, const char *case_id, const char *image_path,
                   const char *output_dir, const char *host_id, size_t *count);

#endif
