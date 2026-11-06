#ifndef AF_COLLECTOR_TSK_H
#define AF_COLLECTOR_TSK_H

#include "db.h"

#include <stddef.h>

int af_collect_tsk_impl(af_db *db, const char *case_id, const char *image_path,
                        const char *output_dir, const char *host_id, int ewf, size_t *count);

#endif
