#include "collect.h"
#include "collector_tsk.h"

int af_collect_tsk(af_db *db, const char *case_id, const char *image_path,
                   const char *output_dir, const char *host_id, size_t *count) {
    return af_collect_tsk_impl(db, case_id, image_path, output_dir, host_id, 0, count);
}
