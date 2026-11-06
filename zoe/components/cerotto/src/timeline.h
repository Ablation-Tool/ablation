#ifndef AF_TIMELINE_H
#define AF_TIMELINE_H

#include "db.h"
#include "util.h"

#include <stddef.h>

typedef struct {
    const char *case_id;
    const char *conversation_id;
    const char *host_id;
    const char *from;
    const char *to;
    size_t limit;
    int metadata_only;
} af_timeline_query;

int af_timeline_build(af_db *db, const af_timeline_query *query, af_buffer *json);
int af_timeline_write(af_db *db, const af_timeline_query *query, FILE *output);

#endif
