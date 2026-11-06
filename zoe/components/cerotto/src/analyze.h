#ifndef AF_ANALYZE_H
#define AF_ANALYZE_H

#include "db.h"
#include "timeline.h"

#include <cJSON.h>

cJSON *af_analysis_document_parse(const char *text, cJSON *timeline);
int af_analyze(af_db *db, const af_timeline_query *query, FILE *output);

#endif
