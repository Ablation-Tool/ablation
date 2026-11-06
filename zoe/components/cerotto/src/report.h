#ifndef AF_REPORT_H
#define AF_REPORT_H

#include "timeline.h"

#include <stdio.h>

int af_report_write(af_db *db, const af_timeline_query *query, const char *analysis_path,
                    const char *format, const char *reviewer, const char *review_status,
                    FILE *output);

#endif
