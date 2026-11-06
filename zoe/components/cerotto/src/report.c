#include "report.h"
#include "analyze.h"
#include "manifest.h"
#include "util.h"

#include <cJSON.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REPORT_ANALYSIS_LIMIT (8U * 1024U * 1024U)

static int add_owned(cJSON *object, const char *name, cJSON *value) {
    if (!value) {
        return -1;
    }
    if (!cJSON_AddItemToObject(object, name, value)) {
        cJSON_Delete(value);
        return -1;
    }
    return 0;
}

static char *read_analysis(const char *path) {
    FILE *file = fopen(path, "rb");
    af_buffer content;
    char chunk[16384];
    size_t length;
    if (!file) {
        return NULL;
    }
    af_buf_init(&content);
    while ((length = fread(chunk, 1, sizeof(chunk), file)) > 0) {
        if (length > REPORT_ANALYSIS_LIMIT - content.len || af_buf_append(&content, chunk, length) != 0) {
            fclose(file);
            af_buf_free(&content);
            return NULL;
        }
    }
    if (ferror(file) || fclose(file) != 0) {
        af_buf_free(&content);
        return NULL;
    }
    return af_buf_take(&content);
}

static int markdown_text(af_buffer *output, const char *text) {
    const unsigned char *cursor = (const unsigned char *)(text ? text : "");
    while (*cursor) {
        const char *replacement = NULL;
        switch (*cursor) {
            case '&': replacement = "&amp;"; break;
            case '<': replacement = "&lt;"; break;
            case '>': replacement = "&gt;"; break;
            case '|': replacement = "&#124;"; break;
            case '`': replacement = "&#96;"; break;
            case '[': replacement = "&#91;"; break;
            case ']': replacement = "&#93;"; break;
            case '\\': replacement = "&#92;"; break;
            case '\n': case '\r': replacement = " "; break;
            default: break;
        }
        if (*cursor < 0x20 && *cursor != '\t' && *cursor != '\n' && *cursor != '\r') {
            ++cursor;
            continue;
        }
        if (replacement) {
            if (af_buf_append(output, replacement, strlen(replacement)) != 0) return -1;
        } else if (af_buf_append(output, cursor, 1) != 0) {
            return -1;
        }
        ++cursor;
    }
    return 0;
}

static const char *json_string(cJSON *object, const char *name) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    return cJSON_IsString(item) ? item->valuestring : "";
}

static int markdown_citations(af_buffer *output, cJSON *finding) {
    cJSON *citations = cJSON_GetObjectItemCaseSensitive(finding, "event_ids");
    cJSON *citation;
    int first = 1;
    cJSON_ArrayForEach(citation, citations) {
        if (!cJSON_IsString(citation)) return -1;
        if (!first && af_buf_append(output, ", ", 2) != 0) return -1;
        if (markdown_text(output, citation->valuestring) != 0) return -1;
        first = 0;
    }
    return 0;
}

static int markdown_literal(af_buffer *output, const char *text) {
    return af_buf_append(output, text, strlen(text));
}

static int markdown_report(cJSON *root, af_buffer *output) {
    cJSON *timeline = cJSON_GetObjectItemCaseSensitive(root, "timeline");
    cJSON *manifest = cJSON_GetObjectItemCaseSensitive(root, "manifest");
    cJSON *review = cJSON_GetObjectItemCaseSensitive(root, "review");
    cJSON *document = cJSON_GetObjectItemCaseSensitive(root, "analysis");
    cJSON *events = cJSON_GetObjectItemCaseSensitive(timeline, "events");
    cJSON *sources = cJSON_GetObjectItemCaseSensitive(manifest, "sources");
    cJSON *item;
    if (markdown_literal(output, "# CEROTTO investigation report\n\n") != 0 ||
        markdown_literal(output, "- **Case:** ") != 0 || markdown_text(output, json_string(root, "case_id")) != 0 ||
        markdown_literal(output, "\n- **Conversation:** ") != 0 ||
        markdown_text(output, json_string(timeline, "conversation_id")) != 0 ||
        markdown_literal(output, "\n- **Generated:** ") != 0 ||
        markdown_text(output, json_string(root, "generated_at")) != 0 ||
        markdown_literal(output, "\n- **Review:** ") != 0 ||
        markdown_text(output, json_string(review, "status")) != 0) {
        return -1;
    }
    if (json_string(review, "reviewer")[0]) {
        if (markdown_literal(output, " by ") != 0 || markdown_text(output, json_string(review, "reviewer")) != 0) return -1;
    }
    if (markdown_literal(output, "\n\n## Evidence sources\n\n| ID | Kind | Status | Origin | SHA-256 (first 12) |\n|---|---|---|---|---|\n") != 0) {
        return -1;
    }
    cJSON_ArrayForEach(item, sources) {
        if (af_buf_printf(output, "| %.0f | ", cJSON_GetObjectItemCaseSensitive(item, "id")->valuedouble) != 0 ||
            markdown_text(output, json_string(item, "kind")) != 0 || markdown_literal(output, " | ") != 0 ||
            markdown_text(output, json_string(item, "status")) != 0 || markdown_literal(output, " | ") != 0 ||
            markdown_text(output, json_string(item, "origin_path")) != 0 ||
            af_buf_printf(output, " | %.12s |\n", json_string(item, "sha256")) != 0) {
            return -1;
        }
    }
    if (markdown_literal(output, "\n## Timeline\n\n| Observed at | Event | PID | PPID | Path | Event ID |\n|---|---|---:|---:|---|---|\n") != 0) {
        return -1;
    }
    cJSON_ArrayForEach(item, events) {
        cJSON *pid = cJSON_GetObjectItemCaseSensitive(item, "process_id");
        cJSON *ppid = cJSON_GetObjectItemCaseSensitive(item, "parent_process_id");
        if (markdown_literal(output, "| ") != 0 || markdown_text(output, json_string(item, "observed_at")) != 0 ||
            markdown_literal(output, " | ") != 0 || markdown_text(output, json_string(item, "event_type")) != 0 ||
            markdown_literal(output, " | ") != 0) {
            return -1;
        }
        if (cJSON_IsNumber(pid)) {
            if (af_buf_printf(output, "%.0f", pid->valuedouble) != 0) return -1;
        } else if (markdown_literal(output, "-") != 0) return -1;
        if (markdown_literal(output, " | ") != 0) return -1;
        if (cJSON_IsNumber(ppid)) {
            if (af_buf_printf(output, "%.0f", ppid->valuedouble) != 0) return -1;
        } else if (markdown_literal(output, "-") != 0) return -1;
        if (markdown_literal(output, " | ") != 0 || markdown_text(output, json_string(item, "path")) != 0 ||
            markdown_literal(output, " | ") != 0 || markdown_text(output, json_string(item, "event_id")) != 0 ||
            markdown_literal(output, " |\n") != 0) {
            return -1;
        }
    }
    if (markdown_literal(output, "\n## Analysis\n\n") != 0) {
        return -1;
    }
    if (!cJSON_IsObject(document)) {
        return markdown_literal(output, "No LLM analysis supplied.\n");
    }
    {
        cJSON *analysis = cJSON_GetObjectItemCaseSensitive(document, "analysis");
        cJSON *observations = cJSON_GetObjectItemCaseSensitive(analysis, "observations");
        cJSON *hypotheses = cJSON_GetObjectItemCaseSensitive(analysis, "hypotheses");
        cJSON *limitations = cJSON_GetObjectItemCaseSensitive(analysis, "limitations");
        if (markdown_literal(output, "**Model:** ") != 0 ||
            markdown_text(output, json_string(document, "model")) != 0 ||
            markdown_literal(output, "\n\n") != 0 || markdown_text(output, json_string(analysis, "summary")) != 0 ||
            markdown_literal(output, "\n\n### Observations\n\n") != 0) {
            return -1;
        }
        cJSON_ArrayForEach(item, observations) {
            if (markdown_literal(output, "- ") != 0 || markdown_text(output, json_string(item, "description")) != 0 ||
                markdown_literal(output, " [events: ") != 0 || markdown_citations(output, item) != 0 ||
                markdown_literal(output, "]\n") != 0) return -1;
        }
        if (markdown_literal(output, "\n### Hypotheses\n\n") != 0) return -1;
        cJSON_ArrayForEach(item, hypotheses) {
            if (markdown_literal(output, "- **") != 0 || markdown_text(output, json_string(item, "confidence")) != 0 ||
                markdown_literal(output, ":** ") != 0 || markdown_text(output, json_string(item, "description")) != 0 ||
                markdown_literal(output, " [events: ") != 0 || markdown_citations(output, item) != 0 ||
                markdown_literal(output, "]\n") != 0) return -1;
        }
        if (markdown_literal(output, "\n### Limitations\n\n") != 0) return -1;
        cJSON_ArrayForEach(item, limitations) {
            if (markdown_literal(output, "- ") != 0 || markdown_text(output, item->valuestring) != 0 ||
                markdown_literal(output, "\n") != 0) return -1;
        }
    }
    return markdown_literal(output, "\nReview status is a human attestation, not a cryptographic signature.\n");
}

int af_report_write(af_db *db, const af_timeline_query *query, const char *analysis_path,
                    const char *format, const char *reviewer, const char *review_status,
                    FILE *output) {
    af_buffer timeline;
    af_buffer rendered;
    cJSON *root = NULL;
    cJSON *timeline_json = NULL;
    cJSON *analysis_document = NULL;
    char *analysis_text = NULL;
    char generated_at[AF_TIMESTAMP_SIZE];
    char *printed = NULL;
    int result = -1;
    af_buf_init(&timeline);
    af_buf_init(&rendered);
    if (strcmp(format, "json") && strcmp(format, "markdown")) {
        af_error("report format must be json or markdown");
        goto cleanup;
    }
    if (strcmp(review_status, "unreviewed") && strcmp(review_status, "reviewed") &&
        strcmp(review_status, "approved") && strcmp(review_status, "rejected")) {
        af_error("invalid review status");
        goto cleanup;
    }
    if ((strcmp(review_status, "unreviewed") != 0 && (!reviewer || !reviewer[0])) ||
        (reviewer && reviewer[0] && !strcmp(review_status, "unreviewed"))) {
        af_error("reviewed decisions require --reviewer, and unreviewed reports cannot include one");
        goto cleanup;
    }
    if (af_timeline_build(db, query, &timeline) != 0 || af_now(generated_at) != 0) {
        goto cleanup;
    }
    timeline_json = cJSON_ParseWithLength(timeline.data, timeline.len);
    if (!timeline_json) {
        goto cleanup;
    }
    if (analysis_path) {
        analysis_text = read_analysis(analysis_path);
        analysis_document = analysis_text ? af_analysis_document_parse(analysis_text, timeline_json) : NULL;
        if (!analysis_document) {
            af_error("analysis file is invalid or cites events outside the report timeline");
            goto cleanup;
        }
    }
    root = cJSON_CreateObject();
    if (!root || !cJSON_AddStringToObject(root, "format", "cerotto-investigation-report-v1") ||
        !cJSON_AddStringToObject(root, "case_id", query->case_id) ||
        !cJSON_AddStringToObject(root, "generated_at", generated_at) ||
        !cJSON_AddStringToObject(root, "review_status", review_status) ||
        !cJSON_AddStringToObject(root, "reviewer", reviewer ? reviewer : "") ||
        add_owned(root, "manifest", af_manifest_create(db, query->case_id)) != 0 ||
        add_owned(root, "timeline", cJSON_Duplicate(timeline_json, 1)) != 0 ||
        add_owned(root, "analysis", analysis_document ? cJSON_Duplicate(analysis_document, 1) : cJSON_CreateNull()) != 0) {
        goto cleanup;
    }
    {
        cJSON *review = cJSON_CreateObject();
        if (!review || !cJSON_AddStringToObject(review, "status", review_status) ||
            !cJSON_AddStringToObject(review, "reviewer", reviewer ? reviewer : "") ||
            !cJSON_AddStringToObject(review, "attestation", "Human-provided review status; not a cryptographic signature.") ||
            add_owned(root, "review", review) != 0) {
            goto cleanup;
        }
    }
    if (!strcmp(format, "json")) {
        printed = cJSON_Print(root);
        if (!printed || fputs(printed, output) == EOF || fputc('\n', output) == EOF) {
            goto cleanup;
        }
    } else {
        if (markdown_report(root, &rendered) != 0 ||
            fwrite(rendered.data, 1, rendered.len, output) != rendered.len) {
            af_error("cannot render Markdown report");
            goto cleanup;
        }
    }
    result = 0;
cleanup:
    free(analysis_text);
    free(printed);
    cJSON_Delete(root);
    cJSON_Delete(timeline_json);
    cJSON_Delete(analysis_document);
    af_buf_free(&timeline);
    af_buf_free(&rendered);
    return result;
}
