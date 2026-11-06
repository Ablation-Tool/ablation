#include "forecast.h"
#include "util.h"

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define AF_FORECAST_MAX_VOCABULARY 100000

static const double thresholds[AF_FORECAST_THRESHOLD_COUNT] = {0.02, 0.05, 0.10, 0.15, 0.30, 0.50};

int af_forecast_measure(cJSON *probabilities, af_forecast_measurement *measurement) {
    int count;
    int index;
    int threshold;
    long double sum = 0.0;
    long double entropy = 0.0;
    double top[10] = {0};
    unsigned char *packed = NULL;
    if (!probabilities || !measurement || sizeof(double) != sizeof(uint64_t)) {
        return -1;
    }
    count = cJSON_GetArraySize(probabilities);
    if (count < 1 || count > AF_FORECAST_MAX_VOCABULARY) {
        return -1;
    }
    memset(measurement, 0, sizeof(*measurement));
    measurement->vocabulary_size = (size_t)count;
    packed = malloc((size_t)count * sizeof(uint64_t));
    if (!packed) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        cJSON *item = cJSON_GetArrayItem(probabilities, index);
        double value;
        uint64_t bits;
        int byte;
        if (!cJSON_IsNumber(item) || !isfinite(item->valuedouble) || item->valuedouble < 0) {
            goto failure;
        }
        value = item->valuedouble;
        sum += value;
        if (value > 0) {
            entropy -= value * log2(value);
        }
        if (value > measurement->max_probability) {
            measurement->max_probability = value;
        }
        for (threshold = 0; threshold < AF_FORECAST_THRESHOLD_COUNT; ++threshold) {
            if (value > thresholds[threshold]) {
                ++measurement->accessible_volume[threshold];
            }
        }
        if (value > top[9]) {
            int position = 9;
            while (position > 0 && value > top[position - 1]) {
                top[position] = top[position - 1];
                --position;
            }
            top[position] = value;
        }
        memcpy(&bits, &value, sizeof(bits));
        for (byte = 0; byte < 8; ++byte) {
            packed[index * 8 + byte] = (unsigned char)(bits >> (byte * 8));
        }
    }
    if (fabsl(sum - 1.0L) > 1e-8L || af_sha256_bytes(packed, (size_t)count * sizeof(uint64_t), measurement->probability_values_sha256) != 0) {
        goto failure;
    }
    measurement->probability_sum = (double)sum;
    measurement->entropy_bits = (double)entropy;
    for (index = 0; index < 10; ++index) {
        measurement->top_10_probability_mass += top[index];
    }
    free(packed);
    return 0;
failure:
    free(packed);
    return -1;
}

cJSON *af_forecast_measurement_json(const af_forecast_measurement *measurement) {
    cJSON *root = NULL;
    cJSON *sweep = NULL;
    int index;
    if (!measurement) {
        return NULL;
    }
    root = cJSON_CreateObject();
    if (!root || !cJSON_AddNumberToObject(root, "schema_version", 1) ||
        !cJSON_AddStringToObject(root, "instrument", "next-token-accessible-volume") ||
        !cJSON_AddStringToObject(root, "measurement_point", "pre_execution") ||
        !cJSON_AddNumberToObject(root, "vocabulary_size", (double)measurement->vocabulary_size) ||
        !cJSON_AddNumberToObject(root, "probability_sum", measurement->probability_sum) ||
        !cJSON_AddStringToObject(root, "probability_values_sha256", measurement->probability_values_sha256) ||
        !cJSON_AddNumberToObject(root, "entropy_bits", measurement->entropy_bits) ||
        !cJSON_AddNumberToObject(root, "max_probability", measurement->max_probability) ||
        !cJSON_AddNumberToObject(root, "top_10_probability_mass", measurement->top_10_probability_mass)) {
        goto failure;
    }
    sweep = cJSON_AddArrayToObject(root, "threshold_sweep");
    if (!sweep) {
        goto failure;
    }
    for (index = 0; index < AF_FORECAST_THRESHOLD_COUNT; ++index) {
        cJSON *entry = cJSON_CreateObject();
        if (!entry || !cJSON_AddNumberToObject(entry, "tau", thresholds[index]) ||
            !cJSON_AddNumberToObject(entry, "accessible_volume", (double)measurement->accessible_volume[index]) ||
            !cJSON_AddNumberToObject(entry, "normalized_accessible_volume",
                                      (double)measurement->accessible_volume[index] / (double)measurement->vocabulary_size) ||
            !cJSON_AddItemToArray(sweep, entry)) {
            cJSON_Delete(entry);
            goto failure;
        }
    }
    return root;
failure:
    cJSON_Delete(root);
    return NULL;
}
