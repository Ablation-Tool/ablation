#ifndef AF_FORECAST_H
#define AF_FORECAST_H

#include <cJSON.h>
#include <stddef.h>

#define AF_FORECAST_THRESHOLD_COUNT 6

typedef struct {
    size_t vocabulary_size;
    double probability_sum;
    double entropy_bits;
    double max_probability;
    double top_10_probability_mass;
    size_t accessible_volume[AF_FORECAST_THRESHOLD_COUNT];
    char probability_values_sha256[65];
} af_forecast_measurement;

int af_forecast_measure(cJSON *probabilities, af_forecast_measurement *measurement);
cJSON *af_forecast_measurement_json(const af_forecast_measurement *measurement);

#endif
