#ifndef EXPE_RUNNER_H
#define EXPE_RUNNER_H

#include "expe_config/expe_config.h"
#include "aes/core/aes_context.h"

typedef struct {
	uint8_t* input;
	uint8_t* key;
	uint8_t iv[16];
	aes_context_t ctx;
} benchmark_data_t;

void prepare_benchmark(benchmark_config_t* config, benchmark_data_t* data);

void free_benchmark_data(benchmark_data_t* data);

void run_benchmark(benchmark_config_t* config);

#endif // EXPE_RUNNER_H