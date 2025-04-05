#ifndef EXPE_CONFIG_H
#define EXPE_CONFIG_H

#include "expe_modes/expe_modes.h"
#include "aes/core/aes_context.h"

typedef struct {
	size_t data_size;
	size_t num_iterations;
	aes_key_size_t key_size;
	benchmark_mode_t* modes;
	size_t num_modes;
} benchmark_config_t;

benchmark_config_t* create_benchmark_config(size_t data_size, size_t num_iterations, aes_key_size_t key_size);

void print_benchmark_config(const benchmark_config_t* config);

void free_benchmark_config(benchmark_config_t* config);

#endif // EXPE_CONFIG_H