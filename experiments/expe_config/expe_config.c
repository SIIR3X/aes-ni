#include "expe_config/expe_config.h"
#include <stdio.h>
#include <stdlib.h>

benchmark_config_t* create_benchmark_config(size_t data_size, size_t num_iterations, aes_key_size_t key_size) {
	benchmark_config_t* config = (benchmark_config_t*)malloc(sizeof(benchmark_config_t));
	if (!config) return NULL;

	config->data_size = data_size;
	config->num_iterations = num_iterations;
	config->key_size = key_size;
	
	config->modes = (benchmark_mode_t*)malloc(NUM_MODES * sizeof(benchmark_mode_t));
	if (!config->modes)
	{
		fprintf(stderr, "create_benchmark_config: Memory allocation failed\n");
		free(config);
		return NULL;
	}

	for (size_t i = 0; i < NUM_MODES; ++i)
	{
		config->modes[i].def = &MODES[i];
		config->modes[i].result = (benchmark_mode_result_t){0, 0};
	}

	config->num_modes = NUM_MODES;

	return config;
}

void print_benchmark_config(const benchmark_config_t* config)
{
	if (!config) return;

	printf("\n[======== Benchmark Config =======]\n");
	printf("[ Data Size: %zu bytes ]\n", config->data_size);
	printf("[ Number of Iterations: %zu ]\n", config->num_iterations);
	printf("[ Key Size: %u bits ]\n", config->key_size * 8);
	printf("[ Number of Modes: %zu ]\n", config->num_modes);
	for (size_t i = 0; i < config->num_modes; ++i)
		printf("[ Mode %zu: %s ]\n", i + 1, config->modes[i].def->name);
	printf("[=================================]\n");
}

void free_benchmark_config(benchmark_config_t* config)
{
	if (!config) return;

	free(config->modes);
	free(config);
}