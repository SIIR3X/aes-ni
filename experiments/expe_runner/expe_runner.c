#include "expe_runner/expe_runner.h"
#include "expe_config/expe_config.h"
#include "expe_utils/expe_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void prepare_benchmark(benchmark_config_t* config, benchmark_data_t* data)
{
	if (config == NULL || data == NULL) return;

	printf("\n[===== Preparing AES Benchmark =====]\n");

	data->input = (uint8_t*)malloc(config->data_size);
	data->key = (uint8_t*)malloc(config->key_size);
	if (data->input == NULL || data->key == NULL)
	{
		fprintf(stderr, "prepare_benchmark: Memory allocation failed\n");
		return;
	}

	printf("[ Generating random data... (%zu bytes) ]\n", config->data_size);
	fill_random(data->input, config->data_size);

	printf("[ Generating random key... (%u bytes) ]\n", config->key_size);
	fill_random(data->key, config->key_size);

	printf("[ Generating random IV... (%zu bytes) ]\n", sizeof(data->iv));
	fill_random(data->iv, sizeof(data->iv));

	aes_context_init(&data->ctx, data->key, config->key_size);

	printf("[===== AES Benchmark Prepared =====]\n");
}

void free_benchmark_data(benchmark_data_t* data)
{
	if (data == NULL) return;

	free(data->input);
	free(data->key);
}

void run_benchmark(benchmark_config_t* config)
{
	if (config == NULL) return;

	benchmark_data_t data;

	prepare_benchmark(config, &data);

	printf("\n[===== Running AES Benchmark =====]\n");

	for (size_t i = 0; i < config->num_modes; ++i)
	{
		benchmark_mode_t* mode = &config->modes[i];

		for (size_t j = 0; j < config->num_iterations; ++j)
		{
			benchmark_mode(&data.ctx, mode, data.iv, data.input, config->data_size);
			printf("[ %s %zu/%zu ]\n", mode->def->name, j + 1, config->num_iterations);
		}
	}

	printf("[===== Finished AES Benchmark =====]\n");

	free_benchmark_data(&data);
}