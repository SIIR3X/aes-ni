#include "expe_utils/expe_utils.h"
#include "expe_config/expe_config.h"
#include "expe_runner/expe_runner.h"
#include "aes/core/aes_constants.h"
#include <stdio.h>

int main(int argc, char* argv[])
{
	if (argc != 4)
	{
		printf("Usage:\n");
		printf("  %s <data_size_mb> <num_iterations> <key_size>\n", argv[0]);
		return 1;
	}

	size_t data_size = MB((size_t)atoi(argv[1]));
	size_t num_iterations = (size_t)atoi(argv[2]);
	size_t key_size = (size_t)atoi(argv[3]);

	if (data_size <= 0 || num_iterations <= 0 || (key_size != AES_128_KEY_SIZE && key_size != AES_192_KEY_SIZE && key_size != AES_256_KEY_SIZE))
	{
		printf("Usage:\n");
		printf("  %s <data_size_mb> <num_iterations> <key_size>\n", argv[0]);
		return 1;
	}

	aes_key_size_t aes_key_size = key_size;

	printf("[========== AES Benchmarking =========]\n");

	benchmark_config_t* config = create_benchmark_config(data_size, num_iterations, aes_key_size);

	print_benchmark_config(config);

	run_benchmark(config);

	print_result(config->modes, config->data_size, config->num_iterations);

	free_benchmark_config(config);

	printf("\n[======================================]\n");

	return 0;
}