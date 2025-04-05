#include "expe_modes/expe_modes.h"
#include "expe_utils/expe_utils.h"
#include "expe_wrappers/expe_wrappers.h"
#include "aes/modes/aes_cbc.h"
#include "aes/modes/aes_cfb.h"
#include "aes/modes/aes_ofb.h"
#include "aes/modes/aes_ctr.h"
#include <stdio.h>
#include <stdlib.h>

const benchmark_mode_def_t MODES[] = {
	{"ECB", benchmark_ecb_encrypt, benchmark_ecb_decrypt},
	{"CBC", aes_cbc_encrypt, aes_cbc_decrypt},
	{"CFB", aes_cfb_encrypt, aes_cfb_decrypt},
	{"OFB", aes_ofb_crypt, aes_ofb_crypt},
	{"CTR", aes_ctr_crypt, aes_ctr_crypt}
};

const size_t NUM_MODES = sizeof(MODES) / sizeof(MODES[0]);

void benchmark_mode(const aes_context_t* ctx, benchmark_mode_t* mode, const uint8_t iv[16], const uint8_t* input, size_t input_len)
{
	if (ctx == NULL || mode == NULL || input == NULL || input_len == 0) return;

	uint64_t start_ns, end_ns;

	uint8_t* output = (uint8_t*)malloc(input_len);
	if (output == NULL)
	{
		fprintf(stderr, "benchmark_mode: Memory allocation failed\n");
		return;
	}

	start_ns = get_time_ns();
	mode->def->encrypt(ctx, iv, input, input_len, output);
	end_ns = get_time_ns();

	mode->result.sum_encrypt_time_ms += (end_ns - start_ns) / 1e6;

	start_ns = get_time_ns();
	mode->def->decrypt(ctx, iv, output, input_len, output);
	end_ns = get_time_ns();

	mode->result.sum_decrypt_time_ms += (end_ns - start_ns) / 1e6;

	free(output);
}

void print_result(const benchmark_mode_t* modes, size_t data_size, size_t num_iterations)
{
	if (modes == NULL) return;

	double data_size_mb = (double)data_size / MB(1);

	printf("\n[======== Benchmark Results =======]\n");
	for (size_t i = 0; i < NUM_MODES; ++i)
	{
		const benchmark_mode_t* mode = &modes[i];

		double average_encrypt_time = mode->result.sum_encrypt_time_ms / num_iterations;
		double average_decrypt_time = mode->result.sum_decrypt_time_ms / num_iterations;

		double encrypt_speed_mb = (average_encrypt_time > 0.0)
		? data_size_mb / (average_encrypt_time / 1000.0)
		: 0.0;
	
		double decrypt_speed_mb = (average_decrypt_time > 0.0)
			? data_size_mb / (average_decrypt_time / 1000.0)
			: 0.0;

		printf("[ %-4s ]\n", mode->def->name);
		printf("  %-24s %8.2f ms\n", "Average Encrypt Time:", average_encrypt_time);
		printf("  %-24s %8.2f MB/s\n", "Average Encrypt Speed:", encrypt_speed_mb);
		printf("  %-24s %8.2f ms\n", "Average Decrypt Time:", average_decrypt_time);
		printf("  %-24s %8.2f MB/s\n", "Average Decrypt Speed:", decrypt_speed_mb);
		
	}
	printf("[==================================]\n");
}