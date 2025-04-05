#ifndef EXPE_MODES_H
#define EXPE_MODES_H

#include "aes/core/aes_context.h"
#include <stdint.h>

typedef void (*encrypt_fn)(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t input_len, uint8_t* output);

typedef void (*decrypt_fn)(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t input_len, uint8_t* output);

typedef struct {
	double sum_encrypt_time_ms;
	double sum_decrypt_time_ms;
} benchmark_mode_result_t;

typedef struct {
	const char* name;
	encrypt_fn encrypt;
	decrypt_fn decrypt;
} benchmark_mode_def_t;

typedef struct {
	const benchmark_mode_def_t* def;
	benchmark_mode_result_t result;
} benchmark_mode_t;

extern const benchmark_mode_def_t MODES[];

extern const size_t NUM_MODES;

void benchmark_mode(const aes_context_t* ctx, benchmark_mode_t* mode, const uint8_t iv[16], const uint8_t* input, size_t input_len);

void print_result(const benchmark_mode_t* modes, size_t data_size, size_t num_iterations);

#endif // EXPE_MODES_H