#ifndef EXPE_WRAPPERS_H
#define EXPE_WRAPPERS_H

#include "aes/core/aes_context.h"
#include <stdint.h>

void benchmark_ecb_encrypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t len, uint8_t* output);

void benchmark_ecb_decrypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t len, uint8_t* output);

#endif // EXPE_WRAPPERS_H