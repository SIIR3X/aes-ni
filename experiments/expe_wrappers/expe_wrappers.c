#include "expe_wrappers/expe_wrappers.h"
#include "aes/modes/aes_ecb.h"

void benchmark_ecb_encrypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t len, uint8_t* output)
{
	(void)iv;
	aes_ecb_encrypt(ctx, input, len, output);
}

void benchmark_ecb_decrypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t len, uint8_t* output)
{
	(void)iv;
	aes_ecb_decrypt(ctx, input, len, output);
}