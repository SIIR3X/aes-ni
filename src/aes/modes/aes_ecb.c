#include "aes/modes/aes_ecb.h"
#include <string.h>

void aes_ecb_encrypt(const aes_context_t* ctx, const uint8_t* input, size_t input_len, uint8_t* output)
{
	if (!ctx || !input || !output || input_len % AES_BLOCK_SIZE != 0) return;

	for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE)
	{
		// Get pointers to the current 16-byte input and output blocks
		const uint8_t* block_in = input + i;
		uint8_t* block_out = output + i;

		// Load plaintext block into SSE register
		__m128i plaintext = _mm_loadu_si128((const __m128i*)block_in);
		__m128i ciphertext;

		// Call the encryption function from context (128, 192, or 256)
		ctx->encrypt_func(plaintext, &ciphertext, ctx->enc_round_keys);

		// Store the encrypted block into the output buffer
		_mm_storeu_si128((__m128i*)block_out, ciphertext);
	}
}

void aes_ecb_decrypt(const aes_context_t* ctx, const uint8_t* input, size_t input_len, uint8_t* output)
{
	if (!ctx || !input || !output || input_len % AES_BLOCK_SIZE != 0) return;

	for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE)
	{
		// Load 16-byte ciphertext block
		__m128i block = _mm_loadu_si128((const __m128i*)(input + i));
		__m128i result;

		// Call the decryption function from context (128, 192, or 256)
		ctx->decrypt_func(block, &result, ctx->dec_round_keys);

		// Store the decrypted block
		_mm_storeu_si128((__m128i*)(output + i), result);
	}
}