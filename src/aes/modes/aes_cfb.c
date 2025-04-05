#include "aes/modes/aes_cfb.h"
#include <string.h>

void aes_cfb_encrypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t input_len, uint8_t* output)
{
	if (!ctx || !iv || !input || !output) return;

	__m128i shift_reg = _mm_loadu_si128((const __m128i*)iv);
	size_t full_blocks = input_len / AES_BLOCK_SIZE;
	size_t remaining = input_len % AES_BLOCK_SIZE;

	// Process full 16-byte blocks
	for (size_t i = 0; i < full_blocks; ++i)
	{
		__m128i encrypted;
		ctx->encrypt_func(shift_reg, &encrypted, ctx->enc_round_keys);

		__m128i plaintext = _mm_loadu_si128((const __m128i*)(input + i*AES_BLOCK_SIZE));
		__m128i ciphertext = _mm_xor_si128(encrypted, plaintext);

		_mm_storeu_si128((__m128i*)(output + i*AES_BLOCK_SIZE), ciphertext);
		shift_reg = ciphertext;
	}

	// Handle partial final block
	if (remaining > 0)
	{
		__m128i encrypted;
		uint8_t keystream[AES_BLOCK_SIZE];
		uint8_t shift_buffer[AES_BLOCK_SIZE];
		const uint8_t* last_in = input + full_blocks * AES_BLOCK_SIZE;
		uint8_t* last_out = output + full_blocks * AES_BLOCK_SIZE;

		// Generate keystream for final partial block
		ctx->encrypt_func(shift_reg, &encrypted, ctx->enc_round_keys);
		_mm_storeu_si128((__m128i*)keystream, encrypted);

		// XOR input with keystream for remaining bytes
		for (size_t i = 0; i < remaining; ++i)
			last_out[i] = last_in[i] ^ keystream[i];

		// Update shift register with new ciphertext bytes
		_mm_storeu_si128((__m128i*)shift_buffer, shift_reg);
		memmove(shift_buffer, shift_buffer + remaining, AES_BLOCK_SIZE - remaining);
		memcpy(shift_buffer + AES_BLOCK_SIZE - remaining, last_out, remaining);
		shift_reg = _mm_loadu_si128((const __m128i*)shift_buffer);
	}
}

void aes_cfb_decrypt(const aes_context_t* ctx, const uint8_t iv[16],
	const uint8_t* input, size_t input_len, uint8_t* output)
{
	if (!ctx || !iv || !input || !output) return;

	__m128i shift_reg = _mm_loadu_si128((const __m128i*)iv);
	size_t full_blocks = input_len / AES_BLOCK_SIZE;
	size_t remaining = input_len % AES_BLOCK_SIZE;

	// Process full 16-byte blocks
	for (size_t i = 0; i < full_blocks; ++i)
	{
		__m128i encrypted;
		ctx->encrypt_func(shift_reg, &encrypted, ctx->enc_round_keys);

		__m128i ciphertext = _mm_loadu_si128((const __m128i*)(input + i*AES_BLOCK_SIZE));
		__m128i plaintext = _mm_xor_si128(encrypted, ciphertext);

		_mm_storeu_si128((__m128i*)(output + i*AES_BLOCK_SIZE), plaintext);
		shift_reg = ciphertext; // CFB always uses ciphertext for next block
	}

	// Handle partial final block
	if (remaining > 0)
	{
		__m128i encrypted;
		uint8_t keystream[AES_BLOCK_SIZE];
		uint8_t shift_buffer[AES_BLOCK_SIZE];
		const uint8_t* last_in = input + full_blocks * AES_BLOCK_SIZE;
		uint8_t* last_out = output + full_blocks * AES_BLOCK_SIZE;

		// Generate keystream for final partial block
		ctx->encrypt_func(shift_reg, &encrypted, ctx->enc_round_keys);
		_mm_storeu_si128((__m128i*)keystream, encrypted);

		// XOR ciphertext with keystream for remaining bytes
		for (size_t i = 0; i < remaining; ++i)
			last_out[i] = last_in[i] ^ keystream[i];

		// Update shift register with ciphertext bytes (from input!)
		_mm_storeu_si128((__m128i*)shift_buffer, shift_reg);
		memmove(shift_buffer, shift_buffer + remaining, AES_BLOCK_SIZE - remaining);
		memcpy(shift_buffer + AES_BLOCK_SIZE - remaining, last_in, remaining);
		shift_reg = _mm_loadu_si128((const __m128i*)shift_buffer);
	}
}