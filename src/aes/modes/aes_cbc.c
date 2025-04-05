#include "aes/modes/aes_cbc.h"
#include <string.h>

void aes_cbc_encrypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t input_len, uint8_t* output)
{
	if (!ctx || !iv || !input || !output || input_len % AES_BLOCK_SIZE != 0)
		return;

	// Load the initialization vector (IV) as the starting "previous ciphertext block"
	__m128i previous = _mm_loadu_si128((const __m128i*)iv);

	for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE)
	{
		// Get pointers to the current 16-byte input and output blocks
		const uint8_t* block_in = input + i;
		uint8_t* block_out = output + i;

		// Load plaintext block into SSE register
		__m128i plaintext = _mm_loadu_si128((const __m128i*)block_in);

		// XOR the plaintext with the previous ciphertext block (or IV for the first block)
		__m128i xored = _mm_xor_si128(plaintext, previous);
		__m128i ciphertext;

		// Call the encryption function from context (128, 192, or 256)
		ctx->encrypt_func(xored, &ciphertext, ctx->enc_round_keys);

		// Store the encrypted block into the output buffer
		_mm_storeu_si128((__m128i*)block_out, ciphertext);

		// Update the previous ciphertext block for the next iteration
		previous = ciphertext;
	}
}

void aes_cbc_decrypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t input_len, uint8_t* output)
{
	if (!ctx || !iv || !input || !output || input_len % AES_BLOCK_SIZE != 0)
		return;

	// Load the initialization vector (IV) as the starting "previous ciphertext block"
	__m128i previous = _mm_loadu_si128((const __m128i*)iv);

	for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE)
	{
		// Get pointers to the current 16-byte input and output blocks
		const uint8_t* block_in = input + i;
		uint8_t* block_out = output + i;

		// Load ciphertext block into SSE register
		__m128i ciphertext = _mm_loadu_si128((const __m128i*)block_in);
		__m128i decrypted;

		// Call the decryption function from context (128, 192, or 256)
		ctx->decrypt_func(ciphertext, &decrypted, ctx->dec_round_keys);

		// XOR the decrypted block with the previous ciphertext block (or IV for the first block)
		__m128i plaintext = _mm_xor_si128(decrypted, previous);

		// Store the decrypted block into the output buffer
		_mm_storeu_si128((__m128i*)block_out, plaintext);

		// Update the previous ciphertext block for the next iteration
		previous = ciphertext;
	}
}