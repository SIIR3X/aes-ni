#include "aes/modes/aes_ofb.h"
#include <string.h>

void aes_ofb_crypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t input_len, uint8_t* output)
{
	if (!ctx || !iv || !input || !output)
		return;

	// Load the initialization vector (IV) into a feedback register
	__m128i feedback = _mm_loadu_si128((const __m128i*)iv);

	for (size_t offset = 0; offset < input_len; offset += AES_BLOCK_SIZE)
	{
		// Encrypt the feedback register to produce the keystream block
		__m128i keystream;
		ctx->encrypt_func(feedback, &keystream, ctx->enc_round_keys);
		_mm_storeu_si128(&feedback, keystream);

		// XOR the keystream with the plaintext to produce the ciphertext
		uint8_t keystream_bytes[16];
		_mm_storeu_si128((__m128i*)keystream_bytes, keystream);

		// Handle the case where input_len is not a multiple of AES_BLOCK_SIZE
		size_t remaining = input_len - offset;
		size_t chunk = remaining >= AES_BLOCK_SIZE ? AES_BLOCK_SIZE : remaining;

		// XOR the keystream with the plaintext block
		for (size_t i = 0; i < chunk; ++i)
			output[offset + i] = input[offset + i] ^ keystream_bytes[i];
	}
}