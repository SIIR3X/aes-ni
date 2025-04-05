#include "aes/modes/aes_ctr.h"
#include <string.h>

void aes_ctr_crypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t input_len, uint8_t* output)
{
	if (!ctx || !iv || !input || !output)
		return;

	// Load the initialization vector (IV) into a counter
	uint8_t counter[16];
	memcpy(counter, iv, 16);

	// Initialize the counter for AES CTR mode
	uint8_t stream_block[16];
	size_t block_offset = 0;

	for (size_t i = 0; i < input_len; ++i)
	{
		// If we have consumed the current block, generate a new one
		if (block_offset == 0)
		{
			// Encrypt the counter to produce the keystream block
			ctx->encrypt_func(_mm_loadu_si128((const __m128i*)counter), (__m128i*)stream_block, ctx->enc_round_keys);

			// Increment the counter
			for (int j = 15; j >= 0; --j)
			{
				if (++counter[j] != 0)
					break;
			}
		}

		// XOR the input byte with the keystream byte
		output[i] = input[i] ^ stream_block[block_offset];

		// Update the block offset
		block_offset = (block_offset + 1) % 16;
	}
}