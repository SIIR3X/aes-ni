#include "aes/core/aes_context.h"
#include "aes/core/aes_key_expansion.h"
#include "aes/core/aes_encrypt.h"
#include "aes/core/aes_decrypt.h"
#include <stdio.h>

int aes_context_init(aes_context_t* ctx, const uint8_t* key, size_t key_size)
{
	if (!ctx || !key)
		return 1;

	switch (key_size)
	{
		// AES_128
		case AES_128:
		{
			ctx->key_size = AES_128;
			aes128_key_expansion(_mm_loadu_si128((const __m128i*)key), ctx->enc_round_keys);
			aes128_invert_round_keys(ctx->enc_round_keys, ctx->dec_round_keys);
			ctx->encrypt_func = (aes_encrypt_func_t)aes128_encrypt_block;
			ctx->decrypt_func = (aes_encrypt_func_t)aes128_decrypt_block;
			break;
		}
		// AES_192
		case AES_192:
		{
			ctx->key_size = AES_192;
			__m128i key192[2] = {
				_mm_loadu_si128((const __m128i*)key),
				_mm_loadu_si128((const __m128i*)(key + 16))
			};
			aes192_key_expansion(key192, ctx->enc_round_keys);
			aes192_invert_round_keys(ctx->enc_round_keys, ctx->dec_round_keys);
			ctx->encrypt_func = (aes_encrypt_func_t)aes192_encrypt_block;
			ctx->decrypt_func = (aes_encrypt_func_t)aes192_decrypt_block;
			break;
		}
		// AES_256
		case AES_256:
		{
			ctx->key_size = AES_256;
			__m128i key256[2] = {
				_mm_loadu_si128((const __m128i*)key),
				_mm_loadu_si128((const __m128i*)(key + 16))
			};
			aes256_key_expansion(key256, ctx->enc_round_keys);
			aes256_invert_round_keys(ctx->enc_round_keys, ctx->dec_round_keys);
			ctx->encrypt_func = (aes_encrypt_func_t)aes256_encrypt_block;
			ctx->decrypt_func = (aes_encrypt_func_t)aes256_decrypt_block;
			break;
		}
		default:
			return 1;
	}

	return 0;
}