#include "aes/core/aes_encrypt.h"

void aes128_encrypt_block(const __m128i plaintext, __m128i* ciphertext, const __m128i enc_round_keys[AES_128_NUM_ROUND_KEYS])
{
	// Initial AddRoundKey
	__m128i tmp = _mm_xor_si128(plaintext, enc_round_keys[0]);

	// 9 standard AES encryption rounds
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[1]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[2]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[3]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[4]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[5]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[6]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[7]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[8]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[9]);

	// Final round (AddRoundKey + SubBytes + ShiftRows)
	tmp = _mm_aesenclast_si128(tmp, enc_round_keys[10]);

	// Store the result
	*ciphertext = tmp;
}

void aes192_encrypt_block(const __m128i plaintext, __m128i* ciphertext, const __m128i enc_round_keys[AES_192_NUM_ROUND_KEYS])
{
	// Initial AddRoundKey
	__m128i tmp = _mm_xor_si128(plaintext, enc_round_keys[0]);

	// 11 standard AES encryption rounds
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[1]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[2]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[3]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[4]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[5]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[6]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[7]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[8]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[9]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[10]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[11]);

	// Final round (AddRoundKey + SubBytes + ShiftRows)
	tmp = _mm_aesenclast_si128(tmp, enc_round_keys[12]);

	// Store the result
	*ciphertext = tmp;
}

void aes256_encrypt_block(const __m128i plaintext, __m128i* ciphertext, const __m128i enc_round_keys[AES_256_NUM_ROUND_KEYS])
{
	// Initial AddRoundKey
	__m128i tmp = _mm_xor_si128(plaintext, enc_round_keys[0]);

	// 13 standard AES encryption rounds
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[1]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[2]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[3]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[4]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[5]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[6]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[7]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[8]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[9]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[10]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[11]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[12]);
	tmp = _mm_aesenc_si128(tmp, enc_round_keys[13]);

	// Final round (AddRoundKey + SubBytes + ShiftRows)
	tmp = _mm_aesenclast_si128(tmp, enc_round_keys[14]);

	// Store the result
	*ciphertext = tmp;
}