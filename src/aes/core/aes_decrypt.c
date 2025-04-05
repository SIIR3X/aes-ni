#include "aes/core/aes_decrypt.h"

void aes128_decrypt_block(const __m128i ciphertext, __m128i* plaintext, const __m128i dec_round_keys[AES_128_NUM_ROUND_KEYS])
{
	// Initial AddRoundKey
	__m128i tmp = _mm_xor_si128(ciphertext, dec_round_keys[0]);

	// 9 standard AES decryption rounds
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[1]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[2]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[3]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[4]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[5]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[6]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[7]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[8]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[9]);

	// Final round (AddRoundKey + SubBytes + ShiftRows)
	tmp = _mm_aesdeclast_si128(tmp, dec_round_keys[10]);

	// Store the result
	*plaintext = tmp;
}

void aes192_decrypt_block(const __m128i ciphertext, __m128i* plaintext, const __m128i dec_round_keys[AES_192_NUM_ROUND_KEYS])
{
	// Initial AddRoundKey
	__m128i tmp = _mm_xor_si128(ciphertext, dec_round_keys[0]);

	// 11 standard AES decryption rounds
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[1]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[2]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[3]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[4]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[5]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[6]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[7]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[8]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[9]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[10]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[11]);

	// Final round (AddRoundKey + SubBytes + ShiftRows)
	tmp = _mm_aesdeclast_si128(tmp, dec_round_keys[12]);

	// Store the result
	*plaintext = tmp;
}

void aes256_decrypt_block(const __m128i ciphertext, __m128i* plaintext, const __m128i dec_round_keys[AES_256_NUM_ROUND_KEYS])
{
	// Initial AddRoundKey
	__m128i tmp = _mm_xor_si128(ciphertext, dec_round_keys[0]);

	// 13 standard AES decryption rounds
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[1]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[2]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[3]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[4]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[5]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[6]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[7]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[8]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[9]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[10]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[11]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[12]);
	tmp = _mm_aesdec_si128(tmp, dec_round_keys[13]);

	// Final round (AddRoundKey + SubBytes + ShiftRows)
	tmp = _mm_aesdeclast_si128(tmp, dec_round_keys[14]);

	// Store the result
	*plaintext = tmp;
}