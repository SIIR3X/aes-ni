#include "aes/core/aes_key_expansion.h"

/**
 * @brief Helper function for AES-128 key expansion.
 *
 * Applies a sequence of left shifts and XORs to derive the next round key block,
 * using the result of the AES key generation assist intrinsic.
 *
 * @param temp1 [in/out] Working key block being expanded.
 * @param temp2 [in] Output of _mm_aeskeygenassist_si128 used in round key derivation.
 */
static inline void aes128_key_assist(__m128i* temp1, __m128i* temp2)
{
	__m128i temp4;

	// Perform 3 consecutive left shifts and XOR to diffuse the key material
	temp4 = _mm_slli_si128(*temp1, 0x4);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	temp4 = _mm_slli_si128(temp4, 0x4);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	temp4 = _mm_slli_si128(temp4, 0x4);
	*temp1 = _mm_xor_si128(*temp1, temp4);

	// Mix with the round constant from aeskeygenassist
	*temp1 = _mm_xor_si128(*temp1, _mm_shuffle_epi32(*temp2, 0xff));
}

void aes128_key_expansion(const __m128i user_key, __m128i enc_round_keys[AES_128_NUM_ROUND_KEYS])
{
	__m128i temp1 = user_key;
	__m128i temp2;

	enc_round_keys[0] = temp1; // Store the original user key as round key 0

	// Generate remaining 10 round keys
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x01);
	aes128_key_assist(&temp1, &temp2);
	enc_round_keys[1] = temp1;

	temp2 = _mm_aeskeygenassist_si128(temp1, 0x02);
	aes128_key_assist(&temp1, &temp2);
	enc_round_keys[2] = temp1;

	temp2 = _mm_aeskeygenassist_si128(temp1, 0x04);
	aes128_key_assist(&temp1, &temp2);
	enc_round_keys[3] = temp1;

	temp2 = _mm_aeskeygenassist_si128(temp1, 0x08);
	aes128_key_assist(&temp1, &temp2);
	enc_round_keys[4] = temp1;

	temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
	aes128_key_assist(&temp1, &temp2);
	enc_round_keys[5] = temp1;

	temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
	aes128_key_assist(&temp1, &temp2);
	enc_round_keys[6] = temp1;

	temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
	aes128_key_assist(&temp1, &temp2);
	enc_round_keys[7] = temp1;

	temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
	aes128_key_assist(&temp1, &temp2);
	enc_round_keys[8] = temp1;

	temp2 = _mm_aeskeygenassist_si128(temp1, 0x1B);
	aes128_key_assist(&temp1, &temp2);
	enc_round_keys[9] = temp1;

	temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
	aes128_key_assist(&temp1, &temp2);
	enc_round_keys[10] = temp1;
}

/**
 * @brief Helper function for AES-192 key expansion.
 *
 * Performs key schedule mixing using left shifts, XORs, and shuffles.
 * AES-192 requires managing two interleaved key parts and generates
 * partial round keys every 64 or 128 bits.
 *
 * @param temp1 [in/out] First key part being expanded.
 * @param temp2 [in/out] Temporary result from _mm_aeskeygenassist_si128.
 * @param temp3 [in/out] Second key part being expanded.
 */
static inline void aes192_key_assist(__m128i* temp1, __m128i* temp2, __m128i* temp3)
{
	__m128i temp4;

	// Update temp1 (first part of the key)
	*temp2 = _mm_shuffle_epi32(*temp2, 0x55); // Extract specific word from keygen assist
	temp4 = _mm_slli_si128(*temp1, 0x4);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	temp4 = _mm_slli_si128(temp4, 0x4);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	temp4 = _mm_slli_si128(temp4, 0x4);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	*temp1 = _mm_xor_si128(*temp1, *temp2);

	// Update temp3 (second part of the key)
	*temp2 = _mm_shuffle_epi32(*temp1, 0xff); // Prepare shuffle for temp3 update
	temp4 = _mm_slli_si128(*temp3, 0x4);
	*temp3 = _mm_xor_si128(*temp3, temp4);
	*temp3 = _mm_xor_si128(*temp3, *temp2);
}

void aes192_key_expansion(const __m128i user_key[2], __m128i enc_round_keys[AES_192_NUM_ROUND_KEYS])
{
	__m128i temp1 = user_key[0];
	__m128i temp3 = user_key[1];
	__m128i temp2;

	enc_round_keys[0] = temp1; // Store the original user key as round key 0
	enc_round_keys[1] = temp3; // Store the second part of the user key as round key 1

	// Generate remaining 11 round keys
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x1);
	aes192_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[1] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(enc_round_keys[1]), _mm_castsi128_pd(temp1), 0));
	enc_round_keys[2] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 1));

	temp2 = _mm_aeskeygenassist_si128(temp3, 0x2);
	aes192_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[3] = temp1;
	enc_round_keys[4] = temp3;

	temp2 = _mm_aeskeygenassist_si128(temp3, 0x4);
	aes192_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[4] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(enc_round_keys[4]), _mm_castsi128_pd(temp1), 0));
	enc_round_keys[5] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 1));

	temp2 = _mm_aeskeygenassist_si128(temp3, 0x8);
	aes192_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[6] = temp1;
	enc_round_keys[7] = temp3;

	temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
	aes192_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[7] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(enc_round_keys[7]), _mm_castsi128_pd(temp1), 0));
	enc_round_keys[8] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 1));

	temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
	aes192_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[9] = temp1;
	enc_round_keys[10] = temp3;

	temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
	aes192_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[10] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(enc_round_keys[10]), _mm_castsi128_pd(temp1), 0));
	enc_round_keys[11] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 1));

	temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
	aes192_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[12] = temp1;
}

/**
 * @brief Helper function for AES-256 key expansion using AES-NI.
 *
 * This function expands two 128-bit key parts (total 256-bit key) into new
 * round key material. The expansion uses the result of _mm_aeskeygenassist_si128,
 * shuffling, and repeated left shifts with XOR to generate strong diffusion.
 *
 * @param temp1 [in/out] First half of the key being expanded.
 * @param temp2 [in/out] Output from _mm_aeskeygenassist_si128 using current RCON value.
 * @param temp3 [in/out] Second half of the key being expanded.
 */
static inline void aes256_key_assist(__m128i* temp1, __m128i* temp2, __m128i* temp3)
{
	__m128i temp4;
	
	// Expand temp1 (first half of the key)
	*temp2 = _mm_shuffle_epi32(*temp2, 0xFF); // Broadcast one word from keygen assist
	temp4 = _mm_slli_si128(*temp1, 0x4);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	temp4 = _mm_slli_si128(temp4, 0x4);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	temp4 = _mm_slli_si128(temp4, 0x4);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	*temp1 = _mm_xor_si128(*temp1, *temp2); // Mix with assist result

	// Expand temp3 (second half of the key)
	temp4 = _mm_aeskeygenassist_si128(*temp1, 0x00); // Generate assist from updated temp1
	temp4 = _mm_shuffle_epi32(temp4, 0xAA); // Broadcast relevant word
	
	*temp3 = _mm_xor_si128(*temp3, _mm_slli_si128(*temp3, 0x4));
	*temp3 = _mm_xor_si128(*temp3, _mm_slli_si128(*temp3, 0x4));
	*temp3 = _mm_xor_si128(*temp3, _mm_slli_si128(*temp3, 0x4));
	*temp3 = _mm_xor_si128(*temp3, temp4); // Final mixing with assist
}

void aes256_key_expansion(const __m128i user_key[2], __m128i enc_round_keys[AES_256_NUM_ROUND_KEYS])
{
	__m128i temp1 = user_key[0]; // First half of the user key
	__m128i temp3 = user_key[1]; // Second half of the user key
	__m128i temp2;

	enc_round_keys[0] = temp1;
	enc_round_keys[1] = temp3;

	// Generate remaining 13 round keys
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
	aes256_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[2] = temp1;
	enc_round_keys[3] = temp3;

	temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
	aes256_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[4] = temp1;
	enc_round_keys[5] = temp3;

	temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
	aes256_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[6] = temp1;
	enc_round_keys[7] = temp3;

	temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
	aes256_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[8] = temp1;
	enc_round_keys[9] = temp3;

	temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
	aes256_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[10] = temp1;
	enc_round_keys[11] = temp3;

	temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
	aes256_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[12] = temp1;
	enc_round_keys[13] = temp3;

	temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
	aes256_key_assist(&temp1, &temp2, &temp3);
	enc_round_keys[14] = temp1;
}

void aes128_invert_round_keys(const __m128i enc_round_keys[AES_128_NUM_ROUND_KEYS], __m128i dec_round_keys[AES_128_NUM_ROUND_KEYS])
{
	// First decryption round key = last encryption round key
	dec_round_keys[0]  = enc_round_keys[10];

	// Apply aesimc to intermediate keys (in reverse order)
	dec_round_keys[1]  = _mm_aesimc_si128(enc_round_keys[9]);
	dec_round_keys[2]  = _mm_aesimc_si128(enc_round_keys[8]);
	dec_round_keys[3]  = _mm_aesimc_si128(enc_round_keys[7]);
	dec_round_keys[4]  = _mm_aesimc_si128(enc_round_keys[6]);
	dec_round_keys[5]  = _mm_aesimc_si128(enc_round_keys[5]);
	dec_round_keys[6]  = _mm_aesimc_si128(enc_round_keys[4]);
	dec_round_keys[7]  = _mm_aesimc_si128(enc_round_keys[3]);
	dec_round_keys[8]  = _mm_aesimc_si128(enc_round_keys[2]);
	dec_round_keys[9]  = _mm_aesimc_si128(enc_round_keys[1]);

	// Last decryption round key = first encryption round key
	dec_round_keys[10] = enc_round_keys[0];
}

void aes192_invert_round_keys(const __m128i enc_round_keys[AES_192_NUM_ROUND_KEYS], __m128i dec_round_keys[AES_192_NUM_ROUND_KEYS])
{
	// First decryption round key = last encryption round key
	dec_round_keys[0]  = enc_round_keys[12];

	// Apply aesimc to intermediate keys (in reverse order)
	dec_round_keys[1]  = _mm_aesimc_si128(enc_round_keys[11]);
	dec_round_keys[2]  = _mm_aesimc_si128(enc_round_keys[10]);
	dec_round_keys[3]  = _mm_aesimc_si128(enc_round_keys[9]);
	dec_round_keys[4]  = _mm_aesimc_si128(enc_round_keys[8]);
	dec_round_keys[5]  = _mm_aesimc_si128(enc_round_keys[7]);
	dec_round_keys[6]  = _mm_aesimc_si128(enc_round_keys[6]);
	dec_round_keys[7]  = _mm_aesimc_si128(enc_round_keys[5]);
	dec_round_keys[8]  = _mm_aesimc_si128(enc_round_keys[4]);
	dec_round_keys[9]  = _mm_aesimc_si128(enc_round_keys[3]);
	dec_round_keys[10] = _mm_aesimc_si128(enc_round_keys[2]);
	dec_round_keys[11] = _mm_aesimc_si128(enc_round_keys[1]);

	// Last decryption round key = first encryption round key
	dec_round_keys[12] = enc_round_keys[0];
}

void aes256_invert_round_keys(const __m128i enc_round_keys[AES_256_NUM_ROUND_KEYS], __m128i dec_round_keys[AES_256_NUM_ROUND_KEYS])
{
	// First decryption round key = last encryption round key
	dec_round_keys[0]  = enc_round_keys[14];

	// Apply aesimc to intermediate keys (in reverse order)
	dec_round_keys[1]  = _mm_aesimc_si128(enc_round_keys[13]);
	dec_round_keys[2]  = _mm_aesimc_si128(enc_round_keys[12]);
	dec_round_keys[3]  = _mm_aesimc_si128(enc_round_keys[11]);
	dec_round_keys[4]  = _mm_aesimc_si128(enc_round_keys[10]);
	dec_round_keys[5]  = _mm_aesimc_si128(enc_round_keys[9]);
	dec_round_keys[6]  = _mm_aesimc_si128(enc_round_keys[8]);
	dec_round_keys[7]  = _mm_aesimc_si128(enc_round_keys[7]);
	dec_round_keys[8]  = _mm_aesimc_si128(enc_round_keys[6]);
	dec_round_keys[9]  = _mm_aesimc_si128(enc_round_keys[5]);
	dec_round_keys[10] = _mm_aesimc_si128(enc_round_keys[4]);
	dec_round_keys[11] = _mm_aesimc_si128(enc_round_keys[3]);
	dec_round_keys[12] = _mm_aesimc_si128(enc_round_keys[2]);
	dec_round_keys[13] = _mm_aesimc_si128(enc_round_keys[1]);

	// Last decryption round key = first encryption round key
	dec_round_keys[14] = enc_round_keys[0];
}