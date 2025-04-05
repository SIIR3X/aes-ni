/**
 * @file aes/core/aes_key_expansion.h
 * @brief AES key expansion and inversion routines (AES-128, AES-192, AES-256).
 *
 * This header defines functions to generate encryption and decryption round keys
 * for the AES algorithm, using Intel AES-NI intrinsics for efficient performance.
 * These round keys are used during the AES block encryption and decryption process.
 *
 * Functions are provided for each AES variant:
 *   - AES-128: 10 rounds, 11 round keys
 *   - AES-192: 12 rounds, 13 round keys
 *   - AES-256: 14 rounds, 15 round keys
 */

#ifndef AES_KEY_EXPANSION_H
#define AES_KEY_EXPANSION_H

#include "aes/core/aes_constants.h"
#include <emmintrin.h>
#include <wmmintrin.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Expands a 128-bit AES user key into the encryption round key schedule.
 *
 * @param user_key The 128-bit user key (single __m128i block).
 * @param enc_round_keys Output array of 11 __m128i encryption round keys (AES_128_WORDS).
 */
void aes128_key_expansion(const __m128i user_key, __m128i enc_round_keys[AES_128_NUM_ROUND_KEYS]);

/**
 * @brief Expands a 192-bit AES user key into the encryption round key schedule.
 *
 * @param user_key The 192-bit user key (as two __m128i blocks, only 192 bits used).
 * @param enc_round_keys Output array of 13 __m128i encryption round keys (AES_192_WORDS).
 */
void aes192_key_expansion(const __m128i user_key[2], __m128i enc_round_keys[AES_192_NUM_ROUND_KEYS]);

/**
 * @brief Expands a 256-bit AES user key into the encryption round key schedule.
 *
 * @param user_key The 256-bit user key (two full __m128i blocks).
 * @param enc_round_keys Output array of 15 __m128i encryption round keys (AES_256_WORDS).
 */
void aes256_key_expansion(const __m128i user_key[2], __m128i enc_round_keys[AES_256_NUM_ROUND_KEYS]);

/**
 * @brief Inverts the AES-128 encryption round keys into decryption round keys.
 *
 * @param enc_round_keys Input array of 11 encryption round keys from aes128_key_expansion().
 * @param dec_round_keys Output array of 11 decryption round keys.
 */
void aes128_invert_round_keys(const __m128i enc_round_keys[AES_128_NUM_ROUND_KEYS], __m128i dec_round_keys[AES_128_NUM_ROUND_KEYS]);

/**
 * @brief Inverts the AES-192 encryption round keys into decryption round keys.
 *
 * @param enc_round_keys Input array of 13 encryption round keys from aes192_key_expansion().
 * @param dec_round_keys Output array of 13 decryption round keys.
 */
void aes192_invert_round_keys(const __m128i enc_round_keys[AES_192_NUM_ROUND_KEYS], __m128i dec_round_keys[AES_192_NUM_ROUND_KEYS]);

/**
 * @brief Inverts the AES-256 encryption round keys into decryption round keys.
 *
 * @param enc_round_keys Input array of 15 encryption round keys from aes256_key_expansion().
 * @param dec_round_keys Output array of 15 decryption round keys.
 */
void aes256_invert_round_keys(const __m128i enc_round_keys[AES_256_NUM_ROUND_KEYS], __m128i dec_round_keys[AES_256_NUM_ROUND_KEYS]);

#ifdef __cplusplus
}
#endif

#endif // AES_KEY_EXPANSION_H