/**
 * @file aes/core/aes_decrypt.h
 * @brief AES block decryption functions (AES-128, AES-192, AES-256) using AES-NI.
 *
 * This header declares functions for decrypting a single 16-byte block using
 * AES with hardware acceleration via Intel AES-NI intrinsics.
 *
 * Each function requires precomputed decryption round keys, which can be derived
 * from the encryption round keys using the corresponding inversion functions.
 */

#ifndef AES_DECRYPT_H
#define AES_DECRYPT_H

#include "aes/core/aes_constants.h"
#include <emmintrin.h>
#include <wmmintrin.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Decrypts a single 128-bit block using AES-128.
 *
 * @param ciphertext Input 16-byte block to decrypt.
 * @param plaintext Output pointer to receive the decrypted 16-byte block.
 * @param dec_round_keys Array of 11 decryption round keys.
 */
void aes128_decrypt_block(const __m128i ciphertext, __m128i* plaintext, const __m128i dec_round_keys[AES_128_NUM_ROUND_KEYS]);

/**
 * @brief Decrypts a single 128-bit block using AES-192.
 *
 * @param ciphertext Input 16-byte block to decrypt.
 * @param plaintext Output pointer to receive the decrypted 16-byte block.
 * @param dec_round_keys Array of 13 decryption round keys.
 */
void aes192_decrypt_block(const __m128i ciphertext, __m128i* plaintext, const __m128i dec_round_keys[AES_192_NUM_ROUND_KEYS]);

/**
 * @brief Decrypts a single 128-bit block using AES-256.
 *
 * @param ciphertext Input 16-byte block to decrypt.
 * @param plaintext Output pointer to receive the decrypted 16-byte block.
 * @param dec_round_keys Array of 15 decryption round keys.
 */
void aes256_decrypt_block(const __m128i ciphertext, __m128i* plaintext, const __m128i dec_round_keys[AES_256_NUM_ROUND_KEYS]);

#ifdef __cplusplus
}
#endif

#endif // AES_DECRYPT_H