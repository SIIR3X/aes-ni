/**
 * @file aes/core/aes_encrypt.h
 * @brief AES block encryption functions (AES-128, AES-192, AES-256) using AES-NI.
 *
 * This header declares functions for encrypting single 16-byte blocks using
 * AES with hardware acceleration through Intel AES-NI intrinsics.
 *
 * Each function operates on a single block and requires the corresponding
 * number of encryption round keys as generated by the key expansion functions.
 */

#ifndef AES_ENCRYPT_H
#define AES_ENCRYPT_H

#include "aes/core/aes_constants.h"
#include <emmintrin.h>
#include <wmmintrin.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypts a single 128-bit block using AES-128.
 *
 * @param plaintext Input 16-byte block to encrypt (as __m128i).
 * @param ciphertext Output pointer to receive the encrypted 16-byte block.
 * @param enc_round_keys Array of 11 round keys generated by aes128_key_expansion().
 */
void aes128_encrypt_block(const __m128i plaintext, __m128i* ciphertext, const __m128i enc_round_keys[AES_128_NUM_ROUND_KEYS]);

/**
 * @brief Encrypts a single 128-bit block using AES-192.
 *
 * @param plaintext Input 16-byte block to encrypt (as __m128i).
 * @param ciphertext Output pointer to receive the encrypted 16-byte block.
 * @param enc_round_keys Array of 13 round keys generated by aes192_key_expansion().
 */
void aes192_encrypt_block(const __m128i plaintext, __m128i* ciphertext, const __m128i enc_round_keys[AES_192_NUM_ROUND_KEYS]);

/**
 * @brief Encrypts a single 128-bit block using AES-256.
 *
 * @param plaintext Input 16-byte block to encrypt (as __m128i).
 * @param ciphertext Output pointer to receive the encrypted 16-byte block.
 * @param enc_round_keys Array of 15 round keys generated by aes256_key_expansion().
 */
void aes256_encrypt_block(const __m128i plaintext, __m128i* ciphertext, const __m128i enc_round_keys[AES_256_NUM_ROUND_KEYS]);

#ifdef __cplusplus
}
#endif

#endif // AES_ENCRYPT_H