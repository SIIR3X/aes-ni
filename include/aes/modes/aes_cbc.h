/**
 * @file aes/modes/aes_cbc.h
 * @brief AES Cipher Block Chaining (CBC) mode encryption and decryption.
 *
 * This header provides functions for performing AES encryption and decryption
 * in CBC mode using a pre-initialized AES context and a 16-byte IV.
 *
 * CBC mode ensures better confidentiality than ECB by chaining blocks.
 * The input must be a multiple of AES_BLOCK_SIZE (16 bytes). Padding
 * must be applied before encryption and removed after decryption.
 */

#ifndef AES_CBC_H
#define AES_CBC_H

#include "aes/core/aes_context.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypts a buffer using AES in CBC mode.
 *
 * The input must be a multiple of 16 bytes (AES block size).
 * Padding must be applied before calling this function.
 * The IV will be used as the starting block and should be random and unique.
 *
 * @param ctx Pointer to a valid AES context (initialized with aes_context_init).
 * @param iv 16-byte initialization vector (IV). Must not be NULL.
 * @param input Pointer to the plaintext buffer.
 * @param input_len Length of the input in bytes (must be a multiple of 16).
 * @param output Pointer to the buffer that will receive the ciphertext.
 *               It must be at least input_len bytes long.
 */
void aes_cbc_encrypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t input_len, uint8_t* output);

/**
 * @brief Decrypts a buffer using AES in CBC mode.
 *
 * The input must be a multiple of 16 bytes (AES block size).
 * Padding removal must be handled externally after decryption.
 * The IV must be the same as used during encryption.
 *
 * @param ctx Pointer to a valid AES context (initialized with aes_context_init).
 * @param iv 16-byte initialization vector (IV) used during encryption. Must not be NULL.
 * @param input Pointer to the ciphertext buffer.
 * @param input_len Length of the input in bytes (must be a multiple of 16).
 * @param output Pointer to the buffer that will receive the plaintext.
 *               It must be at least input_len bytes long.
 */
void aes_cbc_decrypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t input_len, uint8_t* output);

#ifdef __cplusplus
}
#endif

#endif // AES_CBC_H