/**
 * @file aes/modes/aes_ecb.h
 * @brief AES Electronic Codebook (ECB) mode encryption and decryption.
 *
 * This header provides functions for performing AES encryption and decryption
 * in ECB mode using a pre-initialized AES context.
 *
 * ECB mode operates on independent 16-byte blocks. It does not provide semantic security
 * and should generally be avoided in favor of more secure modes (e.g., CBC, GCM).
 * Input length must be a multiple of AES_BLOCK_SIZE (16 bytes), and padding
 * must be handled externally if needed.
 */

#ifndef AES_ECB_H
#define AES_ECB_H

#include "aes/core/aes_context.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypts a buffer using AES in ECB mode.
 *
 * The input must be a multiple of 16 bytes (AES block size).
 * Padding must be applied before calling this function.
 *
 * @param ctx Pointer to a valid AES context (initialized with aes_context_init).
 * @param input Pointer to the plaintext buffer.
 * @param input_len Length of the input in bytes (must be a multiple of 16).
 * @param output Pointer to the buffer that will receive the ciphertext.
 *               It must be at least input_len bytes long.
 */
void aes_ecb_encrypt(const aes_context_t* ctx, const uint8_t* input, size_t input_len, uint8_t* output);

/**
 * @brief Decrypts a buffer using AES in ECB mode.
 *
 * The input must be a multiple of 16 bytes (AES block size).
 * Padding removal must be handled externally after decryption.
 *
 * @param ctx Pointer to a valid AES context (initialized with aes_context_init).
 * @param input Pointer to the ciphertext buffer.
 * @param input_len Length of the input in bytes (must be a multiple of 16).
 * @param output Pointer to the buffer that will receive the plaintext.
 *               It must be at least input_len bytes long.
 */
void aes_ecb_decrypt(const aes_context_t* ctx, const uint8_t* input, size_t input_len, uint8_t* output);

#ifdef __cplusplus
}
#endif

#endif // AES_ECB_H