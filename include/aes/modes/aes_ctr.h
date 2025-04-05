/**
 * @file aes/modes/aes_ctr.h
 * @brief AES Counter (CTR) mode encryption and decryption.
 *
 * This header defines the AES CTR mode API for encrypting or decrypting
 * arbitrary-length data using a counter-based keystream.
 *
 * CTR mode turns a block cipher into a stream cipher by encrypting an incrementing counter
 * and XORing the result with the input. It supports parallel processing and does not require padding.
 */

#ifndef AES_CTR_H
#define AES_CTR_H

#include "aes/core/aes_context.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypts or decrypts a buffer using AES in CTR mode.
 *
 * Since CTR mode is symmetric, this function is used for both encryption and decryption.
 *
 * @param ctx Pointer to a valid AES context (initialized with aes_context_init).
 * @param iv 16-byte initialization vector (nonce + counter). Must not be NULL.
 * @param input Pointer to the input buffer (plaintext or ciphertext).
 * @param input_len Number of bytes to process.
 * @param output Pointer to the buffer that will receive the output.
 *               Must be at least input_len bytes.
 */
void aes_ctr_crypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t input_len, uint8_t* output);

#ifdef __cplusplus
}
#endif

#endif // AES_CTR_H