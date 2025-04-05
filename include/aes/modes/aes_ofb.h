/**
 * @file aes/modes/aes_cfb.h
 * @brief AES Output Feedback (OFB) mode encryption/decryption using a single crypt function.
 *
 * OFB mode transforms AES into a stream cipher using the encryption function only.
 * It is suitable for streaming data where padding is not needed. The encryption and
 * decryption operations are symmetric, meaning the same function is used for both.
 */

#ifndef AES_OFB_H
#define AES_OFB_H

#include "aes/core/aes_context.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypts or decrypts data using AES in OFB mode.
 *
 * OFB mode uses AES encryption to generate a keystream, which is XORed with the input.
 * This function works for both encryption and decryption since the process is symmetric.
 *
 * Padding is not required. The IV must be 16 bytes and should be unique for each message.
 *
 * @param ctx Pointer to a valid AES context (initialized with aes_context_init).
 * @param iv 16-byte initialization vector (IV). Must not be NULL.
 * @param input Pointer to the input data (plaintext or ciphertext).
 * @param input_len Length of the input data in bytes.
 * @param output Pointer to the output buffer (ciphertext or plaintext). Must be at least input_len bytes.
 */
void aes_ofb_crypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t input_len, uint8_t* output);

#ifdef __cplusplus
}
#endif

#endif // AES_OFB_H