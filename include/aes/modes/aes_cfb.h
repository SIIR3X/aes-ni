/**
 * @file aes/modes/aes_cfb.h
 * @brief AES Cipher Feedback (CFB) mode encryption and decryption.
 *
 * This header provides functions for performing AES encryption and decryption
 * in CFB mode using a pre-initialized AES context and a 16-byte IV.
 *
 * CFB is a stream cipher mode built on top of AES block encryption.
 * It allows encryption of data that is not necessarily a multiple of 16 bytes.
 * No padding is required.
 */

#ifndef AES_CFB_H
#define AES_CFB_H

#include "aes/core/aes_context.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypts a buffer using AES in CFB mode.
 *
 * Unlike CBC or ECB, CFB does not require padding. It supports input of any length.
 * The IV is used as the starting feedback and must be unique and random.
 *
 * @param ctx Pointer to a valid AES context (initialized with aes_context_init).
 * @param iv 16-byte initialization vector (IV). Must not be NULL.
 * @param input Pointer to the plaintext buffer.
 * @param input_len Length of the input in bytes.
 * @param output Pointer to the buffer that will receive the ciphertext.
 *               It must be at least input_len bytes long.
 */
void aes_cfb_encrypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t input_len, uint8_t* output);

/**
 * @brief Decrypts a buffer using AES in CFB mode.
 *
 * CFB decryption mirrors the encryption process and supports arbitrary-length input.
 * The IV must match the one used during encryption.
 *
 * @param ctx Pointer to a valid AES context (initialized with aes_context_init).
 * @param iv 16-byte initialization vector (IV) used during encryption. Must not be NULL.
 * @param input Pointer to the ciphertext buffer.
 * @param input_len Length of the input in bytes.
 * @param output Pointer to the buffer that will receive the plaintext.
 *               It must be at least input_len bytes long.
 */
void aes_cfb_decrypt(const aes_context_t* ctx, const uint8_t iv[16], const uint8_t* input, size_t input_len, uint8_t* output);

#ifdef __cplusplus
}
#endif

#endif // AES_CFB_H