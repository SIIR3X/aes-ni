/**
 * @file aes/padding/aes_padding.h
 * @brief AES block cipher padding and unpadding utilities.
 *
 * This header provides functions for applying and removing padding schemes
 * commonly used with AES block ciphers. These functions help ensure that input
 * data aligns to the AES block size (16 bytes) as required by most AES modes.
 *
 * Supported padding schemes:
 * - PKCS#7: Standard padding where each byte of the padding is equal to the number of padding bytes.
 * - Zero padding: Pads with 0x00 bytes. Suitable only when data does not naturally end with 0x00.
 * - ANSI X.923: Pads with 0x00 bytes followed by a final byte indicating the length of the padding.
 *
 * Padding must be applied before encryption and removed after decryption.
 */

#ifndef AES_PADDING_H
#define AES_PADDING_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Supported AES padding schemes
typedef enum {
	AES_PADDING_PKCS7,    ///< PKCS#7 padding (standard for block ciphers)
	AES_PADDING_ZERO,     ///< Zero padding (zeros added until block size)
	AES_PADDING_ANSIX923  ///< ANSI X.923 padding (zeros + padding length byte)
} aes_padding_t;

/**
 * @brief Applies the selected padding scheme to input data.
 *
 * This function allocates a new buffer containing the original input data
 * followed by the appropriate padding to align it with the AES block size (16 bytes).
 * The caller is responsible for freeing the returned buffer.
 *
 * @param input Pointer to the input data to be padded.
 * @param input_len Length of the input data in bytes.
 * @param padded_size Output pointer to receive the length of the padded data.
 * @param padding Padding scheme to apply (e.g., PKCS#7, ZERO, ANSI X.923).
 * @return Pointer to the newly allocated, padded buffer. NULL on error.
 */
uint8_t* aes_add_padding(const uint8_t* input, size_t input_len, size_t* padded_size, aes_padding_t padding);

/**
 * @brief Removes padding from a previously padded buffer.
 *
 * This function inspects the final block of data and validates the padding
 * according to the selected scheme. It returns the original length of the
 * unpadded data.
 *
 * @param input Pointer to the padded buffer.
 * @param input_len Total length of the buffer in bytes (must be a multiple of AES block size).
 * @param padding Padding scheme used during encryption.
 * @return The length of the data after removing padding, or 0 if padding is invalid.
 */
size_t aes_remove_padding(uint8_t* input, size_t input_len, aes_padding_t padding);

#ifdef __cplusplus
}
#endif

#endif // AES_PADDING_Ha