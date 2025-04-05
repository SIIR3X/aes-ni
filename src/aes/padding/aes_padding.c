#include "aes/padding/aes_padding.h"
#include "aes/core/aes_constants.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Applies PKCS#7 padding to the input buffer.
 *
 * Pads the data so that the total length is a multiple of the AES block size.
 * Each padding byte is set to the total number of padding bytes added.
 *
 * @param input Pointer to the buffer (must have enough space for padding).
 * @param input_len Length of the original data in bytes.
 * @param pad_len Number of bytes to pad (1 to AES_BLOCK_SIZE).
 */
static inline void aes_pcks7_pad(uint8_t* input, size_t input_len, size_t pad_len)
{
	memset(input + input_len, (uint8_t)pad_len, pad_len);
}

/**
 * @brief Applies zero padding to the input buffer.
 *
 * Fills the padding space with 0x00 bytes. Only safe if the original data
 * does not naturally end with zero bytes.
 *
 * @param input Pointer to the buffer (must have enough space for padding).
 * @param input_len Length of the original data in bytes.
 * @param pad_len Number of bytes to pad (1 to AES_BLOCK_SIZE).
 */
static inline void aes_zero_pad(uint8_t* input, size_t input_len, size_t pad_len)
{
	memset(input + input_len, 0x00, pad_len);
}

/**
 * @brief Applies ANSI X.923 padding to the input buffer.
 *
 * Fills the padding space with 0x00 bytes, except for the last byte, which
 * contains the number of padding bytes added.
 *
 * @param input Pointer to the buffer (must have enough space for padding).
 * @param input_len Length of the original data in bytes.
 * @param pad_len Number of bytes to pad (1 to AES_BLOCK_SIZE).
 */
static inline void aes_ansix923_pad(uint8_t* input, size_t input_len, size_t pad_len)
{
	memset(input + input_len, 0x00, pad_len - 1);
	input[input_len + pad_len - 1] = (uint8_t)pad_len;
}

uint8_t* aes_add_padding(const uint8_t* input, size_t input_len, size_t* padded_size, aes_padding_t padding)
{
	if (!input || !padded_size) return NULL;

	size_t pad_len = AES_BLOCK_SIZE - (input_len % AES_BLOCK_SIZE);
	if (pad_len == AES_BLOCK_SIZE) pad_len = AES_BLOCK_SIZE;

	*padded_size = input_len + pad_len;

	uint8_t* padded_input = malloc(*padded_size);
	if (!padded_input) return NULL;

	memcpy(padded_input, input, input_len);

	switch (padding)
	{
		case AES_PADDING_PKCS7: aes_pcks7_pad(padded_input, input_len, pad_len); break;
		case AES_PADDING_ZERO: aes_zero_pad(padded_input, input_len, pad_len); break;
		case AES_PADDING_ANSIX923: aes_ansix923_pad(padded_input, input_len, pad_len); break;
		default:
			free(padded_input);
			return NULL;
	}

	return padded_input;
}

/**
 * @brief Removes PKCS#7 padding from a padded buffer.
 *
 * This function checks that all padding bytes at the end of the buffer
 * are equal to the padding length value. If the padding is invalid,
 * it returns 0.
 *
 * @param input Pointer to the padded input buffer.
 * @param input_len Total length of the input buffer (must be a multiple of block size).
 * @param pad_len Padding length (should be equal to the value of the last byte).
 * @return Length of the data after removing padding, or 0 if padding is invalid.
 */
static inline size_t aes_pcks7_unpad(uint8_t* input, size_t input_len, size_t pad_len)
{
	for (size_t i = 0; i < pad_len; ++i)
	{
		if (input[input_len - 1 - i] != pad_len)
			return 0;
	}

	return input_len - pad_len;
}

/**
 * @brief Removes zero padding from a padded buffer.
 *
 * This function removes trailing 0x00 bytes from the end of the buffer.
 * It does not perform validation and assumes that the data does not
 * naturally end with 0x00.
 *
 * @param input Pointer to the padded input buffer.
 * @param input_len Total length of the input buffer.
 * @return Length of the data after removing zero padding.
 */
static inline size_t aes_zero_unpad(uint8_t* input, size_t input_len)
{
	while (input_len > 0 && input[input_len - 1] == 0x00)
		input_len--;

	return input_len;
}

/**
 * @brief Removes ANSI X.923 padding from a padded buffer.
 *
 * This function verifies that the padding bytes (except the last one)
 * are all 0x00 and that the last byte contains the correct padding length.
 * If the padding is invalid, it returns 0.
 *
 * @param input Pointer to the padded input buffer.
 * @param input_len Total length of the input buffer (must be a multiple of block size).
 * @param pad_len Padding length (value of the last byte).
 * @return Length of the data after removing padding, or 0 if padding is invalid.
 */
static inline size_t aes_ansix923_unpad(uint8_t* input, size_t input_len, size_t pad_len)
{
	for (size_t i = 1; i < pad_len; ++i)
	{
		if (input[input_len - 1 - i] != 0x00)
			return 0;
	}

	return input_len - pad_len;
}

size_t aes_remove_padding(uint8_t* input, size_t input_len, aes_padding_t padding)
{
	if (input_len == 0 || input_len % AES_BLOCK_SIZE != 0)
		return 0;
	
	uint8_t pad_len = input[input_len - 1];

	switch (padding)
	{
		case AES_PADDING_PKCS7: return aes_pcks7_unpad(input, input_len, pad_len);
		case AES_PADDING_ZERO: return aes_zero_unpad(input, input_len);
		case AES_PADDING_ANSIX923: return aes_ansix923_unpad(input, input_len, pad_len);
		default: return 0;
	}
}