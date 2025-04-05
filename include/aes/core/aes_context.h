/**
 * @file aes/core/aes_context.h
 * @brief AES context definition and initialization for AES-128, AES-192, and AES-256.
 *
 * This header defines the `aes_context_t` structure, which holds encryption and
 * decryption round keys, as well as function pointers for block-level AES operations.
 *
 * The context is initialized using `aes_context_init()` and can then be reused
 * for multiple encryption/decryption calls with the associated key.
 */

#ifndef AES_CONTEXT_H
#define AES_CONTEXT_H

#include "aes/core/aes_constants.h"
#include <stdint.h>
#include <emmintrin.h>
#include <wmmintrin.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumeration of supported AES key sizes (in bytes).
 */
typedef enum {
	AES_128 = AES_128_KEY_SIZE, ///< AES-128 uses 16-byte keys
	AES_192 = AES_192_KEY_SIZE, ///< AES-192 uses 24-byte keys
	AES_256 = AES_256_KEY_SIZE ///< AES-256 uses 32-byte keys
} aes_key_size_t;

/**
 * @brief Function pointer type for AES encryption and decryption functions.
 *
 * This allows for dynamic selection of the encryption/decryption function based on key size.
 *
 * @param plaintext Input 16-byte block to encrypt/decrypt.
 * @param ciphertext Output pointer to receive the encrypted/decrypted 16-byte block.
 * @param enc_round_keys Array of round keys for encryption/decryption.
 */
typedef void (*aes_encrypt_func_t)(const __m128i plaintext, __m128i* ciphertext, const __m128i* enc_round_keys);

/**
 * @brief AES context structure containing round keys for encryption and decryption.
 *
 * This structure can be initialized with `aes_context_init()` and reused across
 * encryption/decryption operations for performance.
 */
typedef struct {
	aes_key_size_t key_size; ///< Key size used (AES_128, AES_192, or AES_256)
	__m128i enc_round_keys[AES_256_NUM_ROUND_KEYS]; ///< Expanded encryption round keys (up to 14 + 1 for AES-256)
	__m128i dec_round_keys[AES_256_NUM_ROUND_KEYS]; ///< Expanded decryption round keys (same count as enc keys)
	aes_encrypt_func_t encrypt_func; ///< Pointer to the encryption function (AES-128, AES-192, or AES-256)
	aes_encrypt_func_t decrypt_func; ///< Pointer to the decryption function (AES-128, AES-192, or AES-256)
} aes_context_t;

/**
 * @brief Initializes an AES context by expanding the encryption and decryption keys.
 *
 * @param ctx Pointer to the AES context to initialize.
 * @param key Raw AES key (must be 16, 24, or 32 bytes depending on AES version).
 * @param key_size Size of the key in bytes (must match AES_128, AES_192, or AES_256).
 * @return 0 on success, non-zero on failure (e.g., invalid key size or null pointers).
 */
int aes_context_init(aes_context_t* ctx, const uint8_t* key, size_t key_size);

#ifdef __cplusplus
}
#endif

#endif // AES_CONTEXT_H