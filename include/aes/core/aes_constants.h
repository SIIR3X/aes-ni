/**
 * @file aes/core/aes_constants.h
 * @brief Common constants for AES operations (block size, number of rounds, round keys).
 *
 * This header centralizes all compile-time constants used for AES block size and key schedules.
 * It supports AES-128, AES-192, and AES-256 in accordance with the FIPS-197 specification.
 */

#ifndef AES_CONSTANTS_H
#define AES_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

/// AES-128 key size in bytes (128 bits)
#define AES_128_KEY_SIZE 16

/// AES-192 key size in bytes (192 bits)
#define AES_192_KEY_SIZE 24

/// AES-256 key size in bytes (256 bits)
#define AES_256_KEY_SIZE 32

/// AES block size in bytes (128 bits)
#define AES_BLOCK_SIZE 16

/// Number of encryption rounds for AES-128
#define AES_128_NUM_ROUNDS 10

/// Number of encryption rounds for AES-192
#define AES_192_NUM_ROUNDS 12

/// Number of encryption rounds for AES-256
#define AES_256_NUM_ROUNDS 14

/// Total number of round keys (128-bit words) for AES-128
#define AES_128_NUM_ROUND_KEYS (AES_128_NUM_ROUNDS + 1)

/// Total number of round keys (128-bit words) for AES-192
#define AES_192_NUM_ROUND_KEYS (AES_192_NUM_ROUNDS + 1)

/// Total number of round keys (128-bit words) for AES-256
#define AES_256_NUM_ROUND_KEYS (AES_256_NUM_ROUNDS + 1)

#ifdef __cplusplus
}
#endif

#endif // AES_CONSTANTS_H