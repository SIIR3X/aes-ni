/**
 * @file main_utils.h
 * @brief Main argument handling and AES encryption/decryption interface.
 *
 * This header defines the structures and functions used to parse command-line
 * arguments and execute encryption or decryption based on AES parameters.
 * It supports various AES modes and padding schemes, and handles file-based
 * input/output operations.
 */

#ifndef MAIN_UTILS_H
#define MAIN_UTILS_H

#include "aes/core/aes_context.h"
#include "aes/padding/aes_padding.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Supported AES encryption modes.
 */
typedef enum {
	MODE_ECB, ///< Electronic Codebook mode
	MODE_CBC, ///< Cipher Block Chaining mode
	MODE_CFB, ///< Cipher Feedback mode
	MODE_OFB, ///< Output Feedback mode
	MODE_CTR, ///< Counter mode
	MODE_INVALID ///< Invalid mode (used for error handling)
} aes_mode_t;

/**
 * @brief Structure holding program arguments and encryption context.
 *
 * This structure encapsulates all the necessary information for performing
 * encryption or decryption, including the AES context, selected mode, padding
 * scheme, input/output file paths, and operation type.
 */
typedef struct {
	aes_context_t* ctx; ///< AES context containing keys and state
	aes_mode_t mode; ///< Selected AES mode of operation
	aes_padding_t padding; ///< Padding scheme (e.g., PKCS#7)
	uint8_t iv[AES_BLOCK_SIZE]; ///< Initialization Vector (required for some modes)
	const char* input_file; ///< Path to the input file
	const char* output_file; ///< Path to the output file
	int encrypt; ///< Set to 1 for encryption, 0 for decryption
} main_args_t;

/**
 * @brief Prints program usage instructions.
 *
 * @param prog Name of the executable (typically argv[0])
 */
void print_usage(const char* prog);

/**
 * @brief Parses command-line arguments into a main_args_t structure.
 *
 * Allocates and initializes a main_args_t structure based on the given
 * command-line arguments.
 *
 * @param argc Argument count
 * @param argv Argument vector
 * @return Pointer to the initialized main_args_t structure
 */
main_args_t* parse_args(int argc, char* argv[]);

/**
 * @brief Performs encryption based on the given arguments.
 *
 * This function handles file I/O and encryption using the selected mode,
 * padding, and key context provided in the main_args_t structure.
 *
 * @param args Pointer to a populated main_args_t structure
 */
void encrypt_mode(main_args_t* args);

/**
 * @brief Performs decryption based on the given arguments.
 *
 * This function handles file I/O and decryption using the selected mode,
 * padding, and key context provided in the main_args_t structure.
 *
 * @param args Pointer to a populated main_args_t structure
 */
void decrypt_mode(main_args_t* args);

#ifdef __cplusplus
}
#endif

#endif // MAIN_UTILS_H