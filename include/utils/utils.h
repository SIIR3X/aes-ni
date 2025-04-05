/**
 * @file utils/utils.h
 * @brief Utility functions for file I/O, base64 encoding/decoding, and byte-string conversion.
 *
 * This header defines helper functions for reading/writing text files,
 * encoding and decoding data using Base64, and converting between
 * strings and byte arrays. It also includes an error message display
 * function with optional program termination.
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Displays an error or information message.
 *
 * Prints a formatted message to stderr. If the `fatal` flag is non-zero,
 * the program will exit with EXIT_FAILURE after displaying the message.
 *
 * @param fatal Set to 1 to terminate the program after printing the message.
 * @param format printf-style format string.
 * @param ... Additional arguments to format the message.
 */
void show_message(int fatal, const char* format, ...);

/**
 * @brief Reads the entire contents of a text file into a null-terminated string.
 *
 * Allocates and returns a buffer containing the contents of the file,
 * including a null terminator. The length of the file (excluding the null byte)
 * is returned through the `size` pointer.
 *
 * The caller is responsible for freeing the returned buffer.
 *
 * @param filename Path to the input file.
 * @param size Pointer to a size_t that will hold the file length (can be NULL).
 * @return Pointer to the allocated string, or NULL if reading fails.
 */
char* read_file(const char* filename, size_t* size);

/**
 * @brief Writes a null-terminated string to a file.
 *
 * Opens the file in text mode and writes the given string to it.
 *
 * @param filename Path to the output file.
 * @param data Null-terminated string to write.
 * @return 0 on success, -1 on failure.
 */
int write_file(const char* filename, const char* data);

/**
 * @brief Encodes binary data into a Base64 null-terminated string.
 *
 * This function converts raw binary data into a Base64-encoded string
 * using the standard Base64 alphabet (A-Z, a-z, 0-9, +, /).
 *
 * The returned string is dynamically allocated and must be freed by the caller.
 *
 * @param data Pointer to the input binary data.
 * @param input_len Length of the input data in bytes.
 * @return Null-terminated Base64 string, or NULL on failure.
 */
char* base64_encode(const uint8_t* data, size_t input_len);

/**
 * @brief Decodes a Base64 string into raw binary data.
 *
 * This function decodes a Base64-encoded string back into its original
 * binary representation. The output buffer is dynamically allocated and
 * must be freed by the caller.
 *
 * If the input string contains invalid Base64 characters or has an incorrect
 * format, the function returns NULL.
 *
 * @param b64_string Null-terminated Base64-encoded string.
 * @param output_len Pointer to a size_t that will receive the output length (can be NULL).
 * @return Pointer to decoded binary data, or NULL on failure.
 */
uint8_t* base64_decode(const char* b64_string, size_t* output_len);

/**
 * @brief Converts a null-terminated string to a uint8_t byte array.
 *
 * The returned buffer is dynamically allocated and must be freed by the caller.
 * The length of the array (excluding the null terminator) is returned via `out_len`.
 *
 * @param str Null-terminated input string.
 * @param out_len Pointer to store the length of the resulting byte array.
 * @return Pointer to the uint8_t array, or NULL on failure.
 */
uint8_t* string_to_bytes(const char* str, size_t* out_len);

/**
 * @brief Converts a hexadecimal string to a uint8_t byte array.
 *
 * The input string must contain an even number of hex digits (0-9, a-f, A-F).
 * The function allocates memory for the byte array, which must be freed by the caller.
 *
 * @param hex_str Null-terminated string containing hexadecimal characters.
 * @param out_len Pointer to size_t where the output length will be stored.
 * @return Pointer to byte array, or NULL on error (invalid input or memory allocation failure).
 */
uint8_t* hex_string_to_bytes(const char* hex_str, size_t* out_len);

/**
 * @brief Converts a byte array to a null-terminated C string.
 *
 * The returned string is dynamically allocated and must be freed by the caller.
 * The input is assumed to be UTF-8 or ASCII-compatible (no validation is performed).
 *
 * @param bytes Pointer to the byte array.
 * @param len Length of the byte array.
 * @return Null-terminated string, or NULL on failure.
 */
char* bytes_to_string(const uint8_t* bytes, size_t len);

#ifdef __cplusplus
}
#endif

#endif // UTILS_H