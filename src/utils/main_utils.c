#include "utils/main_utils.h"
#include "utils/utils.h"
#include "aes/modes/aes_ecb.h"
#include "aes/modes/aes_cbc.h"
#include "aes/modes/aes_cfb.h"
#include "aes/modes/aes_ofb.h"
#include "aes/modes/aes_ctr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Parses the AES mode from a string.
 *
 * Converts a string representation of the AES mode (e.g., "ECB", "CBC") 
 * into the corresponding enum value.
 *
 * @param mode_str The input string representing the mode.
 * @return The corresponding aes_mode_t value, or MODE_INVALID if unrecognized.
 */
static inline aes_mode_t parse_mode(const char* mode_str)
{
	if (mode_str == NULL) return MODE_INVALID;

	if (strcmp(mode_str, "ECB") == 0) return MODE_ECB;
	if (strcmp(mode_str, "CBC") == 0) return MODE_CBC;
	if (strcmp(mode_str, "CFB") == 0) return MODE_CFB;
	if (strcmp(mode_str, "OFB") == 0) return MODE_OFB;
	if (strcmp(mode_str, "CTR") == 0) return MODE_CTR;

	return MODE_INVALID;
}

/**
 * @brief Parses the padding scheme from a string.
 *
 * Converts a string representation of the padding type 
 * (e.g., "pkcs7", "zero", "x923") into the corresponding enum value.
 * Defaults to PKCS#7 if the string is NULL or unrecognized.
 *
 * @param str The input string representing the padding type.
 * @return The corresponding aes_padding_t value.
 */
static inline aes_padding_t parse_padding(const char* str)
{
	if (str == NULL) return AES_PADDING_PKCS7;

	if (strcmp(str, "pkcs7") == 0) return AES_PADDING_PKCS7;
	if (strcmp(str, "zero") == 0) return AES_PADDING_ZERO;
	if (strcmp(str, "x923") == 0) return AES_PADDING_ANSIX923;

	return AES_PADDING_PKCS7;
}

void print_usage(const char* prog)
{
	printf("Usage:\n");
	printf("  %s -mode <ECB|CBC|CFB|OFB|CTR> -e|-d -in <dir> -out <dir> -key <hex> [-iv <hex>] [-padding <pkcs7|zero|x923>\n", prog);
}

main_args_t* parse_args(int argc, char* argv[])
{
	main_args_t* args = malloc(sizeof(main_args_t));
	if (!args) return NULL;

	args->encrypt = -1;
	const char* key_str = NULL;
	const char* iv_str = NULL;
	const char* padding_str = NULL;

	for (int i = 1; i < argc; ++i)
	{
		if (strcmp(argv[i], "-mode") == 0 && i + 1 < argc)
			args->mode = parse_mode(argv[++i]);
		else if (strcmp(argv[i], "-e") == 0)
			args->encrypt = 1;
		else if (strcmp(argv[i], "-d") == 0)
			args->encrypt = 0;
		else if (strcmp(argv[i], "-in") == 0 && i + 1 < argc)
			args->input_file = argv[++i];
		else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc)
			args->output_file = argv[++i];
		else if (strcmp(argv[i], "-key") == 0 && i + 1 < argc)
			key_str = argv[++i];
		else if (strcmp(argv[i], "-iv") == 0 && i + 1 < argc)
			iv_str = argv[++i];
		else if (strcmp(argv[i], "-padding") == 0 && i + 1 < argc)
			padding_str = argv[++i];
	}

	if (args->mode == MODE_INVALID || args->encrypt == -1 || !args->input_file || !args->output_file || !key_str)
	{
		print_usage(argv[0]);
		free(args);
		return NULL;
	}

	if (args->mode == MODE_ECB && iv_str)
	{
		print_usage(argv[0]);
		free(args);
		return NULL;
	}

	if (args->mode != MODE_ECB && !iv_str)
	{
		print_usage(argv[0]);
		free(args);
		return NULL;
	}

	if (args->mode != MODE_ECB && args->mode != MODE_CBC && padding_str)
	{
		print_usage(argv[0]);
		free(args);
		return NULL;
	}

	size_t key_size;
	uint8_t* key = hex_string_to_bytes(key_str, &key_size);
	if (!key)
	{
		print_usage(argv[0]);
		free(args);
		return NULL;
	}

	if (key_size != AES_128 && key_size != AES_192 && key_size != AES_256)
	{
		print_usage(argv[0]);
		free(args);
		free(key);
		return NULL;
	}

	if (args->mode != MODE_ECB)
	{
		size_t iv_size;
		uint8_t* iv = hex_string_to_bytes(iv_str, &iv_size);
		if (args->mode != MODE_ECB && !iv)
		{
			print_usage(argv[0]);
			free(args);
			free(key);
			return NULL;
		}

		if (iv_size != AES_BLOCK_SIZE)
		{
			print_usage(argv[0]);
			free(args);
			free(key);
			return NULL;
		}

		memcpy(args->iv, iv, AES_BLOCK_SIZE);

		free(iv);
	}

	args->padding = parse_padding(padding_str);

	args->ctx = (aes_context_t*)malloc(sizeof(aes_context_t));
	if (!args->ctx)
	{
		show_message(0, "Failed to allocate memory for AES context.");
		free(args);
		free(key);
		return NULL;
	}

	if (aes_context_init(args->ctx, key, key_size) != 0)
	{
		show_message(0, "Failed to initialize AES context.");
		free(args);
		return NULL;
	}

	free(key);

	return args;
}

void encrypt_mode(main_args_t* args)
{
	size_t input_size;
	char* input_str = read_file(args->input_file, &input_size);
	if (!input_str) return;

	uint8_t* input_data = string_to_bytes(input_str, &input_size);
	if (!input_data) 
	{
		free(input_str);
		return;
	}

	uint8_t* padded_data = input_data;
	size_t padded_size = input_size;

	if (args->mode == MODE_ECB || args->mode == MODE_CBC)
	{
		padded_data = aes_add_padding(input_data, input_size, &padded_size, args->padding);
		free(input_data);
		if (!padded_data) 
		{
			free(input_str);
			return;
		}
	}

	uint8_t* output_data = malloc(padded_size);
	if (!output_data) 
	{
		free(input_str);
		free(padded_data);
		return;
	}

	switch (args->mode)
	{
		case MODE_ECB: aes_ecb_encrypt(args->ctx, padded_data, padded_size, output_data); break;
		case MODE_CBC: aes_cbc_encrypt(args->ctx, args->iv, padded_data, padded_size, output_data); break;
		case MODE_CFB: aes_cfb_encrypt(args->ctx, args->iv, padded_data, padded_size, output_data); break;
		case MODE_OFB: aes_ofb_crypt(args->ctx, args->iv, padded_data, padded_size, output_data); break;
		case MODE_CTR: aes_ctr_crypt(args->ctx, args->iv, padded_data, padded_size, output_data); break;
		default: break;
	}

	char* output = base64_encode(output_data, padded_size);
	if (!output) 
	{
		free(input_str);
		free(padded_data);
		free(output_data);
		return;
	}

	if (write_file(args->output_file, output) != 0)
	{
		free(input_str);
		free(padded_data);
		free(output_data);
		free(output);
		return;
	}

	free(input_str);
	free(padded_data);
	free(output_data);
	free(output);
}

void decrypt_mode(main_args_t* args)
{
	size_t input_size;
	char* input_str = read_file(args->input_file, &input_size);
	if (!input_str) return;

	uint8_t* input_data = base64_decode(input_str, &input_size);
	if (!input_data) 
	{
		free(input_str);
		return;
	}

	uint8_t* output_data = malloc(input_size);
	if (!output_data) 
	{
		free(input_str);
		free(input_data);
		return;
	}

	switch (args->mode)
	{
		case MODE_ECB: aes_ecb_decrypt(args->ctx, input_data, input_size, output_data); break;
		case MODE_CBC: aes_cbc_decrypt(args->ctx, args->iv, input_data, input_size, output_data); break;
		case MODE_CFB: aes_cfb_decrypt(args->ctx, args->iv, input_data, input_size, output_data); break;
		case MODE_OFB: aes_ofb_crypt(args->ctx, args->iv, input_data, input_size, output_data); break;
		case MODE_CTR: aes_ctr_crypt(args->ctx, args->iv, input_data, input_size, output_data); break;
		default: break;
	}

	size_t unpadded_size = input_size;
	if (args->mode == MODE_ECB || args->mode == MODE_CBC)
		unpadded_size = aes_remove_padding(output_data, input_size, args->padding);

	char* output = bytes_to_string(output_data, unpadded_size);
	if (!output) 
	{
		free(input_str);
		free(input_data);
		return;
	}

	if (write_file(args->output_file, output) != 0)
	{
		free(input_str);
		free(input_data);
		free(output_data);
		free(output);
		return;
	}

	free(input_str);
	free(input_data);
	free(output_data);
	free(output);
}