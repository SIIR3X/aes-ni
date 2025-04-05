#include "utils/utils.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static uint8_t b64_reverse_table[256];

static void init_b64_reverse_table(void)
{
	memset(b64_reverse_table, 0x80, 256);
	for (int i = 0; i < 64; i++)
		b64_reverse_table[(unsigned char)b64_table[i]] = (uint8_t)i;
	b64_reverse_table['='] = 0;
}

void show_message(int fatal, const char* format, ...)
{
	va_list args;
	va_start(args, format);
	fprintf(stderr, "[MESSAGE] ");
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	va_end(args);

	if (fatal)
		exit(EXIT_FAILURE);
}

char* read_file(const char* filename, size_t* out_len)
{
	FILE* file = fopen(filename, "rb");
	if (!file)
	{
		show_message(1, "Failed to open file: %s", filename);
		return NULL;
	}

	if (fseek(file, 0, SEEK_END) != 0)
	{
		fclose(file);
		show_message(0, "Failed to seek in file: %s", filename);
		return NULL;
	}

	long size = ftell(file);
	if (size < 0)
	{
		fclose(file);
		show_message(0, "Failed to get file size: %s", filename);
		return NULL;
	}
	rewind(file);

	char* buffer = malloc(size + 1);
	if (!buffer)
	{
		fclose(file);
		show_message(0, "Failed to allocate memory for file: %s", filename);
		return NULL;
	}

	if (fread(buffer, 1, size, file) != (size_t)size)
	{
		free(buffer);
		fclose(file);
		show_message(0, "Failed to read file: %s", filename);
		return NULL;
	}

	buffer[size] = '\0';
	
	if (fclose(file) != 0)
	{
		free(buffer);
		show_message(0, "Failed to close file after reading: %s", filename);
		return NULL;
	}

	if (out_len)
		*out_len = (size_t)size;

	return buffer;
}

int write_file(const char* filename, const char* text)
{
	FILE* file = fopen(filename, "w");
	if (!file)
	{
		show_message(0, "Failed to open file for writing: %s", filename);
		return -1;
	}

	if (fputs(text, file) == EOF)
	{
		fclose(file);
		show_message(0, "Failed to write to file: %s", filename);
		return -1;
	}

	if (fclose(file) != 0)
	{
		show_message(0, "Failed to close file after writing: %s", filename);
		return -1;
	}

	return 0;
}

char* base64_encode(const uint8_t* data, size_t input_len)
{
	if (!data || input_len == 0)
	{
		show_message(0, "Invalid input data for Base64 encoding.");
		return NULL;
	}

	size_t output_len = 4 * ((input_len + 2) / 3);
	char* encoded = malloc(output_len + 1);

	if (!encoded)
	{
		show_message(0, "Failed to allocate memory for Base64 encoding.");
		return NULL;
	}

	size_t j = 0;

	for (size_t i = 0; i < input_len; i += 3)
	{
		uint32_t octet_a = i < input_len ? data[i] : 0;
		uint32_t octet_b = (i + 1) < input_len ? data[i + 1] : 0;
		uint32_t octet_c = (i + 2) < input_len ? data[i + 2] : 0;

		uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

		encoded[j++] = b64_table[(triple >> 18) & 0x3F];
		encoded[j++] = b64_table[(triple >> 12) & 0x3F];
		encoded[j++] = (i + 1 < input_len) ? b64_table[(triple >> 6) & 0x3F] : '=';
		encoded[j++] = (i + 2 < input_len) ? b64_table[triple & 0x3F] : '=';
	}

	encoded[output_len] = '\0';
	return encoded;
}

uint8_t* base64_decode(const char* b64_string, size_t* output_len)
{
	if (!b64_string)
	{
		show_message(0, "Invalid Base64 string for decoding.");
		return NULL;
	}

	static int initialized = 0;
	if (!initialized)
	{
		init_b64_reverse_table();
		initialized = 1;
	}

	size_t input_len = strlen(b64_string);
	if (input_len % 4 != 0)
	{
		show_message(0, "Invalid Base64 string length: %zu", input_len);
		return NULL;
	}

	size_t out_len_est = input_len / 4 * 3;
	if (b64_string[input_len - 1] == '=') out_len_est--;
	if (b64_string[input_len - 2] == '=') out_len_est--;

	uint8_t* decoded = malloc(out_len_est);
	if (!decoded)
	{
		show_message(0, "Failed to allocate memory for Base64 decoding.");
		return NULL;
	}

	size_t j = 0;
	for (size_t i = 0; i < input_len; i += 4)
	{
		uint32_t sextet_a = b64_reverse_table[(unsigned char)b64_string[i]];
		uint32_t sextet_b = b64_reverse_table[(unsigned char)b64_string[i + 1]];
		uint32_t sextet_c = b64_reverse_table[(unsigned char)b64_string[i + 2]];
		uint32_t sextet_d = b64_reverse_table[(unsigned char)b64_string[i + 3]];

		if (sextet_a & 0x80 || sextet_b & 0x80 || sextet_c & 0x80 || sextet_d & 0x80)
		{
			free(decoded);
			show_message(0, "Invalid Base64 characters in input string.");
			return NULL;
		}

		uint32_t triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;

		if (j < out_len_est) decoded[j++] = (triple >> 16) & 0xFF;
		if (j < out_len_est) decoded[j++] = (triple >> 8) & 0xFF;
		if (j < out_len_est) decoded[j++] = triple & 0xFF;
	}

	if (output_len)
		*output_len = out_len_est;

	return decoded;
}

uint8_t* string_to_bytes(const char* str, size_t* out_len)
{
	if (!str)
	{
		show_message(0, "Invalid string for conversion to bytes.");
		return NULL;
	}

	size_t len = strlen(str);
	uint8_t* buffer = malloc(len);
	if (!buffer)
	{
		show_message(0, "Failed to allocate memory for string to bytes conversion.");
		return NULL;
	}

	memcpy(buffer, str, len);

	if (out_len)
		*out_len = len;

	return buffer;
}

uint8_t* hex_string_to_bytes(const char* hex_str, size_t* out_len)
{
	if (!hex_str)
	{
		show_message(0, "Invalid hex string for conversion to bytes.");
		return NULL;
	}

	size_t hex_len = strlen(hex_str);
	if (hex_len % 2 != 0)
	{
		show_message(0, "Hex string must have an even length.");
		return NULL;
	}

	size_t byte_len = hex_len / 2;
	uint8_t* buffer = malloc(byte_len);
	if (!buffer)
	{
		show_message(0, "Failed to allocate memory for hex string to bytes conversion.");
		return NULL;
	}

	for (size_t i = 0; i < byte_len; ++i)
	{
		char byte_str[3] = { hex_str[2*i], hex_str[2*i + 1], '\0' };

		if (!isxdigit(byte_str[0]) || !isxdigit(byte_str[1]))
		{
			free(buffer);
			show_message(0, "Invalid hex character in string: %s", byte_str);
			return NULL;
		}

		buffer[i] = (uint8_t)strtoul(byte_str, NULL, 16);
	}

	if (out_len)
		*out_len = byte_len;

	return buffer;
}

char* bytes_to_string(const uint8_t* bytes, size_t len)
{
	if (!bytes || len == 0)
	{
		show_message(0, "Invalid byte array for conversion to string.");
		return NULL;
	}

	size_t new_len = 0;
	for (size_t i = 0; i < len; ++i)
	{
		if (bytes[i] == '\r' && (i + 1 < len) && bytes[i + 1] == '\n')
			++i;

		new_len++;
	}

	char* str = malloc(new_len + 1);
	if (!str)
	{
		show_message(0, "Failed to allocate memory for byte array to string conversion.");
		return NULL;
	}

	size_t j = 0;
	for (size_t i = 0; i < len; ++i)
	{
		if (bytes[i] == '\r' && (i + 1 < len) && bytes[i + 1] == '\n')
		{
			str[j++] = '\n';
			++i;
		}
		else
			str[j++] = bytes[i];
	}
	
	str[j] = '\0';

	return str;
}