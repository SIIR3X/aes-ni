#include "unity/unity.h"
#include "aes/padding/aes_padding.h"
#include <string.h>
#include <stdlib.h>

void test_aes_add_padding_pkcs7(void)
{
	const uint8_t input[5] = {0x48, 0x45, 0x4C, 0x4C, 0x4F};

	const uint8_t expected[16] = {
		0x48, 0x45, 0x4C, 0x4C, 0x4F,
		0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
		0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
		0x0B
	};

	size_t padded_len = 0;
	uint8_t* padded = aes_add_padding(input, 5, &padded_len, AES_PADDING_PKCS7);

	TEST_ASSERT_NOT_NULL(padded);
	TEST_ASSERT_EQUAL_UINT32(16, padded_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, padded, 16);

	free(padded);
}

void test_aes_unpad_pkcs7(void)
{
	const uint8_t padded[16] = {
		0x48, 0x45, 0x4C, 0x4C, 0x4F,
		0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
		0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
		0x0B
	};

	const uint8_t expected[5] = {
		0x48, 0x45, 0x4C, 0x4C, 0x4F
	};

	uint8_t buffer[32] = {0};
	memcpy(buffer, padded, 16);

	size_t new_len = aes_remove_padding(buffer, 16, AES_PADDING_PKCS7);
	TEST_ASSERT_EQUAL_UINT32(5, new_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, buffer, 5);
}

void test_aes_add_padding_zero(void)
{
	const uint8_t input[5] = {0x48, 0x45, 0x4C, 0x4C, 0x4F};

	const uint8_t expected[16] = {
		0x48, 0x45, 0x4C, 0x4C, 0x4F,
		0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00,
		0x00
	};

	size_t padded_len = 0;
	uint8_t* padded = aes_add_padding(input, 5, &padded_len, AES_PADDING_ZERO);

	TEST_ASSERT_NOT_NULL(padded);
	TEST_ASSERT_EQUAL_UINT32(16, padded_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, padded, 16);

	free(padded);
}

void test_aes_unpad_zero(void)
{
	const uint8_t padded[16] = {
		0x48, 0x45, 0x4C, 0x4C, 0x4F,
		0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00,
		0x00
	};

	const uint8_t expected[5] = {
		0x48, 0x45, 0x4C, 0x4C, 0x4F
	};

	uint8_t buffer[32] = {0};
	memcpy(buffer, padded, 16);

	size_t new_len = aes_remove_padding(buffer, 16, AES_PADDING_ZERO);
	TEST_ASSERT_EQUAL_UINT32(5, new_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, buffer, 5);
}

void test_aes_add_padding_x923(void)
{
	const uint8_t input[5] = {0x48, 0x45, 0x4C, 0x4C, 0x4F};

	const uint8_t expected[16] = {
		0x48, 0x45, 0x4C, 0x4C, 0x4F,
		0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00,
		0x0B
	};

	size_t padded_len = 0;
	uint8_t* padded = aes_add_padding(input, 5, &padded_len, AES_PADDING_ANSIX923);

	TEST_ASSERT_NOT_NULL(padded);
	TEST_ASSERT_EQUAL_UINT32(16, padded_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, padded, 16);

	free(padded);
}

void test_aes_unpad_x923(void)
{
	const uint8_t padded[16] = {
		0x48, 0x45, 0x4C, 0x4C, 0x4F,
		0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00,
		0x0B
	};

	const uint8_t expected[5] = {
		0x48, 0x45, 0x4C, 0x4C, 0x4F
	};

	uint8_t buffer[32] = {0};
	memcpy(buffer, padded, 16);

	size_t new_len = aes_remove_padding(buffer, 16, AES_PADDING_ANSIX923);
	TEST_ASSERT_EQUAL_UINT32(5, new_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, buffer, 5);
}

void register_aes_padding_tests(void)
{
	RUN_TEST(test_aes_add_padding_pkcs7);
	RUN_TEST(test_aes_unpad_pkcs7);
	RUN_TEST(test_aes_add_padding_zero);
	RUN_TEST(test_aes_unpad_zero);
	RUN_TEST(test_aes_add_padding_x923);
	RUN_TEST(test_aes_unpad_x923);
}