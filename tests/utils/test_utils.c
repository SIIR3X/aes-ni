#include "unity/unity.h"
#include "utils/utils.h"
#include <stdlib.h>

void test_base64_encode(void)
{
	const uint8_t input[] = {
		0x48, 0x65, 0x6C, 0x6C, 0x6F,
		0x20,
		0x41, 0x45, 0x53
	};

	const char* expected = "SGVsbG8gQUVT";

	char* encoded = base64_encode(input, sizeof(input));
	TEST_ASSERT_NOT_NULL(encoded);
	TEST_ASSERT_EQUAL_STRING(expected, encoded);

	free(encoded);
}

void test_base64_decode(void)
{
	const char* b64_input = "SGVsbG8gQUVT";

	const uint8_t expected[] = {
		0x48, 0x65, 0x6C, 0x6C, 0x6F,
		0x20,
		0x41, 0x45, 0x53
	};

	size_t output_len = 0;
	uint8_t* decoded = base64_decode(b64_input, &output_len);

	TEST_ASSERT_NOT_NULL(decoded);
	TEST_ASSERT_EQUAL_UINT32(sizeof(expected), output_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, decoded, output_len);

	free(decoded);
}

void test_string_to_bytes(void)
{
	const char* input = "Hello, AES!";

	const uint8_t expected[] = {
		0x48, 0x65, 0x6C, 0x6C, 0x6F,
		0x2C, 0x20, 0x41, 0x45, 0x53, 0x21
	};

	size_t len = 0;
	uint8_t* result = string_to_bytes(input, &len);

	TEST_ASSERT_NOT_NULL(result);
	TEST_ASSERT_EQUAL_UINT32(sizeof(expected), len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, result, len);

	free(result);
}

void test_hex_string_to_bytes(void)
{
	const char* hex_input = "48656C6C6F20414553";
	
	const uint8_t expected[] = {
		0x48, 0x65, 0x6C, 0x6C, 0x6F,
		0x20,
		0x41, 0x45, 0x53
	};

	size_t out_len = 0;
	uint8_t* result = hex_string_to_bytes(hex_input, &out_len);

	TEST_ASSERT_NOT_NULL(result);
	TEST_ASSERT_EQUAL_UINT32(sizeof(expected), out_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, result, out_len);

	free(result);
}

void test_bytes_to_string(void)
{
	const uint8_t input[] = {
		0x48, 0x65, 0x6C, 0x6C, 0x6F,
		0x2C, 0x20, 0x41, 0x45, 0x53, 0x21
	};

	const char* expected = "Hello, AES!";

	char* result = bytes_to_string(input, sizeof(input));

	TEST_ASSERT_NOT_NULL(result);
	TEST_ASSERT_EQUAL_STRING(expected, result);

	free(result);
}

void register_utils_tests(void)
{
	RUN_TEST(test_base64_encode);
	RUN_TEST(test_base64_decode);
	RUN_TEST(test_string_to_bytes);
	RUN_TEST(test_bytes_to_string);
}