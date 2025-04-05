#include "unity/unity.h"
#include "aes/core/aes_context.h"

void test_aes_context_init_128(void)
{
	const uint8_t key_128[AES_128] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f
	};

	aes_context_t ctx;
	int result = aes_context_init(&ctx, key_128, AES_128);
	TEST_ASSERT_EQUAL_INT(0, result);
	TEST_ASSERT_EQUAL_UINT32(AES_128, ctx.key_size);
}

void test_aes_context_init_192(void)
{
	const uint8_t key_192[AES_192] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17
	};

	aes_context_t ctx;
	int result = aes_context_init(&ctx, key_192, AES_192);
	TEST_ASSERT_EQUAL_INT(0, result);
	TEST_ASSERT_EQUAL_UINT32(AES_192, ctx.key_size);
}

void test_aes_context_init_256(void)
{
	const uint8_t key_256[AES_256] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f
	};

	aes_context_t ctx;
	int result = aes_context_init(&ctx, key_256, AES_256);
	TEST_ASSERT_EQUAL_INT(0, result);
	TEST_ASSERT_EQUAL_UINT32(AES_256, ctx.key_size);
}

void test_aes_context_init_invalid_size(void)
{
	const uint8_t invalid_key[10] = {0};
	aes_context_t ctx;
	int result = aes_context_init(&ctx, invalid_key, 10);
	TEST_ASSERT_NOT_EQUAL(0, result);
}

void register_aes_context_tests(void)
{
	RUN_TEST(test_aes_context_init_128);
	RUN_TEST(test_aes_context_init_192);
	RUN_TEST(test_aes_context_init_256);
	RUN_TEST(test_aes_context_init_invalid_size);
}