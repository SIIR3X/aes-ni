#include "unity/unity.h"
#include "aes/core/aes_decrypt.h"
#include "aes/core/aes_key_expansion.h"
#include "utils_test.h"
#include <smmintrin.h>

void test_aes128_decrypt_block(void)
{
	const __m128i key = _mm_setr_epi8(
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f
	);

	const __m128i ciphertext = _mm_setr_epi8(
		0x69, 0xc4, 0xe0, 0xd8,
		0x6a, 0x7b, 0x04, 0x30,
		0xd8, 0xcd, 0xb7, 0x80,
		0x70, 0xb4, 0xc5, 0x5a
	);

	const __m128i expected_plaintext = _mm_setr_epi8(
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff
	);

	__m128i enc_round_keys[AES_128_NUM_ROUND_KEYS];
	aes128_key_expansion(key, enc_round_keys);

	__m128i dec_round_keys[AES_128_NUM_ROUND_KEYS];
	aes128_invert_round_keys(enc_round_keys, dec_round_keys);

	__m128i plaintext;
	aes128_decrypt_block(ciphertext, &plaintext, dec_round_keys);

	__m128i diff = _mm_xor_si128(plaintext, expected_plaintext);
	int match = _mm_test_all_zeros(diff, _mm_set1_epi32(-1));

	if (!match)
	{
		print_block_diff(expected_plaintext, plaintext);
		TEST_FAIL_MESSAGE("AES-128 decryption output mismatch");
	}
}

void test_aes192_decrypt_block(void)
{
	const __m128i user_key[2] = {
		_mm_setr_epi8(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f),
		_mm_setr_epi8(0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	};

	const __m128i ciphertext = _mm_setr_epi8(
		0xdd, 0xa9, 0x7c, 0xa4,
		0x86, 0x4c, 0xdf, 0xe0,
		0x6e, 0xaf, 0x70, 0xa0,
		0xec, 0x0d, 0x71, 0x91
	);

	const __m128i expected_plaintext = _mm_setr_epi8(
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff
	);

	__m128i enc_round_keys[AES_192_NUM_ROUND_KEYS];
	aes192_key_expansion(user_key, enc_round_keys);

	__m128i dec_round_keys[AES_192_NUM_ROUND_KEYS];
	aes192_invert_round_keys(enc_round_keys, dec_round_keys);

	__m128i plaintext;
	aes192_decrypt_block(ciphertext, &plaintext, dec_round_keys);

	__m128i diff = _mm_xor_si128(plaintext, expected_plaintext);
	int match = _mm_test_all_zeros(diff, _mm_set1_epi32(-1));

	if (!match)
	{
		print_block_diff(expected_plaintext, plaintext);
		TEST_FAIL_MESSAGE("AES-192 decryption output mismatch");
	}
}

void test_aes256_decrypt_block(void)
{
	const __m128i user_key[2] = {
		_mm_setr_epi8(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f),
		_mm_setr_epi8(0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f)
	};

	const __m128i ciphertext = _mm_setr_epi8(
		0x8e, 0xa2, 0xb7, 0xca,
		0x51, 0x67, 0x45, 0xbf,
		0xea, 0xfc, 0x49, 0x90,
		0x4b, 0x49, 0x60, 0x89
	);

	const __m128i expected_plaintext = _mm_setr_epi8(
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff
	);

	__m128i enc_round_keys[AES_256_NUM_ROUND_KEYS];
	aes256_key_expansion(user_key, enc_round_keys);

	__m128i dec_round_keys[AES_256_NUM_ROUND_KEYS];
	aes256_invert_round_keys(enc_round_keys, dec_round_keys);

	__m128i plaintext;
	aes256_decrypt_block(ciphertext, &plaintext, dec_round_keys);

	__m128i diff = _mm_xor_si128(plaintext, expected_plaintext);
	int match = _mm_test_all_zeros(diff, _mm_set1_epi32(-1));

	if (!match)
	{
		print_block_diff(expected_plaintext, plaintext);
		TEST_FAIL_MESSAGE("AES-256 decryption output mismatch");
	}
}

void register_aes_decrypt_tests(void)
{
	RUN_TEST(test_aes128_decrypt_block);
	RUN_TEST(test_aes192_decrypt_block);
	RUN_TEST(test_aes256_decrypt_block);
}