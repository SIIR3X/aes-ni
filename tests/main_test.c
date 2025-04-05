#include "unity/unity.h"

void setUp(void) {}
void tearDown(void) {}

extern void register_aes_key_expansion_tests(void);
extern void register_aes_context_tests(void);
extern void register_aes_encrypt_tests(void);
extern void register_aes_decrypt_tests(void);
extern void register_aes_padding_tests(void);
extern void register_aes_ecb_tests(void);
extern void register_aes_cbc_tests(void);
extern void register_aes_cfb_tests(void);
extern void register_aes_ofb_tests(void);
extern void register_aes_ctr_tests(void);
extern void register_utils_tests(void);

int main(void)
{
	UNITY_BEGIN();

	register_aes_key_expansion_tests();
	register_aes_context_tests();
	register_aes_encrypt_tests();
	register_aes_decrypt_tests();
	register_aes_padding_tests();
	register_aes_ecb_tests();
	register_aes_cbc_tests();
	register_aes_cfb_tests();
	register_aes_ofb_tests();
	register_aes_ctr_tests();
	register_utils_tests();

	return UNITY_END();
}