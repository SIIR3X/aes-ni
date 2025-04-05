#include "utils_test.h"
#include <stdio.h>
#include <stdint.h>
#include <tmmintrin.h> 

void print_block_diff(const __m128i expected, const __m128i actual)
{
	uint8_t e[16], a[16], d[16];
	_mm_storeu_si128((__m128i*)e, expected);
	_mm_storeu_si128((__m128i*)a, actual);

	for (int i = 0; i < 16; ++i)
		d[i] = e[i] ^ a[i];

	printf("Mismatch:\n");
	printf("Byte | Expected | Actual | Diff\n");
	printf("-----+----------+--------+-----\n");
	for (int i = 0; i < 16; ++i)
	{
		printf(" %2d  |   %02x     |  %02x    |  %02x\n", i, e[i], a[i], d[i]);
	}
	printf("-----+----------+--------+-----\n");
}