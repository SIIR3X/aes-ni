#ifndef UTILS_TEST_H
#define UTILS_TEST_H

#include <emmintrin.h>

void print_block_diff(const __m128i expected, const __m128i actual);

#endif // UTILS_TEST_H