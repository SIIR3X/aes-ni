#define _POSIX_C_SOURCE 199309L

#include "expe_utils/expe_utils.h"
#include <time.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
uint64_t get_time_ns(void)
{
	LARGE_INTEGER freq, counter;
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&counter);
	return (counter.QuadPart * 1000000000ULL) / freq.QuadPart;
}
#else
uint64_t get_time_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
#endif

void fill_random(uint8_t* buffer, size_t len)
{
	srand((unsigned)time(NULL));

	for (size_t i = 0; i < len; ++i)
		buffer[i] = rand() % 256;
}