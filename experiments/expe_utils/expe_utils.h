#ifndef EXPE_UTILS_H
#define EXPE_UTILS_H

#include <stdint.h>
#include <stddef.h>
#define MB(x) ((size_t)(x) * 1024 * 1024)

uint64_t get_time_ns(void);

void fill_random(uint8_t* buffer, size_t len);

#endif // EXPE_UTILS_H