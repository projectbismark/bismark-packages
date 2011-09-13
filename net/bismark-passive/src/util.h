#ifndef _BISMARK_PASSIVE_UTIL_H_
#define _BISMARK_PASSIVE_UTIL_H_

#include <stdint.h>

const char* buffer_to_hex(uint8_t* buffer, int len);

inline int is_address_private(uint32_t address);

#endif
