#ifndef _BISMARK_PASSIVE_HASHING_H_
#define _BISMARK_PASSIVE_HASHING_H_

#include <stdint.h>

#define FNV_OFFSET_BASIS 0x811c9dc5
static uint32_t fnv_hash_32(const char* data, int len) {
  const unsigned char* bp = (const unsigned char *)data;
  const unsigned char* const be = bp + len;
  uint32_t hval = FNV_OFFSET_BASIS;

  while (bp < be) {
    hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
    hval ^= *bp++;
  }
  return hval;
}

#endif
