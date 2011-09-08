#include "util.h"

#include <stdio.h>

static char output_buffer[1024];

const char* buffer_to_hex(uint8_t* buffer, int len) {
  if (len > sizeof(output_buffer) - 1) {
#ifndef NDEBUG
    fprintf(stderr, "Exceeded max buffer size for hex conversion.\n");
#endif
    return NULL;
  }
  int idx;
  for (idx = 0; idx < len; ++idx) {
    if (sprintf(output_buffer + 2 * idx, "%02x", buffer[idx]) < 2) {
#ifndef NDEBUG
      perror("Error converting buffer to hex.\n");
#endif
      return NULL;
    }
  }
  output_buffer[2 * len] = '\0';
  return output_buffer;
}
