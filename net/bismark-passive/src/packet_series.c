#include "packet_series.h"

#include <stdio.h>

void packet_series_init(packet_series_t* series) {
  series->length = 0;
  series->discarded_by_overflow = 0;
}

int packet_series_add_packet(
    packet_series_t* series,
    const struct timeval* timestamp,
    uint32_t size,
    uint16_t flow) {
  if (series->length >= PACKET_DATA_BUFFER_ENTRIES) {
    ++series->discarded_by_overflow;
    return -1;
  }

  if (series->length == 0) {
    series->start_time_seconds = timestamp->tv_sec;
    series->packet_data[series->length].timestamp = timestamp->tv_usec;
  } else {
    series->packet_data[series->length].timestamp
      = (timestamp->tv_sec - series->packet_data[series->length - 1].timestamp) * NUM_MICROS_PER_SECOND
      + timestamp->tv_usec;
  }
  series->packet_data[series->length].size = size;
  series->packet_data[series->length].flow = flow;
  ++series->length;

  return 0;
}

int packet_series_write_update(packet_series_t* series, FILE* handle) {
  if (fprintf(handle,
              "%ld %d\n",
              series->start_time_seconds,
              series->discarded_by_overflow) < 0) {
    perror("Error writing update");
    return -1;
  }
  int idx;
  for (idx = 0; idx < series->length; ++idx) {
    if (fprintf(handle,
                "%d %hu %hu\n",
                series->packet_data[idx].timestamp,
                series->packet_data[idx].size,
                series->packet_data[idx].flow) < 0) {
      perror("Error writing update");
      return -1;
    }
  }
  fprintf(handle, "\n");
  return 0;
}
