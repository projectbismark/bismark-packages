#include "packet_series.h"

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
    series->start_time = *timestamp;
  }
  series->packet_data[series->length].timestamp
    = (timestamp->tv_sec - series->start_time.tv_sec) * NUM_MICROS_PER_SECOND
      + (timestamp->tv_usec - series->start_time.tv_usec);
  series->packet_data[series->length].size = size;
  series->packet_data[series->length].flow = flow;
  ++series->length;

  return 0;
}
