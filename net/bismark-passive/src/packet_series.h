#ifndef _BISMARK_PASSIVE_PACKET_SERIES_H_
#define _BISMARK_PASSIVE_PACKET_SERIES_H_

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

#include "constants.h"

/* Information about a single packet. */
typedef struct {
  /* The packet's timestamp, expressed as microseconds offset from
   * packet_series_t.start_time. Expressing timestamps this way conserves space
   * (4 bytes vs 8 bytes per timestamp). */
  int32_t timestamp;
  /* Number of bytes in the packet. */
  uint16_t size;
  /* Index into the flow table. Index 0 means "no information available." */
  uint16_t flow;
} packet_data_t;

/** A data structure for storing information about series of packets. For space
 * efficiency, we assume packet timestamps cover a cumulative range of at most
 * 2^31 microseconds (~36 minutes). */
typedef struct {
  /* The timestamp of the first packet in the series. */
  int64_t start_time_seconds;
  /* The number of packets received so far. */
  int32_t length;

  /* Packet data for the series. */
  packet_data_t packet_data[PACKET_DATA_BUFFER_ENTRIES];

  /* If length >= PACKET_DATA_BUFFER_ENTRIES, new packets are discarded because
   * there is no space for them. */
  uint32_t discarded_by_overflow;
} packet_series_t;

void packet_series_init(packet_series_t* packet_series);

int packet_series_add_packet(
    packet_series_t* packet_series,
    const struct timeval* timestamp,
    uint32_t size,
    uint16_t flow);

int packet_series_write_update(packet_series_t* series, FILE* handle);

#endif
