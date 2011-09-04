#ifndef _BISMARK_PASSIVE_FLOW_TABLE_H_
#define _BISMARK_PASSIVE_FLOW_TABLE_H_

#include <stdint.h>
#include <stdio.h>

struct timeval;

#include "constants.h"

typedef struct {
  /* These fields will be taken into account for hashing */
  uint32_t ip_source;
  uint32_t ip_destination;
  uint16_t port_source;
  uint16_t port_destination;
  uint8_t transport_protocol;

  /* These fields will not be taken into account for hashing */
#define ENTRY_EMPTY                  0
#define ENTRY_OCCUPIED_BUT_UNSENT    1
#define ENTRY_OCCUPIED               2
#define ENTRY_DELETED                3
  uint8_t occupied;
  uint32_t last_update_time_seconds;
} flow_table_entry_t;

typedef struct {
  flow_table_entry_t entries[FLOW_TABLE_ENTRIES];
  uint64_t base_timestamp_seconds;
  uint32_t num_elements;
  int num_expired_flows;
  int num_dropped_flows;
} flow_table_t;

void flow_table_init(flow_table_t* table);

int flow_table_process_flow(flow_table_t* table,
                            flow_table_entry_t* entry,
                            const struct timeval* timestamp);

int flow_table_write_update(flow_table_t* table, FILE* handle);

#ifndef NDEBUG
void testing_set_hash_function(uint32_t (*hasher)(const char* data, int len));
#endif

#endif
