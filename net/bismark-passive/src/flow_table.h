#ifndef _BISMARK_PASSIVE_FLOW_TABLE_H_
#define _BISMARK_PASSIVE_FLOW_TABLE_H_

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <zlib.h>

#include "constants.h"

typedef struct {
  /* These fields will be taken into account for hashing */
  uint32_t ip_source;
  uint32_t ip_destination;
  uint16_t port_source;
  uint16_t port_destination;
  uint8_t transport_protocol;

  /* These fields will not be taken into account for hashing */
  uint8_t occupied;
#define ENTRY_EMPTY                  0
  /* All new flow entries are in this state, which indicates that their
   * information hasn't been sent to the server yet. */
#define ENTRY_OCCUPIED_BUT_UNSENT    1
  /* An entry is valid and has already been sent to the server. */
#define ENTRY_OCCUPIED               2
  /* An entry is "deleted". Needed because the hash table is open addressed. */
#define ENTRY_DELETED                3

  /* An offset from base_timestamp_seconds. This restricts the age of a flow
   * record to around 9 hours. */
  int16_t last_update_time_seconds;
} flow_table_entry_t;

typedef struct {
  /* An open addressed hash table with quadratic probing. */
  flow_table_entry_t entries[FLOW_TABLE_ENTRIES];
  /* The timestamp used to calculate all timestamp offsets in the table. */
  time_t base_timestamp_seconds;
  uint32_t num_elements;
  /* Flows are expired after FLOW_TABLE_EXPIRATION_SECONDS */
  int num_expired_flows;
  int num_dropped_flows;
} flow_table_t;

void flow_table_init(flow_table_t* const table);

/* Add a flow to the hash table if it doesn't already exist. Does not claim
 * ownership of entry or timestamp. If expired entries are encountered in the
 * process, then delete them. */
int flow_table_process_flow(flow_table_t* const table,
                            flow_table_entry_t* const entry,
                            time_t timestamp_seconds);

/* Advance the base timestamp to a new value. This will rewrite offsets of
 * existing flows to match the new base timestamp, which can cause flows to be
 * deleted if the new base makes the offsets larger than INT16_MAX. */
void flow_table_advance_base_timestamp(flow_table_t* const table,
                                       time_t new_timestamp);

/* Write entries in the hash table that are marked ENTRY_OCCUPIED_BUT_UNSENT,
 * then update their state to ENTRY_OCCUPIED. This ensures each flow record is
 * only sent once. */
int flow_table_write_update(flow_table_t* const table, gzFile handle);

#ifndef NDEBUG
void testing_set_hash_function(uint32_t (*hasher)(const char* data, int len));
#endif

#endif
