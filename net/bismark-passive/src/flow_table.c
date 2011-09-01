#include "flow_table.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#ifdef TESTING
/* This is for testing only */
static uint32_t (*alternate_hash_function)(const char* data, int len) = NULL;
#endif

/* Implementation from http://isthe.com/chongo/src/fnv/hash_32.c */
#define FNV_OFFSET_BASIS 0x811c9dc5
static uint32_t fnv_hash_32(const char* data, int len) {
  const unsigned char *bp = (const unsigned char *)data;
  const unsigned char *be = bp + len;
  uint32_t hval = FNV_OFFSET_BASIS;

  while (bp < be) {
    hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
    hval ^= *bp++;
  }
  return hval;
}

static int flow_entry_compare(flow_table_entry_t* first,
                                   flow_table_entry_t* second) {
    return first->occupied == second->occupied
        && first->ip_source == second->ip_source
        && first->ip_destination == second->ip_destination
        && first->transport_protocol == second->transport_protocol
        && first->port_source == second->port_source
        && first->port_destination == second->port_destination;
}

void flow_table_init(flow_table_t* table) {
  memset(table->entries, '\0', sizeof(table->entries));
  table->num_elements = 0;
  table->base_timestamp_seconds = 0;
  table->num_expired_flows = 0;
  table->num_dropped_flows = 0;
}

int flow_table_process_flow(flow_table_t* table,
                            flow_table_entry_t* new_entry,
                            const struct timeval* timestamp) {
  uint32_t hash;
  int probe;
  int first_available = -1;

  new_entry->occupied = ENTRY_OCCUPIED;
  hash = fnv_hash_32((char *)new_entry, sizeof(*new_entry));
#ifdef TESTING
  if (alternate_hash_function) {
    hash = alternate_hash_function((char *)new_entry, sizeof(*new_entry));
  }
#endif

  for (probe = 0; probe < HT_NUM_PROBES; ++probe) {
    uint32_t table_idx
      = (uint32_t)(hash + HT_C1*probe + HT_C2*probe*probe) % FLOW_TABLE_ENTRIES;
    flow_table_entry_t* entry = &table->entries[table_idx];
    if (entry->occupied == ENTRY_OCCUPIED
        && table->base_timestamp_seconds
            + entry->last_update_time_seconds
            + FLOW_TABLE_EXPIRATION_SECONDS < timestamp->tv_sec) {
      entry->occupied = ENTRY_DELETED;
      --table->num_elements;
      ++table->num_expired_flows;
    }
    if (flow_entry_compare(new_entry, entry)) {
      entry->last_update_time_seconds
          = timestamp->tv_sec - table->base_timestamp_seconds;
      return table_idx;
    }
    if (entry->occupied != ENTRY_OCCUPIED) {
      if (first_available < 0) {
        first_available = table_idx;
      }
      if (entry->occupied == ENTRY_EMPTY) {
        break;
      }
    }
  }

  if (first_available >= 0) {
    if (table->num_elements == 0) {
      table->base_timestamp_seconds = timestamp->tv_sec;
    }
    new_entry->last_update_time_seconds
        = timestamp->tv_sec - table->base_timestamp_seconds;
    table->entries[first_available] = *new_entry;
    ++table->num_elements;
    return first_available;
  }

  ++table->num_dropped_flows;
  return -1;
}

#ifdef TESTING
void testing_set_hash_function(uint32_t (*hasher)(const char* data, int len)) {
  alternate_hash_function = hasher;
}
#endif
