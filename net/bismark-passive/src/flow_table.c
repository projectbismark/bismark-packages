#include "flow_table.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#define NUM_PROBES 3
#define C1 0.5
#define C2 0.5
#define FNV_OFFSET_BASIS 0x811c9dc5

static uint32_t (*alternate_hash_function) (const char* data, int len) = NULL;

/* Implementation from http://isthe.com/chongo/src/fnv/hash_32.c */
static uint32_t fnv_hash_32 (const char* data, int len) {
  const unsigned char *bp = (const unsigned char *)data;
  const unsigned char *be = bp + len;
  uint32_t hval = FNV_OFFSET_BASIS;

  while (bp < be) {
    hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
    hval ^= *bp++;
  }
  return hval;
}

static int flow_entry_compare (flow_table_entry_t* first,
                                   flow_table_entry_t* second) {
    return first->occupied == second->occupied
        && first->ip_source == second->ip_source
        && first->ip_destination == second->ip_destination
        && first->transport_protocol == second->transport_protocol
        && first->port_source == second->port_source
        && first->port_destination == second->port_destination;
}

void flow_table_init (flow_table_t* table) {
  memset(table->entries, '\0', sizeof(table->entries));
  table->num_elements = 0;
  table->base_timestamp_seconds = 0;
  table->num_expired_flows = 0;
  table->num_dropped_flows = 0;
}

int flow_table_process_flow (flow_table_t* table,
                             flow_table_entry_t* new_entry,
                             const struct timeval* timestamp) {
  uint32_t hash;
  int probe;
  flow_table_entry_t* first_available = NULL;

  new_entry->occupied = ENTRY_OCCUPIED;
  hash = fnv_hash_32((char *)new_entry, sizeof(*new_entry));
  if (alternate_hash_function) {
    hash = alternate_hash_function((char *)new_entry, sizeof(*new_entry));
    fprintf(stderr, "Hello: %d", hash);
  } else {
    fprintf(stderr, "Hello: %d", hash);
  }

  for (probe = 0; probe < NUM_PROBES; ++probe) {
    uint32_t final_hash
      = (uint32_t)(hash + C1*probe + C2*probe*probe) % FLOW_TABLE_ENTRIES;
    flow_table_entry_t* entry = &table->entries[final_hash];
    if (flow_entry_compare (new_entry, entry)) {
      entry->last_update_time_seconds
          = table->base_timestamp_seconds + timestamp->tv_sec;
      return 0;
    } else if (entry->occupied == ENTRY_OCCUPIED
        && table->base_timestamp_seconds
            + entry->last_update_time_seconds
            + FLOW_TABLE_EXPIRATION_SECONDS < timestamp->tv_sec) {
      entry->occupied = ENTRY_DELETED;
      --table->num_elements;
      ++table->num_expired_flows;
    }
    if (entry->occupied != ENTRY_OCCUPIED) {
      if (!first_available) {
        first_available = entry;
      }
      if (entry->occupied == ENTRY_EMPTY) {
        break;
      }
    }
  }

  if (first_available) {
    *first_available = *new_entry;
    first_available->last_update_time_seconds
        = table->base_timestamp_seconds + timestamp->tv_sec;
    if (table->num_elements == 0) {
      table->base_timestamp_seconds = timestamp->tv_sec;
    }
    ++table->num_elements;
    return 0;
  }

  ++table->num_dropped_flows;
  return -1;
}

void testing_set_hash_function(uint32_t (*hasher)(const char* data, int len)) {
  alternate_hash_function = hasher;
}
