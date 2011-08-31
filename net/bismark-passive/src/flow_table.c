#include "flow_table.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#define NUM_PROBES 3
#define C1 0.5
#define C2 0.5
#define FNV_PRIME 16777619
#define FNV_OFFSET_BASIS 2166136261

static uint32_t fnv_hash_32 (const char* data, int len) {
  int idx;
  uint32_t hash = FNV_OFFSET_BASIS;
  for (idx = 0; idx < len; ++idx) {
    hash *= FNV_PRIME;
    hash ^= (uint32_t)data[idx];
  }
  return hash;
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
  table->num_expired_flows = 0;
  table->num_dropped_flows = 0;
}

int flow_table_process_flow (flow_table_t* table,
                             flow_table_entry_t* new_entry,
                             const struct timeval* timestamp) {
  uint32_t hash;
  int probe;
  flow_table_entry_t* first_available = NULL;

  /* TODO(sburnett): Set initial flow statistics here */
  new_entry->occupied = ENTRY_OCCUPIED;
  hash = fnv_hash_32((char *)new_entry, sizeof(*new_entry));

  for (probe = 0; probe < NUM_PROBES; ++probe) {
    uint32_t final_hash
      = (uint32_t)(hash + C1*probe + C2*probe*probe) % FLOW_TABLE_ENTRIES;
    flow_table_entry_t* entry = &table->entries[final_hash];
    if (flow_entry_compare (entry, new_entry)) {
      entry->last_updated = timestamp->tv_sec;
      return 0;
    } else if (entry->occupied == ENTRY_OCCUPIED
        && entry->last_updated + FLOW_TABLE_EXPIRATION_SECONDS < timestamp->tv_sec) {
      entry->occupied = ENTRY_DELETED;
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
    first_available->last_updated = timestamp->tv_sec;
    return 0;
  }

  ++table->num_dropped_flows;
  return -1;
}
