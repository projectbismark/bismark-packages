#include "flow_table.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "hashing.h"

#ifdef TESTING
static uint32_t (*alternate_hash_function)(const char* data, int len) = NULL;
#endif

static int flow_entry_compare(flow_table_entry_t* first,
                                   flow_table_entry_t* second) {
    return (first->occupied == ENTRY_OCCUPIED_BUT_UNSENT
            || first->occupied == ENTRY_OCCUPIED)
        && (second->occupied == ENTRY_OCCUPIED_BUT_UNSENT
            || second->occupied == ENTRY_OCCUPIED)
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
                            int64_t timestamp_seconds) {

  const int hash_size = sizeof(new_entry->ip_source)
                      + sizeof(new_entry->ip_destination)
                      + sizeof(new_entry->port_source)
                      + sizeof(new_entry->port_destination)
                      + sizeof(new_entry->transport_protocol);
  uint32_t hash = fnv_hash_32((char *)new_entry, hash_size);
#ifdef TESTING
  if (alternate_hash_function) {
    hash = alternate_hash_function((char *)new_entry, sizeof(*new_entry));
  }
#endif

  /* Don't let the last_update of a flow exceed its datatype bounds. */
  if (timestamp_seconds - table->base_timestamp_seconds
          > FLOW_TABLE_MAX_UPDATE_OFFSET
      || timestamp_seconds - table->base_timestamp_seconds
          < FLOW_TABLE_MIN_UPDATE_OFFSET) {
    ++table->num_dropped_flows;
    return -1;
  }

  int first_available = -1;
  int probe;
  for (probe = 0; probe < HT_NUM_PROBES; ++probe) {
    uint32_t table_idx
      = (uint32_t)(hash + HT_C1*probe + HT_C2*probe*probe) % FLOW_TABLE_ENTRIES;
    flow_table_entry_t* entry = &table->entries[table_idx];
    if (entry->occupied == ENTRY_OCCUPIED
        && table->base_timestamp_seconds
            + entry->last_update_time_seconds
            + FLOW_TABLE_EXPIRATION_SECONDS < timestamp_seconds) {
      entry->occupied = ENTRY_DELETED;
      --table->num_elements;
      ++table->num_expired_flows;
    }
    if (flow_entry_compare(new_entry, entry)) {
      entry->last_update_time_seconds
          = timestamp_seconds - table->base_timestamp_seconds;
      return table_idx;
    }
    if (entry->occupied != ENTRY_OCCUPIED
        && entry->occupied != ENTRY_OCCUPIED_BUT_UNSENT) {
      if (first_available < 0) {
        first_available = table_idx;
      }
      if (entry->occupied == ENTRY_EMPTY) {
        break;
      }
    }
  }

  if (first_available < 0) {
    ++table->num_dropped_flows;
    return -1;
  }

  if (table->num_elements == 0) {
    table->base_timestamp_seconds = timestamp_seconds;
  }
  new_entry->occupied = ENTRY_OCCUPIED_BUT_UNSENT;
  new_entry->last_update_time_seconds
      = timestamp_seconds - table->base_timestamp_seconds;
  table->entries[first_available] = *new_entry;
  ++table->num_elements;
  return first_available;
}

void flow_table_advance_base_timestamp(flow_table_t* table,
                                       int64_t new_timestamp) {
  const int64_t offset = new_timestamp - table->base_timestamp_seconds;
  int idx;
  for (idx = 0; idx < FLOW_TABLE_ENTRIES; ++idx) {
    if (table->entries[idx].occupied == ENTRY_OCCUPIED_BUT_UNSENT ||
        table->entries[idx].occupied == ENTRY_OCCUPIED) {
      if ((int32_t)table->entries[idx].last_update_time_seconds - offset
          < FLOW_TABLE_MIN_UPDATE_OFFSET) {
        table->entries[idx].occupied = ENTRY_DELETED;
        --table->num_elements;
      } else {
        table->entries[idx].last_update_time_seconds -= offset;
      }
    }
  }
  table->base_timestamp_seconds = new_timestamp;
}

int flow_table_write_update(flow_table_t* table, gzFile handle) {
  if (!gzprintf(handle,
                "%ld %u %d %d\n",
                table->base_timestamp_seconds,
                table->num_elements,
                table->num_expired_flows,
                table->num_dropped_flows)) {
    perror("Error sending update");
    return -1;
  }

  int idx;
  for (idx = 0; idx < FLOW_TABLE_ENTRIES; ++idx) {
    if (table->entries[idx].occupied == ENTRY_OCCUPIED_BUT_UNSENT) {
      if (!gzprintf(handle,
            "%u %u %u %hhu %hu %hu\n",
            idx,
            table->entries[idx].ip_source,
            table->entries[idx].ip_destination,
            table->entries[idx].transport_protocol,
            table->entries[idx].port_source,
            table->entries[idx].port_destination)) {
        perror("Error sending update");
        return -1;
      }
      table->entries[idx].occupied = ENTRY_OCCUPIED;
    }
  }
  if (!gzprintf(handle, "\n")) {
    perror("Error sending update");
    return -1;
  }

  return 0;
}

#ifdef TESTING
void testing_set_hash_function(uint32_t (*hasher)(const char* data, int len)) {
  alternate_hash_function = hasher;
}
#endif
