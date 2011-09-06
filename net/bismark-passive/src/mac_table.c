#include "mac_table.h"

#include <string.h>

void mac_table_init(mac_table_t* const table) {
  memset(table, '\0', sizeof(*table));
}

#define MODULUS(m, d)  ((((m) % (d)) + (d)) % (d))
#define NORM(m)  (MODULUS(m, MAC_TABLE_ENTRIES))

int mac_table_lookup(mac_table_t* const table, uint64_t mac) {
  if (table->length > 0) {
    /* Search table starting w/ most recent MAC addresses. */
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if (table->entries[mac_id] == mac) {
        return mac_id;
      }
    }
  }

  if (table->length == MAC_TABLE_ENTRIES) {
    /* Discard the oldest MAC address. */
    table->first = NORM(table->first + 1);
  } else {
    ++table->length;
  }
  if (table->length > 1) {
    table->last = NORM(table->last + 1);
  }
  table->entries[table->last] = mac;
  if (table->added_since_last_update < MAC_TABLE_ENTRIES) {
    ++table->added_since_last_update;
  }
  return table->last;
}

int mac_table_write_update(mac_table_t* const table, gzFile handle) {
  int idx;
  for (idx = table->added_since_last_update; idx > 0; --idx) {
    int mac_id = NORM(table->last - idx + 1);
    if (!gzprintf(handle, "%lu\n", table->entries[mac_id])) {
      perror("Error writing update");
      return -1;
    }
  }
  if (!gzprintf(handle, "\n")) {
    perror("Error writing update");
    return -1;
  }
  table->added_since_last_update = 0;
  return 0;
}
