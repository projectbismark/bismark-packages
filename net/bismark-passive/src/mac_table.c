#include "mac_table.h"

#include <string.h>

void mac_table_init(mac_table_t* table) {
  memset(table, '\0', sizeof(*table));
}

int mac_table_lookup(mac_table_t* table, uint64_t mac) {
  if (mac == 0) {
    return -1;
  }

  int mac_id;
  for (mac_id = 0; mac_id < MAC_TABLE_ENTRIES; ++mac_id) {
    if ((*table)[mac_id] == 0) {
      (*table)[mac_id] = mac;
    }
    if ((*table)[mac_id] == mac) {
      return mac_id;
    }
  }
  return -1;
}

int mac_table_write_update(mac_table_t* table, gzFile handle) {
  int mac_id;
  for (mac_id = 0;
       mac_id < MAC_TABLE_ENTRIES && (*table)[mac_id] != 0;
       ++mac_id) {
    if (!gzprintf(handle, "%d %lu\n", mac_id, (*table)[mac_id])) {
      perror("Error writing update");
      return -1;
    }
  }
  if (!gzprintf(handle, "\n")) {
    perror("Error writing update");
    return -1;
  }
  return 0;
}
