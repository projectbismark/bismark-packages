#include "mac_table.h"

#include <inttypes.h>
#include <string.h>

#include "anonymization.h"
#include "util.h"

void mac_table_init(mac_table_t* const table) {
  memset(table, '\0', sizeof(*table));
}

#define MODULUS(m, d)  ((((m) % (d)) + (d)) % (d))
#define NORM(m)  (MODULUS(m, MAC_TABLE_ENTRIES))

int mac_table_lookup(mac_table_t* const table, const uint8_t mac[ETH_ALEN]) {
  if (table->length > 0) {
    /* Search table starting w/ most recent MAC addresses. */
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if (!memcmp(table->entries[mac_id], mac, ETH_ALEN)) {
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
  memcpy(table->entries[table->last], mac, sizeof(mac));
  if (table->added_since_last_update < MAC_TABLE_ENTRIES) {
    ++table->added_since_last_update;
  }
  return table->last;
}

int mac_table_write_update(mac_table_t* const table, gzFile handle) {
  int idx;
  for (idx = table->added_since_last_update; idx > 0; --idx) {
    int mac_id = NORM(table->last - idx + 1);
#ifndef DISABLE_ANONYMIZATION
    uint8_t digest_mac[ETH_ALEN];
    if (anonymize_mac(table->entries[mac_id], digest_mac)) {
#ifndef NDEBUG
      fprintf(stderr, "Error anonymizing MAC\n");
#endif
      return -1;
    }
    if (!gzprintf(handle, "%s\n", buffer_to_hex(digest_mac, ETH_ALEN))) {
#else
    if (!gzprintf(handle, "%s\n", buffer_to_hex(table->entries[mac_id], ETH_ALEN))) {
#endif
#ifndef NDEBUG
      perror("Error writing update");
#endif
      return -1;
    }
  }
  if (!gzprintf(handle, "\n")) {
#ifndef NDEBUG
    perror("Error writing update");
#endif
    return -1;
  }
  table->added_since_last_update = 0;
  return 0;
}
