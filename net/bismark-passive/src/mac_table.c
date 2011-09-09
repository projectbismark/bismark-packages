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

int mac_table_lookup(mac_table_t* const table,
                     const uint32_t ip_address,
                     const uint8_t mac[ETH_ALEN]) {
  if (table->length > 0) {
    /* Search table starting w/ most recent MAC addresses. */
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if (table->entries[mac_id].ip_address == ip_address
          && !memcmp(table->entries[mac_id].mac_address, mac, ETH_ALEN)) {
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
  table->entries[table->last].ip_address = ip_address;
  memcpy(table->entries[table->last].mac_address, mac, ETH_ALEN);
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
    uint64_t digest_ip;
    uint8_t digest_mac[ETH_ALEN];
    if (anonymize_ip(table->entries[mac_id].ip_address, &digest_ip)
        || anonymize_mac(table->entries[mac_id].mac_address, digest_mac)) {
#ifndef NDEBUG
      fprintf(stderr, "Error anonymizing MAC mapping\n");
#endif
      return -1;
    }
    if (!gzprintf(handle,
                  "%s %" PRIu64 "\n",
                  buffer_to_hex(digest_mac, ETH_ALEN),
                  digest_ip)) {
#else
    if (!gzprintf(handle,
                  "%s %" PRIu32 "\n",
                  buffer_to_hex(table->entries[mac_id].mac_address, ETH_ALEN),
                  table->entries[mac_id].ip_address)) {
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
