#ifndef _BISMARK_PASSIVE_MAC_TABLE_
#define _BISMARK_PASSIVE_MAC_TABLE_

#include <stdint.h>
#include <stdio.h>
#include <zlib.h>
#include <net/ethernet.h>

#include "constants.h"

/* A mapping from IP address to MAC address. */
typedef struct {
  uint32_t ip_address;  /* In host byte order. */
  uint8_t mac_address[ETH_ALEN];
} mac_table_entry_t;

typedef struct {
  /* A list of MAC mappings. A mapping ID is simply
   * that mapping's index offset into this array. */
  mac_table_entry_t entries[MAC_TABLE_ENTRIES];
  /* The index of the first (i.e., oldest) mapping in the list */
  int first;
  /* The index of the last (i.e., newest) mapping in the list */
  int last;
  int length;
  /* The index of the last mapping sent to the server. */
  int added_since_last_update;
} mac_table_t;

void mac_table_init(mac_table_t* const table);

/* Add a new mapping to the table. If the table if full, then the oldest
 * address will be discarded to make room. */
int mac_table_lookup(mac_table_t* const table,
                     const uint32_t ip_address,
                     const uint8_t mac[ETH_ALEN]);

/* Serialize all mappings in the table to a file. */
int mac_table_write_update(mac_table_t* const table, gzFile handle);

#endif
