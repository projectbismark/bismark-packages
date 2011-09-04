#ifndef _BISMARK_PASSIVE_MAC_TABLE_
#define _BISMARK_PASSIVE_MAC_TABLE_

#include <stdint.h>
#include <stdio.h>
#include <zlib.h>

#include "constants.h"

typedef uint64_t mac_table_t[MAC_TABLE_ENTRIES];

void mac_table_init(mac_table_t* table);

int mac_table_lookup(mac_table_t* table, uint64_t mac);

int mac_table_write_update(mac_table_t* table, gzFile handle);

#endif
