/* Check that QR == 1, OPCODE == 0, RCODE == 0.
 * Check ANCOUNT > 0 || ARCOUNT > 0; if so:
 * For each RR in Anwer and Additional Records sections:
 *   Check CLASS is IN
 *   Check TYPE is A:
 *   If TYPE is CNAME:
 *      Add CNAME to set of domains
 *      Add Domain to set of domains
 *   If TYPE is A:
 *      Add ADDRESS to set of addresses
 *      Add Domain to set of domains
 *
 * MAC table: [(MAC, MAC_ID)]
 * Data representation: [(MAC_ID, IP address) -> [domain]]
 *
 */

#include "dns_table.h"

#include <string.h>

#define MAC_TABLE_SIZE 256
static uint64_t mac_table[MAC_TABLE_SIZE];  /* Initialized to zeros. */

int lookup_mac_id(uint64_t mac) {
  if (mac == 0) {
    return -1;
  }

  int mac_id;
  for (mac_id = 0; mac_id < MAC_TABLE_SIZE; ++mac_id) {
    if (mac_table[mac_id] == 0) {
      mac_table[mac_id] = mac;
    }
    if (mac_table[mac_id] == mac) {
      return mac_id;
    }
  }
  return -1;
}

void dns_table_init(dns_table_t* table) {
  memset(table, '\0', sizeof(*table));
}

int dns_table_add_a(dns_table_t* table, dns_a_entry_t* new_entry) {
  if (A_TABLE_LEN(table) >= DNS_TABLE_A_ENTRIES - 1) {
    ++table->num_dropped_a_entries;
    return -1;
  }
  table->a_entries[table->a_last] = *new_entry;
  table->a_last = (table->a_last + 1) % DNS_TABLE_A_ENTRIES;
  return 0;
}

int dns_table_add_cname(dns_table_t* table, dns_cname_entry_t* new_entry) {
  if (CNAME_TABLE_LEN(table) >= DNS_TABLE_CNAME_ENTRIES - 1) {
    ++table->num_dropped_cname_entries;
    return -1;
  }
  table->cname_entries[table->cname_last] = *new_entry;
  table->cname_last = (table->cname_last + 1) % DNS_TABLE_CNAME_ENTRIES;
  return 0;
}
