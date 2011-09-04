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

#include <stdlib.h>
#include <string.h>

void dns_table_init(dns_table_t* table) {
  memset(table, '\0', sizeof(*table));
}

void dns_table_destroy(dns_table_t* table) {
  int idx;
  for (idx = table->a_first; idx != table->a_last; ++idx) {
    free(table->a_entries[idx].domain_name);
  }
  for (idx = table->cname_first; idx != table->cname_last; ++idx) {
    free(table->cname_entries[idx].domain_name);
  }
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

int dns_table_write_update(dns_table_t* table, FILE* handle) {
  if (fprintf(handle,
              "%d %d\n",
              table->num_dropped_a_entries,
              table->num_dropped_cname_entries) < 0) {
    perror("Error writing update");
    return -1;
  }
  int idx;
  for (idx = table->a_first;
       idx != table->a_last;
       idx = (idx + 1) % DNS_TABLE_A_ENTRIES) {
    if (fprintf(handle,
                "%hhu %s %u\n",
                table->a_entries[idx].mac_id,
                table->a_entries[idx].domain_name,
                table->a_entries[idx].ip_address) < 0) {
      perror("Error writing update");
      return -1;
    }
  }
  if (fprintf(handle, "\n") < 0) {
    perror("Error writing update");
    return -1;
  }

  for (idx = table->cname_first;
       idx != table->cname_last;
       idx = (idx + 1) % DNS_TABLE_CNAME_ENTRIES) {
    if (fprintf(handle,
                "%hhu %s %s\n",
                table->cname_entries[idx].mac_id,
                table->cname_entries[idx].domain_name,
                table->cname_entries[idx].cname) < 0) {
      perror("Error writing update");
      return -1;
    }
  }
  if (fprintf(handle, "\n") < 0) {
    perror("Error writing update");
    return -1;
  }
  return 0;
}
