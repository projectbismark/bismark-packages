#include "dns_table.h"

#include <stdlib.h>
#include <string.h>

void dns_table_init(dns_table_t* table) {
  memset(table, '\0', sizeof(*table));
}

void dns_table_destroy(dns_table_t* const table) {
  int idx;
  for (idx = 0; idx < table->a_length; ++idx) {
    free(table->a_entries[idx].domain_name);
  }
  for (idx = 0; idx < table->cname_length; ++idx) {
    free(table->cname_entries[idx].domain_name);
    free(table->cname_entries[idx].cname);
  }
}

int dns_table_add_a(dns_table_t* const table,
                    const dns_a_entry_t* const new_entry) {
  if (table->a_length >= DNS_TABLE_A_ENTRIES) {
    ++table->num_dropped_a_entries;
    return -1;
  }
  table->a_entries[table->a_length] = *new_entry;
  ++table->a_length;
  return 0;
}

int dns_table_add_cname(dns_table_t* const table,
                        const dns_cname_entry_t* const new_entry) {
  if (table->cname_length >= DNS_TABLE_CNAME_ENTRIES) {
    ++table->num_dropped_cname_entries;
    return -1;
  }
  table->cname_entries[table->cname_length] = *new_entry;
  ++table->cname_length;
  return 0;
}

int dns_table_write_update(dns_table_t* const table, gzFile handle) {
  if (!gzprintf(handle,
                "%d %d\n",
                table->num_dropped_a_entries,
                table->num_dropped_cname_entries)) {
    perror("Error writing update");
    return -1;
  }
  int idx;
  for (idx = 0; idx < table->a_length; ++idx) {
    if (!gzprintf(handle,
                  "%hhu %s %u\n",
                  table->a_entries[idx].mac_id,
                  table->a_entries[idx].domain_name,
                  table->a_entries[idx].ip_address)) {
      perror("Error writing update");
      return -1;
    }
  }
  if (!gzprintf(handle, "\n")) {
    perror("Error writing update");
    return -1;
  }

  for (idx = 0; idx < table->cname_length; ++idx) {
    if (!gzprintf(handle,
                  "%hhu %s %s\n",
                  table->cname_entries[idx].mac_id,
                  table->cname_entries[idx].domain_name,
                  table->cname_entries[idx].cname)) {
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
