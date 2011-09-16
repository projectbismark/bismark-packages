#include "dns_table.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "anonymization.h"
#include "util.h"

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
#ifndef NDEBUG
    perror("Error writing update");
#endif
    return -1;
  }
  int idx;
  for (idx = 0; idx < table->a_length; ++idx) {
#ifndef DISABLE_ANONYMIZATION
    unsigned char domain_digest[ANONYMIZATION_DIGEST_LENGTH];
    uint64_t address_digest;
    if (anonymize_domain(table->a_entries[idx].domain_name, domain_digest)
        || anonymize_ip(table->a_entries[idx].ip_address, &address_digest)) {
      fprintf(stderr, "Error anonymizing DNS data\n");
      return -1;
    }
#endif
    if (!gzprintf(handle,
#ifndef DISABLE_ANONYMIZATION
                  "%" PRIu8 " %s %" PRIx64 "\n",
#else
                  "%" PRIu8 " %s %" PRIx32 "\n",
#endif
                  table->a_entries[idx].mac_id,
#ifndef DISABLE_ANONYMIZATION
                  buffer_to_hex(domain_digest, ANONYMIZATION_DIGEST_LENGTH),
                  address_digest
#else
                  table->a_entries[idx].domain_name,
                  table->a_entries[idx].ip_address
#endif
                 )) {
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

  for (idx = 0; idx < table->cname_length; ++idx) {
#ifndef DISABLE_ANONYMIZATION
    unsigned char domain_digest[ANONYMIZATION_DIGEST_LENGTH];
    unsigned char cname_digest[ANONYMIZATION_DIGEST_LENGTH];
    if (anonymize_domain(table->cname_entries[idx].domain_name, domain_digest)
        || anonymize_domain(table->cname_entries[idx].cname, cname_digest)) {
      fprintf(stderr, "Error anonymizing DNS data\n");
      return -1;
    }
    char hex_domain_digest[ANONYMIZATION_DIGEST_LENGTH * 2 + 1];
    strcpy(hex_domain_digest,
           buffer_to_hex(domain_digest, ANONYMIZATION_DIGEST_LENGTH));
    char hex_cname_digest[ANONYMIZATION_DIGEST_LENGTH * 2 + 1];
    strcpy(hex_cname_digest,
           buffer_to_hex(cname_digest, ANONYMIZATION_DIGEST_LENGTH));
#endif
    if (!gzprintf(handle,
                  "%" PRIu8 " %s %s\n",
                  table->cname_entries[idx].mac_id,
#ifndef DISABLE_ANONYMIZATION
                  hex_domain_digest,
                  hex_cname_digest
#else
                  table->cname_entries[idx].domain_name,
                  table->cname_entries[idx].cname
#endif
                 )) {
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
  return 0;
}
