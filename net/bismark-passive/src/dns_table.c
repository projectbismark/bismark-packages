#include "dns_table.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "anonymization.h"
#include "util.h"
#include "whitelist.h"

void dns_table_init(dns_table_t* table, domain_whitelist_t* whitelist) {
  memset(table, '\0', sizeof(*table));
  table->whitelist = whitelist;
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
                    dns_a_entry_t* const new_entry) {
  if (table->a_length >= DNS_TABLE_A_ENTRIES) {
    ++table->num_dropped_a_entries;
    return -1;
  }
#ifndef DISABLE_ANONYMIZATION
  if (table->whitelist
      && !domain_whitelist_lookup(table->whitelist, new_entry->domain_name)) {
    new_entry->unanonymized = 1;
  } else {
    new_entry->unanonymized = 0;
  }
#endif
  table->a_entries[table->a_length] = *new_entry;
  ++table->a_length;
  return 0;
}

int dns_table_add_cname(dns_table_t* const table,
                        dns_cname_entry_t* const new_entry) {
  if (table->cname_length >= DNS_TABLE_CNAME_ENTRIES) {
    ++table->num_dropped_cname_entries;
    return -1;
  }
#ifndef DISABLE_ANONYMIZATION
  if (table->whitelist
      && (!domain_whitelist_lookup(table->whitelist, new_entry->domain_name)
        || !domain_whitelist_lookup(table->whitelist, new_entry->cname))) {
    new_entry->unanonymized = 1;
  } else {
    new_entry->unanonymized = 0;
  }
#endif
  table->cname_entries[table->cname_length] = *new_entry;
  ++table->cname_length;
  return 0;
}

void dns_table_mark_unanonymized(dns_table_t* const table,
                                 flow_table_t* const flow_table) {
  int idx;
  for (idx = 0; idx < table->cname_length; ++idx) {
    if (table->cname_entries[idx].unanonymized) {
      int aidx;
      for (aidx = 0; aidx < table->a_length; ++aidx) {
        if (!strcmp(table->cname_entries[idx].domain_name,
                    table->a_entries[aidx].domain_name)) {
          table->a_entries[aidx].unanonymized = 1;
        }
      }
    }
  }

  int aidx;
  for (aidx = 0; aidx < table->a_length; ++aidx) {
    if (table->a_entries[aidx].unanonymized) {
      int fidx;
      for (fidx = 0; fidx < FLOW_TABLE_ENTRIES; ++fidx) {
        if (flow_table->entries[fidx].occupied == ENTRY_OCCUPIED_BUT_UNSENT) {
          if (flow_table->entries[fidx].ip_source
              == table->a_entries[aidx].ip_address) {
            flow_table->entries[fidx].ip_source_unanonymized = 1;
          } else if (flow_table->entries[fidx].ip_destination
              == table->a_entries[aidx].ip_address) {
            flow_table->entries[fidx].ip_destination_unanonymized = 1;
          }
        }
      }
    }
  }
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
    if (!table->a_entries[idx].unanonymized) {
#else
    if (1) {
#endif
      unsigned char domain_digest[ANONYMIZATION_DIGEST_LENGTH];
      uint64_t address_digest;
      if (anonymize_domain(table->a_entries[idx].domain_name, domain_digest)
          || anonymize_ip(table->a_entries[idx].ip_address, &address_digest)) {
        fprintf(stderr, "Error anonymizing DNS data\n");
        return -1;
      }
      if (!gzprintf(handle,
            "%" PRIu8 " 1 %s %" PRIx64 "\n",
            table->a_entries[idx].mac_id,
            buffer_to_hex(domain_digest, ANONYMIZATION_DIGEST_LENGTH),
            address_digest)) {
#ifndef NDEBUG
        perror("Error writing update");
#endif
        return -1;
      }
    } else {
      if (!gzprintf(handle,
                    "%" PRIu8 " 0 %s %" PRIx32 "\n",
                    table->a_entries[idx].mac_id,
                    table->a_entries[idx].domain_name,
                    table->a_entries[idx].ip_address)) {
#ifndef NDEBUG
        perror("Error writing update");
#endif
        return -1;
      }
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
    if (!table->cname_entries[idx].unanonymized) {
#else
    if (1) {
#endif
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
      if (!gzprintf(handle,
                    "%" PRIu8 " 1 %s %s\n",
                    table->cname_entries[idx].mac_id,
                    hex_domain_digest,
                    hex_cname_digest)) {
#ifndef NDEBUG
        perror("Error writing update");
#endif
        return -1;
      }
    } else {
      if (!gzprintf(handle,
                    "%" PRIu8 " 0 %s %s\n",
                    table->cname_entries[idx].mac_id,
                    table->cname_entries[idx].domain_name,
                    table->cname_entries[idx].cname)) {
#ifndef NDEBUG
        perror("Error writing update");
#endif
        return -1;
      }
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
