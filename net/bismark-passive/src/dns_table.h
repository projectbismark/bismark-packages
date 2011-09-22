#ifndef _BISMARK_PASSIVE_DNS_TABLE_H_
#define _BISMARK_PASSIVE_DNS_TABLE_H_

#include <stdint.h>
#include <stdio.h>
#include <zlib.h>

#include "constants.h"
#include "flow_table.h"
#include "whitelist.h"

/* A single A record from a DNS response. */
typedef struct {
  uint8_t mac_id;  /* See mac_table.h */
  uint8_t unanonymized : 1;
  char* domain_name;  /* A regular C string, not a DNS compressed string */
  uint32_t ip_address;  /* IPv4 address in network byte order */
} dns_a_entry_t;

typedef struct {
  uint8_t mac_id;
  uint8_t unanonymized : 1;
  char* domain_name;
  char* cname;  /* A regular C string, not a DNS compressed string */
} dns_cname_entry_t;

typedef struct {
  dns_a_entry_t a_entries[DNS_TABLE_A_ENTRIES];
  dns_cname_entry_t cname_entries[DNS_TABLE_CNAME_ENTRIES];
  int a_length, cname_length;
  int num_dropped_a_entries, num_dropped_cname_entries;
  domain_whitelist_t* whitelist;
} dns_table_t;

/* whitelist can be NULL, in which case no whitelist is performed. Does not
 * claim ownership of the whitelist. */
void dns_table_init(dns_table_t* const table, domain_whitelist_t* whitelist);

/* You *must* call this before a table goes out of scope, since tables contain
 * malloced strings that must be freed. */
void dns_table_destroy(dns_table_t* const table);

/* Add a new DNS A record to the table. Claims ownership of entry->domain_name
 * and will free() at some later point. Does *not* claim ownership of entry. */
int dns_table_add_a(dns_table_t* const table, dns_a_entry_t* const entry);

/* Add a new DNS CNAME record to the table. Claims ownership of
 * entry->domain_name and entry->cname and will free() at some later point. Does
 * *not* claim ownership of entry. */
int dns_table_add_cname(dns_table_t* const table,
                        dns_cname_entry_t* const entry);

/* Given that some entries in the DNS table have already been marked as
 * unanonymized, this function marks additional DNS and flow records as
 * unanonymized. It only marks flows as unanonymized if they have not been
 * previously sent to the server. Doing otherwise would break anonymity in case
 * the user later decides to remove a domain from the whitelist. */
void dns_table_mark_unanonymized(dns_table_t* const table,
                                 flow_table_t* const flow_table);

/* Serialize all table data to an open gzFile handle. */
int dns_table_write_update(dns_table_t* const table, gzFile handle);

#endif
