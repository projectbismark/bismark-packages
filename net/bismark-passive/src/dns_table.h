#ifndef _BISMARK_PASSIVE_DNS_TABLE_H_
#define _BISMARK_PASSIVE_DNS_TABLE_H_

#include <stdint.h>
#include <stdio.h>

#include "constants.h"

typedef struct {
  uint8_t mac_id;
  char* domain_name;
  uint32_t ip_address;
} dns_a_entry_t;

typedef struct {
  uint8_t mac_id;
  char* domain_name;
  char* cname;
} dns_cname_entry_t;

typedef struct {
  dns_a_entry_t a_entries[DNS_TABLE_A_ENTRIES];
  dns_cname_entry_t cname_entries[DNS_TABLE_CNAME_ENTRIES];
  int a_first, a_last;
  int cname_first, cname_last;
  int num_dropped_a_entries, num_dropped_cname_entries;
} dns_table_t;

void dns_table_init(dns_table_t* table);
void dns_table_destroy(dns_table_t* table);

int dns_table_add_a(dns_table_t* table, dns_a_entry_t* entry);
int dns_table_add_cname(dns_table_t* table, dns_cname_entry_t* entry);

int dns_table_write_update(dns_table_t* table, FILE* handle);

#define MODULUS(a, n) (((a) % (n) + (n)) % (n))
#define A_TABLE_LEN(t) (MODULUS((t)->a_last - (t)->a_first, DNS_TABLE_A_ENTRIES))
#define CNAME_TABLE_LEN(t) (MODULUS((t)->cname_last - (t)->cname_first, DNS_TABLE_CNAME_ENTRIES))

#endif
