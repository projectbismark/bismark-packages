#ifndef _BISMARK_PASSIVE_DNS_PARSER_
#define _BISMARK_PASSIVE_DNS_PARSER_

#include <stdint.h>

#include "dns_table.h"

/* Parse a DNS response packet and add relevent entries to the provided DNS
 * table. Assumes the packet is destined for the MAC address denoted by the
 * provided MAC ID. */
int process_dns_packet(const uint8_t* const bytes,
                       int len,
                       dns_table_t* const dns_table,
                       uint8_t mac_id);

#endif
