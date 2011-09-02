#ifndef _BISMARK_PASSIVE_DNS_PARSER_
#define _BISMARK_PASSIVE_DNS_PARSER_

#include <stdint.h>

#include "dns_table.h"

int process_dns_packet(const uint8_t* bytes,
                       int len,
                       dns_table_t* dns_table,
                       uint8_t mac_id);

#endif
