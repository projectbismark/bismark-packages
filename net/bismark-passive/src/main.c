#include <resolv.h>
#include <stdio.h>
/* strdup */
#include <string.h>
/* inet_ntoa */
#include <arpa/inet.h>
/* DNS message header */
#include <arpa/nameser.h>
/* ETHER_HDR_LEN */
#include <net/ethernet.h>
/* IPPROTO_... */
#include <netinet/in.h>
/* struct ip */
#include <netinet/ip.h>
/* struct tcphdr */
#include <netinet/tcp.h>
/* struct udphdr */
#include <netinet/udp.h>

#include <pcap.h>

#include "dns_table.h"
#include "flow_table.h"
#include "packet_series.h"

static packet_series_t packet_data;
static flow_table_t flow_table;
static dns_table_t dns_table;

static int add_dns_entries_for_packet(const u_char* bytes,
                                      int len,
                                      int mac_id) {
  ns_msg handle;
  if (ns_initparse(bytes, len, &handle) < 0) {
#ifdef DEBUG
    fprintf(stderr, "Error parsing DNS response\n");
#endif
    return -1;
  }

  int num_answers = ns_msg_count(handle, ns_s_an);
  int num_additional = ns_msg_count(handle, ns_s_ar);
  if (ns_msg_getflag(handle, ns_f_qr) != ns_s_an
      || ns_msg_getflag(handle, ns_f_opcode) != ns_o_query
      || ns_msg_getflag(handle, ns_f_rcode) != ns_r_noerror
      || (num_answers <= 0 && num_additional <= 0)) {
#ifdef DEBUG
    fprintf(stderr, "Irrelevant DNS response\n");
#endif
    return -1;
  }

  int idx;
  for (idx = 0; idx < num_answers + num_additional; idx++) {
    ns_rr rr;
    if (ns_parserr(&handle,
          idx < num_answers ? ns_s_an : ns_s_ar,
          idx < num_answers ? idx : idx - num_answers,
          &rr)) {
#ifdef DEBUG
      fprintf(stderr, "Error parsing DNS record\n");
#endif
      continue;
    }

    if (ns_rr_class(rr) != ns_c_in) {
#ifdef DEBUG
      fprintf(stderr, "Non-IN DNS record\n");
#endif
      continue;
    }

    if (ns_rr_type(rr) == ns_t_a) {
      dns_a_entry_t entry;
      entry.mac_id = mac_id;
      entry.domain_name = strdup(ns_rr_name(rr));
      entry.ip_address = *(uint32_t*)ns_rr_rdata(rr);
      dns_table_add_a(&dns_table, &entry);
#ifdef DEBUG
      char ip_buffer[256];
      inet_ntop(AF_INET, &entry.ip_address, ip_buffer, sizeof(ip_buffer));
      fprintf(stderr,
              "Added DNS A entry %d: %s %s\n",
              A_TABLE_LEN(&dns_table),
              entry.domain_name,
              ip_buffer);
#endif
    } else if (ns_rr_type(rr) == ns_t_cname) {
      dns_cname_entry_t entry;
      entry.mac_id = mac_id;
      entry.domain_name = strdup(ns_rr_name(rr));
      char domain_name[MAXDNAME];
      dn_expand(ns_msg_base(handle),
                ns_msg_end(handle),
                ns_rr_rdata(rr),
                domain_name,
                sizeof(domain_name));
      entry.cname = strdup(domain_name);
      dns_table_add_cname(&dns_table, &entry);
#ifdef DEBUG
      fprintf(stderr,
              "Added DNS CNAME entry %d: %s %s\n",
              CNAME_TABLE_LEN(&dns_table),
              entry.domain_name,
              entry.cname);
#endif
    }
  }
  return 0;
}

static void get_flow_entry_for_packet(
    const u_char* bytes,
    int len,
    flow_table_entry_t* entry) {
  const struct ether_header* eth_header = (const struct ether_header*)bytes;
  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    const struct iphdr* ip_header = (const struct iphdr*)(bytes + ETHER_HDR_LEN);
    entry->ip_source = ip_header->saddr;
    entry->ip_destination = ip_header->daddr;
    entry->transport_protocol = ip_header->protocol;
    if (ip_header->protocol == IPPROTO_TCP) {
      const struct tcphdr* tcp_header = (const struct tcphdr*)(
          (void *)ip_header + ip_header->ihl * sizeof(uint32_t));
      entry->port_source = tcp_header->source;
      entry->port_destination = tcp_header->dest;
    } else if (ip_header->protocol == IPPROTO_UDP) {
      const struct udphdr* udp_header = (const struct udphdr*)(
          (void *)ip_header + ip_header->ihl * sizeof(uint32_t));
      entry->port_source = udp_header->source;
      entry->port_destination = udp_header->dest;

      if (ntohs(entry->port_source) == NS_DEFAULTPORT) {
        u_char* dns_bytes = (u_char*)udp_header + sizeof(struct udphdr);
        int dns_len = len - (dns_bytes - bytes);
        uint64_t mac_address = 0;
        memcpy(&mac_address, eth_header->ether_dhost, ETH_ALEN);
        int mac_id = lookup_mac_id(mac_address);
        process_dns_packet(dns_bytes, dns_len, &dns_table, mac_id);
      }
    } else {
#ifdef DEBUG
      fprintf(stderr, "Unhandled transport protocol: %u\n", ip_header->protocol);
#endif
    }
  } else {
#ifdef DEBUG
    fprintf(stderr, "Unhandled network protocol: %hu\n", ntohs(eth_header->ether_type));
#endif
  }
}

void process_packet(
        u_char* user,
        const struct pcap_pkthdr* header,
        const u_char* bytes) {
#ifdef DEBUG
  pcap_t* handle = (pcap_t*)user;
  static int packets_received = 0;
  static int last_dropped = 0;
  struct pcap_stat statistics;
  ++packets_received;
  if (packets_received % 1000 == 0) {
    int idx;
    int flow_counter;
    pcap_stats(handle, &statistics);
    printf("%d ", statistics.ps_drop - last_dropped);
    fflush(stdout);
    last_dropped = statistics.ps_drop;

    flow_counter = 0;
    for (idx = 0; idx < FLOW_TABLE_ENTRIES; ++idx) {
      if (flow_table.entries[idx].occupied == ENTRY_OCCUPIED) {
        ++flow_counter;
      }
    }
    printf("There are %d entries in the flow table\n", flow_counter);
    printf("Flow table has dropped %d flows\n", flow_table.num_dropped_flows);
    printf("Flow table has expired %d flows\n", flow_table.num_expired_flows);

    /*    char src_buffer[256];
        char dest_buffer[256];
        flow_table_entry_t* entry = &flow_table.entries[idx];
        printf("Entry: %s %s %hu %hu\n",
                inet_ntop(AF_INET, &entry->ip_source, src_buffer, 256),
                inet_ntop(AF_INET, &entry->ip_destination, dest_buffer, 256),
                ntohs(entry->port_source),
                ntohs(entry->port_destination));
      }
    }*/
  }
  if (packet_data.discarded_by_overflow % 1000 == 1) {
    printf("[%d] ", packet_data.discarded_by_overflow);
  }
#endif

  flow_table_entry_t flow_entry;
  get_flow_entry_for_packet(bytes, header->caplen, &flow_entry);
  int table_idx = flow_table_process_flow(&flow_table, &flow_entry, &header->ts);
#ifdef DEBUG
  if (table_idx < 0) {
    fprintf(stderr, "Error adding to flow table\n");
  }
#endif

  if (packet_series_add_packet(
        &packet_data, &header->ts, header->len, table_idx)) {
#ifdef DEBUG
    fprintf(stderr, "Error adding to packet series\n");
#endif
  }
}

int main(int argc, char *argv[]) {
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
    return 1;
  }

  dev = argv[1];
  handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
  if (!handle) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return 2;
  }

  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "Must capture on an Ethernet link\n");
    return 3;
  }

  packet_series_init(&packet_data);
  flow_table_init(&flow_table);
  dns_table_init(&dns_table);

  /* By default, pcap uses an internal buffer of 500 KB. Any packets that
   * overflow this buffer will be dropped. pcap_stats tells the number of
   * dropped packets.
   *
   * Because pcap does its own buffering, we don't need to run packet
   * processing in a separate thread. (It would be easier to just increase
   * the buffer size if we experience performance problems.) */
  return pcap_loop(handle, -1, process_packet, (u_char *)handle);
}
