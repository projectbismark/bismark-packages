#include <stdio.h>
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

#include "flow_table.h"
#include "packet_series.h"

static packet_series_t packet_data;
static flow_table_t flow_table;

static void get_flow_entry_for_packet (
    const u_char* bytes,
    flow_table_entry_t* entry) {
  const struct ether_header* eth_header = (const struct ether_header*)bytes;
  if (ntohs (eth_header->ether_type) == ETHERTYPE_IP) {
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
    } else {
#ifdef DEBUG
      fprintf (stderr, "Unhandled transport protocol: %d\n", ip_header->protocol);
#endif
    }
  } else {
#ifdef DEBUG
    fprintf (stderr, "Unhandled network protocol: %hd\n", eth_header->ether_type);
#endif
  }
}

void process_packet (
        u_char* user,
        const struct pcap_pkthdr* header,
        const u_char* bytes) {
  pcap_t* handle = (pcap_t*)user;
  flow_table_entry_t entry;
#ifdef DEBUG
  static int packets_received = 0;
  static int last_dropped = 0;
  struct pcap_stat statistics;
  ++packets_received;
  if (packets_received % 1000 == 0) {
    pcap_stats (handle, &statistics);
    printf ("%d ", statistics.ps_drop - last_dropped);
    fflush (stdout);
    last_dropped = statistics.ps_drop;
  }
  if (packet_data.discarded_by_overflow % 1000 == 1) {
    printf("[%d] ", packet_data.discarded_by_overflow);
  }
#endif

  packet_series_add_packet (&packet_data, &header->ts, header->len, 0);
  get_flow_entry_for_packet (bytes, &entry);
  if (flow_table_process_flow (&flow_table, &entry)) {
#ifdef DEBUG
    fprintf(stderr, "Error adding to flow table\n");
#endif
  }
}

int main (int argc, char *argv[]) {
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  if (argc != 2) {
    fprintf (stderr, "Usage: %s <interface>\n", argv[0]);
    return 1;
  }

  dev = argv[1];
  handle = pcap_open_live (dev, BUFSIZ, 1, 1000, errbuf);
  if (!handle) {
    fprintf (stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return 2;
  }

  if (pcap_datalink (handle) != DLT_EN10MB) {
    fprintf (stderr, "Must capture on an Ethernet link\n");
    return 3;
  }

  packet_series_init(&packet_data);
  flow_table_init(&flow_table);

  /* By default, pcap uses an internal buffer of 500 KB. Any packets that
   * overflow this buffer will be dropped. pcap_stats tells the number of
   * dropped packets.
   *
   * Because pcap does its own buffering, we don't need to run packet
   * processing in a separate thread. (It would be easier to just increase
   * the buffer size if we experience performance problems.) */
  return pcap_loop (handle, -1, process_packet, (u_char *)handle);
}
