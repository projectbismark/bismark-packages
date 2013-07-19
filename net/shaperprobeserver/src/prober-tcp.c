/*
* Packet replayer/cloner.
  * 
  * November 2008.
  *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>

#define __FAVOR_BSD /* For compilation in Linux.  */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <sys/select.h>
#include <ctype.h>

#include <pcap.h>

#define PROBER_CONFIG "prober.conf"

/* Global paremeters from config.  */
unsigned int serverip = 0;
unsigned int clientip = 0;
unsigned int targetport = 0;
int serverMAC[6];
int clientMAC[6];
char device_id[6];

/* Utility functions.  */

void swait(struct timeval tv)
{
  /* Wait for based on select(2). Wait time is given in microsecs.  */
#if DEBUG
  fprintf(stderr, "Waiting for %d microseconds.\n", wait_time);
#endif

  select(0,NULL,NULL,NULL,&tv); 
}

char * ip2str(bpf_u_int32 ip)
{
  struct in_addr ia;

  ia.s_addr = ip;

  return inet_ntoa(ia);
}

unsigned int str2ip(char *ip)
{
  struct in_addr ia;
  int r;
  r = inet_aton(ip, &ia);
  if (r) return ntohl(ia.s_addr);
  return 0;
}

void printMAC(int *MAC)
{
  fprintf(stderr, "%x:%x:%x:%x:%x:%x\n", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
}

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
  register long sum;
  u_short oddbyte;
  register u_short answer;

  sum = 0;
  while(nbytes > 1)
  {
    sum += *ptr++;
    nbytes -= 2;
  }

  if(nbytes == 1)
  {
    oddbyte = 0;
    *((u_char *) &oddbyte) = *(u_char *)ptr;
    sum += oddbyte;
  }

  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;

  return(answer);
}

void die(char *msg)
{
  fprintf(stderr, "%s\n", msg);
  exit(0);
}

/* Configuration.  */

void prober_config_inspect(void)
{
  fprintf(stderr, "Inspecting Prober Configuration.\n");
  fprintf(stderr, "Server IP: %s (%d)\n", ip2str(serverip), serverip);
  printMAC(serverMAC);
  fprintf(stderr, "Client IP: %s (%d)\n", ip2str(clientip), clientip);
  printMAC(clientMAC);
  fprintf(stderr, "Target Port: %d\n", targetport);
}


void prober_config_parse_var(char *var)
{
  char *seek;

  seek = (char *) memchr(var, ':', 255);
  seek++;

  if (!strncmp(var, "server", strlen("server")))
    serverip = htonl(str2ip(seek));
  else if (!strncmp(var, "client", strlen("client")))
    clientip = htonl(str2ip(seek));
  else if (!strncmp(var, "targetport", strlen("targetport")))
    targetport = atoi(seek);
  else if (!strncmp(var, "sMAC", strlen("sMAC")))
    sscanf(seek, "%02X,%02X,%02X,%02X,%02X,%02X", 
    &serverMAC[0], &serverMAC[1], &serverMAC[2], &serverMAC[3], &serverMAC[4], &serverMAC[5]);
  else if (!strncmp(var, "cMAC", strlen("cMAC")))
    sscanf(seek, "%02X,%02X,%02X,%02X,%02X,%02X", 
    &clientMAC[0], &clientMAC[1], &clientMAC[2], &clientMAC[3], &clientMAC[4], &clientMAC[5]);
  else if (!strncmp(var, "device", strlen("device")))
    strncpy(device_id, seek, strlen(seek) - 1);

}

void prober_config_load(void)
{
  FILE *cfg;
  char cfgvar[255];

  if (!(cfg = fopen(PROBER_CONFIG, "r")))
    die("Cannot load configuration.");

  while (fgets(cfgvar, sizeof(cfgvar), cfg)) {
    if (cfgvar[0] == '#' || cfgvar[0] == '\n') continue;

    prober_config_parse_var(cfgvar);
  }

#ifdef DEBUG
  prober_config_inspect();
#endif
  fclose(cfg);
}

/* Main thing.  */

void prober_device_info(char *dev)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  int ret = 0;

  bpf_u_int32 netp;   /* ip          */
  bpf_u_int32 maskp;  /* subnet mask */

  ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

  if(ret == -1) 
    die(errbuf);

  fprintf(stderr, "Device: %s\nIP: %s\n", dev, ip2str(netp));
  fprintf(stderr, "Netmask: %s\n", ip2str(maskp));
}


pcap_t * prober_device_load(char *id)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t * device;
  
  device = pcap_open_live(id, sizeof(int), 1, 1, errbuf);
  if (device == NULL)
    die(errbuf);
    
  fprintf(stderr, "Using device: %s.\n", id);
  
  return (device);
}


pcap_t * prober_trace_load(char *trace)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *dev;

  dev = pcap_open_offline(trace, errbuf);
  if (dev == NULL) {
    printf("%s\n", errbuf);
    exit(1);
  }

  return dev; 
}

void prober_data_inspect(const u_char *buffer, unsigned int len)
{
  int i;

#ifdef DEBUG
  fprintf(stderr, "Inspecting %d of data.\n", len);
#endif 

  for (i = 0; i < len; i++) {
    if (isprint((int)buffer[i]))
      fprintf(stderr, "%c", buffer[i]);
    else
      fprintf(stderr, ".");
  }
  fprintf(stderr, "\n");
}

void prober_ethernet_inspect(struct ether_header *eth)
{
  fprintf(stderr, "%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X ",
    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
    eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
    eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
    eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
}

void prober_udp_inspect(struct ip *iph, struct udphdr *udp)
{
  fprintf(stderr, "UDP (%s:%d - ", inet_ntoa(iph->ip_src), ntohs(udp->uh_sport));
  fprintf(stderr, "%s:%d) l: %d\n", inet_ntoa(iph->ip_dst), ntohs(udp->uh_dport), ntohs(udp->uh_ulen));
}

void prober_tcp_inspect(struct ip *iph, struct tcphdr *tcp)
{
  fprintf(stderr, "TCP (%s:%d - ", inet_ntoa(iph->ip_src), ntohs(tcp->th_sport));
  fprintf(stderr, "%s:%d)\n", inet_ntoa(iph->ip_dst), ntohs(tcp->th_dport));
}

void prober_packet_inspect(struct pcap_pkthdr *hdr, const u_char *packet)
{
  struct ether_header *eth;
  struct ip *iph;
  struct udphdr *udp;
  struct tcphdr *tcp;

  /* All headers (Ethernet, IP and TCP/UDP).  */
  int hdrs_size;

  /* Ethernet.  */
  eth = (struct ether_header *) packet;

#ifdef DEBUG
  prober_ethernet_inspect(eth);
#endif

  /* IP.  */
  iph = (struct ip *)(packet + ETHER_HDR_LEN);
  switch(iph->ip_p) {
    case IPPROTO_ICMP:
      fprintf(stderr, "ICMP\n");
      break;
    case IPPROTO_UDP:
      udp = (struct udphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
      prober_udp_inspect(iph, udp);
      break;
    case IPPROTO_TCP:
      tcp = (struct tcphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
      prober_tcp_inspect(iph, tcp);

      hdrs_size = ETHER_HDR_LEN + (iph->ip_hl << 2) + (tcp->th_off << 2);
      const u_char *payload = (packet + hdrs_size);
      prober_data_inspect(payload, hdr->caplen - hdrs_size);
    break;
  }

#ifdef DEBUG  
  fprintf(stderr, "Len: %d CapLen: %d HDRS: %d IP len: %d\n", hdr->len, hdr->caplen, hdrs_size, ntohs(iph->ip_len));
#endif
}

void prober_packet_clone(struct pcap_pkthdr *hdr, const u_char *packet, u_char *packet_cloned)
{
  struct ether_header *eth;
  struct ip *iph;
  struct udphdr *udp;
  struct tcphdr *tcp;

  /* All headers (Ethernet, IP and TCP/UDP).  */
  int hdrs_size;

  /* Ethernet.  */
  eth = (struct ether_header *) packet;

  /* IP.  */
  iph = (struct ip *)(packet + ETHER_HDR_LEN);
  switch(iph->ip_p) {
    case IPPROTO_UDP:
      udp = (struct udphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
      /* FIXME. */
      break;
    case IPPROTO_TCP:
      tcp = (struct tcphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
      hdrs_size = ETHER_HDR_LEN + (iph->ip_hl << 2) + (tcp->th_off << 2);

      //packet_cloned = malloc(hdr->caplen*sizeof(char));
      memcpy(packet_cloned, packet, hdr->caplen);

      //for (int i = 0; i < hdr->caplen - hdrs_size; i++) 
      //  packet_cloned[hdrs_size + i] = '0';     
      memset(packet_cloned + hdrs_size, 0, hdr->caplen - hdrs_size);

      break;
  }
}

struct timeval prober_packet_gap(struct pcap_pkthdr *packet, struct pcap_pkthdr *next_packet)
{
  struct timeval x = next_packet->ts;
  struct timeval y = packet->ts;
  struct timeval result;

  /* Perform the carry for the later subtraction by updating y. */
  if (x.tv_usec < y.tv_usec) 
  {
	  int nsec = (y.tv_usec - x.tv_usec) / 1000000 + 1;
	  y.tv_usec -= 1000000 * nsec;
	  y.tv_sec += nsec;
  }
  if (x.tv_usec - y.tv_usec > 1000000) 
  {
	  int nsec = (x.tv_usec - y.tv_usec) / 1000000;
	  y.tv_usec += 1000000 * nsec;
	  y.tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result.tv_sec = x.tv_sec - y.tv_sec;
  result.tv_usec = x.tv_usec - y.tv_usec;

  return result;
}

void prober_packet_mac_adjust(const u_char *packet)
{
  struct ether_header *eth;

  eth = (struct ether_header *) packet;
  eth->ether_shost[0] = clientMAC[0];
  eth->ether_shost[1] = clientMAC[1];
  eth->ether_shost[2] = clientMAC[2];
  eth->ether_shost[3] = clientMAC[3];
  eth->ether_shost[4] = clientMAC[4];
  eth->ether_shost[5] = clientMAC[5];

  eth->ether_dhost[0] = serverMAC[0];
  eth->ether_dhost[1] = serverMAC[1];
  eth->ether_dhost[2] = serverMAC[2];
  eth->ether_dhost[3] = serverMAC[3];
  eth->ether_dhost[4] = serverMAC[4];
  eth->ether_dhost[5] = serverMAC[5];
}

void prober_packet_ip_adjust(const u_char *packet)
{
  /*  Attach information from configuration file:
  - server and client IP
    - target port.
  */
  struct ip *iph;

  struct in_addr server, client;

  server.s_addr = serverip;
  client.s_addr = clientip;

  /* IP.  */
  iph = (struct ip *)(packet + ETHER_HDR_LEN);
  iph->ip_src = client;
  iph->ip_dst = server;
  iph->ip_ttl = 255;

  /* Recompute checksum.  */
  iph->ip_sum = 0;
  iph->ip_sum = in_cksum((unsigned short *)iph, sizeof(struct ip));
}

struct pseudo_header
{
	unsigned long s_addr;
	unsigned long d_addr;
	char zer0;
	unsigned char protocol;
	unsigned short length;
};

void prober_packet_transport_adjust(const u_char *packet, u_char *psuedo)
{
  /*  Recompute TCP/UDP checksum.  */
  struct ip *iph;
  struct udphdr *udp;
  struct tcphdr *tcp;

  iph = (struct ip *)(packet + ETHER_HDR_LEN);
  switch(iph->ip_p) {
    case IPPROTO_UDP:
      udp = (struct udphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
      udp->uh_sum = 0;
      /* FIXME.  */
      break;
    case IPPROTO_TCP:
      tcp = (struct tcphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
      tcp->th_dport = htons(targetport);
      tcp->th_sum = 0;

      int datalen = ntohs(iph->ip_len) - (iph->ip_hl << 2) - (tcp->th_off << 2);
      int plen = sizeof(struct pseudo_header) + (tcp->th_off << 2) + datalen;
      memset(psuedo, 0, plen);
      struct pseudo_header *ps = (struct pseudo_header *)psuedo;
      ps->protocol = IPPROTO_TCP;
      ps->length = htons((tcp->th_off << 2) + datalen);
      ps->s_addr = iph->ip_src.s_addr;
      ps->d_addr = iph->ip_dst.s_addr;
      ps->zer0 = 0;
      memcpy(psuedo + sizeof(struct pseudo_header), tcp, (tcp->th_off << 2)+datalen);
      tcp->th_sum = in_cksum((unsigned short *)psuedo, plen);
  }

}

enum clProtocol { kUnknown, kAuthentic, kProbe }; 

void prober_packet_classify(const u_char *packet, enum clProtocol app_protocol)
{
  /*  Classify the packet using the TOS field in the  
  IP heaeder.
  */
  struct ip *iph;

  /* IP.  */
  iph = (struct ip *)(packet + ETHER_HDR_LEN);
  iph->ip_tos = app_protocol;

  /* Recompute checksum.  */
  iph->ip_sum = 0;
  iph->ip_sum = in_cksum((unsigned short *)iph, sizeof(struct ip));
}

void prober_run(pcap_t *trace, pcap_t *replayer, int min_packet_gap)
{
  const u_char *packet;

  struct pcap_pkthdr *hdr = malloc(sizeof *hdr);
  struct pcap_pkthdr *lasthdr = malloc(sizeof *lasthdr);

  struct timeval packet_gap;

  u_char *packet_cloned = malloc(2000*sizeof(char)); //max size
  u_char *pseudohdr = malloc(2000*sizeof(char));

  packet = pcap_next(trace, hdr);
  while (packet) {

    /* Attach information from configuration file.  */
    prober_packet_mac_adjust(packet);
    prober_packet_ip_adjust(packet);
#ifdef DEBUG
    prober_packet_inspect(hdr, packet);
#endif
    prober_packet_clone(hdr, packet, packet_cloned);

    /* Classify packets.  */
    prober_packet_classify(packet, kAuthentic);
    prober_packet_classify(packet_cloned, kProbe);

    /* Re-compute checksums.  */
    prober_packet_transport_adjust(packet, pseudohdr);
    prober_packet_transport_adjust(packet_cloned, pseudohdr);

    /* Send packet and the cloned one.  */
    pcap_sendpacket(replayer, packet, hdr->caplen);
    //pcap_sendpacket(replayer, packet_cloned, hdr->caplen);

    memcpy(lasthdr, hdr, sizeof(struct pcap_pkthdr));

    packet = pcap_next(trace, hdr);

    packet_gap = prober_packet_gap(lasthdr, hdr);

    /*  If packet gap is less than min_packet_gap 
     * we sent the packet immediately. min_packet_gap is in microseconds.  
     */
    printf("."); fflush(stdout);
    if (packet_gap.tv_sec*1000000 + packet_gap.tv_usec > min_packet_gap)
      swait(packet_gap);
  }

  free(packet_cloned);
  free(hdr);
  free(lasthdr);
  free(pseudohdr);
}

int main(int argc, char *argv[])
{
  pcap_t *trace;
  pcap_t *replayer;

  prober_config_load();

  replayer = prober_device_load(device_id);

  trace = prober_trace_load(argv[1]);

  prober_run(trace, replayer, 500);

  return(0);
}

