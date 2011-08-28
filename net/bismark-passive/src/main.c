#include <stdio.h>

#include <pcap.h>


void process_packet (
        u_char *user,
        const struct pcap_pkthdr *header,
        const u_char *bytes) {
    static int packets_received = 0;
    static int last_dropped = 0;
    static struct pcap_stat statistics;
    pcap_t *handle = (pcap_t*)user;
    ++packets_received;
    if (packets_received % 1000 == 0) {
        pcap_stats (handle, &statistics);
        printf ("%d ", statistics.ps_drop - last_dropped);
        fflush (stdout);
        last_dropped = statistics.ps_drop;
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

    /* By default, pcap uses an internal buffer of 500 KB. Any packets that
     * overflow this buffer will be dropped. pcap_stats tells the number of
     * dropped packets.
     *
     * Because pcap does its own buffering, we don't need to run packet
     * processing in a separate thread. (It would be easier to just increase
     * the buffer size if we experience performance problems.) */
    return pcap_loop (handle, -1, process_packet, (u_char *)handle);
}
