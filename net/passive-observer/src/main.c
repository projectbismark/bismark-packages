#include <stdio.h>

#include <pcap.h>

void callback (
        u_char *user,
        const struct pcap_pkthdr *header,
        const u_char *bytes) {
    printf("%d ", header->len);
    fflush(stdout);
}

int main (int argc, char *argv[]) {
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live (dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf (stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    return pcap_loop (handle, -1, callback, NULL);
}
