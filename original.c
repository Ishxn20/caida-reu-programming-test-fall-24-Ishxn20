#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h> // Use this header for Ethernet structures

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    int packet_count = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        // Check if the packet is large enough to contain an Ethernet header
        if (header.caplen < sizeof(struct ether_header)) {
            fprintf(stderr, "Packet %d is too short to contain an Ethernet header\n", packet_count + 1);
            continue;
        }

        // Parse the Ethernet header
        struct ether_header *eth_header = (struct ether_header *)packet; // Changed from 'struct ethhdr' to 'struct ether_header' for portability and compatibility

        // Check if the Ethernet frame contains an IP packet
        if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) { // Added a check to ensure we're processing only IP packets
            // Skip non-IP packets
            continue;
        }

        // Check if the packet is large enough to contain an IP header
        if (header.caplen < sizeof(struct ether_header) + sizeof(struct ip)) { // Added a check for sufficient packet length for IP header
            fprintf(stderr, "Packet %d is too short to contain an IP header\n", packet_count + 1);
            continue;
        }

        // Parse the IP header
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header)); // Changed from 'struct iphdr' to 'struct ip' for better portability

        // Print the destination IP address
        printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(ip_header->ip_dst)); // Changed to use 'ip_dst' field from 'struct ip'
    }

    pcap_close(handle);
    return 0;
}
