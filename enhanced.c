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
    int last_octet_counts[256] = {0}; // Added array to count occurrences of each last octet value (0-255)

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

        // Extract the destination IP address
        struct in_addr dest_ip = ip_header->ip_dst; // Using 'ip_dst' field from 'struct ip'

        // Convert the IP address to host byte order and extract the last octet
        uint32_t ip_addr = ntohl(dest_ip.s_addr); // Convert IP address to host byte order
        int last_octet = ip_addr & 0xFF; // Extract the last 8 bits (last octet) of the IP address

        // Increment the count for this last octet
        last_octet_counts[last_octet]++; // Added counting of last octet occurrences

        packet_count++; // Increment packet count
    }

    pcap_close(handle);

    // Print the counts of last octet occurrences
    for (int i = 0; i < 256; i++) {
        if (last_octet_counts[i] > 0) {
            printf("Last octet %d: %d\n", i, last_octet_counts[i]); // Added output of last octet counts
        }
    }

    return 0;
}
