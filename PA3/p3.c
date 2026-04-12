#include "mypcap.h"

extern int mapSize;
extern arpmap_t myARPmap[MAXARPMAP];
extern unsigned countMine;

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <input_pcap> <output_pcap> <arp_mappings>\n", argv[0]);
        return 1;
    }

    char *inputPcap = argv[1];
    char *outputPcap = argv[2];
    char *arpMappings = argv[3];

    // 1. Read ARP mappings
    if (readARPmap(arpMappings) == -1) {
        printf("Error reading ARP mapping file: %s\n", arpMappings);
        return 1;
    }

    // 2. Print ARP mappings
    printf("Read %d ARP mappings:\n", mapSize);
    for (int i = 0; i < mapSize; i++) {
        char ipBuf[MAXIPv4ADDRLEN];
        char macBuf[MAXMACADDRLEN];
        IPv4addr ip;
        ip.ip = myARPmap[i].ip;
        printf("   %-16s %s\n", ipToStr(ip, ipBuf), macToStr(myARPmap[i].mac, macBuf));
    }
    printf("\n");

    // 3. Read input PCAP header
    pcap_hdr_t pcapHdr;
    if (readPCAPhdr(inputPcap, &pcapHdr) == -1) {
        printf("Error reading input PCAP header: %s\n", inputPcap);
        return 1;
    }

    // 4. Write output PCAP header
    if (writePCAPhdr(outputPcap, &pcapHdr) == -1) {
        printf("Error writing output PCAP header: %s\n", outputPcap);
        return 1;
    }

    // 5. Iterate through packets
    packetHdr_t pktHdr;
    uint8_t ethFrame[MAXFRAMESZ];
    while (getNextPacket(&pktHdr, ethFrame)) {
        printPacketMetaData(&pktHdr);
        processRequestPacket(&pktHdr, ethFrame);
    }

    // 6. Print summary
    printf("\nDone! Number of packets targeting my machine = %u\n", countMine);
    printf("Check %s for generated traffic.\n", outputPcap);

    cleanUp();
    return 0;
}
