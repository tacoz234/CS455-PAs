#include "mypcap.h"

extern int mapSize;                           // number of arp mapping entries read from file
extern arpmap_t myARPmap[MAXARPMAP];          // array storing ip to mac address mappings
extern unsigned countMine;                    // counter for packets for monitored interfaces

int main(int argc, char *argv[]) {            // entry point of application
    if (argc != 4) {                          // validate that exactly 3 command line arguments provided
        printf("Usage: %s <input_pcap> <output_pcap> <arp_mappings>\n", argv[0]); // print usage instructions
        return 1;                             // exit with error status if arguments missing
    }

    char *inputPcap = argv[1];                // filename of source pcap capture
    char *outputPcap = argv[2];               // filename for newly generated pcap results
    char *arpMappings = argv[3];              // text file containing ip/mac mapping pairs

    // read arp mappings from provided text file
    if (readARPmap(arpMappings) == -1) {      // attempt to load mapping database into memory
        printf("Error reading ARP mapping file: %s\n", arpMappings); // failure if file occurs
        return 1;                             // exit if mapping file is invalid or missing
    }

    // print loaded arp mappings to console for verification
    printf("Read %d ARP mappings:\n", mapSize); // display count of successfully parsed mappings
    for (int i = 0; i < mapSize; i++) {       // go through each entry in mapping array
        char ipBuf[MAXIPv4ADDRLEN];           // temporary buffer for dotted-decimal ip string
        char macBuf[MAXMACADDRLEN];           // temporary buffer for colon-separated mac string
        IPv4addr ip;                          // structure to hold current ip address
        ip.ip = myARPmap[i].ip;               // extract raw ip from mapping entry
        // convert addresses to human readable strings and print them
        printf("   %-16s %s\n", ipToStr(ip, ipBuf), macToStr(myARPmap[i].mac, macBuf));
    }
    printf("\n");                             // add newline for output formatting

    // open and read global header of input pcap file
    pcap_hdr_t pcapHdr;                       // structure to store pcap global metadata (magic num, version, others)
    if (readPCAPhdr(inputPcap, &pcapHdr) == -1) { // load header and detect endianness/timestamps
        printf("Error reading input PCAP header: %s\n", inputPcap); // log failure if read fails
        return 1;                             // exit if pcap file is corrupted or missing
    }

    // create output pcap file and write same global header
    if (writePCAPhdr(outputPcap, &pcapHdr) == -1) { // initialize response traffic file
        printf("Error writing output PCAP header: %s\n", outputPcap); // log failure if write fails
        return 1;                             // exit if unable to create output file
    }

    // main packet processing loop goes through every packet in capture
    packetHdr_t pktHdr;                       // structure for individual packet metadata (timestamp, length)
    uint8_t ethFrame[MAXFRAMESZ];             // buffer to hold raw Ethernet frame data
    while (getNextPacket(&pktHdr, ethFrame)) { // read next packet until end of file
        printPacketMetaData(&pktHdr);         // display packet number + time + original size
        processRequestPacket(&pktHdr, ethFrame); // inspect packet and generate replies if it targets us
    }

    // print final summary statistics
    printf("\nDone! Number of packets targeting my machine = %u\n", countMine); // show total matches
    printf("Check %s for generated traffic.\n", outputPcap); // remind user where the results are

    cleanUp();                                // close all file pointers and release resources
    return 0;                                 // exit successfully
}
