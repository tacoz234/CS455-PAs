/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2026

    Implemented By:     Cole Determan
    File Name:          p2.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

int main(int argc, char *argv[]) {
  pcap_hdr_t globalHdr;
  packetHdr_t pktHdr;
  uint8_t ethFrame[MAXFRAMESZ];

  if (argc < 2)
    errorExit("Must provide a PCAP file name");

  printf("\nProcessing PCAP file '%s'\n\n", argv[1]);

  if (readPCAPhdr(argv[1], &globalHdr))
    errorExit("Failed to process the global header of the PCAP file");

  printPCAPhdr(&globalHdr);

  printf("PktNum     Time Stamp OrgLen / Captrd Source               "
         "Destination          Protocol info\n");

  while (getNextPacket(&pktHdr, ethFrame)) {
    printPacketMetaData(&pktHdr);
    printPacket((etherHdr_t *)ethFrame);
  }

  printf("\nReached end of PCAP file '%s'\n", argv[1]);

  cleanUp();

  return 0;
}
