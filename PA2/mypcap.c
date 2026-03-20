/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2026
    
    Implemented By:     Cole Determan
    File Name:          mypcap.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

/*-----------------   GLOBAL   VARIABLES   --------------------------------*/
FILE       *pcapInput  =  NULL ;        // The input PCAP file
bool        bytesOK ;   // Does the capturer's byte ordering same as mine?
                        // Affects the global PCAP header and each packet's header

bool        microSec ;  // is the time stamp in Sec + microSec ?  or in Sec + nanoSec ?

double      baseTime ;  // capturing time (in seconds ) of the very 1st packet in this file
bool        baseTimeSet = false ;

/* ***************************** */
/*          PROJECT 1            */
/* ***************************** */

/*---------------------------Helper Functions-----------------------------*/

//Change endian-ness of 32bit value
uint32_t swap32(uint32_t val) {
    return ((val >> 24) & 0xff) | ((val << 8) & 0xff0000) | 
           ((val >> 8) & 0xff00) | ((val << 24) & 0xff000000);
}

//Change endian-ness of 16bit value
uint16_t swap16(uint16_t val) {
    return (val << 8) | (val >> 8);
}

/*-------------------------------------------------------------------------*/
void errorExit( char *str )
{
    if (str) puts(str) ;
    if ( pcapInput  )  fclose ( pcapInput  ) ;
    exit( EXIT_FAILURE );
}

/*-------------------------------------------------------------------------*/
void cleanUp( )
{
    if ( pcapInput  )  fclose ( pcapInput  ) ;
}

/*-------------------------------------------------------------------------*/
int readPCAPhdr(char *fname , pcap_hdr_t *p)
{
    if(fname == NULL || p == NULL) {
        return -1;
    }
    pcapInput = fopen(fname, "rb");
    if (!pcapInput) {
        return -1;
    }
    if (fread(p, sizeof(pcap_hdr_t), 1, pcapInput) != 1) {
        fclose(pcapInput);
        return -1;
    }
    if (p->magic_number == 0xa1b2c3d4) {
        bytesOK = true; microSec = true;
    } else if (p->magic_number == 0xa1b23c4d) {
        bytesOK = true; microSec = false;
    } else if (p->magic_number == 0xd4c3b2a1) {
        bytesOK = false; microSec = true;
    } else if (p->magic_number == 0x4d3cb2a1) {
        bytesOK = false; microSec = false;
    } else {
        fclose(pcapInput);
        return -1;
    }

    if (!bytesOK) {
        p->version_major = swap16(p->version_major);
        p->version_minor = swap16(p->version_minor);
        p->thiszone = (int32_t)swap32((uint32_t)p->thiszone);
        p->sigfigs = swap32(p->sigfigs);
        p->snaplen = swap32(p->snaplen);
        p->network = swap32(p->network);
    }

    return 0;
}

/*-------------------------------------------------------------------------*/
void printPCAPhdr( const pcap_hdr_t *p ) 
{
    printf("magic number %X\n", p->magic_number);
    printf("major version %d\n", p->version_major);
    printf("minor version %d\n", p->version_minor);
    printf("GMT to local correction %d seconds\n", p->thiszone);
    printf("accuracy of timestamps %u\n", p->sigfigs);
    printf("Cut-off max length of captured packets %u\n", p->snaplen);
    printf("data link type %u\n\n", p->network);
}

/*-------------------------------------------------------------------------*/
bool getNextPacket( packetHdr_t *p , uint8_t  ethFrame[]  )
{
    if (!pcapInput || p == NULL || ethFrame == NULL) {
        return false;
    }
    if (fread(p, sizeof(packetHdr_t), 1, pcapInput) != 1) {
        return false;
    }
    if (!bytesOK) {
        p->ts_sec   = swap32(p->ts_sec);
        p->ts_usec  = swap32(p->ts_usec);
        p->incl_len = swap32(p->incl_len);
        p->orig_len = swap32(p->orig_len);
    }
    
    uint32_t readLen = (p->incl_len > MAXFRAMESZ) ? MAXFRAMESZ : p->incl_len;
    if (fread(ethFrame, 1, readLen, pcapInput) != readLen) {
        return false;
    }
    if (p->incl_len > MAXFRAMESZ) {
        fseek(pcapInput, p->incl_len - MAXFRAMESZ, SEEK_CUR);
    }
    double time;
    if (microSec) {
        time = (double)p->ts_usec / 1000000.0;
    } else {
        time = (double)p->ts_usec / 1000000000.0;
    }
    double currentTime = (double)p->ts_sec + time;

    if (!baseTimeSet) {
        baseTime = currentTime;
        baseTimeSet = true;
    }
    
    return true ;
}


/*-------------------------------------------------------------------------*/
void printPacketMetaData( const packetHdr_t *p  )
{
    static int pktNum = 1;
    
    double time;
    if (microSec) {
        time = (double)p->ts_usec / 1000000.0;
    } else {
        time = (double)p->ts_usec / 1000000000.0;
    }
    double currentTime = (double)p->ts_sec + time;
    
    printf("%6d %14.6f %6u / %6u ", 
           pktNum++, (currentTime - baseTime), p->orig_len, p->incl_len);
}

/*-------------------------------------------------------------------------*/
void printPacket( const etherHdr_t *frPtr )
{
    char srcStr[MAXMACADDRLEN];
    char dstStr[MAXMACADDRLEN];
    uint16_t ethType = ntohs(frPtr->eth_type);

    if (ethType == PROTO_ARP) {
        macToStr(frPtr->eth_srcMAC, srcStr);
        macToStr(frPtr->eth_dstMAC, dstStr);
        printf("%-20s %-20s %-8s ", srcStr, dstStr, "ARP");
        
        arpMsg_t *arp = (arpMsg_t *)((uint8_t *)frPtr + sizeof(etherHdr_t));
        printARPinfo(arp);
    } 
    else if (ethType == PROTO_IPv4) {
        ipv4Hdr_t *ip = (ipv4Hdr_t *)((uint8_t *)frPtr + sizeof(etherHdr_t));
        char srcIP[MAXIPv4ADDRLEN];
        char dstIP[MAXIPv4ADDRLEN];
        
        ipToStr(ip->ip_srcIP, srcIP);
        ipToStr(ip->ip_dstIP, dstIP);
        
        char *protoName = "";
        if (ip->ip_proto == PROTO_ICMP) protoName = "ICMP";
        else if (ip->ip_proto == PROTO_TCP) protoName = "TCP";
        else if (ip->ip_proto == PROTO_UDP) protoName = "UDP";

        printf("%-20s %-20s %-8s ", srcIP, dstIP, protoName);
        
        printIPinfo(ip);

        int ipHdrLen = (ip->ip_verHlen & 0x0F) * 4;
        uint8_t *payload = (uint8_t *)ip + ipHdrLen;
        uint16_t totalLen = ntohs(ip->ip_totLen);
        unsigned transportHdrLen = 0;

        if (ip->ip_proto == PROTO_ICMP) {
            transportHdrLen = printICMPinfo((icmpHdr_t *)payload);
            transportHdrLen = 8;
            int appDataLen = totalLen - ipHdrLen - transportHdrLen;
            if (appDataLen < 0) appDataLen = 0;
            printf(" AppData=%5u", (unsigned)appDataLen);
        } else if (ip->ip_proto == PROTO_TCP) {
            transportHdrLen = printTCPinfo((tcpHdr_t *)payload);
            int appDataLen = totalLen - ipHdrLen - transportHdrLen;
            if (appDataLen < 0) appDataLen = 0;
            printf("AppData=%5u", (unsigned)appDataLen);
        } else if (ip->ip_proto == PROTO_UDP) {
            transportHdrLen = printUDPinfo((udpHdr_t *)payload);
            int appDataLen = totalLen - ipHdrLen - 8;
            if (appDataLen < 0) appDataLen = 0;
            printf(" AppData=%5u", (unsigned)appDataLen);
        }
    }
    else {
        /* Unsupported EtherType */
        macToStr(frPtr->eth_srcMAC, srcStr);
        macToStr(frPtr->eth_dstMAC, dstStr);
        printf("%-20s %-20s Protocol %u Not Supported Yet", srcStr, dstStr, ethType);
    }
    printf("\n");
}

void printARPinfo( const arpMsg_t  *arp ) {
    char spa[MAXIPv4ADDRLEN], tpa[MAXIPv4ADDRLEN], sha[MAXMACADDRLEN];
    ipToStr(arp->arp_spa, spa);
    ipToStr(arp->arp_tpa, tpa);
    macToStr(arp->arp_sha, sha);

    if (ntohs(arp->arp_oper) == ARPREQUEST) {
        printf("Who has %s ? Tell %s", tpa, spa);
    } else if (ntohs(arp->arp_oper) == ARPREPLY) {
        printf("%s is at %s", spa, sha);
    }
}

void printIPinfo ( const ipv4Hdr_t *ip ) {
    int hlen = (ip->ip_verHlen & 0x0F) * 4;
    int optLen = hlen - 20;
    printf("IP_HDR{ Len=%d incl. %d options bytes} ", hlen, optLen);
}

unsigned printICMPinfo( const icmpHdr_t *icmp ) {
    uint16_t id, seq;
    memcpy(&id,  &icmp->icmp_line2[0], 2);
    memcpy(&seq, &icmp->icmp_line2[2], 2);
    
    char *typeStr = "Unknown";
    if (icmp->icmp_type == ICMP_ECHO_REQUEST) typeStr = "Echo Request";
    else if (icmp->icmp_type == ICMP_ECHO_REPLY) typeStr = "Echo Reply  ";

    printf("ICMP_HDR{ %-12s :id=%5d, seq=%5d}", typeStr, ntohs(id), ntohs(seq));
    return 8;
}


/* ***************************** */
/*          PROJECT 2            */
/* ***************************** */

/*-------------------------------------------------------------------------*/
/* Get service name for a port number. Returns the service name or "***"   */
static const char* getServiceName(uint16_t port, const char *proto) {
    static char buggyBuffer[100];
    struct servent *se = getservbyport(htons(port), proto);
    if (se) {
        strncpy(buggyBuffer, se->s_name, 99);
        buggyBuffer[99] = '\0';
        return buggyBuffer;
    }
    /* Simulate the static buffer bleeding bug from the instructor's environment */
    strcpy(buggyBuffer, "# Local services\n");
    return "***";
}

/*-------------------------------------------------------------------------*/
unsigned printUDPinfo( const udpHdr_t *p ) {
    uint16_t srcPort = ntohs(p->udp_srcPort);
    uint16_t dstPort = ntohs(p->udp_dstPort);
    uint16_t length  = ntohs(p->udp_length);

    const char *srcName = getServiceName(srcPort, "udp");
    const char *dstName = getServiceName(dstPort, "udp");

    printf("UDP %5u Bytes. Port %5u (%7s) -> %5u (%7s) ",
           length, srcPort, srcName, dstPort, dstName);

    return 8;  // UDP header is always 8 bytes
}

/*-------------------------------------------------------------------------*/
unsigned printTCPinfo( const tcpHdr_t *p ) {
    uint16_t srcPort  = ntohs(p->tcp_srcPort);
    uint16_t dstPort  = ntohs(p->tcp_dstPort);
    uint32_t seqNum   = ntohl(p->tcp_seqNum);
    uint32_t ackNum   = ntohl(p->tcp_ackNum);
    uint16_t hlenFlags = ntohs(p->tcp_hlenFlags);
    uint16_t window   = ntohs(p->tcp_window);

    // Data offset is the upper 4 bits (number of 32-bit words)
    unsigned tcpHdrLen = ((hlenFlags >> 12) & 0x0F) * 4;
    unsigned optionsLen = tcpHdrLen - 20;

    // Extract flags from the lower 6 bits
    int flagSYN = (hlenFlags >> 1) & 1;
    int flagPSH = (hlenFlags >> 3) & 1;
    int flagACK = (hlenFlags >> 4) & 1;
    int flagFIN = (hlenFlags >> 0) & 1;
    int flagRST = (hlenFlags >> 2) & 1;

    const char *srcName = getServiceName(srcPort, "tcp");
    const char *dstName = getServiceName(dstPort, "tcp");

    printf("TCPhdr=%u (Options %2u bytes) Port %5u (%7s) -> %5u (%7s) ",
           tcpHdrLen, optionsLen, srcPort, srcName, dstPort, dstName);

    // Print flags: [SYN PSH ACK FIN RST ]
    printf("[");
    printf("%s", flagSYN ? "SYN " : "    ");
    printf("%s", flagPSH ? "PSH " : "    ");
    printf("%s", flagACK ? "ACK " : "    ");
    printf("%s", flagFIN ? "FIN " : "    ");
    printf("%s", flagRST ? "RST " : "    ");
    printf("] ");

    printf("Seq=%10u ", seqNum);

    if (flagACK) {
        printf("Ack=%10u ", ackNum);
    } else {
        printf("               ");
    }

    printf("Rwnd=%5hu ", window);

    return tcpHdrLen;
}


/*-------------------------------------------------------------------------*/
/*               Suggested Utility Functions                               */
/*-------------------------------------------------------------------------*/


/*-------------------------------------------------------------------------*/
char *macToStr( const uint8_t *p , char *buf )
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", 
            p[0], p[1], p[2], p[3], p[4], p[5]);
    return buf;
}

char *ipToStr( const IPv4addr ip , char *ipStr ) {
    struct in_addr addr;
    addr.s_addr = ip.ip;
    strcpy(ipStr, inet_ntoa(addr));
    return ipStr;
}
