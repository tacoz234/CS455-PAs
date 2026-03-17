/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2026
    
    Implemented By:     Ben Berry
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
/*  Open the input PCAP file 'fname' 
    and read its global header into buffer 'p'
    Side effects:    
        - Set the global FILE *pcapInput to the just-opened file
        - Properly set the global flags: bytesOK  and   microSec
        - If necessary, reorder the bytes of all globap PCAP header 
          fields except for the magic_number

    Remember to check for incuming NULL pointers

    Returns:  0 on success
             -1 on failure  */

int readPCAPhdr(char *fname , pcap_hdr_t *p)
{
	// Always check for incoming NULL poiters
    if(fname == NULL || p == NULL) {
        return -1;
    }
	// Successfully open the input 'fname'
    pcapInput = fopen(fname, "rb");
    if (!pcapInput) {
        return -1;
    }
    //read input into the golbal header
    if (fread(p, sizeof(pcap_hdr_t), 1, pcapInput) != 1) {
        fclose(pcapInput);
        return -1;
    }
    // Determine the capturer's byte ordering
    // Issue: magic_number could also be 0xa1b23c4D to indicate nano-second 
    // resolution instead of microseconds. This affects the interpretation
    // of the ts_usec field in each packet's header.
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
/* Print the global header of the PCAP file from buffer 'p'                */
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
/*  Read the next packet (Header and entire ethernet frame) 
    from the previously-opened input  PCAP file 'pcapInput'
    Must check for incoming NULL pointers and incomplete frame payload
    
    If this is the very first packet from the PCAP file, set the baseTime 
    
    Returns true on success, or false on failure for any reason */

bool getNextPacket( packetHdr_t *p , uint8_t  ethFrame[]  )
{
    // Check for incoming NULL pointers
    if (!pcapInput || p == NULL || ethFrame == NULL) {
        return false;
    }
    // Read the header of the next paket in the PCAP file
    if (fread(p, sizeof(packetHdr_t), 1, pcapInput) != 1) {
        return false;
    }
    // Did the capturer use a different 
    // byte-ordering than mine (as determined by the magic number)?
    if (!bytesOK) {
        // reorder the bytes of the fields in this packet header
        p->ts_sec   = swap32(p->ts_sec);
        p->ts_usec  = swap32(p->ts_usec);
        p->incl_len = swap32(p->incl_len);
        p->orig_len = swap32(p->orig_len);
    }
    // Read 'incl_len' bytes from the PCAP file into the ethFrame[]
    if (fread(ethFrame, 1, p->incl_len, pcapInput) != p->incl_len) {
        return false;
    }
    // If necessary, set the baseTime .. Pay attention to possibility of nano second 
    // time precision (instead of micro seconds )
    double time;
    if (microSec) {
        // Microseconds
        time = (double)p->ts_usec / 1000000.0;
    } else {
        // Nanoseconds
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
/* print packet's capture time (realative to the base time),
   the priginal packet's length in bytes, and the included length */
   
void printPacketMetaData( const packetHdr_t *p  )
{
    static int pktNum = 1;
    
    double time;
    if (microSec) {
        // Microseconds
        time = (double)p->ts_usec / 1000000.0;
    } else {
        // Nanoseconds
        time = (double)p->ts_usec / 1000000000.0;
    }
    double currentTime = (double)p->ts_sec + time;
    
    printf("%6d %14.6f %6u / %6u ", 
           pktNum++, (currentTime - baseTime), p->orig_len, p->incl_len);
}

/*-------------------------------------------------------------------------*/
/* Print the packet's captured data starting with its ethernet frame header
   and moving up the protocol hierarchy */ 

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

        if (ip->ip_proto == PROTO_ICMP) {
            printICMPinfo((icmpHdr_t *)payload);
            int transportHdrLen = 8; 
            int appDataLen = totalLen - ipHdrLen - transportHdrLen;
            if (appDataLen < 0) appDataLen = 0;
            printf("AppData=%5d", appDataLen);
        } else {
            printf("AppData=%5d", 0);
        }
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
    else if (icmp->icmp_type == ICMP_ECHO_REPLY) typeStr = "Echo Reply";

    printf("ICMP_HDR{ %-12s :id=%5d, seq=%5d} ", typeStr, ntohs(id), ntohs(seq));
    return 0;
}


/*-------------------------------------------------------------------------*/
/*               Suggested Utility Functions                               */
/*-------------------------------------------------------------------------*/


/*-------------------------------------------------------------------------*/
/*  Convert a MAC address to the format xx:xx:xx:xx:xx:xx 
    in the caller-provided 'buf' whose maximum 'size' is given
    Returns 'buf'  */

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


