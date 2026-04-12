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
FILE       *pcapOutput =  NULL ;        // The output PCAP file
arpmap_t    myARPmap[ MAXARPMAP ] ;    // List of my IPs, their MACs
int         mapSize = 0;               // Number of mapping pairs read
unsigned    countMine = 0;             // Number of packets targeting mine
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
    if ( pcapOutput )  fclose ( pcapOutput ) ;
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


/*          PROJECT 2            */

/*-------------------------------------------------------------------------*/
/* Get service name for a port number. Returns the service name or "***"   */
static const char* getServiceName(uint16_t port, const char *proto, char *outBuf) {
    struct servent *se = getservbyport(htons(port), proto);
    
    if (se && se->s_name && strncmp(se->s_name, "***", 3) != 0) {
        strncpy(outBuf, se->s_name, 99);
        outBuf[99] = '\0';
        return outBuf;
    }
    
    return "*** ";
}

/*-------------------------------------------------------------------------*/
unsigned printUDPinfo( const udpHdr_t *p ) {
    uint16_t srcPort = ntohs(p->udp_srcPort);
    uint16_t dstPort = ntohs(p->udp_dstPort);
    uint16_t length  = ntohs(p->udp_length);

    char srcBuf[100];
    char dstBuf[100];
    const char *srcName = getServiceName(srcPort, "udp", srcBuf);
    const char *dstName = getServiceName(dstPort, "udp", dstBuf);

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

    char srcBuf[100];
    char dstBuf[100];
    const char *srcName = getServiceName(srcPort, "tcp", srcBuf);
    const char *dstName = getServiceName(dstPort, "tcp", dstBuf);

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

/* ***************************** */
/*          PROJECT 3            */
/* ***************************** */

/*-------------------------------------------------------------------------*/
int writePCAPhdr( char *fname , pcap_hdr_t *p )
{
    if ( !fname || !p ) return -1;
    pcapOutput = fopen( fname , "wb" );
    if ( !pcapOutput ) return -1;

    pcap_hdr_t pCopy = *p;
    if ( !bytesOK ) 
    {
        pCopy.version_major = swap16( pCopy.version_major );
        pCopy.version_minor = swap16( pCopy.version_minor );
        pCopy.thiszone      = (int32_t)swap32( (uint32_t)pCopy.thiszone );
        pCopy.sigfigs       = swap32( pCopy.sigfigs );
        pCopy.snaplen       = swap32( pCopy.snaplen );
        pCopy.network       = swap32( pCopy.network );
    }

    if ( fwrite( &pCopy , sizeof( pcap_hdr_t ) , 1 , pcapOutput ) != 1 )
    {
        fclose( pcapOutput );
        return -1;
    }
    return 0;
}

/*-------------------------------------------------------------------------*/
int readARPmap( char *arpDB )
{
    FILE *f = fopen( arpDB , "r" );
    if ( !f ) return -1;

    char ipStr[100], macStr[100];
    mapSize = 0;
    while ( mapSize < MAXARPMAP && fscanf( f , "%s %s" , ipStr , macStr ) == 2 )
    {
        struct in_addr addr;
        if ( inet_aton( ipStr , &addr ) == 0 ) continue;
        myARPmap[mapSize].ip = addr.s_addr;

        unsigned int m[6];
        if ( sscanf( macStr , "%x:%x:%x:%x:%x:%x" , &m[0], &m[1], &m[2], &m[3], &m[4], &m[5] ) == 6 )
        {
            for ( int i = 0 ; i < 6 ; i++ )
                myARPmap[mapSize].mac[i] = (uint8_t)m[i];
            mapSize++;
        }
    }
    fclose( f );
    return mapSize;
}

/*-------------------------------------------------------------------------*/
uint16_t inet_checksum( void * data , uint16_t lenBytes )
{
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *) data;

    while ( lenBytes > 1 )
    {
        sum += *ptr++;
        lenBytes -= 2;
    }

    if ( lenBytes == 1 )
    {
        sum += *(uint8_t *)ptr;
    }

    while ( sum >> 16 )
        sum = ( sum & 0xFFFF ) + ( sum >> 16 );

    return (uint16_t) ~sum;
}

/*-------------------------------------------------------------------------*/
bool myIP( IPv4addr someIP , uint8_t **ptr )
{
    for ( int i = 0 ; i < mapSize ; i++ )
    {
        if ( myARPmap[i].ip == someIP.ip )
        {
            if ( ptr ) *ptr = myARPmap[i].mac;
            return true;
        }
    }
    if ( ptr ) *ptr = NULL;
    return false;
}

/*-------------------------------------------------------------------------*/
bool myMAC( uint8_t someMAC[] )
{
    // Check broadcast
    bool isBroadcast = true;
    for ( int i = 0 ; i < 6 ; i++ )
        if ( someMAC[i] != 0xFF ) { isBroadcast = false; break; }
    if ( isBroadcast ) return true;

    for ( int i = 0 ; i < mapSize ; i++ )
    {
        bool match = true;
        for ( int j = 0 ; j < 6 ; j++ )
        {
            if ( myARPmap[i].mac[j] != someMAC[j] )
            {
                match = false;
                break;
            }
        }
        if ( match ) return true;
    }
    return false;
}

/*-------------------------------------------------------------------------*/
void processRequestPacket( packetHdr_t *pktHdr, uint8_t ethFrame[] )
{
    etherHdr_t *ethHdr = (etherHdr_t *) ethFrame;
    char macBuf[MAXMACADDRLEN];
    macToStr( ethHdr->eth_dstMAC , macBuf );

    bool mine = myMAC( ethHdr->eth_dstMAC );
    printf( "   Dest MAC: %s (%s)\n" , macBuf , mine ? "Mine" : "Not Mine" );

    if ( !mine ) return;

    uint16_t ethType = ntohs( ethHdr->eth_type );
    bool shouldRespond = false;
    uint8_t replyFrame[MAXFRAMESZ];
    int replyLen = 0;

    if ( ethType == PROTO_ARP )
    {
        arpMsg_t *arpReq = (arpMsg_t *)( ethFrame + sizeof( etherHdr_t ) );
        uint8_t *myMacPtr;
        if ( ntohs( arpReq->arp_oper ) == ARPREQUEST && myIP( arpReq->arp_tpa , &myMacPtr ) )
        {
            shouldRespond = true;
            countMine++;

            // Prepare Reply
            replyLen = pktHdr->incl_len;
            if ( replyLen > MAXFRAMESZ ) replyLen = MAXFRAMESZ;
            memcpy( replyFrame , ethFrame , replyLen );

            etherHdr_t *replyEth = (etherHdr_t *) replyFrame;
            arpMsg_t *replyArp = (arpMsg_t *)( replyFrame + sizeof( etherHdr_t ) );

            // Ethernet Header
            memcpy( replyEth->eth_dstMAC , ethHdr->eth_srcMAC , 6 );
            memcpy( replyEth->eth_srcMAC , myMacPtr , 6 );
            replyEth->eth_type = ethHdr->eth_type;

            // ARP Message
            replyArp->arp_htype = arpReq->arp_htype;
            replyArp->arp_ptype = arpReq->arp_ptype;
            replyArp->arp_hlen  = arpReq->arp_hlen;
            replyArp->arp_plen  = arpReq->arp_plen;
            replyArp->arp_oper  = htons( ARPREPLY );
            memcpy( replyArp->arp_sha , myMacPtr , 6 );
            replyArp->arp_spa   = arpReq->arp_tpa;
            memcpy( replyArp->arp_tha , ethHdr->eth_srcMAC , 6 );
            replyArp->arp_tpa   = arpReq->arp_spa;
        }
    }
    else if ( ethType == PROTO_IPv4 )
    {
        ipv4Hdr_t *ipReq = (ipv4Hdr_t *)( ethFrame + sizeof( etherHdr_t ) );
        uint8_t *myMacPtr;
        if ( ipReq->ip_proto == PROTO_ICMP && myIP( ipReq->ip_dstIP , &myMacPtr ) )
        {
            int ipHdrLen = ( ipReq->ip_verHlen & 0x0F ) * 4;
            icmpHdr_t *icmpReq = (icmpHdr_t *)( (uint8_t *)ipReq + ipHdrLen );
            if ( icmpReq->icmp_type == ICMP_ECHO_REQUEST )
            {
                shouldRespond = true;
                countMine++;

                // Prepare Reply
                replyLen = pktHdr->incl_len;
                if ( replyLen > MAXFRAMESZ ) replyLen = MAXFRAMESZ;
                memcpy( replyFrame , ethFrame , replyLen );

                etherHdr_t *replyEth = (etherHdr_t *) replyFrame;
                ipv4Hdr_t *replyIp = (ipv4Hdr_t *)( replyFrame + sizeof( etherHdr_t ) );
                icmpHdr_t *replyIcmp = (icmpHdr_t *)( (uint8_t *)replyIp + ipHdrLen );

                // Ethernet Header
                memcpy( replyEth->eth_dstMAC , ethHdr->eth_srcMAC , 6 );
                memcpy( replyEth->eth_srcMAC , myMacPtr , 6 );

                // IP Header
                static uint16_t nextId = 1000;
                replyIp->ip_srcIP = ipReq->ip_dstIP;
                replyIp->ip_dstIP = ipReq->ip_srcIP;
                replyIp->ip_id    = htons( nextId++ );
                replyIp->ip_ttl   = 64; // Default TTL
                replyIp->ip_flagsFrag = htons( 0x4000 ); // Do Not Fragment
                replyIp->ip_hdrChk = 0;
                replyIp->ip_hdrChk = htons( inet_checksum( replyIp , ipHdrLen ) );

                // ICMP Header
                replyIcmp->icmp_type = ICMP_ECHO_REPLY;
                replyIcmp->icmp_check = 0;
                int icmpLen = ntohs( ipReq->ip_totLen ) - ipHdrLen;
                replyIcmp->icmp_check = htons( inet_checksum( replyIcmp , icmpLen ) );
            }
        }
    }

    if ( shouldRespond )
    {
        packetHdr_t replyHdr = *pktHdr;
        uint32_t delta = microSec ? 30 : 30000;
        uint32_t limit = microSec ? 1000000 : 1000000000;

        replyHdr.ts_usec += delta;
        if ( replyHdr.ts_usec >= limit )
        {
            replyHdr.ts_sec++;
            replyHdr.ts_usec -= limit;
        }
        replyHdr.incl_len = replyLen;
        replyHdr.orig_len = replyLen;

        packetHdr_t sPktHdr = *pktHdr;
        packetHdr_t sReplyHdr = replyHdr;

        if ( !bytesOK ) 
        {
            sPktHdr.ts_sec   = swap32( sPktHdr.ts_sec );
            sPktHdr.ts_usec  = swap32( sPktHdr.ts_usec );
            sPktHdr.incl_len = swap32( sPktHdr.incl_len );
            sPktHdr.orig_len = swap32( sPktHdr.orig_len );

            sReplyHdr.ts_sec   = swap32( sReplyHdr.ts_sec );
            sReplyHdr.ts_usec  = swap32( sReplyHdr.ts_usec );
            sReplyHdr.incl_len = swap32( sReplyHdr.incl_len );
            sReplyHdr.orig_len = swap32( sReplyHdr.orig_len );
        }

        // Write Request Duplicate
        fwrite( &sPktHdr , sizeof( packetHdr_t ) , 1 , pcapOutput );
        fwrite( ethFrame , pktHdr->incl_len , 1 , pcapOutput );

        // Write Reply
        fwrite( &sReplyHdr , sizeof( packetHdr_t ) , 1 , pcapOutput );
        fwrite( replyFrame , replyLen , 1 , pcapOutput );
    }
}
