/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2026
    
    Implemented By:     Cole Determan
    File Name:          mypcap.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

/*-----------------   GLOBAL   VARIABLES   --------------------------------*/
FILE       *pcapInput  =  NULL ;        // input pcap file
FILE       *pcapOutput =  NULL ;        // output pcap file
arpmap_t    myARPmap[ MAXARPMAP ] ;    // ip to mac mapping entries
int         mapSize = 0;               // count of mapping entries
unsigned    countMine = 0;             // running total of packets
bool        bytesOK ;   // true if file endianness matches host, false requires swapping
bool        microSec ;  // true if timestamps are microsecond precision, false if nanosecond

double      baseTime ;  // captures the seconds + subseconds of the 1st packet
bool        baseTimeSet = false ;       // ensure baseTime is locked to packet 1

/* ***************************** */
/*          PROJECT 1            */
/* ***************************** */

/*---------------------------Helper Functions-----------------------------*/

// swap bytes for a 32-bit value (big-to-little or little-to-big)
uint32_t swap32(uint32_t val) {
    return ((val >> 24) & 0xff) | ((val << 8) & 0xff0000) | 
           ((val >> 8) & 0xff00) | ((val << 24) & 0xff000000);
}

// swap bytes for a 16-bit value
uint16_t swap16(uint16_t val) {
    return (val << 8) | (val >> 8);
}

/*-------------------------------------------------------------------------*/
// safely exits the program with error message and closes input file
void errorExit( char *str )
{
    if (str) puts(str) ;               // print descriptive error string
    if ( pcapInput  )  fclose ( pcapInput  ) ; // clean up file handle
    exit( EXIT_FAILURE );              // signal failure to parent shell
}

/*-------------------------------------------------------------------------*/
// resource cleanup function called at program end
void cleanUp( )
{
    if ( pcapInput  )  fclose ( pcapInput  ) ; // input file is closed
    if ( pcapOutput )  fclose ( pcapOutput ) ; // output file is flushed and closed
}

/*-------------------------------------------------------------------------*/
// processes global PCAP header to discover file format and endianness
int readPCAPhdr(char *fname , pcap_hdr_t *p)
{
    if(fname == NULL || p == NULL) {   // null pointer validation
        return -1;
    }
    pcapInput = fopen(fname, "rb");    // open source capture in binary mode
    if (!pcapInput) {                  // validate file existence
        return -1;
    }
    if (fread(p, sizeof(pcap_hdr_t), 1, pcapInput) != 1) { // read 24-byte global header block
        fclose(pcapInput);
        return -1;
    }
    // inspect magic number to see global byte-order and timestamp scale
    if (p->magic_number == 0xa1b2c3d4) {
        bytesOK = true; microSec = true;  // native big endian (or same as host), microseconds
    } else if (p->magic_number == 0xa1b23c4d) {
        bytesOK = true; microSec = false; // native, nanoseconds
    } else if (p->magic_number == 0xd4c3b2a1) {
        bytesOK = false; microSec = true; // foreign little endian (requires swap), microseconds
    } else if (p->magic_number == 0x4d3cb2a1) {
        bytesOK = false; microSec = false;// foreign, nanoseconds
    } else {
        fclose(pcapInput);                 // magic number check failed
        return -1;
    }

    if (!bytesOK) {                        // swap fields if capture byte order is reversed
        p->version_major = swap16(p->version_major);
        p->version_minor = swap16(p->version_minor);
        p->thiszone = (int32_t)swap32((uint32_t)p->thiszone);
        p->sigfigs = swap32(p->sigfigs);
        p->snaplen = swap32(p->snaplen);
        p->network = swap32(p->network);
    }

    return 0;                              // global header processed
}

/*-------------------------------------------------------------------------*/
// debug tool for human-readable global PCAP properties
void printPCAPhdr( const pcap_hdr_t *p ) 
{
    printf("magic number %X\n", p->magic_number);         // format identifier
    printf("major version %d\n", p->version_major);       // specification major
    printf("minor version %d\n", p->version_minor);       // specification minor
    printf("GMT to local correction %d seconds\n", p->thiszone); // capture timezone
    printf("accuracy of timestamps %u\n", p->sigfigs);    // sub-second precision
    printf("Cut-off max length of captured packets %u\n", p->snaplen); // snaplen
    printf("data link type %u\n\n", p->network);          // DLT (Link Layer ID)
}

/*-------------------------------------------------------------------------*/
// tries to load next packet (header + data) into buffers
bool getNextPacket( packetHdr_t *p , uint8_t  ethFrame[]  )
{
    if (!pcapInput || p == NULL || ethFrame == NULL) {    // argument validation
        return false;
    }
    if (fread(p, sizeof(packetHdr_t), 1, pcapInput) != 1) { // read 16 bytes of metadata
        return false;                      // prob end of file reached
    }
    if (!bytesOK) {                        // apply byte swapping if file endianness targets are reversed
        p->ts_sec   = swap32(p->ts_sec);
        p->ts_usec  = swap32(p->ts_usec);
        p->incl_len = swap32(p->incl_len);
        p->orig_len = swap32(p->orig_len);
    }
    
    // bounds check so packet doesnt exceed maximum frame buffer size
    uint32_t readLen = (p->incl_len > MAXFRAMESZ) ? MAXFRAMESZ : p->incl_len;
    if (fread(ethFrame, 1, readLen, pcapInput) != readLen) {
        return false;                      // read error on raw frame data
    }
    if (p->incl_len > MAXFRAMESZ) {        // skip extra bytes if frame truncated in buffer
        fseek(pcapInput, p->incl_len - MAXFRAMESZ, SEEK_CUR);
    }
    
    // calculate fractional part of timestamp
    double time;
    if (microSec) {
        time = (double)p->ts_usec / 1000000.0;
    } else {
        time = (double)p->ts_usec / 1000000000.0;
    }
    double currentTime = (double)p->ts_sec + time; // combine seconds and sub-seconds

    // record timestamp of first packet to serve as zero-base for time
    if (!baseTimeSet) {
        baseTime = currentTime;
        baseTimeSet = true;
    }
    
    return true ;                          // packet staged
}


/*-------------------------------------------------------------------------*/
// prints leading columns for each packet index, time offset, and bytes
void printPacketMetaData( const packetHdr_t *p  )
{
    static int pktNum = 1;                 // persistence tracks packet sequence order
    
    double time;
    if (microSec) {
        time = (double)p->ts_usec / 1000000.0; // seconds from microseconds
    } else {
        time = (double)p->ts_usec / 1000000000.0;// seconds from nanoseconds
    }
    double currentTime = (double)p->ts_sec + time;
    
    // id abs_offset size_on_wire / size_in_file
    printf("%6d %14.6f %6u / %6u ", 
           pktNum++, (currentTime - baseTime), p->orig_len, p->incl_len);
}

/*-------------------------------------------------------------------------*/
// analyzing and printing protocol layers
void printPacket( const etherHdr_t *frPtr )
{
    char srcStr[MAXMACADDRLEN];        // formatted string macs
    char dstStr[MAXMACADDRLEN];
    uint16_t ethType = ntohs(frPtr->eth_type); // convert network-order type to host

    if (ethType == PROTO_ARP) {        // handle arp layer
        macToStr(frPtr->eth_srcMAC, srcStr);
        macToStr(frPtr->eth_dstMAC, dstStr);
        printf("%-20s %-20s %-8s ", srcStr, dstStr, "ARP");
        
        // offset beyond ethernet fixed header
        arpMsg_t *arp = (arpMsg_t *)((uint8_t *)frPtr + sizeof(etherHdr_t));
        printARPinfo(arp);             // move to arp reporter
    } 
    else if (ethType == PROTO_IPv4) {  // handle ipv4 layer
        // offset beyond ethernet fixed header
        ipv4Hdr_t *ip = (ipv4Hdr_t *)((uint8_t *)frPtr + sizeof(etherHdr_t));
        char srcIP[MAXIPv4ADDRLEN];
        char dstIP[MAXIPv4ADDRLEN];
        
        ipToStr(ip->ip_srcIP, srcIP);  // format binary ip to dotted string
        ipToStr(ip->ip_dstIP, dstIP);
        
        // identify layer 4 protocol
        char *protoName = "";
        if (ip->ip_proto == PROTO_ICMP) protoName = "ICMP";
        else if (ip->ip_proto == PROTO_TCP) protoName = "TCP";
        else if (ip->ip_proto == PROTO_UDP) protoName = "UDP";

        printf("%-20s %-20s %-8s ", srcIP, dstIP, protoName);
        
        printIPinfo(ip);               // describe ip fixed header

        int ipHdrLen = (ip->ip_verHlen & 0x0F) * 4; // ihl in bytes
        uint8_t *payload = (uint8_t *)ip + ipHdrLen; // transport payload start
        uint16_t totalLen = ntohs(ip->ip_totLen);   // total ip packet size
        unsigned transportHdrLen = 0;

        // route based on transport id
        if (ip->ip_proto == PROTO_ICMP) {
            transportHdrLen = printICMPinfo((icmpHdr_t *)payload);
            transportHdrLen = 8;       // default icmp header assumption
            int appDataLen = totalLen - ipHdrLen - transportHdrLen; // app payload calculation
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
    else {                             // unknown/unsupported ethertype
        macToStr(frPtr->eth_srcMAC, srcStr);
        macToStr(frPtr->eth_dstMAC, dstStr);
        printf("%-20s %-20s Protocol %u Not Supported Yet", srcStr, dstStr, ethType);
    }
    printf("\n");                      // end line for current packet
}

// gets and prints arp address pairing
void printARPinfo( const arpMsg_t  *arp ) {
    char spa[MAXIPv4ADDRLEN], tpa[MAXIPv4ADDRLEN], sha[MAXMACADDRLEN];
    ipToStr(arp->arp_spa, spa);        // sender ip
    ipToStr(arp->arp_tpa, tpa);        // target ip
    macToStr(arp->arp_sha, sha);       // sender mac string

    if (ntohs(arp->arp_oper) == ARPREQUEST) {
        printf("Who has %s ? Tell %s", tpa, spa); // request context
    } else if (ntohs(arp->arp_oper) == ARPREPLY) {
        printf("%s is at %s", spa, sha);          // reply context
    }
}

// shows ip header length and presence of options
void printIPinfo ( const ipv4Hdr_t *ip ) {
    int hlen = (ip->ip_verHlen & 0x0F) * 4;   // extract from nibble
    int optLen = hlen - 20;                   // fixed part is 20
    printf("IP_HDR{ Len=%d incl. %d options bytes} ", hlen, optLen);
}

// reports icmp identity fields (id and seq)
unsigned printICMPinfo( const icmpHdr_t *icmp ) {
    uint16_t id, seq;
    memcpy(&id,  &icmp->icmp_line2[0], 2);    // identifier field
    memcpy(&seq, &icmp->icmp_line2[2], 2);    // sequence field
    
    char *typeStr = "Unknown";
    // check type byte for ping requests/replies
    if (icmp->icmp_type == ICMP_ECHO_REQUEST) typeStr = "Echo Request";
    else if (icmp->icmp_type == ICMP_ECHO_REPLY) typeStr = "Echo Reply  ";

    // ntohs for console output
    printf("ICMP_HDR{ %-12s :id=%5d, seq=%5d}", typeStr, ntohs(id), ntohs(seq));
    return 8;                          // min size of header
}


/*          PROJECT 2            */

// helper using system netdb to resolve ports
static const char* getServiceName(uint16_t port, const char *proto, char *outBuf) {
    struct servent *se = getservbyport(htons(port), proto); // call system services database
    
    // return service name if available and not placeholder
    if (se && se->s_name && strncmp(se->s_name, "***", 3) != 0) {
        strncpy(outBuf, se->s_name, 99);
        outBuf[99] = '\0';
        return outBuf;
    }
    
    return "*** ";                     // generic placeholder if no match
}

/*-------------------------------------------------------------------------*/
// describes udp sizing and mapping (ports -> names)
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

    return 8;                          // header always 8
}

/*-------------------------------------------------------------------------*/
// describes tcp complexity: ports, seq/ack, flags, and headers
unsigned printTCPinfo( const tcpHdr_t *p ) {
    uint16_t srcPort  = ntohs(p->tcp_srcPort);
    uint16_t dstPort  = ntohs(p->tcp_dstPort);
    uint32_t seqNum   = ntohl(p->tcp_seqNum);
    uint32_t ackNum   = ntohl(p->tcp_ackNum);
    uint16_t hlenFlags = ntohs(p->tcp_hlenFlags);
    uint16_t window   = ntohs(p->tcp_window);

    // calculate effective header length from the doff field
    unsigned tcpHdrLen = ((hlenFlags >> 12) & 0x0F) * 4;
    unsigned optionsLen = tcpHdrLen - 20;      // count option baggage

    // bit level flag extraction for state report
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

    // visual flag indicators [syn psh ack fin rst ]
    printf("[");
    printf("%s", flagSYN ? "SYN " : "    ");
    printf("%s", flagPSH ? "PSH " : "    ");
    printf("%s", flagACK ? "ACK " : "    ");
    printf("%s", flagFIN ? "FIN " : "    ");
    printf("%s", flagRST ? "RST " : "    ");
    printf("] ");

    printf("Seq=%10u ", seqNum);

    // contextual ack report
    if (flagACK) {
        printf("Ack=%10u ", ackNum);
    } else {
        printf("               ");     // grid padding
    }

    printf("Rwnd=%5hu ", window);      // receiver window report

    return tcpHdrLen;                 // size consumed
}


/*-------------------------------------------------------------------------*/
// helper to serialize raw mac bytes to a readable-colon-separated string
char *macToStr( const uint8_t *p , char *buf )
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", 
            p[0], p[1], p[2], p[3], p[4], p[5]);
    return buf;
}

// helper to serialize binary ip to dotted-decimal notation
char *ipToStr( const IPv4addr ip , char *ipStr ) {
    struct in_addr addr;
    addr.s_addr = ip.ip;               // input is network order
    strcpy(ipStr, inet_ntoa(addr));    // call standard library
    return ipStr;
}

/* ***************************** */
/*          PROJECT 3            */
/* ***************************** */

/*-------------------------------------------------------------------------*/
// writes the global pcap header to the output stream
int writePCAPhdr( char *fname , pcap_hdr_t *p )
{
    if ( !fname || !p ) return -1;     // pointer validation
    pcapOutput = fopen( fname , "wb" ); // destination initialization
    if ( !pcapOutput ) return -1;      // file handle check

    pcap_hdr_t pCopy = *p;              // local scratch copy of input header
    if ( !bytesOK )                     // reverse endianness if input capture was swapped
    {
        pCopy.version_major = swap16( pCopy.version_major );
        pCopy.version_minor = swap16( pCopy.version_minor );
        pCopy.thiszone      = (int32_t)swap32( (uint32_t)pCopy.thiszone );
        pCopy.sigfigs       = swap32( pCopy.sigfigs );
        pCopy.snaplen       = swap32( pCopy.snaplen );
        pCopy.network       = swap32( pCopy.network );
    }

    // persist header to binary disk output
    if ( fwrite( &pCopy , sizeof( pcap_hdr_t ) , 1 , pcapOutput ) != 1 )
    {
        fclose( pcapOutput );
        return -1;
    }
    return 0;                          // initialization successful
}

/*-------------------------------------------------------------------------*/
// reads arp table from disk into lookup array
int readARPmap( char *arpDB )
{
    FILE *f = fopen( arpDB , "r" );     // input mapping text file
    if ( !f ) return -1;

    char ipStr[100], macStr[100];      // intermediate parse buffers
    mapSize = 0;                        // tracker reset
    // tokenize ip/mac pairs until file end or buffer full
    while ( mapSize < MAXARPMAP && fscanf( f , "%s %s" , ipStr , macStr ) == 2 )
    {
        struct in_addr addr;
        if ( inet_aton( ipStr , &addr ) == 0 ) continue; // graceful skip on bad IP strings
        myARPmap[mapSize].ip = addr.s_addr; // store net-order IP

        unsigned int m[6];              // intermediate hex parser
        if ( sscanf( macStr , "%x:%x:%x:%x:%x:%x" , &m[0], &m[1], &m[2], &m[3], &m[4], &m[5] ) == 6 )
        {
            for ( int i = 0 ; i < 6 ; i++ )
                myARPmap[mapSize].mac[i] = (uint8_t)m[i]; // cast and store MAC octets
            mapSize++;                  // registration successful
        }
    }
    fclose( f );                        // local file close
    return mapSize;                     // total entries loaded
}

/*-------------------------------------------------------------------------*/
// generic internet checksum (rfc 1071) used for ip and icmp headers
uint16_t inet_checksum( void * data , uint16_t lenBytes )
{
    uint8_t *ptr = (uint8_t *) data;
    uint32_t sum = 0;                   // 32-bit accumulator for overflow/carries

    // sum paired bytes as 16-bit words
    for ( int i = 0 ; i < lenBytes ; i++ )
    {
        if ( i % 2 == 0 ) sum += (uint32_t)ptr[i] << 8; // high octet
        else             sum += (uint32_t)ptr[i];      // low octet
    }

    // fold carries into lower 16 bits until stable
    while ( sum >> 16 )
        sum = ( sum & 0xFFFF ) + ( sum >> 16 );

    return (uint16_t) ~sum;             // bitwise NOT for the checksum result
}

/*-------------------------------------------------------------------------*/
// checks if an ip resides within my monitored set
bool myIP( IPv4addr someIP , uint8_t **ptr )
{
    for ( int i = 0 ; i < mapSize ; i++ )
    {
        if ( myARPmap[i].ip == someIP.ip ) // targeted byte match
        {
            if ( ptr ) *ptr = myARPmap[i].mac; // pass back pointer to mac address
            return true;
        }
    }
    if ( ptr ) *ptr = NULL;            // out of scope
    return false;
}

/*-------------------------------------------------------------------------*/
// checks if a mac address is targeted at my interfaces
bool myMAC( uint8_t someMAC[] )
{
    // special case: ethernet broadcast (FF:FF...)
    bool isBroadcast = true;
    for ( int i = 0 ; i < 6 ; i++ )
        if ( someMAC[i] != 0xFF ) { isBroadcast = false; break; }
    if ( isBroadcast ) return true;     // broadcasts target everyone

    // standard case: unicast table lookup
    for ( int i = 0 ; i < mapSize ; i++ )
    {
        bool match = true;              // assume match then falsify
        for ( int j = 0 ; j < 6 ; j++ )
        {
            if ( myARPmap[i].mac[j] != someMAC[j] )
            {
                match = false;
                break;
            }
        }
        if ( match ) return true;       // explicit unicast target found
    }
    return false;                       // external packet traffic
}

/*-------------------------------------------------------------------------*/
// core analyzer: inspects incoming traffic and generates needed arp/ping replies
void processRequestPacket( packetHdr_t *pktHdr, uint8_t ethFrame[] )
{
    static u_int16_t ipID = 1000;       // tracks sequential identification for replies
    etherHdr_t *ethHdr = (etherHdr_t *) ethFrame; // link layer overlay
    char macBuf[MAXMACADDRLEN];
    macToStr( ethHdr->eth_dstMAC , macBuf );

    bool mine = myMAC( ethHdr->eth_dstMAC ); // should i ignore it?
    printf( "   Dest MAC: %s\n" , macBuf);  // console report

    if ( !mine ) return;                // drop packets not destined for it

    uint16_t ethType = ntohs( ethHdr->eth_type ); // protocol identifier
    bool shouldRespond = false;         // final traffic generation signal
    uint8_t replyFrame[MAXFRAMESZ];     // buffer context for building message
    int replyLen = 0;                   // size of built message

    if ( ethType == PROTO_ARP )        // respond to arp query
    {
        arpMsg_t *arpReq = (arpMsg_t *)( ethFrame + sizeof( etherHdr_t ) );
        uint8_t *myMacPtr;
        // verify query targets a virtual ip interface its protecting
        if ( ntohs( arpReq->arp_oper ) == ARPREQUEST && myIP( arpReq->arp_tpa , &myMacPtr ) )
        {
            shouldRespond = true;       // set write flag
            countMine++;                // hit record

            // template initialization (copy entire frame)
            replyLen = pktHdr->incl_len;
            if ( replyLen > MAXFRAMESZ ) replyLen = MAXFRAMESZ;
            memcpy( replyFrame , ethFrame , replyLen );

            etherHdr_t *replyEth = (etherHdr_t *) replyFrame;
            arpMsg_t *replyArp = (arpMsg_t *)( replyFrame + sizeof( etherHdr_t ) );

            // construct ethernet headers for arp reply
            memcpy( replyEth->eth_dstMAC , ethHdr->eth_srcMAC , 6 ); // send to sender
            memcpy( replyEth->eth_srcMAC , myMacPtr , 6 );           // send from its mac
            replyEth->eth_type = ethHdr->eth_type;

            // construct arp message headers
            replyArp->arp_htype = arpReq->arp_htype;
            replyArp->arp_ptype = arpReq->arp_ptype;
            replyArp->arp_hlen  = arpReq->arp_hlen;
            replyArp->arp_plen  = arpReq->arp_plen;
            replyArp->arp_oper  = htons( ARPREPLY );                 // opcode 2
            memcpy( replyArp->arp_sha , myMacPtr , 6 );               // it is me
            replyArp->arp_spa   = arpReq->arp_tpa;                   // my ip
            memcpy( replyArp->arp_tha , ethHdr->eth_srcMAC , 6 );     // it is you
            replyArp->arp_tpa   = arpReq->arp_spa;                   // your ip
        }
    }
    else if ( ethType == PROTO_IPv4 )  // respond to ping query
    {
        ipv4Hdr_t *ipReq = (ipv4Hdr_t *)( ethFrame + sizeof( etherHdr_t ) );
        uint8_t *myMacPtr;
        // verify ip destination and transport action (icmp)
        if ( ipReq->ip_proto == PROTO_ICMP && myIP( ipReq->ip_dstIP , &myMacPtr ) )
        {
            int ipHdrLen = ( ipReq->ip_verHlen & 0x0F ) * 4;         // variable hdr size
            icmpHdr_t *icmpReq = (icmpHdr_t *)( (uint8_t *)ipReq + ipHdrLen );
            // verify specific icmp type is echo request
            if ( icmpReq->icmp_type == ICMP_ECHO_REQUEST )
            {
                shouldRespond = true;   // do write
                countMine++;            // match counted

                // template from original frame
                replyLen = pktHdr->incl_len;
                if ( replyLen > MAXFRAMESZ ) replyLen = MAXFRAMESZ;
                memcpy( replyFrame , ethFrame , replyLen );

                etherHdr_t *replyEth = (etherHdr_t *) replyFrame;
                ipv4Hdr_t *replyIp = (ipv4Hdr_t *)( replyFrame + sizeof( etherHdr_t ) );
                icmpHdr_t *replyIcmp = (icmpHdr_t *)( (uint8_t *)replyIp + ipHdrLen );

                // layer 2 construction
                memcpy( replyEth->eth_dstMAC , ethHdr->eth_srcMAC , 6 );
                memcpy( replyEth->eth_srcMAC , ethHdr->eth_dstMAC , 6 );

                // layer 3 construction
                replyIp->ip_srcIP = ipReq->ip_dstIP;                 // swap ip targets
                replyIp->ip_dstIP = ipReq->ip_srcIP;
                
                replyIp->ip_id = htons(ipID);                        // set sequential id (big endian)
                ipID++;                                              // increment global
                memcpy( &replyIp->ip_flagsFrag , &ipReq->ip_flagsFrag , 2 ); // preserve original flags
                
                // finish ip header with new checksum
                replyIp->ip_hdrChk = 0;                              // reset baseline
                uint16_t ipChkOut = htons( inet_checksum( replyIp , ipHdrLen ) );
                memcpy( &replyIp->ip_hdrChk , &ipChkOut , 2 );        // finish header

                // layer 4 construction: icmp
                replyIcmp->icmp_type = ICMP_ECHO_REPLY;              // reply
                replyIcmp->icmp_code = 0;                            // default code
                replyIcmp->icmp_check = 0;                           // reset baseline
                int icmpLen = ntohs( ipReq->ip_totLen ) - ipHdrLen;  // payload scope
                uint16_t icmpVal = inet_checksum( replyIcmp , icmpLen ); // final checksum
                uint16_t icmpChkOut = htons( icmpVal );              // byte-swap for write
                memcpy( &replyIcmp->icmp_check , &icmpChkOut , 2 );   // finish icmp
            }
        }
    }

    if ( shouldRespond )               // put persisted traffic to pcap file
    {
        packetHdr_t replyHdr = *pktHdr;                              // metadata for reply
        uint32_t delta = microSec ? 30 : 30000;                      // 30 unit offset
        uint32_t limit = microSec ? 1000000 : 1000000000;            // micro vs nano wrap

        // apply timestamp forward leap for reply packet
        replyHdr.ts_usec += delta;
        if ( replyHdr.ts_usec >= limit )
        {
            replyHdr.ts_sec++;                                      // proper carry
            replyHdr.ts_usec -= limit;
        }
        replyHdr.incl_len = replyLen;                                // final sizing
        replyHdr.orig_len = replyLen;

        packetHdr_t sPktHdr = *pktHdr;                              // work headers for potential swapping
        packetHdr_t sReplyHdr = replyHdr;

        if ( !bytesOK )                                              // swap metadata back to file format
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

        // duplicate request into output trace
        fwrite( pktHdr , sizeof( packetHdr_t ) , 1 , pcapOutput ); 
        fwrite( ethFrame , pktHdr->incl_len , 1 , pcapOutput );

        // append generated reply into trace
        fwrite( &sReplyHdr , sizeof( packetHdr_t ) , 1 , pcapOutput );
        fwrite( replyFrame , replyLen , 1 , pcapOutput );
    }
}
