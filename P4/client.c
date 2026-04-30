/*********************************************************************
    PA-04:  Sockets

    FILE:   client.c   SKELETON

	Code completed by:
		1- Cole Determan
		2- Ben Berry
		
    Submitted on:   4/30/26
**********************************************************************/

#include    "myNetLib.h"

void mirrorFile( int in , int copy , int mirror , int audit );

int main( int argc , char *argv[] )
{
    int     sd_mirror ,     // Socket to Mirror TCP server
            sd_audit  ;     // Socket to Auditor UDP server
    int     queLen = 10 ;   // Max #of pending connection requests

    char *mirrorIP  = MIRROR_IP ,                   // default Mirror Server
         *auditorIP = AUDITOR_IP ,                  // Default Auditor Server
         *inFile    = "GoldilockAnd3Bears.txt" ;    // Default input file

    char *developerName = "Cole Determan & Ben Berry" ;
    
    printf( "\n****  Client **** by %s\n\n" , developerName ) ;

    // Get the input file name from and both servers' IPs argv
    switch ( argc )
    {
        case 4: auditorIP = argv[3] ;
        case 3: mirrorIP  = argv[2] ;
        case 2: inFile    = argv[1] ;
        case 1: break ;

        default:
            printf("\nInvalid argument(s). Usage: %s <inputFileName> [mirror-IP]"
            " [auditor-IP]\n\n" , argv[0] ) ;
            exit(-1);        
    }

    printf("Working with these arguments:\n" ) ;
    printf("\tInput   File Name is '%s'\n" , inFile    ) ;
    printf("\tMirror  Server IP is '%s'\n" , mirrorIP  ) ;
    printf("\tAuditor Server IP is '%s'\n" , auditorIP ) ;

    int  fd_in , fd_cpy ;

    // Open the input file name from argv
    // Then create a file by same name.copy
    fd_in = open( inFile , O_RDONLY ) ;
    if ( fd_in < 0 )
        err_sys( "Can't open input file" ) ;

    char copyName[ 100 ] ;
    snprintf( copyName , 100 , "%s.copy" , inFile ) ;
    fd_cpy = open( copyName , O_WRONLY | O_CREAT | O_TRUNC , 0644 ) ;
    if ( fd_cpy < 0 )
        err_sys( "Can't create copy file" ) ;

    // Create a local TCP socket with ephemeral port, and connect it to
    // the mirror server at  mirrorIP : MIRROR_TCP_PORT

    puts("") ;
    sd_mirror = socketTCP( 0 , mirrorIP , MIRROR_TCP_PORT );
    
    struct sockaddr_in mirrorAddr;
    socklen_t addrLen = sizeof( mirrorAddr );
    if ( getpeername( sd_mirror , (SA *) &mirrorAddr , &addrLen ) < 0 )
        err_sys( "getpeername failed" );
    char ipStr[ 20 ];
    inet_ntop( AF_INET , &mirrorAddr.sin_addr , ipStr , 20 );

    printf("TCP Client is now connected to the TCP Mirror server %s : %hu\n" , 
            ipStr, ntohs( mirrorAddr.sin_port ) ) ;

    { 
        // This block to be implemented in Phase Two
    
        // Use socketUDP() to created an ephemeral local UDP socket and restrict 
        // its peer to the Auditor server
        sd_audit = socketUDP( 0 , auditorIP , AUDITOR_UDP_PORT ) ;
    
    }

    // Now, Start moving data: fd_in ==> sd_mirror ==> fd_cpy
    // While logging all send and receive transactions to
    // the Auditor UDP Server
    mirrorFile( fd_in , sd_mirror , fd_cpy , sd_audit ) ;
    
    puts("TCP Client finished sending the local file to the TCP Mirror server");
    // Close( sd_mirror ) ;  // Observe the traffic when we use close() vs shutdown()
    shutdown( sd_mirror , SHUT_WR ) ;
    puts("\nTCP Client closed the connection to the TCP Mirror server\n");
    
    return 0;
    
}

/*------------------------------------------------------------------------
 * Trasfer data from descriptor 'in' to descriptor 'mirror' 
 * and receive it back through descriptor 'mirror'. 
 * // This is for Phase Two: Report sending & receiving transactions to descriptor 'audit'
 *------------------------------------------------------------------------*/
 
#define CHUNK_SZ  1000
#define MAXSTRLEN 256

void mirrorFile( int in , int mirror , int copy , int audit )
{
    unsigned char buf[ CHUNK_SZ ] , buf2[ CHUNK_SZ ] ;
    audit_t  activity ; // This is for Phase Two
    struct sockaddr_in      mySocket, mirrorServer ;
    socklen_t    alen ;
    
    // Learn my IP:Port associated with 'mirror' 
    alen = sizeof( mySocket );
    if ( getsockname( mirror , (SA *) &mySocket , &alen ) < 0 )
        err_sys( "getsockname failed" );
        
    // Learn the IP:Port of my peer on the other side of 'mirror'     
    alen = sizeof( mirrorServer );
    if ( getpeername( mirror , (SA *) &mirrorServer , &alen ) < 0 )
        err_sys( "getpeername failed" );
        
    int nread;
    // Repeat untill all data has been sent and received back
    // As this happens, save the received copy to the 'copy' file descriptor
    while ( ( nread = Read( in , buf , CHUNK_SZ ) ) > 0 )
    {
        // Get up to CHUNK_SZ bytes from input file  and send ALL of what I get
        // to the 'mirror' socket
        writen( mirror , buf , nread );

        { 
            // This block to be implemented in Phase Two

            // by setting the fields of 'activity'        
            // Report this sending activity to the Auditor
            activity.op = sent;
            activity.nBytes = nread;
            activity.ip = mirrorServer.sin_addr.s_addr;
            if ( send( audit , &activity , sizeof( audit_t ) , 0 ) < 0 )
                err_sys( "send to audit failed" );
        }
       
        // Now read from 'mirror' EXACTLY the same number of bytes I sent earlier
        Readn( mirror , buf2 , nread );

        { 
            // This block to be implemented in Phase Two
        
            // Report this receiving activity to the Auditor
            // by setting the fields of 'activity'
            activity.op = received;
            activity.nBytes = nread;
            activity.ip = mirrorServer.sin_addr.s_addr;
            if ( send( audit , &activity , sizeof( audit_t ) , 0 ) < 0 )
                err_sys( "send to audit failed" );
        }
        
        // Finally, save a copy of what I received back to the 'copy' file
        writen( copy , buf2 , nread );
    }
}
