/*********************************************************************
    PA-04:  Sockets

    FILE:   subMirror.c   SKELETON 

	Code completed by:
		1- Cole Determan	
		2- Ben Berry	
		
    Submitted on:   5/1/26
**********************************************************************/

#include    "myNetLib.h"

/*------------------------------------------------------------------------
 * This is a child server attending to an incoming client on 'sd'
 * Audit activities to the Auditor via 'sd_audit'
 *------------------------------------------------------------------------
 */


#define CHUNK_SZ 1000

int main( int argc , char *argv[] )
{
    int sd, sd_audit ;
    
    char *developerName = "Cole Determan and Ben Berry" ;
    
    printf( "\n****  sub-Mirror Server **** by %s\n\n" , developerName ) ;

        
    // Get the required  socket descriptors of the Client
    // and of the Auditor from the command line arguments
    if( argc < 3 )
    {
        printf("\nMissing command-line socket descriptors: %s <client "
               "connected TCP socket> <Auditor UDP socket>\n" , argv[0]) ;
        exit(-1) ;
    }

    sd        = atoi( argv[1] ) ;  // client connected TCP socket from argv[1]
    sd_audit  = atoi( argv[2] ) ;  // Auditor UDP socket  from argv[2]

    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof( clientAddr );
    if ( getpeername( sd , (SA *) &clientAddr , &addrLen ) < 0 )
        err_sys( "getpeername failed" );

    { 
        // This block to be implemented in Phase Two
    
        audit_t  activity ;     // activity auditing
        
        unsigned char buf[ CHUNK_SZ ];
        int nread;
        while ( ( nread = Read( sd , buf , CHUNK_SZ ) ) > 0 )   // Loop until client closes socket
        {
            { 
                // This block to be implemented in Phase Two
            
                // Report this receive activity to the Auditor
                activity.op = received;
                activity.nBytes = nread;
                activity.ip = clientAddr.sin_addr.s_addr;
                send( sd_audit , &activity , sizeof( audit_t ) , 0 );
            }
            

            // send all bytes received above back to the client
            writen( sd , buf , nread );


            { 
                // This block to be implemented in Phase Two
            
                // Report this send activity to the Auditor
                activity.op = sent;
                activity.nBytes = nread;
                activity.ip = clientAddr.sin_addr.s_addr;
                send( sd_audit , &activity , sizeof( audit_t ) , 0 );
            }
        }
    }

    Close ( sd ) ;
    return 0;
}
