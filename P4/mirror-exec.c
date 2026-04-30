/*********************************************************************
    PA-04:  Sockets

    FILE:   mirror-exec.c   SKELETON

	Code completed by:
		1- Cole Determan
		2- Ben Berry
		
    Submitted on:   5/1/26
**********************************************************************/

#include    "myNetLib.h"

void reaper(int sig) ;      // Handle SIGCHLD
void killHandler(int sig) ; // Handle SIGTERM

//------------------------------------------------------------
int main( int argc , char *argv[] )
{
    int     sd_listen ,             // Receiving Socket descriptor to Server
            sd_audit ;              // Socket descriptor with Auditor
    int     queLen = 10 ;           // Max #of pending connection requests
    struct sockaddr_in  cl_addr;    // the address of a client

    char *developerName = "Cole Determan & Ben Berry" ;
    
    printf( "\n****  Mirror Server **** by %s\n\n" , developerName ) ;


    char *auditorIP = AUDITOR_IP ;      // Default Auditor Server

    // Get the optional Auditon IP address from argv, otherwise use default
    switch ( argc )
    {
        case 2: auditorIP = argv[1] ; break ;
        case 1: break ;

        default:
            printf("\nUsage: %s [auditor-IP]\n\n" , argv[0] ) ;
            exit(-1);        
    }

    printf("Working with these arguments:\n" ) ;
    printf("\tAuditor Server IP is '%s'\n" , auditorIP ) ;
    

    // Create a TCP socket bound to this local port MIRROR_TCP_PORT
    sd_listen = socketTCP( MIRROR_TCP_PORT , NULL , 0 ) ;

    // Now, start listening on this TCP port
    Listen( sd_listen , queLen );

    printf( "Mirror Server Started. Listening at socket %d\n" , sd_listen );


    { 
        // This block to be implemented in Phase Two
    
        // Create a UDP socket with ephemeral port, but 'connected' to the Auditor server
        sd_audit = socketUDP( 0 , auditorIP , AUDITOR_UDP_PORT ) ;
    
    }

    /* Let reaper clean up after completed child processes */
    sigactionWrapper( SIGCHLD , reaper ) ;
    
    /* Let killHandler() handle CTRL-C or a KILL command from terminal*/
    sigactionWrapper( SIGTERM , killHandler ) ;

   
    // For ever, wait till clients connect to me
    // Will only terminate when I receive a 'SIGTERM'
    while( 1 )
    {
        // Wait for a client to connect & record the 'accepted' socket in sd_clnt
        int sd_clnt;
        socklen_t alen = sizeof( cl_addr );
        sd_clnt = Accept( sd_listen , (SA *) &cl_addr , &alen );

        // Display IP : Port of the client
        char ipStr[ 20 ];
        inet_ntop( AF_INET , &cl_addr.sin_addr , ipStr , 20 );
        printf( "Server just accepted connection from %s : %hu\n" , ipStr , ntohs( cl_addr.sin_port ) );

        // Delegate a sub-server child process to handle this client
        // Start a subMirror server using one of the 'exec' family of system calls
        // Pass the 'sd_clnt'  as argument-1, and  'sd_audit' as argument-2 to that subServer
        if ( Fork() == 0 )
        {
            // In child
            Close( sd_listen );
            char sdStr[ 10 ] , auditStr[ 10 ];
            snprintf( sdStr , 10 , "%d" , sd_clnt );
            snprintf( auditStr , 10 , "%d" , sd_audit );
            execlp( "./subMirror" , "./subMirror" , sdStr , auditStr , (char *)NULL );
            err_sys( "execlp failed" );
        }
        
        // As for the parent server, make sure you close sockets you don't need
        Close( sd_clnt );
    }    
    return 0;
}

/*------------------------------------------------------------------------
 * reaper - clean up zombie children
 *------------------------------------------------------------------------
 */
 
void reaper( int sig )
{
    pid_t  pid ;
	int	   status;

	// Don't know how many signals, so loop till there are still 
    // more signals from child processes

    while ( ( pid = waitpid( -1 , &status , WNOHANG ) ) > 0 ) 
	    fprintf( stderr , "\nA Child server process %d has terminated\n" , pid );

    return ;
}

/*------------------------------------------------------------------------
 * killHandler - clean up after receiving a KILL signal
 *------------------------------------------------------------------------
 */
void killHandler( int sig )
{
    fprintf( stdout , "\nThe Mirror Server is now closing\n" );
    exit( 0 ) ;
}
