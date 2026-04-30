/*********************************************************************
    PA-04:  Sockets

    FILE:   auditor.c   SKELETON

	Code completed by:
		1- Cole Determan
		2- Ben Berry
		
    Submitted on:   5/1/26
**********************************************************************/

#include    "myNetLib.h"

FILE * auditFp ;

/*------------------------------------------------------------------------
 * killHandler - clean up after receiving a KILL command from terminal
 *------------------------------------------------------------------------
 */
void killHandler(int sig)
{
    puts( "\nAuditor is now closing\n" );
    fprintf( auditFp , "\nAuditor is now closing\n" );
    fclose( auditFp ) ;
    exit( 0 ) ;
}


#define  REPO_SZ 200
//------------------------------------------------------------
int main( int argc , char *argv[] )
{
    int      sd_audit ;      // Receiving Socket descriptor of Recorder
    int      queLen = 10 ;   // Max #of pending connection requests

    unsigned            alen ;
    struct sockaddr_in  cl_addr;     // the address of a client
    unsigned char       ipStr[30] , ipStr2[30] ;
    audit_t             activity ;
    char                buff[REPO_SZ] , 
                       *outFile = "activityLog.txt";

    char *developerName = "MUST  WRITE  YOUR  NAMES  HERE  OR  LOSE  BIG  POINTS" ;
    
    printf( "\n****  Auditor Server **** by %s\n\n" , developerName ) ;

    // Open the log file wiping any previous content that could 
    // have been there from past runs
    auditFp = fopen( outFile , "w") ;
    if( auditFp == NULL )
        err_sys("Could not create copy file") ;

    // Create a local UDP socket at this specific port: AUDITOR_UDP_PORT
    // Do NOT restrict this socket to any specific client IP:Port
    sd_audit = socketUDP( AUDITOR_UDP_PORT , NULL , 0 ) ;

    // Gracefully clean-up when receiving the SIGTERM signal
    sigactionWrapper( SIGTERM , killHandler ) ; 

    snprintf( buff , REPO_SZ , "****  Auditor Server **** by %s has started\n" , developerName);
    printf( "\n### %s" , buff );
    fprintf( auditFp , "### %s" , buff  );
    fflush( auditFp ) ;
    
    // Repeat forever. Only the KILL signal will stop me

    while(1)
    {        
        // Wait for data to arrive at the UDP socket & capture the Client's socket address
        // The expected data is an 'audit_t' object
        alen        = sizeof( cl_addr ) ;
        if ( recvfrom( sd_audit, &activity , sizeof( audit_t ) , 0 , (SA *) &cl_addr , &alen ) < 0 )
            err_sys( "recvfrom" ) ;

        // Print the details of this activity, both to the stdout and to the log file
        inet_ntop( AF_INET , &cl_addr.sin_addr , ipStr , 30 ) ;
        inet_ntop( AF_INET , &activity.ip , ipStr2 , 30 ) ;

        snprintf( buff , REPO_SZ , "Activity By %-17s:%hu   ..."
                                   "  %9s  %8d Bytes. Peer's IP: %s" ,
                                   ipStr , ntohs( cl_addr.sin_port ) , 
                                   (activity.op == sent ? "Sent" : "Received") , 
                                   activity.nBytes , ipStr2 
                ) ;
        
        printf( "\n### %s\n" , buff );
        fprintf( auditFp , "### %s\n" , buff  );
        fflush( auditFp ) ;
    }    

    return 0;
    
}
