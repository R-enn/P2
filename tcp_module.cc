
// You will build this in project part B - this is merely a
// stub that does nothing but integrate into the stack

// For project parts A and B, an appropriate binary will be 
// copied over as part of the build process



#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"

// Using the provided tcpstate stub.
#include "tcpstate.h"

using namespace std;

int WriteTCPToIP(int ack, int seq, short windowsize) {
	// create packet using max size (header + data???)
	unsigned bytes = MIN_MACRO(TCP_MAXIMUM_SEGMENT_SIZE, req.data.GetSize());
					
	// add all of the data to a packet
	Packet p(req.data.ExtractFront(bytes));
				
	// we are writing tcp to ip, so set IP headers first to encapsulate in a datagram
	IPHeader ih;
	ih.SetProtocol(IP_PROTO_TCP);
	ih.SetSourceIP(req.connection.src);
	ih.SetDestIP(req.connection.dest);
	// or set max header size here????????? wtf 
	ih.SetTotalLength(bytes+TCP_HEADER_MAX_LENGTH);
					
	// push header onto packet
	p.PushFrontHeader(ih);
				
	// build tcp header
	TCPHeader th;
	th.SetSourcePort(req.connection.srcport, p);
	th.SetDestPort(req.connection.destport, p);
	th.SetSeqNum(seq, p);
	th.SetActNum(ack, p);
	th.SetWinSize(windowsize, p);
	th.SetHeaderLen(TCP_HEADER_MAX_LENGTH,p);
	// do we need these?? 
	//th.SetFlags(SOME CHAR, p);
	//th.SetOptions(TCPOptions); 
					
	// push header onto packet after ip header
	p.PushBackHeader(th);
	
	return 0; // lol need to return something else if an error occurred
}					

int main(int argc, char * argv[]) {

    MinetHandle mux;
    MinetHandle sock;
    
    // List of current connections. 
    ConnectionList<TCPState> clist;

    // Initializes this TCP module with the Minet stack.
    MinetInit(MINET_TCP_MODULE);

    // Attempts to connect o IP_MUX and SOCK_MODULE.
    mux = MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
    sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

    // Checks if connection to IP_MUX was successful. The IP multiplexor forwards IP packets according
    // to package type. Basically, the TCP module will recieve a TCP packet. Utilize this class to
    // send and receive packets between server and client.
    if ( (mux == MINET_NOHANDLE) && (MinetIsModuleInConfig(MINET_IP_MUX)) ) {
        MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));
        return -1;
    }

    // Checks if connection to SOCK was successful.
    if ( (sock == MINET_NOHANDLE) && (MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {
        MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));
        return -1;
    }
    
    cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";
    MinetSendToMonitor(MinetMonitoringEvent("tcp_module STUB VERSION handling tcp traffic........"));
    MinetEvent event;
    double timeout = 1;

    // Deals with MinetEvents.
    while (MinetGetNextEvent(event, timeout) == 0) {

        // Handles arriving Data / Packets.
        if ((event.eventtype == MinetEvent::Dataflow) && (event.direction == MinetEvent::IN)) {
        
            // Ip packet has arrived! (From the IP_MUX)
            if (event.handle == mux) {

                Packet p;
                unsigned short len, header_len;
                unsigned int ack, seq_num;
                unsigned char flags;
                bool checksumok;

                // Recieves TCP packet from the IP_MUX and obtains information.
                MinetReceive(mux, p);

                // Prints out the packet using the Minet IP. Messy af.
                cout << "\n\n" << p.Print(cout);

                // Extracts the headers (given the estimate).
                header_len = TCPHeader::EstimateTCPHeaderLength(p);
                p.ExtractHeaderFromPayload<TCPHeader>(header_len);

                // Extracts the TCP header and performs a checksum.
                TCPHeader tcph;
                tcph = p.FindHeader(Headers::TCPHeader);
                checksumok = tcph.IsCorrectChecksum(p);
                
                // Extracts the IP header. This holds the source and destination address.
                IPHeader iph;
                iph = p.FindHeader(Headers::IPHeader);

                // Sets up the connection so that we can check it in our list.
                Connection c;
                iph.GetDestIP(c.src);
                iph.GetSourceIP(c.dest);
                iph.GetProtocol(c.protocol);
                tcph.GetDestPort(c.srcport);
                tcph.GetSourcePort(c.destport);

                // Finds if we have a connection with them.
                ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
                if ( cs != clist.end() ) {

                    // Obtains the mapped state.
                    cout << "\n\nWe recognize this connection!\n";
                    cout << cs.Print(cout) << "\n";

                    // Calculates and extracts the data.
                    tcph.GetHeaderLength(len);
                    Buffer &data = p.GetPayLoad().ExtractBack(len);

                    // DEBUG:
                    cout << "\n\nChecks data that' we're sending.\n";
                    cout << data << "\n";

                    // Obtains the flags from the TCPheader.
                    tcph.GetAckNum(ack);
                    tcph.GetSeqNum(seq_num);
                    tcph.GetFlags(flags);

                    // Creates a socket response.
                    SocketRequestResponse write(WRITE, (*cs).connection, data, len, EOK);

                    // SET FLAGS based on packet.
                    // Received a SYN from remote. Sends SYN+ACK back as Server.
                    if ( IS_SYN(flags) ) {

                        cout << "\n\nWants to connect. Recieved SYN segment from remote.\n";
                        cout << "Setting up a new TCP state with the SYN_SENT flag " << eState::SYN_SENT << "\n";
                        cs.state.SetState( eState::SYN_SENT );

                    }


                }
                else {
                    cout << "\n\nWe don't have this state?\n";
                }                
            }

            // Socket request or response has arrived.
            if (event.handle == sock) {

                // A SockRequestResponse is a 5 tuple of the following struct:
                //
                //  srrType    type;
                //  Connection connection;
                //  Buffer     data;
                //  unsigned   bytes;
                //  int        error;
                //
                // The following two lines obtains the connection request.
                SockRequestResponse req;
                MinetReceive(sock, req);

                // Prints the Socket Request
                cout << "\n\n Printing out a Socket Request.\n";
                cout << "\n\n" << req.Print(cout);

                // Handles the different requests and responses based on type.
                // Types: CONNECT=0, ACCEPT=1, WRITE=2, FORWARD=3, CLOSE=4, STATUS=5 
                switch (req.type) {

                    // Active open from remote. The connection should be fully bound. The data, 
                    // byte count, and error code fields are ignored. The TCP module will begin
                    // the active open and immediately return a STATUS with the same connection
                    // no data, no byte count, and the error code.
                    case CONNECT:
                    {
                        SockRequestResponse repl;
                        repl.type = STATUS;
                        repl.error = EOK;

                        // Starts the passive open. Creating a new connection and state that is
                        // in LISTEN mode.
                        Connection c;
                        c = repl.connection;
                        
                        cout << "\n\nPrinting out Connection in CONNECT request.\n\n";
                        cout << c.Print(cout) << "\n";

                        // Constructs new TCPState

                        MinetSend(sock,repl);
                    }

                    // Passive open. We set up our "socket" and set our TCPState to listen.
                    case ACCEPT:
                    {
                        ConnectionToStateMapping<TCPState> m;
                        m.connection = req.connection;
                        m.state.SetState(LISTEN);

                        // Checking our mapping.
                        cout << "\n\nPrinting the LISTEN flag: " << LISTEN << "\n";
                        cout << "\n\nPrinting our Mapping.\n";
                        cout << m.Print(cout);

                        // Remove any old forward that might be there.
                        ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
                        if ( cs!=clist.end()) {
                            clist.erase(cs);
                        }
                        clist.push_back(m);

                        // Ignored. Send OK response.
                        SockRequestResponse repl;
                        repl.type = WRITE;
                        repl.connection = req.connection;

                        // Buffer is zero bytes.
                        repl.bytes = 0;
                        repl.error = EOK;
                        MinetSend(sock,repl);
                    }
                    break;
            
                    // STATUS
                    // This is NOT ignored in TCP. It's basically a status update. The should be sent in
                    
                    case STATUS:
                    break;

                    // WRITE
                    case WRITE:
                    {
                        // TODO: Write stuff.
						
						// figure out seq and ack #'s, window size
						
						// create TCP segment with WriteIPToTCP
						
						// start timer
						
						// send segment to ip layer
						MinetSend(mux, p);
						
						// set up for response from socket?????
						SockRequestResponse repl;
						// repl.type=SockRequestResponse::STATUS;
						repl.type=STATUS;
						repl.connection=req.connection;
						repl.bytes=bytes;
						repl.error=EOK;
						MinetSend(sock,repl);
						
						// increment sequence number
                    }
                    break;

                    // FORWARD. TCP modules ignores this message. A zero error STATUS will be
                    // returned.
                    case FORWARD:
                    {
                        SockRequestResponse repl;
                        repl.type = STATUS;
                        repl.error = EOK;
                        MinetSend(sock,repl);
                    }
                    break;

                    // CLOSE
                    case CLOSE:
                    {
                        // Sets up SocketReply. Just a status.
                        SockRequestResponse repl;
                        repl.connection = req.connection;
                        repl.type = STATUS;

                        // Remove connection mapping. Error if no mapping exists. This is to keep
                        // track of our running connections!
                        ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
                        if ( cs == clist.end() ) {
                            repl.error = ENOMATCH;
                        }
                        else {
                            repl.error = EOK;
                            clist.erase(cs);
                        }
                        MinetSend(sock,repl);
                    }
                    break;

                    // DEFAULT. Type not recognized.
                    default:
                    {
                        SockRequestResponse repl;
                        repl.type = STATUS;
                        repl.error = EWHAT;
                        MinetSend(sock,repl);
                    }

                }

            } // END SOCK HANDLER

        } // END EVENT HANDLER

        // Timeout ! Probably need to resend some packets.
        if (event.eventtype == MinetEvent::Timeout) {
			// Resend un-acked segment with smallest seq number
			// also start timer again
        }

    } // END EVENT WHILE LOOP

    MinetDeinit();
    return 0;
}