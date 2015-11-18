

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

//  .________________________.
// _| CREATE PACKET FUNCTION |_
// The CreatePacket function will create a packet given a connection, the flags to set, sequence
// number, ack number, window size, and data.
void CreatePacket(Packet &reply, Connection c, unsigned char flags, unsigned int seq_num, unsigned int ack_num, unsigned int win_size, std::ostream &cout ) {

    // TODO: Calculates the size of the data. (The number of bytes will help calcuting lengths).

    // .__________.
    //_| IPHEADER |_
    // Creates the IPHeader to encapsulate our TCP datagram. Three main things.
    // IPHeader contains the protocol, Source, and Destination IP.
    IPHeader iph_src;
    iph_src.SetProtocol(IP_PROTO_TCP);
    iph_src.SetSourceIP(c.src);
    iph_src.SetDestIP(c.dest);

    // Sets the IPHeader total length. This is the length of the IPHEADER and its
    // Payload. This is the size in bytes.
    iph_src.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);

    // DEBUG: Created IPHeader
    std::cout << "\n\nCreated new source IPHeader.\n";
    std::cout << iph_src.Print(cout);

    // Pushes the IPHeader into our Packet.
    reply.PushFrontHeader(iph_src);

    // .___________.
    //_| TCPHEADER |_
    // Creates the TCPHeader. Includes important info for the remote the check.
    // ( source port, destination port, length, ack, seqnum, flags, windsize )
    TCPHeader tcph_src;
    tcph_src.SetSourcePort(c.srcport, reply);
    tcph_src.SetDestPort(c.destport, reply);

    // Calculates the TCPHeader length. The defined values in tcp.h are actually
    // the number of bytes when they should be the number of 32-bit words. We need 
    // to convert this number to word; as there are 4 bytes in a word, the
    // calculation is TCP_HEADER_LEN >> 2.
    unsigned word_len;
    word_len = TCP_HEADER_BASE_LENGTH >> 2;
    tcph_src.SetHeaderLen(word_len, reply);

    // Sets our flags, ack number, and sequence number in Source TCPHeader.
    tcph_src.SetAckNum(ack_num, reply);
    tcph_src.SetSeqNum(seq_num, reply);
    tcph_src.SetFlags(flags, reply);
    tcph_src.SetWinSize(win_size, reply);

    // DEBUG:
    cout << "\n\nCreated new source TCPHeader.\n";
    cout << tcph_src.Print(cout) << "\n\n";

    // Pushes TCPheader onto our Packet and sends to IP_MUX.
    reply.PushBackHeader(tcph_src);
}

using namespace std;

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
                unsigned short header_len, len;
                unsigned int ack_rem, seqnum_rem;
                unsigned char flags_rem;
                bool checksumok;

                // Recieves TCP packet from the IP_MUX and obtains information.
                MinetReceive(mux, p);

                // Prints out the packet using the Minet IP.
                cout << "\n\nRecieved Packet\n";

                // Extracts the headers (given the estimate). Technically, we should be calculating this
                // ourselves. Something to do with a number times 4.
                header_len = TCPHeader::EstimateTCPHeaderLength(p);
                p.ExtractHeaderFromPayload<TCPHeader>(header_len);

                // Extracts the TCP header and performs a checksum.
                TCPHeader tcph_rem;
                tcph_rem = p.FindHeader(Headers::TCPHeader);
                checksumok = tcph_rem.IsCorrectChecksum(p);
                
                // Extracts the IP header. This holds the source and destination address.
                IPHeader iph_rem;
                iph_rem = p.FindHeader(Headers::IPHeader);

                // Initalizes connection 5-tuple to hold information: 
                // (src_ip, src_port, dest_ip, dest_port, protocol)
                Connection c;

                // Sets up the connection so that we can check it in our list. This connection can be new.
                // We're going to use it to make sure that the packet is supposed to be sent to us.
                // (Destination IP and Port point to this machine). Note the assignment is reversed as the
                // IPHeader was created by the remote host (Source is Dest and vice versa)
                iph_rem.GetDestIP(c.src);
                iph_rem.GetSourceIP(c.dest);
                iph_rem.GetProtocol(c.protocol);
                tcph_rem.GetDestPort(c.srcport);
                tcph_rem.GetSourcePort(c.destport);

                // DEBUG: Prints out Remote IPHeader.
                cout << "\n\nRemote IPHeader.\n";
                cout << iph_rem.Print(cout);

                // Obtains flags from TCP Header.
                tcph_rem.GetAckNum(ack_rem);
                tcph_rem.GetSeqNum(seqnum_rem);
                tcph_rem.GetFlags(flags_rem);
                
                // DEBUG: Prints out our remote TCPheader.
                cout << "\n\nRemote TCP Header\n";
                cout << tcph_rem.Print(cout);

				// TODO: PLAN
				// 1. We determine a new connection if the packet has a SYN. This is a separate request from a client
				// 	  to connect with us. (This will only happen on the server side)
				// 2. We create a new TCPState and map it to this new connection. We can then add this to our connection
				//    list. The initial TCPState will be SYN_RECVD.
				// 3. If it is not a SYN packet, then assume that we already have a Connection Mapping to it. Thus it should
				//    be in our connection list.
				// 4. We'll check to see if it actually is in our connection mapping list (and this should hold the TCPState)
				// 5. Minet API allows us to check the TCPState state (SYN_RECVD, ESTABLISHED, etc). We can the switch case
				//    our behavior on this state. Hand everything from there.

                // THREE WAY HANDSHAKE
                // There are three scenarios that can occur during the three way handshake.
                // - Server recieves an SYN.
                // - Client recieves a SYN+ACK.
                // - Server recieves an ACK.
				//
                // Technically, given the "TCPState" we should be able to determine what we're
                // expecting to recieve. But not using that at the moment.
				
				//  ._________________.
				// _| SERVER SYN_RCVD |_
				// Server recieved a SYN (no ACK). We create a new TCPState > Connection mapping.
				if ( IS_SYN(flags_rem) && !IS_ACK(flags_rem) ) {
					
					// Creates our mapping to this new connection. We bind this connection locally and
					// will handle it after we find it again in our ConnectionList.
					ConnectionToStateMapping<TCPState> m;
					m.connection = c;
					m.state.SetState(LISTEN);

					// Remove any old forwarding that might be there. Assuming that a previous connection
					// has already been closed.
					ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
					if ( cs != clist.end() ) {
						clist.erase(cs);
					}
					
					// Adds our new connection mapping to the connection list.
					clist.push_back(m);
				}
				
                //  .__________.
                // _| ACK FLAG |_
                // Recieves ACK from remote. Once we get this, and validation checks out, the 
                // connection is ESTABLISHED and we can notify the application (SOCK).
                //else if ( IS_ACK(flags_rem) ) {

                //    cout << "\n\nRecieved an ACK. Not implemented.\n";

                //    // We need to send info to our SOCK that the connection is now ESTABLISED.
                //    // In reality, we'd double check the ACK matches up with a given TCPSTATE.
                //    SockRequestResponse reply;

                //    // This SockRequest is a zero byte WRITE with the fully bound connection.
                //    reply.type = WRITE;
                //    reply.connection = c;
                //    reply.bytes = 0;
                //    reply.error = EOK;

                //    // Sends up to SOCK.
                //    MinetSend(sock,reply);
                //}

                // In actuality, depending on the TCPState of the connection, we can determine the
                // case of how we should treat the packet. i.e. TCPState is ESTABLISHED, then ACKS
                // are expected to push data up to the Sock > Application.

                // FLAG is not part of the three-way-handshake.
                else {
                    cout << "\n\nNot a SYN. Going to handle in our ConnectionList thing.\n";
                }
				
				// Searches through our ConnectionList mapping to find the associated TCPState to handle.
				ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
				if ( cs!=clist.end() ) {
					 
					// DEBUG:
					cout << "\n\nFound Connection in our ConnectionListMapping.\n";
					cout << (*cs).Print(cout);
                    
					// Handles TCPStates.
					switch ( (*cs).state.GetState() ) {
					
						// Server has recieved a SYN, we can then start sending out our SYN+ACK and transition
						// to the state: SYN_RCVD.
						case LISTEN: 
                        {

                            // DEBUG:
                            cout << "\n\nLISTEN case. Server will return a SYN+ACK.\n";
							
							// We need to reply with a packet with a SYN and ACK flag set.
							Packet reply;

                            // Extracts the initailized Sequence number from the TCPState.
                            unsigned int ack_num = cs.state.GetLastSent();
                            unsigned int win_size = cs.state.GetRwnd();
                            unsigned int seq_num = ack_rem+1;
							
							// Sets our flags. We want to send a SYN and ACK.
							unsigned char flags_src = 0;
							SET_ACK(flags_src);
							SET_SYN(flags_src);
							
							// Creates a new packet. Using the following custom function:
							// CreatePacket( packet, connection, flags, ack_num, seq_num, win_size);
							CreatePacket( reply, c, flags_src, seq_num, ack_num, win_size, cout );

                            // DEBUG:
                            cout << "\n\nDouble Checking Packet Creationg out of Function.\n";
                            cout << reply.Print(cout);
							
							// Send out Packet.
							MinetSend(mux, reply);
							
							// Update TCPState. We transition to SYN_RCVD on the Server end. We also note our init SeqNumber, the
							// ack number, etc etc.
							(*cs).state.SetState(SYN_RCVD);
							(*cs).state.SetLastAcked(ack_num); // This might just be one. I don't know.
                            (*cs).state.SetLastSent(seq_num);
							
							// DEBUG: Prints out TCPSTATE.
							cout << "\n\nHandled LISTEN state on server. Updated State is now:\n";
							cout << (*cs).state.Print(cout);
						}
						break;

                        // Server Only.
                        // In the SYN_RCVD state we are waiting for an appropriate ACK before we can notify the SOCK that the
                        // connection has been ESTABLISHED. This will validate the ACK sent in the packet, and send a WRITE
                        // up to the socket module if everything checks out. If there is an error, we will attach a non-zero
                        // error code.
                        case SYN_RCVD: 
                        {
                            // DEBUG:
                            cout << "SYN_RCVD case. Server will inform sock that connection is ESTABLISHED.\n";
                            cout << "Not implemented at the moment.\n";
                        }

                        // Client Only.
                        // In the SYN_SENT state, the client is waiting for a SYN+ACK from the server. We validate the ACK
                        // and send an appropriate ACK in return before informing the SOCK tha the connection has been
                        // ESTABLISHED.
                        case SYN_SENT:
                        {
							// if received SYN, send ACK and move to SYN-RECEIVED
							if (IS_SYN(flags_rem) && !IS_ACK(flags_rem)) {
								// Extracts the initailized Sequence number from the TCPState.
								unsigned int ack_num = cs.state.GetLastSent();
								unsigned int win_size = cs.state.GetRwnd();
								unsigned int seq_num = ack_rem+1;
								unsigned char flags_src = 0;
								SET_ACK(flags_src);
								Packet p;
								
								// create and send packet
								CreatePacket(&p, c, flags, seq_num, ack_num, win_size);
								MinetSend(mux, p);
								
								// Set state to SYN_RECEIVED
								(*cs).SetState(SYN_RCVD);
							}
							
							// if received SYN+ACK, send ACK and move to established
							else if (IS_SYN(flags_rem) && IS_ACK(flags_rem)) {
								// Extracts the initailized Sequence number from the TCPState.
								unsigned int ack_num = cs.state.GetLastSent();
								unsigned int win_size = cs.state.GetRwnd();
								unsigned int seq_num = ack_rem+1;
								unsigned char flags_src = 0;
								SET_ACK(flags_src);
								Packet p;
								
								// create and send packet
								CreatePacket(&p, c, flags, seq_num, ack_num, win_size);
								MinetSend(mux, p);
								
								// Set state to ESTABLISHED
								(*cs).SetState(ESTABLISHED);
							}
							
							// else, something unexpected happened
							else {
								cout << "In SYN_SENT, received something besides SYN or SYN+ACK\n";
							}
                        }
                        break;
						 
                        // ESTABLISH. Both Clien and Server. This is where we extract application data. Main handle.
						// With Established, we extract the the data and send it up to our application. At this point
						// the packet SHOULD have application data.
					    case ESTABLISHED: {
							 
						}
						break;
						
						 
						// I'm just adding examples here now.
						FIN_RCVD: {
							 
						}
						break;
					} 
				}
				else {
					cout << "\n\nERROR: ConnectionMapping was not found.\n";
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

                    // .________________.
                    //_| CLIENT CONNECT |_
                    // Active open from remote. The connection should be fully bound. The data, 
                    // byte count, and error code fields are ignored. The TCP module will begin
                    // the active open and immediately return a STATUS with the same connection
                    // no data, no byte count, and the error code.
                    case CONNECT:
                    {
                        // DEBUG:
                        cout << "\n\nSOCK requesting to CONNECT.\n";
                        cout << req.Print(cout);

                        // Creates our mapping to this new connection. We bind this connection
                        // locally and then send a SYN over.
                        ConnectionToStateMapping<TCPState> m;
                        m.connection = req.connection;
                        m.state.SetState(SYN_SENT);

                        // Remove any old forwarding that might be there.
                        ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
                        if ( cs != clist.end() ) {
                            clist.erase(cs);
                        }
                        clist.push_back(m);

                        // Immediately sends a STATUS to the SOCK layer. 
                        // No data, no byte count, and the error code. 
                        SockRequestResponse repl;
                        repl.type = STATUS;
                        repl.error = EOK;
                        MinetSend(sock,repl);

                        // Creates a packet to request to CONNECT with the given connection.
                        Packet request;

                        //  .__________.
                        // _| IPHEADER |_
                        // Creats the IPHeader to encapsulate our TCP datagram. Three main things.
                        // IPHeader contains the protocol, source, and destination IP. We can find
                        // this within out req.connection = { src, dest, srcport, destport }
                        IPHeader iph_src;
                        iph_src.SetProtocol(IP_PROTO_TCP);
                        iph_src.SetSourceIP(req.connection.src);
                        iph_src.SetDestIP(req.connection.dest);

                        // Sets the IPHeader total length. This is the length of the IPHEADER and its
                        // Payload. (Size in BYTES)
                        iph_src.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);

                        // DEBUG: Created IPHeader
                        cout << "\n\nCreated new source IPHeader.\n";
                        cout << iph_src.Print(cout);

                        // Pushes the IPHeader into our packet.
                        request.PushFrontHeader(iph_src);

                        // .___________.
                        //_| TCPHEADER |_
                        // Creates the TCPHeader. Includes important info for the remote the check.
                        // ( source port, destination port, length, ack, seqnum, flags, windsize )
                        TCPHeader tcph_src;
                        tcph_src.SetSourcePort(req.connection.srcport, request);
                        tcph_src.SetDestPort(req.connection.destport, request);

                        // Calculates the TCPHeader length. (Number of WORDS) 
                        unsigned word_len;
                        word_len = TCP_HEADER_BASE_LENGTH >> 2;
                        tcph_src.SetHeaderLen(word_len, request);

                        // Creates our flags. We want to send a SYN.
                        unsigned char flags_src = 0;
                        SET_SYN(flags_src);

                        // Sets our flags, ack number, and sequence number in Source TCPHeader.
                        // We're not ACK-ing anything so we can initialize everything to 0 (for now).
                        tcph_src.SetAckNum(0, request);
                        tcph_src.SetSeqNum(0, request);
                        tcph_src.SetFlags(flags_src, request);

                        // DEBUG:
                        cout << "\n\nCreated new source TCPHeader.\n";
                        cout << tcph_src.Print(cout) << "\n\n";

                        // Pushes TCPheader onto our Packet and sends to IP_MUX. There's actually a bug
                        // with this...
                        request.PushBackHeader(tcph_src);
                        MinetSend(mux, request);
                        MinetSend(mux, request);
                    }

                    // Passive open. We set up our "socket" and set our TCPState to listen. Technically, this
                    // state is always supposed to LISTEN? The socket is always listening, but we create a NEW
                    // connection mapping when we recieve a SYN packet from remote client. 
                    case ACCEPT:
                    {
                        // Create our persisting mapping to the LISTEN sock.
                        ConnectionToStateMapping<TCPState> m;
                        m.connection = req.connection;
                        m.state.SetState(LISTEN);

                        // Remove any old forward that might be there.
                        ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
                        if ( cs!=clist.end()) {
                            clist.erase(cs);
                        }
                        clist.push_back(m);

                        // We've bound a connection locally, but we haven't connected to a remote as
                        // of this moment. We just send a STATUS with the error code set. WRITE only 
                        // occurs after the connection is established via the three-way handshake.
                        SockRequestResponse repl;
                        repl.type = STATUS;
                        repl.error = EOK;
                        MinetSend(sock,repl);
                    }
                    break;
            
                    // STATUS
                    // This is NOT ignored in TCP. It's basically a status update for how much data
                    // was read in the SOCK. It determine whether or not we should send more data from
                    // our buffer (?). 
                    case STATUS:
                    break;

                    // WRITE
                    // The application sends data down to the socket for the host to send out to a
                    // remote. We create a packet with the given connection.
                    case WRITE:
                    {
                        // TODO: Write stuff.
                        cout << "\n\nWe're in Write for socket.\n\n";
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
                        // DEBUG:
                        cout << "\n\nSock request to close.\n\n";

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

        }

    } // END WHILE LOOP

    MinetDeinit();
    return 0;
}
