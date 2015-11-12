
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
                cout << "\n\nRecieved Packet\n" << p.Print(cout);

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

                // Finds if we have an existing connection with them, or if they want to open up a 
                // connection. We're assuming hand shake, so no data right now.
                ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
                if ( cs != clist.end() ) {

                    // DEBUG:
                    cout << "\n\nConnection exists or the destination is correct.\n";
                    cout << (*cs).connection.Print(cout);

                    // Obtains the flags from the remote TCPheader.
                    tcph_rem.GetAckNum(ack_rem);
                    tcph_rem.GetSeqNum(seqnum_rem);
                    tcph_rem.GetFlags(flags_rem);

                    // DEBUG: Prints out our remote TCPheader.
                    cout << "\n\nRemote TCP Header\n";
                    cout << tcph_rem.Print(cout);

                    // DEBUG: Printing out Ack number manually.
                    cout << "\n\nPrinting out Sequence Number extracted from TCPHeader\n";
                    cout << seqnum_rem;

                    // THREE WAY HANDSHAKE
                    // There are three scenarios that can occur during the three way handshake.
                    // Server recieves an SYN.
                    // Client recieves a SYN+ACK.
                    // Server recieves an ACK.
                    // Technically, given the "TCPState" we should be able to determine what we're
                    // expecting to recieve. But not using that at the moment.

                    // Recieves a SYN and ACK from server. (Only case)
                    if ( IS_SYN(flags_rem) && IS_ACK(flags_rem) ) {
                        cout << "\n\nRecieved a SYN and ACK. Not implemented.\n";
                    }
                    
                    // Received a SYN from remote. Sends SYN+ACK back as Server.
                    if ( IS_SYN(flags_rem) ) {

                        // DEBUG:
                        cout << "\n\nRecieved SYN flag from remote. It wants to start a connection.\n";

                        // We need to reply with a packet with a SYN and ACK flag set.
                        Packet reply;

                        // .__________________________________.
                        //_| TCP_STATE AND CONNECTION MAPPING |_
                        // Adds the "new" connection to our list so that we can keep track of it. This was
                        // already initialized as c. We create a new Connection State mapping to this.
                        ConnectionToStateMapping<TCPState> new_tcp_state;
                        new_tcp_state.connection = c;
                        new_tcp_state.state.SetState(eState::SYN_RCVD);      

                        // Adds the "last acked" value, or the sequence number of the SYN packet we just
                        // recieved from the remote. Actually, the ACK'd value is what *WE* recieve.
                        // XXX: This is actually lastrcvd
                        // new_tcp_state.state.SetLastAcked(seqnum_rem);

                        // Pushes this new state mapping into our Connections list.
                        clist.push_back(new_tcp_state);

                        // DEBUG: Print out our new TCPState.
                        cout << "\n\nCreated new TCPState to Connection Mapping.\n";
                        cout << new_tcp_state.Print(cout);

                        // .__________.
                        //_| IPHEADER |_
                        // Creates the IPHeader to encapsulate our TCP datagram. Three main things.
                        // IPHeader contains the protocol, Source, and Destination IP.
                        IPHeader iph_src;
                        iph_src.SetProtocol(IP_PROTO_TCP);
                        iph_src.SetSourceIP(c.src);
                        iph_src.SetDestIP(c.dest);

                        // XXX: Fix this later?
                        // We need to compute and set the total length? Not exactly sure about this
                        // computation. This may be different when we actually have data. Dunno.
                        iph_src.SetTotalLength(TCP_HEADER_OPTION_MAX_LENGTH+IP_HEADER_BASE_LENGTH);

                        // DEBUG: Created IPHeader
                        cout << "\n\nCreated new source IPHeader.\n";
                        cout << iph_src.Print(cout);

                        // Pushes the IPHeader into our Packet.
                        reply.PushFrontHeader(iph_src);

                        // .___________.
                        //_| TCPHEADER |_
                        // Creates the TCPHeader. Includes important info for the remote the check.
                        // ( source port, destination port, length, ack, seqnum, flags, windsize )
                        TCPHeader tcph_src;
                        tcph_src.SetSourcePort(c.srcport, reply);
                        tcph_src.SetDestPort(c.destport, reply);
                        tcph_src.SetHeaderLen(TCP_HEADER_OPTION_MAX_LENGTH, reply);

                        // Creates our flags. We want to send a SYN and ACK.
                        unsigned char flags_src;
                        SET_SYN(flags_src);
                        SET_ACK(flags_src);

                        // Sets our flags, window size, ack number,  and sequence number in Source TCPHeader.
                        tcph_src.SetAckNum(seqnum_rem, reply);
                        tcph_src.SetSeqNum(new_tcp_state.state.GetLastSent(), reply);
                        tcph_src.SetWinSize(new_tcp_state.state.GetN(), reply);
                        tcph_src.SetFlags(flags_src, reply);

                        // DEBUG:
                        cout << "\n\nCreated new source TCPHeader.\n";
                        cout << tcph_src.Print(cout);

                        // Pushes TCPheader onto our Packet and sends to IP_MUX.
                        reply.PushBackHeader(tcph_src);
                        MinetSend(mux, reply);
                    }

                    // Recieves ACK from remote.
                    if ( IS_ACK(flags_rem) ) {
                        cout << "\n\nRecieved an ACK. Not implemented.\n";
                    }

                    // In actuality, depending on the TCPState of the connection, we can determine the
                    // case of how we should treat the packet. i.e. TCPState is ESTABLISHED, then ACKS
                    // are expected to push data up to the Sock > Application.


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

                    // Passive open. We set up our "socket" and set our TCPState to listen. Technically, this
                    // state is always supposed to LISTEN? The socket is always listening, but we create a NEW
                    // connection mapping when we recieve a SYN packet from remote client. 
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

                        // XXX
                        // We've bound a connection locally, but we haven't connected to a remote as
                        // of this moment. We should just send a status. WRITE only occurs after the
                        // connection is established via the three-way handshake.
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

    } // END EVENT WHILE LOOP

    MinetDeinit();
    return 0;
}
