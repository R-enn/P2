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

#include <string.h>
#include <iostream>

#include "Minet.h"

using std::cout;
using std::cerr;
using std::endl;


struct UDPState {
  std::ostream & Print(std::ostream &os) const { os <<"UDPState()"; return os;}

  friend std::ostream &operator<<(std::ostream &os, const UDPState& L) {
    return L.Print(os);
  }
};


int main(int argc, char *argv[])
{
    MinetHandle mux;
    MinetHandle sock;

    ConnectionList<UDPState> clist;

    MinetInit(MINET_UDP_MODULE);

    mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
    sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

    // Attempts to connect to IP_MUX. IP multiplexor forwards IP packets according to package type.
    // Basically, the UDP module will recieve a UDP packet, TCP a TCP packet, so on and so forth.
    // Utilized this API to recieve packets that are sent to the server / client.
    if (mux==MINET_NOHANDLE && MinetIsModuleInConfig(MINET_IP_MUX)) {
        MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));
        return -1;
    }

    // Attemps to connect to SOCK_MODULE.
    if (sock==MINET_NOHANDLE && MinetIsModuleInConfig(MINET_SOCK_MODULE)) {
        MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));
        return -1;
    }

    cerr << "udp_module handling udp traffic.......\n";
    MinetSendToMonitor(MinetMonitoringEvent("udp_module handling udp traffic........"));
    MinetEvent event;

    // Handles events.
    while (MinetGetNextEvent(event)==0) {

          if (event.eventtype!=MinetEvent::Dataflow || event.direction!=MinetEvent::IN) {
            MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
          } 
          else {

              if (event.handle==mux) {

                  Packet p;
                  unsigned short len;
                  bool checksumok;
                      
                  // Recieves a UDP packet from the IP_MUX and obtains information.
                  MinetReceive(mux,p);

                  // Extracts the header and performs a checksum. The UDPHeader is
                  // a 32-bit number consisting of the source and dest port #.
                  p.ExtractHeaderFromPayload<UDPHeader>(8);
                  
                  // Checks the UDP header.
                  UDPHeader udph;
                  udph=p.FindHeader(Headers::UDPHeader);
                  checksumok=udph.IsCorrectChecksum(p);

                  // Checks the IP header for the IP datagram.
                  // This is the source and dest IP addresses.
                  IPHeader iph;
                  iph=p.FindHeader(Headers::IPHeader);

                  // Connection class represents the five tuple: ( src_ip, src_port, dest_ip, dest_port, protocol )
                  // You can use this to map a connection with a particular UDP state. We basically use this to
                  // describe and store our current connection given the packet.
                  Connection c;

                  // We then take the info from our IPHeader (iph) and store it in our Connection tuple (c). 
                  // Note: This is flipped around because "source" is interepreted as "this machine"
                  iph.GetDestIP(c.src);
                  iph.GetSourceIP(c.dest);
                  iph.GetProtocol(c.protocol);

                  // Stores the destination and source port number from in the UDP header.
                  udph.GetDestPort(c.srcport);
                  udph.GetSourcePort(c.destport);

                  // Iterates through connection list to find if we have connected with the source
                  // before? I believe this iterator returns some index. If we recieve an index that
                  // exists, then we found it. Else, there's an error. o-O
                  ConnectionList<UDPState>::iterator cs = clist.FindMatching(c);

                  // Found a legitimate port? We extract the data and update the sock module that we want
                  // to WRITE. 
                  if ( cs!=clist.end() ) {

                      // Calculate and extract data.
                      udph.GetLength(len);
                      len-=UDP_HEADER_LENGTH;
                      Buffer &data = p.GetPayload().ExtractFront(len);

                      // Create a socket response.
                      SockRequestResponse write(WRITE,
                                  (*cs).connection,
                                  data,
                                  len,
                                  EOK);

                      // Notify failed checksum.
                      if (!checksumok) {
                          MinetSendToMonitor(MinetMonitoringEvent("forwarding packet to sock even though checksum failed"));
                      }

                      // Send response.
                      MinetSend(sock,write);
                  } 

                  // We didn't find a matching connection in our mapping.
                  else {
                      MinetSendToMonitor(MinetMonitoringEvent("Unknown port, sending ICMP error message"));
                      IPAddress source; iph.GetSourceIP(source);
                      ICMPPacket error(source,DESTINATION_UNREACHABLE,PORT_UNREACHABLE,p);
                      MinetSendToMonitor(MinetMonitoringEvent("ICMP error message has been sent to host"));
                      MinetSend(mux, error);
                  }
            }
                
            // Socket request! OH. This is use attempting to connect to a socket.
            if (event.handle==sock) {

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

                // Handles different requests and responses based on type.
                switch (req.type) {

                    // CONNECT leads to ACCEPT.
                    case CONNECT:
                    case ACCEPT: { 

                        // Ignored. Send OK response
                        SockRequestResponse repl;
                        repl.type=STATUS;
                        repl.connection=req.connection;

                        // buffer is zero bytes
                        repl.bytes=0;
                        repl.error=EOK;
                        MinetSend(sock,repl);
                    }
                    break;

                    // STATUS.
                    // Ignored. NO response needed.
                    case STATUS:
                    break;

                    // WRITE:
                    case WRITE:
                    {
                        // XXX: I'm not sure what MIN_MACRO does. You can find this in the utility.cc file.
                        // Basically, it's either the max data that can fit in a packet, (thereby cutting
                        // the data into several packets), or the size of the data if it can fit in a single
                        // packet.
                        unsigned bytes = MIN_MACRO(UDP_MAX_DATA, req.data.GetSize());

                        // Create the payload of the packet. We need to create a packet to
                        // send back to the source. We push the data into the packet first.
                        Packet p(req.data.ExtractFront(bytes));

                        // Make the IP header first since we need it to do the udp checksum
                        // Recall, the IP header includes the source and destination IP. The
                        // length is computed by adding everything together.
                        IPHeader ih;
                        ih.SetProtocol(IP_PROTO_UDP);
                        ih.SetSourceIP(req.connection.src);
                        ih.SetDestIP(req.connection.dest);
                        ih.SetTotalLength(bytes+UDP_HEADER_LENGTH+IP_HEADER_BASE_LENGTH);

                        // Push it onto the packet
                        p.PushFrontHeader(ih);

                        // Now build the UDP header
                        // notice that we pass along the packet so that the udpheader can find
                        // the ip header because it will include some of its fields in the checksum
                        UDPHeader uh;
                        uh.SetSourcePort(req.connection.srcport,p);
                        uh.SetDestPort(req.connection.destport,p);
                        uh.SetLength(UDP_HEADER_LENGTH+bytes,p);

                        // Now we want to have the udp header BEHIND the IP header. Thus, we push the UDP
                        // header back in the Headers queue. (This is all in the same packet.) We can then
                        // send it back to the source.
                        p.PushBackHeader(uh);
                        MinetSend(mux,p);

                        // Sets up the SocketReply for Minet Modules. The details of how this is setup can
                        // be found in the Minet TCP/IP Stack.
                        SockRequestResponse repl;
                        repl.type=STATUS;
                        repl.connection=req.connection;
                        repl.bytes=bytes;
                        repl.error=EOK;
                        MinetSend(sock,repl);
                    }
                    break;

                    // FORWARD
                    case FORWARD:
                    {
                        ConnectionToStateMapping<UDPState> m;
                        m.connection=req.connection;

                        // Remove any old forward that might be there.
                        ConnectionList<UDPState>::iterator cs = clist.FindMatching(req.connection);
                        if (cs!=clist.end()) {
                            clist.erase(cs);
                        }
                        clist.push_back(m);

                        // Create Socket reply.
                        SockRequestResponse repl;
                        repl.type=STATUS;
                        repl.connection=req.connection;
                        repl.error=EOK;
                        repl.bytes=0;
                        MinetSend(sock,repl);
                    }
                    break;

                    // CLOSE
                    case CLOSE:
                    {
                        // Sets up SocketReply.
                        SockRequestResponse repl;
                        repl.connection=req.connection;
                        repl.type=STATUS;
            
                        // Remove connection mapping. Error if no mapping exists. This is to keep
                        // track of our running connections!
                        ConnectionList<UDPState>::iterator cs = clist.FindMatching(req.connection);
                        if (cs==clist.end()) {
                            repl.error=ENOMATCH;
                        } 
                        else {
                          repl.error=EOK;
                          clist.erase(cs);
                        }
                        MinetSend(sock,repl);
                    }
                    break;

                    // DEFAULT case. TYPE wasn't recognized.
                    default:
                    {
                        SockRequestResponse repl;
                        repl.type=STATUS;
                        repl.error=EWHAT;
                        MinetSend(sock,repl);
                    }
                    
                }

            } // END SOCK HANDLER
        } // END EVENT HANDLER
    } // END EVENT WHILE

    return 0;
}
