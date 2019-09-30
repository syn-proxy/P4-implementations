/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_BROADCAST = 0x1234;
const bit<8>  TCP_PROTOCOL = 0x06;
const bit<8>  UDP_PROTOCOL = 0x11;   // UDP parsing is not implemented

#define TIMER_COUNT 15
#define MSS_SERVER_ENCODING_VALUE 1
//represents MSS 1460

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct learn_t {
    bit<8> digest;
    bit<32> srcIP;
    bit<32> dstIP;
}


struct metadata {
    bit<1> is_valid_cookie;
    bit<32> seq_cookie_num;

    bit<32> connectionHash;

    bit<16> tcpLength; // this value is computed for each packet for TCP checksum recalculations

    learn_t learn; //used for debugging from control plan
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t      tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TCP_PROTOCOL: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
     verify_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr},
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
     }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }

    // forward packet to the appropriate port
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action learn_ip() {
    //send digest message to control plane, structure can be adjusted to send any data for debugging
        random(meta.learn.digest,(bit<8>) 0, (bit<8>) 255);
        meta.learn.srcIP = hdr.ipv4.srcAddr;
        meta.learn.dstIP = hdr.ipv4.dstAddr;
        //digest packet
        digest(1, meta.learn);
    }


    action reset_connection(){
        //Set RST flag and bounce packet back out on the same port it came into
        hdr.tcp.rst = 1;
        hdr.tcp.syn = 0;
        hdr.tcp.ack = 0;

        //Set the correct IP addresses, RESET from SERVER to CLIENT

        bit<32> clientAddr = hdr.ipv4.srcAddr;
        bit<32> serverAddr = hdr.ipv4.dstAddr;

        hdr.ipv4.srcAddr = serverAddr;
        hdr.ipv4.dstAddr = clientAddr;

        //Switch port numbers as well
        bit<16> clientPort = hdr.tcp.srcPort;
        bit<16> serverPort = hdr.tcp.dstPort;
        hdr.tcp.dstPort = clientPort;
        hdr.tcp.srcPort = serverPort;
    }

    // create SYN-cookie packet or SYN-ACK in response to a new connection from a client that is not whitelisted
    action create_syn_cookie_packet(){
        //This action is using the SYN packet received from the client and transform it to SYN-ACK
        //SeqNo is replaced with custom cookie value computed based in several values.

        //Save all the values before exchangiung them, to be used for hash later
        bit<32> clientIPAddress = hdr.ipv4.srcAddr;
        bit<16> clientPortNum = hdr.tcp.srcPort;

        // reverse MAC address
        bit<48> srcMAC = hdr.ethernet.srcAddr;
        bit<48> dstMAC = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = srcMAC;
        hdr.ethernet.srcAddr = dstMAC;

        // return the packet to the same port it came from
        // is this really necessary ? you are already doing this in the forwarding part
        //standard_metadata.egress_spec = standard_metadata.ingress_port;


        // switch source and destination IP addresses
        bit<32> clientAddr = hdr.ipv4.srcAddr;
        bit<32> serverAddr = hdr.ipv4.dstAddr;

        hdr.ipv4.srcAddr = serverAddr;
        hdr.ipv4.dstAddr = clientAddr;

        //Switch port numbers as well
        bit<16> clientPort = hdr.tcp.srcPort;
        bit<16> serverPort = hdr.tcp.dstPort;
        hdr.tcp.dstPort = clientPort;
        hdr.tcp.srcPort = serverPort;

        // set data offset to 5, to indicate that no options are included
        //hdr.tcp.dataOffset=5;  // ignore dataoffset did not solve retransmission issues
        // parsing TCP option is also complicated and removed. use random MSS encoding value

        // set SYN-ACK flags to create the second packet in the TCP handshake
        hdr.tcp.syn = 1;
        hdr.tcp.ack = 1;

        // set the Acknowledgement number to the sequence number received + size of packet (check from wireshark)
        hdr.tcp.ackNo = hdr.tcp.seqNo + 1;
        //ref" https://cr.yp.to/syncookies.html
        //generate a valid cookie, check limitations on each part
        //syn cookie is the initial sequence number selected by the proxy
        // first 5 bits: t mod 32, where t is 32 bit time counter
        // next 3 bits: encoding of MSS selected by the server in response to client's MSS
        // bottom 24 bits: hash of client IP address port and t
        // random value for all connections for now
        bit<5> time = TIMER_COUNT;   //constant value for time
        bit<3> mss_encoding = MSS_SERVER_ENCODING_VALUE; //random value for mss encvoding
        bit<24> hash_value;

        //metadata has a timestamp standard_metadata.enq_timestamp ---> bit <32>

        // compute the hash over source address and port number in addition to time counter
        //check if you need information for the server as well inside the hash or just the client!
        hash(hash_value,
	    HashAlgorithm.crc16,
	    (bit<24>)0,
	    { clientIPAddress,
              clientPortNum,
              time
            },
	     (bit<24>)2^24);

        //TODO: find an alternative way to concatenate bit strings --> P4_16 spec says ++ but it does not work!
	bit <8> temp = (bit<8>)time;
	bit <8> tempWT = temp << 3;
	bit <8> tempWTE = tempWT | (bit<8>)mss_encoding;
	bit <32> tempSeq = (bit<32>)tempWTE;
	bit <32> tempSeqS = tempSeq << 24;
        hdr.tcp.seqNo =tempSeqS | (bit<32>)hash_value;
    }

    //Validate SYN cookie received from a client, last packet in the handshake
    //if a valid cookie is received, the client information is added to whitelist (bloom filter)
    action validate_syn_cookie(){
        // check if the sequence number of SYN-ACK packet is a valid cookie for the client
        bit<5> time = TIMER_COUNT;   //constant value for time
        bit<3> mss_encoding = MSS_SERVER_ENCODING_VALUE; //random value for mss encvoding
        bit<24> hash_value;

        // compute the hash over source address and port number in addition to time counter
        hash(hash_value,
	    HashAlgorithm.crc16,
	    (bit<24>)0,
	    { hdr.ipv4.srcAddr,
              hdr.tcp.srcPort,
              time
            },
	     (bit<24>)2^24);

        // find an alternative way to concatenate bit strings --> P4_16 spec says ++ but it does not work !
	bit <8> temp = (bit<8>)time;
	bit <8> tempWT = temp << 3;
	bit <8> tempWTE = tempWT | (bit<8>)mss_encoding;
	bit <32> tempSeq = (bit<32>)tempWTE;
	bit <32> tempSeqS = tempSeq << 24;
        bit <32> seqNo=tempSeqS | (bit<32>)hash_value;


        // cookie sequence number is ack -1
        if(hdr.tcp.ackNo -1 == seqNo){
           meta.is_valid_cookie = 1;
        }else{
           meta.is_valid_cookie = 0;
        }
    }

    // for TCP checksum calculations, TCP checksum requires some IPv4 header fields in addition to TCP checksum that is
    //not present as a value and must be computed, tcp length = length in bytes of TCP header + TCP payload
    // from IPv4 header we have ipv4 total length that is a sum of the ip header and the ip payload (in our case) the TCP length
    // IPv4 length is IHL field * 4 bytes (or 32 bits 8*4), therefore, tcp length = ipv4 total length - ipv4 header length
    action compute_tcp_length(){
        bit<16> tcpLength;
        bit<16> ipv4HeaderLength = ((bit<16>) hdr.ipv4.ihl) * 4;
        //this gives the size of IPv4 header in bytes, since ihl value represents
        //the number of 32-bit words including the options field
        tcpLength = hdr.ipv4.totalLen - ipv4HeaderLength;
        // save this value to metadata to be used later in checksum computation
        meta.tcpLength = tcpLength;
    }

    // we have one table responsible for forwarding packets
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;   // maximum number of entries in the table
        default_action = drop();
    }

    table whitelist {
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            learn_ip;
            NoAction;
        }
        size = 4096;
        default_action = NoAction;
    }

    apply {
       if(hdr.ipv4.isValid() && hdr.tcp.isValid()){
          //if white-listed just forward
          if (whitelist.apply().hit){
              //do nothing, wait for forwarding
          }else{
             // if the packet is a ACK response for the TCP handshake and not HTTP GET request
               if(hdr.tcp.syn == 1 && hdr.tcp.ack == 0){
                // if the packet is establishing a TCP connection with only SYN flag set
                //if it is a new connection, create a new syn cookie and forward
                create_syn_cookie_packet();

               }else if(hdr.tcp.ack == 1 && hdr.tcp.syn == 0 && hdr.tcp.psh == 0 && hdr.tcp.rst == 0 && hdr.tcp.fin == 0){
                  // if the packet is a ACK response for the TCP handshake
                  // check cookie value first if it is a valid cookie or not
                  validate_syn_cookie();
                  if(meta.is_valid_cookie == 1){
                   //reset the meta value
                    meta.is_valid_cookie = 0;
                     // add the client to the white list, and reset the connection
                    learn_ip();
                    reset_connection();
                  }else{
                     // if it is not valid cookie, just drop the packet
                     drop();
                     return;
                  }
               }

          }
       }
        // Normal forwarding scenario after processing based on the scenario
       if (hdr.ipv4.isValid()) {
           ipv4_lpm.apply();
       }
       // TCP length is required for TCP header checksum value calculations.
       // compute TCP length after modification of TCP header
       compute_tcp_length();
    }
}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

        update_checksum_with_payload(
	    hdr.tcp.isValid() && hdr.ipv4.isValid(),
            { hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
              8w0,
              hdr.ipv4.protocol,
              meta.tcpLength,
              hdr.tcp.srcPort,
              hdr.tcp.dstPort,
              hdr.tcp.seqNo,
              hdr.tcp.ackNo,
              hdr.tcp.dataOffset,
              hdr.tcp.res,
              hdr.tcp.cwr,
              hdr.tcp.ece,
              hdr.tcp.urg,
              hdr.tcp.ack,
              hdr.tcp.psh,
              hdr.tcp.rst,
              hdr.tcp.syn,
              hdr.tcp.fin,
              hdr.tcp.window,
              hdr.tcp.urgentPtr
              },
            hdr.tcp.checksum,
            HashAlgorithm.csum16);

    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
