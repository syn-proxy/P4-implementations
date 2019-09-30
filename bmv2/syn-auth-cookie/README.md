## Topology 


```
                                +--+      
                     client     |h1+----|
                                +--+    |    P4
                                        |   +--+     +--+
                                        |---+s1+-----+h3+  WebServer
                                        |   +--+     +--+
                                +--+    |  Proxy     
                     Attacker   |h2+----|
                                +--+      

```

The topology consists of 3 hosts (h1, h2, h3) and one P4 programmable switch (S1).

- **h1**: client.
- **h2**: attacker.
- **h3**: webserver.
- **s1**: P4 proxy.

## SYN-Authentication with cookie Implementation Visualization   
   
        Client                          Proxy                         Server
        
                          SYN
                   ---------------->
                   seq = x, ack = 0
                                     check if source IP address is in the whitelist
                                     if white-listed --> forward
                                     o.w 
                                     k= createCookie({srcAddr,dstAddr,srcPort,dstPort,protocol},MSS, time)
                                     seq= k
                        SYN-ACK     
                  <-----------------
                  seq = k, ack = x+1
                  
                         ACK
                  ------------------>
                  seq = x+1, ack = k+1  
                                     verify the cookie value k from the acknowledgment
                                     if valid cookie --> IP address is added to whitelist
                                     then reset the connection similar to SYN-Authentication
                                     o.w --> drop packet
                          RST
                   <---------------       
        
    legitimate client reconnects
    
                         SYN
                   ---------------->   source IP is white-listed
                   seq = x, ack = 0
             
                                        Forward
                                   
                                   
                                                          SYN
                                                     --------------->
                                                     seq = x, ack = 0
                                   
                                                         SYN-ACK
                                       Forward      <----------------
                                                    seq = r, ack = x+1
                       SYN-ACK
                  <----------------   
                  seq = r, ack = x+1

                          ACK
                  ----------------->
                  seq = x+1, ack = r+1
                                      
                                      Forward

                                                          ACK
                                                    ----------------->
                                                    seq = x+1, ack = r+1

                      HTTP GET                           HTTP GET
                 ----------------->    FORWARD     ------------------>
                 seq = x+1, ack = r+1               seq = x+1, ack = r+1
    
                       ACK                                ACK
                 <-----------------     FORWARD     <------------------
                 seq = r+1, ack = x+1+payload      seq = r+1, ack = x+1+payload
                                          .
                                          .
                                          .
                                        FIN
                                  ---------------->    
                                  
                                       FIN-ACK
                                  <----------------
                                  
                                        ACK
                                  ---------------->


## Description 

Simple forwarding switch implementation is extended to implement a control-plane mitigation mechanism for SYN-flood using SYN-authentication with syn-cookie for verifying legitimate client on first use. This is considered a hybrid approach between SYN-authentication with connection reset and syn-cookie generation from the client's information. When a valid cookie is received by the proxy the client is white-listed and the connection is reset. A legitimate client will try to reconnect, therefore, the white-list table will be checked if it does contain an entry for the client and then the connection can be forwarded to the server.


This implementation of SYN-Authentication with cookies is considered a control-plane approach since the white-list is implemented using a table in the control plan. In P4, in order to send data to control plan two approaches are available: copy to CPU approach that sends the whole packet using a specific port to the control plan controller to be processed. The second approach is Digest messages, where these message structure is defined in the P4 program and are sent to the control plan controller to be parsed accordingly, and then perform some operation on tables e.g. add, delete, update entries. 

This approach is not fully transparent to the client, although the cookie generation and validation are totally transparent, the connection reset can be noticed by the client. the cookie is generated from the 5-tuple (srcAddr,dstAddr,srcPort,dstPort, protocol) in addition to MSS and time information to generate 32bit value that is used as a sequence number for the SYN-ACK packet sent to the client. Once the client responds with ACK packet with correct ack that contains the correct cookie value, the client is then verified and considered legitimate, therefore, the client IP address will be added to the white-list table in control plane and the connection is reset using RST packet. 

