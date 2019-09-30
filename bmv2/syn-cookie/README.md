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
- **s1**: P4 proxy.- 


## SYN-Cookie Implementation Visualization   
   
        Client                          Proxy                       Server
   
                   SYN
             ---------------->
             seq = x, ack = 0
             
                                   k = createCookie()
                   SYN-ACK
             <----------------
             seq = k, ack = x+1
             

                    ACK
             ----------------->
             seq = x+1, ack = k+1
                                   bool = verifyCookie(k)
                                   add to whitelist 
                                   start TCP connection 
                                                                     SYN
                                   use the same initial SYN    --------------->
                                                               seq = x, ack = 0

                                                                    SYN-ACK
                                  Connection is established    <----------------   r=selectRandomSeq()
                                                               seq = r, ack = x+1
                                  Add state of the connection
                                  to connections table               ACK
                                                               ----------------->
                                                               seq = x+1, ack = r+1

                  HTTP GET                                          HTTP GET
             ----------------->         TRANSFORM              ------------------>
             seq = x+1, ack = k+1                              seq = x+1, ack = r+1

                   ACK                                                ACK
             <-----------------         TRANSFORM              <------------------
             seq = k+1, ack = x+1+payload                     seq = r+1, ack = x+1+payload
             
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


Simple forwarding switch implementation is extended to implement a control-plane mitigation mechanism for SYN-flood using SYN-cookie for verifying legitimate client on first use. Upon connection, the proxy creates a cookie from connection information and replace the sequence number in the SYN-ACK packet. When a valid cookie is received by the proxy the client is white-listed and another TCP connection will be established with the server since the client is legitimate and provided a valid cookie. 


This implementation of SYN-cookies is considered a control-plane approach since both the connection state and the white-list are implemented using a table in the control-plane. In P4, in order to send data to control plan two approaches are available: copy to CPU approach that sends the whole packet using a specific port to the control plan controller to be processed. The second approach is Digest messages, where these message structure is defined in the P4 program and are sent to the control plan controller to be parsed accordingly, and then perform some operation on tables e.g. add, delete, update entries. 

This approach is fully transparent to the client since the normal TCP handshake is established with the proxy and the translation of sequence and acknowledgment numbers for each packet exchanged in the connection between the client and the server. The cookie is generated from the 5-tuple (srcAddr,dstAddr,srcPort,dstPort, protocol) in addition to MSS and time information to generate 32bit value that is used as a sequence number for the SYN-ACK packet sent to the client. Once the client responds with ACK packet with correct ack that contains the correct cookie value, the client is then verified and considered legitimate, therefore, the client IP address will be added to the white-list table in the control plane and a connection will be established between the proxy and the server to forward all upcoming traffic from the client.
