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

## SYN-Authentication with Bloom filter Implementation Visualization   
   
        Client                          Proxy                         Server
        
                          SYN
                   ---------------->
                   seq = x, ack = 0
                                     check if source IP address is in the whitelist
                                     if white-listed --> forward
                                     o.w --> Reset connection
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

Simple forwarding switch implementation is extended to implement a data-plane mitigation mechanism for SYN-flood using SYN-authentication with reset on the first connection. After the client tries to connect to the server for the first time, the proxy responds with a RST packet to reset the connection and then add the client source IP address to the bloom filter. A legitimate client will try to reconnect, therefore, the bloom filter will be checked if it does contain an entry for the client and then the connection can be forwarded to the server.


This implementation of SYN-Authentication is considered a data-plane the only approach since the white-list is implemented using a bloom filter. In P4 a bloom filter is implemented using register with a length of 4096 bits and width of 1 bit, also 2 hashes are computed for adding entries to the bloom filter. 