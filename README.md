Simple Router Project

====================================

## Makefile

The provided `Makefile` provides several targets, including to build `router` implementation.  The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually stopped and started again.

## Project Report

This project create a simple router that forwards packets. For any incoming packet that could pass the sanity check( minimum size, ttl, etc.), the router will fist deal with the Ethernet header. The router can handle two type of headers, arp and ip. For arp, the router will read the arp header, and deal with each type of arp, either send out apr request or read receied arp reply and deal with queued packets. For ip, the router will either reply with icmp message or forward the packet to the next hop. 

This is a challenging progect for me. I ran into lots of problems. Like, how to keep track of the arp list and how to loop through the packets that are queued for each arp request, how to delete and add arp entry and how to send out arp requests. Arp is a big headache. Another big headache is the checksum. After I estabilished the connection, I could not receive any packet, it takes me a very long period to find out that my checksum is not right. Fix the check sum is also full of trouble. I feel like this project is so hard to debug, the debugging is more complicated than writing the code. 








