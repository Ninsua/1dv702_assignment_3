# 1DV702 at Linnaeus University: Assignment 3

Some code to run a Software Defined Network (SDN) in Mininet with POX as the SDN controller and Virtualized Network Functions (VNF) using Click.
Note that the code is very basic and is static for this specific topology. Could be optimized and refactorized, to say the least.
A brief description of all the files below.

## SDNTopo.py
The Mininet topology.
Adds one client, two servers, four bridges as well as four devices that will run the VNFs.
Appropriate links are created between the devices.

## controlapp.py
The POX SDN controller.
Installs proactive flow rules on the bridges for the upper part of the network.
Defines reactive flow rules for the lower part of the network.

## VNF/arp_responder.click
Returns an ARP reply when an ARP request is received.

## VNF/packetprinter.click
Prints the content of an incoming packet into console.

## VNF/nat.click
Acts as a basic NAT device.

## VNF/firewall.click
Drops TCP packets on port 5000. Forwards other packets.
