// Declarations
//------------------------------------------------------------
// +++++ eth0 interface - Inbound and Outbound +++++
E0_IN	::  FromDevice($Name-eth0, METHOD LINUX);
E0_OUT	::  Queue(200) -> ToDevice($Name-eth0);


Respond to ARP requests
//------------------------------------------------------------
c	::	Classifier(12/0806 20/0001, ...);
ar	::	ARPResponder(10.4.4.100 10.5.5.100 172.20.1.100 00-00-C0-AE-67-EF);
c[0] -> ar;
ar -> ToDevice(E0_OUT);