//Inputs and outputs
input0	::	FromDevice(nat-eth0, METHOD LINUX);
input1	::	FromDevice(nat-eth1, METHOD LINUX);
output0	::	ToDevice(nat-eth0);
output1	::	ToDevice(nat-eth1);

//Queues
q0	::	Queue(200);
q1	::	Queue(200);

//Classifies frames
//[0] = IP packets, [1] = other packets
c0	::	Classifier(12/0800, -);

//Classifies IP packets
//[0] = Packets coming from 172.20.1.0/24 or to 10.5.5.0/24, [1] = other packets
ipc0	::	IPClassifier(src 172.20.1.0/24 or dst 10.5.5.0/24, -);
nat	:: IPRewriterPatterns(NAT 10.5.5.5 10.5.5.1)
rewriter	::	IPAddrPairRewriter(pattern NAT 0 1)


input0
	->	[0] c0;
	
input1
	->	Print('Packet unmodified', 1000)
	->	[0] c0;

c0[0]
	->	Strip(14)
	->	CheckIPHeader()
	->	MarkIPHeader()
	->	[0]ipc0;
	
ipc0[0]
	->	[0]rewriter;
	
rewriter[0]
	->	Unstrip(14)
	->	EtherRewrite(94:8c:7b:00:ed:da, 5c:ee:b6:72:f3:a4)
	->	q1;
	
rewriter[1]
	->	Unstrip(14)
	->	Print('Return packets modified', 1000)
	->	q0;
	
ipc0[1]
	->	q1;

//Sends non-IP packets to output queue with no action
c0[1]
	->	q1;

//Output queues to output ports
q0 ->	output0;
q1 ->	output1;