//Inputs and outputs
input0	::	FromDevice(fw-eth0, METHOD LINUX);
input1	::	FromDevice(fw-eth1, METHOD LINUX);
output0	::	ToDevice(fw-eth0);
output1	::	ToDevice(fw-eth1);

//Queues
queue0	::	Queue(200);
queue1	::	Queue(200);

//Classifies frames
//[0] = ARP packets, [1] = IP packets, [2] = other packets
c0	::	Classifier(12/0806 20/0001, 12/0800, -);
c1	::	Classifier(12/0806 20/0001, -);

//IP classifier
ipc0	::	IPClassifier(tcp port 5000, -);

//ARP responders
ar0	::	ARPResponder(172.20.1.100 96:6e:dd:86:f5:84);
ar1	::	ARPResponder(10.4.4.100 10.5.5.0/24 94:8c:7b:00:ed:da);

//-------------------------------------------------------------------------------

//Sends input frames/packets into the classifiers for classification
input0	->	[0]c0;
input1	->	[0]c1;

//Sends ARP responses to output queues
c0[0]	->	ar0;
c1[0]	->	ar1;
ar0	->	queue0;
ar1	->	queue1;

//IP packets from port0
c0[1]
		->	Strip(14)
		->	CheckIPHeader()
		->	MarkIPHeader()
		->	[0]ipc0;

//Discard IP packets which are matched
ipc0[0]
		->	Print('Dropped packet!', 1000)
		->	Discard;
	
//Pass other packets
ipc0[1]
		->	Unstrip(14)
		->	queue1;

//Other packets from port0
c0[2]	->	queue1;

//Other packets from port1
c1[1]
		->	queue0;

//Output queues to ports
queue0	->	output0;
queue1	->	output1;