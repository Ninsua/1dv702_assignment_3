from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info, error

class SDNTopo(Topo):    
    def __init__(self):        
        # Initialize topology    
        Topo.__init__(self)    
        # Add hosts and switches    
        cli =self.addNode('cli', mac='94:8c:7b:00:ed:da', ip='172.20.1.1/24', defaultRoute='via 172.20.1.100')    
        srv1 =self.addNode('srv1', ip='10.4.4.1/24', defaultRoute='via 10.4.4.100', mac='96:6e:dd:86:f5:84')    
        srv2 =self.addNode('srv2', ip='10.5.5.1/24', defaultRoute='via 10.5.5.100', mac='5c:ee:b6:72:f3:a4')
        br0 =self.addSwitch('br0', dpid="00000000101")
        br1 =self.addSwitch('br1', dpid="00000000102")
        br2 =self.addSwitch('br2', dpid="00000000103")
        br3 =self.addSwitch('br3', dpid="00000000104")
        
        firewall =self.addNode('fw', mac='none', ip='none')
        nat =self.addNode('nat', mac='none', ip='none')
        pp1 =self.addNode('pp1', mac='none', ip='none') 
        pp2 =self.addNode('pp2', mac='none', ip='none') 
        
        #Add links  
        self.addLink(cli, br0, port1=0, port2=5)
        self.addLink(srv1, br3, port1=0, port2=5)
        self.addLink(srv2, br3, port1=0, port2=6)
        
        self.addLink(br0, br1, port1=1, port2=1)
        self.addLink(br0, br2, port1=2, port2=1)
        self.addLink(br1, br3, port1=2, port2=1)
        self.addLink(br2, br3, port1=2, port2=2)
        
        self.addLink(firewall, br1, port1=0, port2=3)
        self.addLink(firewall, br1, port1=1, port2=4)
        self.addLink(pp1, br1, port1=0, port2=5)
        
        self.addLink(nat, br2, port1=0, port2=3)
        self.addLink(nat, br2, port1=1, port2=4)
        self.addLink(pp2, br2, port1=0, port2=5)

topos = {'ass3': (lambda: SDNTopo())}

