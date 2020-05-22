from pox.core import core
from forwarding.l2_learning import LearningSwitch
from lib.util import dpid_to_str
from pox.lib.packet import *
from pox.lib.addresses import IPAddr, EthAddr

import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
import time

log = core.getLogger()

class OpenFlowAids(object):
    
    @staticmethod
    def output_packet_to_port(event, packet, output_port):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = output_port))
        msg.data = event.ofp
        event.connection.send(msg)
            
    @staticmethod
    def match_input_port(msg, in_port):
        msg.match.in_port = in_port
    
    @staticmethod   
    def match_dst_ip(msg, ip_string):
        msg.match.dl_type = 0x800
        msg.match.nw_dst = IPAddr(ip_string)
    
    @staticmethod
    def set_timeouts(msg, idle_timeout, hard_timeout):
        msg.idle_timeout = idle_timeout
        msg.hard_timeout = hard_timeout
    
    @staticmethod
    def set_output_port(msg, output_port):
        msg.actions.append(of.ofp_action_output(port = output_port))

class ControllerApp(object):
    def __init__(self):
        core.openflow.addListeners(self)
        #You may want to store each event.connection in an array
        self.connections=[]

    def _handle_ConnectionUp(self, event):
        def br1_proactive_rules(connection):
            def install_rule(input_port, output_port):
                msg = of.ofp_flow_mod()
                OpenFlowAids.match_input_port(msg, input_port)
                OpenFlowAids.set_timeouts(msg,0,0)
                OpenFlowAids.set_output_port(msg, output_port)
                connection.send(msg)
        
            #Ports
            br0_port = 1
            br3_port = 2
            fw_in_port = 3
            fw_out_port = 4
            packet_printer_port = 5
                
            #br0 -> fw_in
            install_rule(br0_port, fw_in_port)
            #br3 -> fw_out
            install_rule(br3_port, fw_out_port)
            #fw_in -> br0
            install_rule(fw_in_port, br0_port) 
            #fw_out -> packetprinter
            install_rule(fw_out_port, packet_printer_port)
            #packetprinter -> br3
            install_rule(packet_printer_port, br3_port)
               
        data_path_id = dpid_to_str(event.dpid)
        
        #the DPID in string form is dash separated like "00-00-00-00-00-00"
        log.debug("\nHandling the connection up event for DPID : %s" %data_path_id)

        if data_path_id == '00-00-00-00-01-01':
            br0_rules(event.dpid, event.connection)            
        elif data_path_id == '00-00-00-00-01-02':
            br1_proactive_rules(event.connection)
        elif data_path_id == '00-00-00-00-01-04':
            br3_rules(event.dpid, event.connection)
    
    def _handle_PacketIn (self, event):         
        packet = event.parsed
        
        #Rules for br2
        if dpid_to_str(event.dpid) == '00-00-00-00-01-03':
            br0_port = 1
            br3_port = 2
            nat_in_port = 3
            nat_out_port = 4
            packetprinter_port = 5

            #br0 -> br3
            if (event.port == br0_port and packet.type == ethernet.IP_TYPE):
                log.debug("Installing packet to NAT flow for port %i -> %i as %s" % (event.port, nat_in_port, dpid_to_str(event.dpid)))
                OpenFlowAids.output_packet_to_port(event, packet, nat_in_port)
                
            elif (event.port == nat_out_port and packet.type == ethernet.IP_TYPE):
                log.debug("Installing packet to PPT flow for port %i -> %i as %s" % (event.port, packetprinter_port, dpid_to_str(event.dpid)))
                OpenFlowAids.output_packet_to_port(event, packet, packetprinter_port)
                
            elif (event.port == packetprinter_port and packet.type == ethernet.IP_TYPE):
                log.debug("Installing IP flow for port %i -> %i as %s" % (event.port, br3_port, dpid_to_str(event.dpid)))
                OpenFlowAids.output_packet_to_port(event, packet, br3_port)
                
            #br3 -> br0
            elif (event.port == br3_port):
                log.debug("Installing packet to NAT flow for port %i -> %i as %s" % (event.port, nat_out_port, dpid_to_str(event.dpid)))
                OpenFlowAids.output_packet_to_port(event, packet, nat_out_port)
            
            elif (event.port == nat_in_port):
                log.debug("Installing packet to NAT flow for port %i -> %i as %s" % (event.port, br0_port, dpid_to_str(event.dpid)))
                OpenFlowAids.output_packet_to_port(event, packet, br0_port)
                        
class br0_rules(object):  
    def __init__ (self, dpid, connection):
        def install_proactive_rules(connection):
            #cli IP packets -> br1
            msg = of.ofp_flow_mod()
            OpenFlowAids.match_dst_ip(msg,'10.4.4.1')
            OpenFlowAids.set_timeouts(msg,0,0)
            OpenFlowAids.set_output_port(msg, self.br1_port)
            connection.send(msg)
            
            #cli ARP packets -> br1
            msg = of.ofp_flow_mod()
            msg.match.dl_type = 0x806 #match ARP packets
            OpenFlowAids.match_input_port(msg, self.cli_port)
            OpenFlowAids.set_timeouts(msg,0,0)
            OpenFlowAids.set_output_port(msg, self.br1_port)
            connection.send(msg)
            
            #br1 -> cli
            msg = of.ofp_flow_mod()
            OpenFlowAids.match_input_port(msg, self.br1_port)
            OpenFlowAids.set_timeouts(msg,0,0)
            OpenFlowAids.set_output_port(msg, self.cli_port)
            connection.send(msg)
        
        # The bridge itself
        self.dpid = dpid
        self.connection = connection

        # We want to hear PacketIn messages, so we listen
        # to the connection
        connection.addListeners(self)

        #Port variables
        self.br1_port = 1
        self.br2_port = 2
        self.cli_port = 5
    
        install_proactive_rules(self.connection)

        log.debug('Proactive rules installed on bridge %s' % dpid_to_str(self.dpid))
        
        
    def _handle_PacketIn (self, event):
        packet = event.parsed
            
        if packet.type == ethernet.IP_TYPE:
            ip_header = packet.find('ipv4')
            
            if ip_header.dstip == IPAddr('10.5.5.1'):
                log.debug("Installing IP flow for port %i -> %i as %s" % (event.port, self.br2_port, dpid_to_str(event.dpid)))
                OpenFlowAids.output_packet_to_port(event, packet, self.br2_port)
                
            elif event.port == self.br2_port and ip_header.dstip == IPAddr('172.20.1.1'):
                log.debug("Installing IP flow for port %i -> %i as %s" % (event.port, self.cli_port, dpid_to_str(event.dpid)))
                OpenFlowAids.output_packet_to_port(event, packet, self.cli_port)

class br3_rules(object):   
    def __init__ (self, dpid, connection):
        def install_proactive_rules(connection):
            #srv1 -> br1
            msg = of.ofp_flow_mod()
            OpenFlowAids.match_input_port(msg, self.srv1_port)
            OpenFlowAids.set_timeouts(msg,0,0)
            OpenFlowAids.set_output_port(msg, self.br1_port)
            connection.send(msg)
            
            #br1 IP -> srv1
            msg = of.ofp_flow_mod()
            OpenFlowAids.match_input_port(msg, self.br1_port)
            OpenFlowAids.match_dst_ip(msg, '10.4.4.1') 
            OpenFlowAids.set_timeouts(msg,0,0)
            OpenFlowAids.set_output_port(msg, self.srv1_port)
            connection.send(msg)
                     
            #br1 ARP -> br0
            msg = of.ofp_flow_mod()
            msg.match.dl_type = 0x806 #match ARP packets
            msg.match.nw_dst = IPAddr('10.4.4.1')
            OpenFlowAids.match_input_port(msg, self.br1_port)
            OpenFlowAids.set_timeouts(msg,0,0)
            OpenFlowAids.set_output_port(msg, self.srv1_port)
            connection.send(msg)
            
        # The bridge itself
        self.dpid = dpid
        self.connection = connection

        # We want to hear PacketIn messages, so we listen
        # to the connection
        connection.addListeners(self)
        
        self.br1_port = 1
        self.br2_port = 2
        self.srv1_port = 5
        self.srv2_port = 6
        
        install_proactive_rules(self.connection)
        
        log.debug('Proactive rules installed on bridge %s' % dpid_to_str(self.dpid))
        
    def _handle_PacketIn (self, event):    
        packet = event.parsed
        
        #Forward ARP packets
        if packet.type == ethernet.ARP_TYPE:
            arphdr = packet.find('arp')

            #If packets come from SRV2 machine
            if arphdr.opcode == arp.REQUEST and event.port == self.srv2_port:
                log.debug("Installing ARP flow for port %i -> %i on %s" % (event.port, self.br1_port, dpid_to_str(self.dpid)))
                OpenFlowAids.output_packet_to_port(event, packet, self.br1_port)
                  
            #If packets come from br1 machine
            elif arphdr.opcode == arp.REPLY:
                if arphdr.protodst == IPAddr('10.5.5.1'):
                    log.debug("Installing ARP flow for port %i -> %i on %s" % (event.port, self.srv2_port, dpid_to_str(self.dpid)))
                    OpenFlowAids.output_packet_to_port(event, packet, self.srv2_port)
        
        elif event.port == self.srv2_port:
            log.debug("Installing IP flow for port %i -> %i on %s" % (event.port, self.br2_port, dpid_to_str(self.dpid)))
            OpenFlowAids.output_packet_to_port(event, packet, self.br2_port)
                
        elif event.port == self.br2_port:
            log.debug("Installing IP flow for port %i -> %i on %s" % (event.port, self.srv2_port, dpid_to_str(self.dpid)))
            OpenFlowAids.output_packet_to_port(event, packet, self.srv2_port)
                
def launch():
        core.registerNew(ControllerApp)