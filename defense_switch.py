# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from operator import attrgetter
from operator import itemgetter

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4
import random
import math
import string

MODE_NORMAL = 0
MODE_DEFENSE = 1

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    global count_pkt
    global count_time
    global count_defense 

    count_pkt = 0
    count_time = 0
    count_defense = 0
	
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.current_mode = MODE_NORMAL
        hub.spawn(self._timer)
        
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self,ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
    
    def _timer(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(1)

    def _request_stats(self,datapath):
        # request stats
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        #actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 0, match, actions)
        self.add_flow(datapath, 10000, match, actions)
    
        self.add_rule(datapath)
        print "add rule success"

    def add_rule(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # add default rule
        for i in range(0, 256):
            src_addr = str(i) + '.0.0.0'
            subnet   = '255.0.0.0'
            rand = random.randint(0,math.pow(2,32))

            match = parser.OFPMatch(eth_type_nxm=0x0800, ip_proto_nxm=6,
                                    ipv4_src=(src_addr, '255.0.0.0'),
                                    tcp_flags_nxm=(tcp.TCP_SYN,tcp.TCP_SYN),
                                    eth_dst='00:00:00:00:00:02')
            actions = [parser.NXActionRegMove(src_field="ipv4_dst",
                                              dst_field="reg0", n_bits=32, src_ofs=0),
                       parser.NXActionRegMove(src_field="ipv4_src",
                                              dst_field="ipv4_dst", n_bits=32, src_ofs=0),
                       parser.NXActionRegMove(src_field="reg0",
                                              dst_field="ipv4_src", n_bits=32, src_ofs=0),
                       parser.NXActionRegMove(src_field="tcp_src",
                                              dst_field="tcp_dst", n_bits=16, src_ofs=0),
                       parser.NXActionRegMove(src_field="eth_src",
                                              dst_field="eth_dst", n_bits=48, src_ofs=0),
                       parser.OFPActionSetField(eth_src='00:00:00:00:00:02'),
                       parser.OFPActionSetField(tcp_src=80),
                       parser.OFPActionSetField(tcp_seq=rand),
                       parser.OFPActionSetField(tcp_ack=1),
                       parser.OFPActionSetField(tcp_flags_nxm=0x12),
                       parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
            self.add_flow(datapath, 1000, match, actions)

            match = parser.OFPMatch(eth_type_nxm=0x0800, ip_proto_nxm=6,
                                    in_port=1, ipv4_src=(src_addr,'255.0.0.0'),
                                    tcp_ack=rand+1,
                                    tcp_flags_nxm=(tcp.TCP_ACK,tcp.TCP_ACK),
                                    eth_dst='00:00:00:00:00:02')
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                ofproto.OFPCML_NO_BUFFER)]
            
            self.add_flow(datapath, 1000, match, actions)
           
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
	
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        
        body = ev.msg.body
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        global count_pkt
        global count_time
        global count_defense
        count_time+=1

        for stat in sorted([flow for flow in body if flow.priority==10001],
                            key=lambda flow: (flow.match['eth_dst'])):
            if stat.match['eth_dst'] == '00:00:00:00:00:02':
                if count_time > 5:
                    count_pkt = stat.packet_count
                    count_time = 0
                
                if ((stat.packet_count-count_pkt) >= 10000 and self.current_mode == MODE_NORMAL):
                    count_time = 0
                    self.current_mode = MODE_DEFENSE

                if (self.current_mode == MODE_DEFENSE and count_defense == 0):
                    count_defense = 1
                    match = parser.OFPMatch(in_port=2,eth_dst='00:00:00:00:00:01')
                    self.remove_flow(datapath, 10001, match)
                    match = parser.OFPMatch(in_port=1,eth_dst='00:00:00:00:00:02')
                    self.remove_flow(datapath, 10001, match)
                    match = parser.OFPMatch(in_port=3,eth_dst='00:00:00:00:00:02')
                    self.remove_flow(datapath, 10001, match)
                    match = parser.OFPMatch(in_port=2,eth_dst='00:00:00:00:00:03')
                    self.remove_flow(datapath, 10001, match)
                    match = parser.OFPMatch()
                    self.remove_flow(datapath, 10000, match)
                    print "remove flow entry"  
                    
                    #self.add_rule(datapath)
                    #print "add rule success"

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        
        if self.current_mode == MODE_NORMAL:
            self.normal_switch(msg)
        else:
            #In Defense MODE
            self.defense_switch(msg)

    def normal_switch(self, msg):
        print "MODE: Normal"

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]

        if pkt_eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = pkt_eth.dst
        src = pkt_eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        
        # learn a mac address to avoid FLOOD next time
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10001, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 10001, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        #packet-out to client
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                    in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def defense_switch(self, msg):
        print "MODE: Defense"

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        
        if pkt_eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        if pkt_tcp and pkt_tcp.bits == tcp.TCP_ACK: 
            #print "ACK"
            #print pkt_tcp.ack
            pkt_add = packet.Packet()
            pkt_add.add_protocol(ethernet.ethernet(dst=pkt_eth.src,
                                                   src=pkt_eth.dst,
                                                   ethertype=0x0800)) 

            pkt_add.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                           src=pkt_ipv4.dst,
                                           proto=6)) 
            pkt_add.add_protocol(tcp.tcp(dst_port=pkt_tcp.src_port,
                                         src_port=pkt_tcp.dst_port,
                                         seq=pkt_tcp.ack,ack=0,
                                         bits=tcp.TCP_RST))
            self._send_packet(datapath, 1, pkt_add)
            #add rule
            match = parser.OFPMatch(eth_type=0x0800,
                                    ipv4_src=pkt_ipv4.src,ipv4_dst=pkt_ipv4.dst)
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 2000, match, actions)
        elif pkt_tcp:
            print "tcp"
        else:
            src = pkt_eth.src
            dst = pkt_eth.dst
            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})
        
            # learn a mac address to avoid FLOOD next time
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    def remove_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE_STRICT,
                                priority=priority,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
