# Author: Hank Huynh
# base on the paper: https://ieeexplore.ieee.org/document/7779007
# I use source code: https://github.com/wildan2711/multipath
# for find the best short way and base on it to re-implement this paper.
#
# Still have issue: Because I test on mininet, but mininet can't set vlan_id.
# Only host could set vlan_id.
# So that I fix vlan id in host packet, and on switch I use it for detection.
#

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib import mac, ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event

from collections import defaultdict
from operator import itemgetter

import os
import random
import time

# Cisco Reference bandwidth = 1 Gbps
REFERENCE_BW = 10000000

DEFAULT_BW = 10000000

MAX_PATHS = 2
VLAN_ID = 2

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        self.arp_table = {}
        self.switches = []
        self.hosts = {}
        self.multipath_group_ids = {}
        self.group_ids = []
        self.best_path = {}
        self.ip_src_dst = {}
        self.link_change = 0
        self.ind_r = 0
        self.adjacency = defaultdict(dict)
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: DEFAULT_BW))

    def get_paths(self, src, dst):
        '''
        Get all paths from src to dst using DFS algorithm    
        '''
        if src == dst:
            # host target is on the same switch
            return [[src]]
        paths = []
        stack = [(src, [src])]
        while stack:
            (node, path) = stack.pop()
            for next in set(self.adjacency[node].keys()) - set(path):
                if next is dst:
                    paths.append(path + [next])
                else:
                    stack.append((next, path + [next]))
        print ("Available paths from ", src, " to ", dst, " : ", paths)
        return paths

    def get_link_cost(self, s1, s2):
        '''
        Get the link cost between two switches 
        '''
        e1 = self.adjacency[s1][s2]
        e2 = self.adjacency[s2][s1]
        bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
        ew = REFERENCE_BW/bl
        return ew

    def get_path_cost(self, path):
        '''
        Get the path cost
        '''
        cost = 0
        for i in range(len(path) - 1):
            cost += self.get_link_cost(path[i], path[i+1])
        return cost

    def get_optimal_paths(self, src, dst):
        '''
        Get the n-most optimal paths according to MAX_PATHS
        '''
        paths = self.get_paths(src, dst)
        paths_count = len(paths) if len(
            paths) < MAX_PATHS else MAX_PATHS
        return sorted(paths, key=lambda x: self.get_path_cost(x))[0:(paths_count)]

    def add_ports_to_paths(self, paths, first_port, last_port):
        '''
        Add the ports that connects the switches for all paths
        '''
        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = self.adjacency[s1][s2]
                p[s1] = (in_port, out_port)
                in_port = self.adjacency[s2][s1]
            p[path[-1]] = (in_port, last_port)
            paths_p.append(p)
        return paths_p

    def generate_openflow_gid(self):
        '''
        Returns a random OpenFlow group id
        '''
        n = random.randint(0, 2**32)
        while n in self.group_ids:
            n = random.randint(0, 2**32)
        return n


    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        computation_start = time.time()
        paths = self.get_optimal_paths(src, dst)
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path))
            print (path, "cost = ", pw[len(pw) - 1])
        sum_of_pw = sum(pw) * 1.0
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        switches_in_paths = set().union(*paths)

        ind_mx = pw.index(min(pw))
        print(src, dst, paths, "---", paths_with_ports, "---", switches_in_paths, 
            "\n---", ind_mx, paths_with_ports[ind_mx])

        if self.link_change == 0 and ('n'+str(src)+str(dst) not in self.best_path.keys() or self.best_path['n'+str(src)+str(dst)] != paths_with_ports[ind_mx]):
            self.best_path['n'+str(src)+str(dst)] = paths_with_ports[ind_mx]
            self.mac_to_port.setdefault('n'+str(self.ind_r), {})
            b_path = self.best_path['n'+str(src)+str(dst)]

            print("############### Stable ################### ")
            for node in b_path.keys():
                dp = self.datapath_list[node]
                ofp = dp.ofproto
                ofp_parser = dp.ofproto_parser

                # ports = defaultdict(list)
                actions = []

                # for path in paths_with_ports:
                # if node in b_path:
                in_port = b_path[node][0]
                out_port = b_path[node][1]
                # if (out_port, pw[ind_mx]) not in ports[in_port]:
                #     ports[in_port].append((out_port, pw[ind_mx]))
                # else:
                #     continue
                self.mac_to_port['n'+str(self.ind_r)].setdefault(node, {})
                self.mac_to_port['n'+str(self.ind_r)][node] = [ip_src, in_port]

                print("mac_to_port", self.mac_to_port, node, ip_src, in_port, ip_dst, out_port)

                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_src=ip_src, 
                    ipv4_dst=ip_dst
                )
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )

                actions = [ofp_parser.OFPActionOutput(out_port)]

                self.add_flow(dp, 32768, match_ip, actions)
                self.add_flow(dp, 1, match_arp, actions)
            self.ind_r += 1
            print ("Path installation finished in ", time.time() - computation_start)

        elif self.link_change == 1:
            self.best_path['o'+str(src)+str(dst)] = self.best_path['n'+str(src)+str(dst)]
            self.best_path['n'+str(src)+str(dst)] = paths_with_ports[ind_mx]

            b_path = self.best_path['n'+str(src)+str(dst)]

            node = src#[src, dst]:
            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            actions = []
            print("############### ", b_path)
            if node in b_path:
                out_port = b_path[node][1]
            else:
                print("Dont' have src port!!")
                return -1

            src_ip_arp = {}
            for arp_host in self.hosts.keys():
                if self.hosts[arp_host][0] == node:
                    for ip_host in self.arp_table.keys():
                        if self.arp_table[ip_host] == arp_host:
                            src_ip_arp[arp_host] = [ip_host, '0']
                if arp_host in src_ip_arp.keys():
                    for [ip_s, ip_d] in self.ip_src_dst[dp.id]:
                        if src_ip_arp[arp_host][0] == ip_s:
                            src_ip_arp[arp_host][1] = ip_d

            print(src_ip_arp, "\n")
            for source in src_ip_arp.keys():
                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_src=src_ip_arp[source][0], 
                    ipv4_dst=src_ip_arp[source][1]
                )
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=src_ip_arp[source][0], 
                    arp_tpa=src_ip_arp[source][1]
                )
                print (dp.id, "out_port: ", out_port, src_ip_arp[source][0],  src_ip_arp[source][1])

                actions = [ofp_parser.OFPActionOutput(out_port), 
                        ofp_parser.OFPActionSetField(vlan_vid=VLAN_ID|ofproto_v1_3.OFPVID_PRESENT)]
                self.add_flow(dp, 32768, match_ip, actions)
                self.add_flow(dp, 1, match_arp, actions)
        

            ind = 1
            for node in b_path.keys():
                if node == src or node == dst:
                    ind += 1
                    continue

                dp = self.datapath_list[node]
                ofp = dp.ofproto
                ofp_parser = dp.ofproto_parser

                actions = []
                out_port = b_path[node][1]
                match_vlan = ofp_parser.OFPMatch(
                    vlan_vid=(VLAN_ID|ofproto_v1_3.OFPVID_PRESENT), #|ofproto_v1_3.OFPVID_PRESENT 0x1000
                    in_port=b_path[node][0]
                )
                if ind == len(b_path.keys()) - 1:
                    actions = [ofp_parser.OFPActionOutput(out_port), 
                                ofp_parser.OFPActionSetField(vlan_vid=0)]
                else:
                    actions = [ofp_parser.OFPActionOutput(out_port)]

                self.add_flow(dp, 32768, match_vlan, actions)
                ind += 1

            # self.link_change = 0

        return self.best_path['n'+str(src)+str(dst)][src][1]
        # return paths_with_ports[0][src][1]

    def delete_flow(self, datapath, id_dst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        print(self.mac_to_port)
        for ind in range(self.ind_r):
            ind_srt, ind_stp = 0, 0
            ind_cnt = 0
            for sw_id in self.mac_to_port['n'+str(ind)].keys():
                ind_cnt += 1
                if sw_id == datapath.id:
                    ind_srt = ind_cnt
                elif sw_id == id_dst:
                    ind_stp = ind_cnt

                

            if ind_srt < ind_stp:
                print("delete", datapath.id, datapath.id, self.mac_to_port['n'+str(ind)][datapath.id])
                ip_src = self.mac_to_port['n'+str(ind)][datapath.id][0]
            else:
                continue

            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)#ipv4_src  eth_dst
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

            match = parser.OFPMatch(eth_type=0x0806, arp_spa=ip_src)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # print "Adding flow ", match, actions
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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        print ("switch_features_handler is called")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        print("EventOFPSwitchFeatures")

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath

        print("EventOFPPortDescStatsReply", switch)

        for p in ev.msg.body:
            self.bandwidths[switch.id][p.port_no] = p.curr_speed

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)


        # avoid broadcast from LLDP
        if eth.ethertype == 35020:
            return

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        for p in pkt:
            if p.protocol_name == 'vlan':
                print(dpid, ' ######### vlan_id = ', p.vid)

        if arp_pkt:
            # print dpid, pkt
            print(arp_pkt)
            print("arp_table", self.arp_table)
            print("hosts", self.hosts)

            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            self.ip_src_dst.setdefault(dpid, [])
            if [src_ip, dst_ip] not in self.ip_src_dst[dpid]:
                self.ip_src_dst[dpid].append([src_ip, dst_ip])

            print("ip_src_dst", self.ip_src_dst)
            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                h1 = self.hosts[src]
                h2 = self.hosts[dst]
                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]
                    out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                    self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse

        # print (pkt)
        # print ("EventOFPPacketIn", dpid, in_port, out_port)

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)


    
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser
        print("EventSwitchEnter", switch)
        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch

            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        print (ev)
        switch = ev.switch.dp.id
        print("EventSwitchLeave", switch)
        if switch in self.switches:
            self.switches.remove(switch)
            del self.datapath_list[switch]
            del self.adjacency[switch]

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        print("EventLinkAdd", s1, s2)
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        self.link_change = 1
        # Exception handling if switch already deleted
        print("EventLinkDelete", s1, s2)
        self.delete_flow(self.datapath_list[s1.dpid], s2.dpid)
        # self.delete_flow(self.datapath_list[s2.dpid])

        try:
            del self.adjacency[s1.dpid][s2.dpid]
            del self.adjacency[s2.dpid][s1.dpid]
        except KeyError:
            pass
    