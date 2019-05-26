# Author: Hank Huynh
# use for the paper: https://ieeexplore.ieee.org/document/7779007
# For simulate the topology.
#

import time, sys
from mininet.node import Host
from mininet.topo import Topo
from mininet.util import quietRun
from mininet.log import error
from mininet.examples.vlanhost import VLANHost


class MyTopo( Topo ):
    def __init__(self):
        Topo.__init__(self)
        host_11 = self.addHost( 'h11', cls=VLANHost, vlan=2)
        host_12 = self.addHost( 'h12', cls=VLANHost, vlan=2)
        host_13 = self.addHost( 'h13', cls=VLANHost, vlan=2)
        host_21 = self.addHost( 'h21', cls=VLANHost, vlan=2)
        host_22 = self.addHost( 'h22', cls=VLANHost, vlan=2)
        host_23 = self.addHost( 'h23', cls=VLANHost, vlan=2)

        switch_1 = self.addSwitch('s1')
        switch_2 = self.addSwitch('s2')
        switch_3 = self.addSwitch('s3')
        switch_4 = self.addSwitch('s4')
        switch_5 = self.addSwitch('s5')
        switch_6 = self.addSwitch('s6')


        self.addLink(host_11, switch_1)
        self.addLink(host_12, switch_1)
        self.addLink(host_13, switch_1)
        self.addLink(host_21, switch_2)
        self.addLink(host_22, switch_2)
        self.addLink(host_23, switch_2)

        self.addLink(switch_1, switch_2)
        #self.addLink(switch_1, switch_6)
        #self.addLink(switch_6, switch_2)
        self.addLink(switch_1, switch_3)
        self.addLink(switch_3, switch_4)
        self.addLink(switch_4, switch_5)
        self.addLink(switch_5, switch_2)


topos = {'mytopo': MyTopo}
