#!/usr/bin/python

import os
from mininet.net import Mininet
from mininet.topo import Topo, SingleSwitchTopo
from mininet.node import OVSSwitch, RemoteController, Node
from mininet.cli import CLI
from mininet.link import OVSLink, Intf
from mininet.log import setLogLevel, info


class LinuxRouter(Node):
    """A Node with IP forwarding enabled."""

    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class NetworkTopo(Topo):

    def build(self, **_opts):
        h1 = self.addNode('h1', cls=LinuxRouter)
        h2 = self.addNode('h2', cls=LinuxRouter)
        # h3 = self.addNode('h3', cls=LinuxRouter, default='192.168.0.2')

        info("### Add links")
        l1 = self.addLink(h1, h2, intfName1='h1-eth0', intfName2='h2-eth0')
        # l2 = self.addLink(h2, h3, intfName1='h2-eth1', intfName2='h3-eth0')
        # l3 = self.addLink(h1, h3, intfName1='h1-eth1', intfName2='h3-eth1')


def run():
    info("### Create a network \n")
    net = Mininet(topo=NetworkTopo(), controller=None)

    info("### Start network \n")
    net.start()

    info("### Getting nodes \n")
    h1 = net.getNodeByName('h1')
    h2 = net.getNodeByName('h2')
    # h3 = net.getNodeByName('h3')

    info("### Add addresses \n")
    h1.cmd('ip addr add 10.0.0.1/32 dev lo')
    # h1.setIP(ip="172.16.1.1", prefixLen=30, intf="h1-eth0")
    h2.cmd('ip addr add 10.0.0.2/32 dev lo')
    # h2.setIP(ip="172.16.1.2", prefixLen=30, intf="h2-eth0")

    info("### Add routes \n")
    # h1.cmd('ip route add 10.0.0.0/30 via 172.16.1.2 dev h1-eth0')
    h1.cmd('ip route add default dev h1-eth0')
    h1.cmd('sysctl net.ipv4.conf.enp0s9.rp_filter=0')
    h1.cmd("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
    h2.cmd("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")

    info("### Add external interfaces \n")
    intf1 = Intf(name='enp0s8', node=h2, ip='192.168.0.2/30')
    intf2 = Intf(name='enp0s9', node=h1, ip='172.16.0.1/30')

    info("### Starting services \n")
    h1.cmd('xterm &')
    h1.cmd('xterm &')
    h2.cmd('xterm &')

    CLI(net)

    info("### Stopping network \n")
    net.stop()


def main():
    setLogLevel('info')
    run()


if __name__ == '__main__':
    main()
