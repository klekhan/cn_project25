#!/usr/bin/env python3
"""
Mininet topology for Project 25.

   h1 (10.0.0.1, normal client) --+
   h2 (10.0.0.2, attacker) -------+-- s1 (OVS, OpenFlow 1.3) -- Ryu controller (127.0.0.1:6653)
   h3 (10.0.0.3, victim server) --+

Run (after starting the controller):   sudo python3 topology.py
"""
import os
import subprocess
import time

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

HERE = os.path.dirname(os.path.abspath(__file__))


def kernel_datapath_available():
    """Normal Ubuntu has the Open vSwitch kernel module. WSL2's kernel usually does not,
    so we fall back to OVS's userspace datapath (same OpenFlow behaviour, just slower)."""
    if os.path.isdir('/sys/module/openvswitch'):
        return True
    return subprocess.call('modprobe openvswitch', shell=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def build():
    net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=True,
                  waitConnected=False)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    dp = 'kernel' if kernel_datapath_available() else 'user'
    info('*** Open vSwitch datapath: %s\n' % dp)
    s1 = net.addSwitch('s1', protocols='OpenFlow13', datapath=dp)
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    for h in (h1, h2, h3):
        net.addLink(h, s1)

    net.start()
    time.sleep(2)  # let the switch connect to the controller

    # Victim services on h3: our own TCP socket server (port 5000) + HTTP (port 80)
    # (server logs go to /tmp so we never create root-owned files in the project folder)
    h3.cmd('cd "%s" && python3 server.py --port 5000 > /tmp/ids_server.log 2>&1 &' % HERE)
    h3.cmd('cd /tmp && python3 -m http.server 80 --bind 10.0.0.3 > /tmp/ids_http.log 2>&1 &')

    info('\n*** Topology ready.\n')
    info('*** h1 = client, h2 = attacker, h3 = server (TCP 5000, HTTP 80)\n')
    info('*** Tip: xterm h1 h2 h3  (open terminals on the hosts)\n\n')
    return net


if __name__ == '__main__':
    setLogLevel('info')
    network = build()
    CLI(network)
    network.get('h3').cmd('pkill -f "server.py|http.server"')   # stop the victim services
    network.stop()
