# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Target scanning module (ActiveScan and PassiveScan)
"""

import pcap, time
import ethercut.context as ctx
import ethercut.net.target as target
import ethercut.types.ticker as ticker
import ethercut.exceptions as exceptions
import ethercut.types.basethread as basethread

from ethercut.types.colorstr import CStr
from scapy.layers.l2 import Ether, ARP

class ActiveScan(object):

    def __init__(self, scanlist, initial=False):
        self.scanlist = scanlist
        self.initial  = initial
        self.probe = ticker.Ticker(3.0, self.probing, name="Probing")
        self.acquire = basethread.BaseThread("Acquire")
        self.acquire.run = self.acquiring
        self.running  = False

    def start(self):
        if self.running:
            return
        self.running = True
        self.acquire.start()
        self.probe.start()

    def stop(self):
        if not self.running:
            return
        self.running = False
        self.probe.end()
        self.acquire.end()

    def probing(self):
        """
        Probing thread activity, probe the network for targets
        """
        if self.running:
            if self.initial: # An initial scan
                ctx.ui.instant_msg("[%s] Scanning the network for %s hosts..." %(CStr("DISCOVERY").green,
                                                                                len(self.scanlist)))
                ctx.ui.progressbar(len(self.scanlist), "Target scanning")
            for i, h in enumerate(self.scanlist):
                ctx.injector.push(self.get_probe(h))
                ctx.ui.update_progressbar(i+1)
            if self.initial:
                # Terminate the activity
                self.probe.end(False) # We can't join current thread

    def get_probe(self, ip):
        """
        Get a probe for an ip address
        """
        # Build an ARP query message
        pkt = Ether(src=ctx.iface.mac,
                    dst="ff:ff:ff:ff:ff:ff",
                    type=0x0806) /\
              ARP(hwsrc=ctx.iface.mac,
                  psrc=ctx.iface.ip,
                  hwdst="00:00:00:00:00:00",
                  pdst=ip)
        return pkt

    def acquiring(self):
        """
        Target acquiring thread activity, listens for ARP replies and adds
        those hosts to the targetlist.
        """
        pcp = pcap.pcap(ctx.iface.name, promisc=False, timeout_ms=1)
        pcp.setfilter("(arp[6:2]=2) and dst host %s and ether dst %s" %(ctx.iface.ip, ctx.iface.mac))
        if pcp.datalink() != 1:
            raise exceptions.EthercutException("This media is not supported for target discovery")
        while self.running:
            ret = pcp.__next__()
            if not ret:
                if self.initial: # Terminate the activity
                    self.acquire.end(False)
                    self.running = False
                continue
            ts, pkt = ret
            packet = Ether(str(pkt))
            if packet.psrc in self.scanlist:
                targ = ctx.targetlist.get_bymac(packet.hwsrc)
                if not targ: # New target, add it to the list
                    ctx.targetlist.append(target.Target(packet.psrc, packet.hwsrc))
                else:
                    targ.seen()
