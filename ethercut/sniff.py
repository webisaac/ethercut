# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Sniffing thread module
"""

import pcap
import scapy.utils
import ethercut.context as ctx
import ethercut.types.basethread as basethread

from ethercut.config import conf
from scapy.layers.l2 import Ether


class Sniffer(basethread.BaseThread):
    """
    Packet sniffing thread: this thread is responsible of capturing/reading the packets and pushing
    them to the captured packets queue.
    If a dump file is specified, the packets will be dumped on it.
    """

    def __init__(self):
        super(Sniffer, self).__init__("Sniffing")
        self.active = False if ctx.opt.sniff.sniff is False else True
        if self.active:
            # Configure the source
            src = ctx.opt.sniff.read if ctx.opt.sniff.read else ctx.iface.name
            self.pcap = pcap.pcap(src, conf.snaplen, ctx.opt.sniff.promisc, conf.sniff_timeout, False)
            self.pcap.setfilter(ctx.opt.sniff.filter)
            self.dumpfile = ctx.opt.sniff.write

    def start(self):
        if not self.active:
            return
        super(Sniffer, self).start()

    def run(self):
        try:
            while self.running:
                # Get the packet anf timestamp from pcap
                ret = self.pcap.__next__()
                if not ret:
                    continue
                ts, pkt = ret
                packet = Ether(str(pkt))
                packet.time = ts
                # Put the packet in the sniffed queue to be processed later
                ctx.sniffed_packets.put(packet)
                # Write the packet in the dump file
                if self.dumpfile:
                    scapy.utils.wrpcap(self.dumpfile, packet, append=True)
        except StopIteration:
            # Raised when EOF is reached while reading from a file
            self.end(False)

    def end(self, join=True):
        if not self.active or not self.running:
            return
        # Put None in the queue to signal the end of the capturing process
        ctx.sniffed_packets.put(None)
        super(Sniffer, self).end(join)
