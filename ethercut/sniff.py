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
import ethercut.types.basethread as basethread
import scapy.layers.l2 as l2

from ethercut.config import ethconf
from ethercut.context import ctx
from ethercut.types.colorstr import CStr


class Sniffer(basethread.BaseThread):
    """
    Packet sniffing thread: this thread is responsible of capturing/reading the packets and pushing
    them to the captured packets queue.
    If a dump file is specified, the packets will be dumped on it.
    """

    def __init__(self):
        super(Sniffer, self).__init__("Sniffing")
        self.pcap = None
        self.dumpfile = None
        self.enabled = False

    def start(self):
        if not self.enabled:
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
                packet = l2.Ether(str(pkt))
                packet.time = ts
                # Put the packet in the sniffed queue to be processed later
                ctx.sniffed_packets.put(packet)
                # Write the packet in the dump file
                if self.dumpfile:
                    scapy.utils.wrpcap(self.dumpfile, packet, append=True)
        except StopIteration:
            # Raised when EOF is reached while reading from a file
            self.end(False)
        except Exception as e:
            print "Hoooooolay: %s" %str(e)

    def end(self, join=True):
        if not self.running:
            return
        # Put None in the queue to signal the end of the capturing process
        ctx.sniffed_packets.put(None)
        super(Sniffer, self).end(join)

    def configure(self):
        """
        Configure the parameters of the sniffer
        """
        if ctx.opt.sniff.sniff:
            src = ctx.opt.sniff.read or ctx.iface.name
            self.pcap = pcap.pcap(src, ethconf.snaplen, ctx.opt.sniff.promisc, ethconf.sniff_timeout)
            self.pcap.setfilter(ctx.opt.sniff.filter)
            self.dumpfile = ctx.opt.sniff.write

            sniff_source = "offline (%s)" if ctx.opt.sniff.read else "live (%s)"
            ctx.ui.msg("Sniffing %s" %sniff_source%CStr(src).green)
            if ctx.opt.sniff.filter:
                ctx.ui.msg("Pcap filter: \"%s\"" %CStr(ctx.opt.sniff.filter).green)
            if self.dumpfile:
                ctx.ui.msg("Dump file: %s" %CStr(ctx.opt.sniff.write).green)
            self.enabled = True

        else:
            ctx.ui.msg("Sniffer module disabled, ethercut won't collect any data (enable it with -s)")
            self.enabled = False
