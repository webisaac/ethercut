# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Koala filter
"""

import Queue
import ethercut.platform as platform
import ethercut.exceptions as exceptions
import ethercut.types.basethread as basethread

from ethercut.context import ctx
from ethercut.types.colorstr import CStr

import scapy.layers.inet


class KoalaFilter(object):
    """
    This class is responsible of filtering the packets
    """

    def __init__(self, decmanager):
        # Filter statistics
        self.stats = FilterStats()
        # Queues to pass packets to the corresponding threads
        self.to_forward = Queue.Queue()
        self.to_decode = Queue.Queue()
        self.from_file = None
        self.sniffed_packets = None
        self.decoder_manager = decmanager

        # Packet evaluation thread
        self.eval_thread = basethread.BaseThread("Packet eval")
        self.eval_thread.run = self.eval_packets

        # Tread with the filter activity
        self.filter_thread = basethread.BaseThread("Filter")
        self.filter_thread.run = self.filter_activity

        # Packet decoding
        self.decode_thread = basethread.BaseThread("Packet decode")
        self.decode_thread.run = self.decode_packets

        self.enabled = False
        self.running = False

    def configure(self):
        """
        Configures the filter engine
        """
        if self.running:
            ctx.ui.warning("Can't configure the filter engine while it's running")
            return
        if not ctx.opt.sniff.sniff:
            # No sniffed packets to filter :P
            self.enabled = False
            ctx.ui.msg("Filter engine disabled")
        else:
            # Check if we are reading from a file or we are live
            self.from_file = ctx.opt.sniff.read
            self.sniffed_packets = ctx.sniffed_packets
            self.enabled = True

            if self.from_file:  # No packets to drop nor forward while reading from a file

                drop = CStr("OFF").red
                forward = CStr("OFF").red

            elif ctx.opt.attack.unoffensive: # Let the kernel do the forwarding, we are just going to decode

                platform.enable_ip_forward()
                drop = CStr("KERNEL").green
                forward = CStr("KERNEL").green

            elif ctx.opt.attack.kill: # Drop every packet that matches the filter

                platform.disable_ip_forward()
                drop = CStr("ON").green
                forward = CStr("OFF").green

            else: # Ethercut is responsible of forwarding/dropping the packets
                # XXX: This feature is not working jet!!
                raise exceptions.EthercutException("This filter configuration is not available jet :(")
                platform.disable_ip_forward()
                drop = CStr("ON").green
                forward = CStr("ON").green

            decode = CStr("ON").green

            ctx.ui.msg("Koala filter enabled | Dropping: %s | Forwarding: %s | Decoding: %s" %(drop, forward, decode))

    def filter_activity(self):
        while self.running:
            try:
                packet = self.to_forward.get(block=False, timeout=1)
            except Queue.Empty:
                continue

            if packet is None:
                self.to_decode.put(None)
                break

            if not packet.eth_ignore:
                # Pass it to the decoder chain
                self.to_decode.put(packet)

            else:
                self.stats.ignored += 1

            if not self.from_file:
                self.stats.forwarded += 1


    def eval_packets(self):
        while self.running:
            try:
                packet = self.sniffed_packets.get(block=False, timeout=1)
            except Queue.Empty:
                continue

            if packet == None:  # No more packets to filter
                self.to_forward.put(None)
                break
            else:
                self.stats.total += 1

            drop = True
            ignore = True

            try:

                # Don't drop the packet if we are reading from a file or the packet MAC address
                # is ours but the IP address is different
                if self.from_file or (packet.dst == ctx.iface.mac and packet.payload.src != ctx.iface.ip):
                    drop = False

                    # Now we have to check if the packet should be treated by ethercut or should
                    # be ignored. We have to check if the packet complies with the target specifications

                    # Check TARGET1 ---> TARGET2
                    if (ctx.target1.check((packet.payload.src, packet.src, packet.sport))) and \
                    ctx.target2.check((packet.payload.dst, packet.dst, packet.dport)):
                        ignore = False

                    # Check TARGET1 <--- TARGET2
                    elif (ctx.target2.check((packet.payload.src, packet.src, packet.sport))) and \
                    ctx.target1.check((packet.payload.dst, packet.dst, packet.dport)):
                        ignore = False

                # Update the stats
                if drop:
                    self.stats.dropped += 1

                else:
                    # Don't update the forwarded stats right now as the packet may be dropped by
                    # the filters
                    packet.eth_ignore = ignore
                    self.to_forward.put(packet)

            except AttributeError: # Packet has no IP, IPv6, UDP or TCP layer therefore we can't forward it
                if not self.from_file:
                    self.stats.dropped += 1


    def decode_packets(self):
        while self.running:
            try:
                packet = self.to_decode.get(block=False, timeout=1)
            except Queue.Empty:
                continue

            if packet is None:
                break

            self.decoder_manager.decode(packet)
            self.stats.decoded += 1


    def start(self):
        """
        Start the filter engine
        """
        if not self.enabled or self.running:
            return
        self.running = True
        self.eval_thread.start()
        self.filter_thread.start()
        self.decode_thread.start()

    def stop(self):
        """
        Stop the filter engine
        """
        if not self.running or not self.enabled:
            return
        self.running = False
        self.eval_thread.end()
        self.filter_thread.end()
        self.decode_thread.end()


class FilterStats(object):

    __slots__ = [ "total", "dropped", "forwarded",
                  "decoded", "ignored" ]

    def __init__(self):
        self.total = 0
        self.dropped = 0
        self.decoded = 0
        self.forwarded = 0
        self.ignored = 0

    def get(self):
        return "< Filter Stats | %s dropped | %s forwarded | %s decoded | %s ignored | Total: %s >"%(self.dropped,
                                                                                                    self.forwarded,
                                                                                                    self.decoded,
                                                                                                    self.ignored,
                                                                                                    self.total)
    def __str__(self):
        return self.get()
