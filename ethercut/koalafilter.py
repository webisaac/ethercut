# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Koala filter
"""

import Queue, socket
import ethercut.platform as platform
import ethercut.exceptions as exceptions
import ethercut.types.basethread as basethread

from ethercut.context import ctx
from ethercut.types.colorstr import CStr

import scapy.layers.inet


class KoalaFilter(object):

    __slots__ = [ "stats", "eval_thread", "forward_thread",
                  "decode_thread", "to_forward", "to_decode",
                  "sniffed_packets", "decoder_manager",
                  "from_file", "enabled", "running" ]

    def __init__(self, decmanager):
        self.stats = FilterStats()
        self.decoder_manager = decmanager
        self.to_forward = Queue.Queue()
        self.to_decode = Queue.Queue()
        # Need to be configured when the context is updated
        self.from_file = None
        self.sniffed_packets = None

        self.enabled = False
        self.running = False

        # Threads that make up the filter activity

        # Packet evaluation thread
        self.eval_thread = basethread.BaseThread("Packet eval")
        self.eval_thread.run = self.eval_packets

        # Packet forwarding thread
        self.forward_thread = basethread.BaseThread("Packet forward")
        self.forward_thread.run = self.forward_packets

        # Packet decode thread
        self.decode_thread = basethread.BaseThread("Packet decode")
        self.decode_thread.run = self.decode_packets


    def configure(self):
        """
        This function configures the filter, the filter must be configured at least once
        before running it (as it is disabled by default).
        """
        # The filter can't be configured while it is running
        if self.running:
            ctx.ui.warning("The filter can't be configured while it is running")
            return

        if not ctx.opt.sniff.sniff:
            # There are no packets to filter :P
            self.enabled = False
            ctx.ui.msg("Koala filter disabled")

        else:
            self.enabled = True
            self.sniffed_packets = ctx.sniffed_packets

            # Configure the filter for live or offline sniffing
            self.from_file = ctx.opt.sniff.read

            if self.from_file:
                # No packets to drop nor forward while sniffing offline!
                drop = CStr("off").red
                forward = CStr("off").red

            elif ctx.opt.attack.unoffensive:
                # Use kernel forwarding, this configuration won't allow the koala filter
                # to manipulate the packets before forwarding them
                platform.enable_ip_forward()
                drop = CStr("kernel").green
                forward = drop = CStr("kernel").green

            elif ctx.opt.attack.kill:
                # Kill every connection
                platform.disable_ip_forward()
                drop = CStr("on").green
                forward = CStr("off").red

            else:
                # The koala filter will handle dropping and forwarding
                platform.disable_ip_forward()
                drop = CStr("on").green
                forward = CStr("on").green

            decode = CStr("on").green
            ctx.ui.msg("Koala filter enabled | Dropping: %s | Forwarding: %s | Decoding: %s" %(drop, forward, decode))


    def eval_packets(self):
        """
        Function that contains the activity of the evaluation thread.
        This thread evaluates the packets from the sniffed queue and determines whether
        they should be forwarded or dropped and decoded or ignored.
        """
        while self.running:
            try:
                packet = self.sniffed_packets.get(block=False, timeout=1)
            except Queue.Empty:
                continue

            if packet is None:
                # There are no more packets to filter
                self.to_forward.put(None)
                self.to_decode.put(None)
                break
            else:
                # Add packet to statistics
                self.stats.total += 1

            drop = True
            ignore = True

            try:
                # Don't drop packets that come from a file or that have our MAC address as
                # the ethernet destination field and different IP address on the IP destination
                # field (those packets must be forwarded)
                if self.from_file or (ctx.iface.mac == packet.dst and ctx.iface.ip != packet.payload.dst):
                    drop = False

                    # Now check if we can decode the packet or it should be ignored. We have to
                    # check if it complies with the TARGET specifications

                    # Check from TARGET1 to TARGET2
                    if (ctx.target1.check((packet.payload.src, packet.src, packet.sport)) and
                    ctx.target2.check((packet.payload.dst, packet.dst, packet.dport))):
                        ignore = False

                    # Check from TARGET2 to TARGET1
                    elif (ctx.target2.check((packet.payload.src, packet.src, packet.sport)) and
                    ctx.target1.check((packet.payload.dst, packet.dst, packet.dport))):
                        ignore = False

            except AttributeError:
                # The packet doesn't have an IP datagram or a TCP/UDP segment ecapsulated
                pass

            if not self.from_file:
                if drop:
                    self.stats.dropped += 1
                else:
                    self.to_forward.put(packet)

            if not ignore:
                self.to_decode.put(packet)
            else:
                self.stats.ignored += 1


    def forward_packets(self):
        """
        This function represents the activity of packet forwarding.
        Takes the packets from to_forward queue and sends them back to the wire at layer 3 to
        their real destination.
        """

        # Use dnet to send the packets at layer 3
        snd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        snd.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

        while self.running:
            try:
                packet = self.to_forward.get(block=False, timeout=1)
            except Queue.Empty:
                continue

            if packet is None:
                # No more packets to forward
                break

            # Send the packet at layer 3 and let the kernel do the forwarding
            snd.sendto(str(packet.payload), (packet.payload.dst, 0))
            self.stats.forwarded += 1

    def decode_packets(self):
        """
        This function represents the activity of packet decoding.
        Takes the packets from to_decode queue and pass them to the decoder manager that
        will handle the parsing.
        """
        while self.running:
            try:
                packet = self.to_decode.get(block=False, timeout=1)
            except Queue.Empty:
                continue

            if packet is None:
                # No more packets to decode
                break

            # Pass the packet to the decoder manager
            self.decoder_manager.decode(packet)
            self.stats.decoded += 1

    def start(self):
        """
        Starts the koala filter activity
        """
        if not self.enabled or self.running:
            return
        self.running = True
        self.eval_thread.start()
        self.forward_thread.start()
        self.decode_thread.start()

    def stop(self):
        """
        Stops the koala filter activity
        """
        if not self.enabled or not self.running:
            return
        self.running = False
        self.eval_thread.end()
        self.forward_thread.end()
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
