# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Packet injection
"""

import time
import pcap
import Queue
import ethercut.types.basethread as basethread

from ethercut.context import ctx
from ethercut.config import ethconf
from ethercut.types.colorstr import CStr


#####################
##  Worker thread  ##
#####################

class _InjectorWorker(basethread.BaseThread):
    """
    This worker is responsible of writing packets from the queue to the wire.

    +param: pktq   - Queue object representing the packet queue
    +param: stream - Injecting stream
    +param: ts     - Delay time between packets
    """

    def __init__(self, pktq, stream, ts=0.0, name="Injector worker"):
        super(_InjectorWorker, self).__init__(name)
        self.queue = pktq
        self.stream= stream
        self.delay = ts

    def inject(self, pkt):
        """
        Use the pcap stream to send the packet
        """
        self.lock.acquire()
        self.stream.sendpacket(str(pkt))
        self.lock.release()

    def run(self):
        """
        Injection logic
        """
        while self.running:
            packet = self.queue.get()
            if packet is None: # Terminate activity when None is received
                break
            self.inject(packet)
            time.sleep(self.delay)


#######################
##  Packet injector  ##
#######################

class Injector(object):
    """
    Packet injector. Spawns a number of workers to inject the packets on the queue
    """

    __slots__ = [ "queue", "workers", "running", "enabled" ]

    def __init__(self):
        self.queue = Queue.Queue()
        self.running = False
        self.workers = []
        self.enabled = False
        ctx.injector = self

    def configure(self):
        # Configure the pcap stream for the workers
        self.enabled = True
        pcp = pcap.pcap(ctx.iface.name, 65535, False, 1)
        self.workers = [_InjectorWorker(self.queue, pcp, ethconf.inject_timeout, name="Injector worker %d")
                        for n in xrange(1, ethconf.inject_workers)]
        ctx.ui.msg("[%s] Workers: %s | Delay: %sms" %(CStr("INJECTOR").cyan, ethconf.inject_workers, ethconf.inject_timeout))

    def start(self):
        """
        Starts the injector
        """
        if self.running or not self.enabled:
            return
        for t in self.workers:
            t.start()
        self.running = True

    def stop(self):
        """
        Stops the injector engine
        """
        if not self.running or not self.enabled:
            return
        # Push None to the queue tho signal the end of the activity
        for i in xrange(len(self.workers)):
            self.queue.put(None)
        for t in self.workers:
            t.end() # Clean exit for all workers
        self.running = False

    def push(self, pkt, block=True, timeout=None):
        """
        Push a packet into the queue
        """
        # Prevent other threads to push packets to the queue while shutting down
        if self.running and self.enabled:
            self.queue.put(pkt, block, timeout)

    def __nonzero__(self):
        """
        Returns True if the injector is running, False otherwise
        """
        return self.running and self.enabled
