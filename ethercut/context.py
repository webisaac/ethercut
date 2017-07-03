# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Program context: handles global states and data
"""

import Queue
import logging

class Context:
    """
    master  : The master
    opt     : Program options
    log     : Logging subsytem
    iface   : Network interface
    gateway : Network gateway
    network : Network that we are auditing
    ui      : User interface
    targetlist: List containing the targets
    target1 : Target group 1 specifications
    target2 : Target group 2 specifications
    injector: Packet injector
    sniffed_packets: Queue containing all the packets sniffed that need to be processed
    """

    __slots__ = [ "master", "opts", "log", "iface", "gateway",
                  "network", "ui", "targetlist", "target1", "target2",
                  "injector", "sniffed_packets" ]
    master     = None
    opt        = None
    log        = logging.getLogger("ethercut")
    iface      = None
    gateway    = None
    network    = None
    ui         = None
    targetlist = None
    target1    = None
    target2    = None
    injector   = None
    sniffed_packets = Queue.Queue()

    log.setLevel(logging.INFO)

ctx = Context()
