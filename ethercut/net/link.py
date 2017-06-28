# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Link (network interface), the attacking device
"""

import ethercut.utils as utils


class Link(object):
    """
    This class represents a network interface (link).
    It will make use of ifconfig to get all the relevant network parameters.

    +param:  name - name of the network interface
    """

    __slots__ = ["name", "mac", "ip", "ip6", "bcast",
                 "mtu", "netmask", "vendor"]

    def __init__(self, name):
        # Get a shell to parse the interface configuration
        cnf = utils.get_iface(name)

        self.name    = name
        self.vendor  = None # Set by __setattr__ when setting mac attribute
        self.mac     = cnf["hw"]
        self.ip      = cnf["inet"]
        self.ip6     = cnf["inet6"]
        self.mtu     = cnf["mtu"]
        self.netmask = cnf["netmask"]
        self.bcast   = cnf["bcast"]

    def __repr__(self):
        s  = "%s: \n" %self.name
        s += "\tmac: %s" %self.mac
        s += "\tinet: %s  netmask: %s  bcast: %s\n" %(self.ip, self.netmask, self.bcast)
        s += "\tinet6: %s\n" %self.inet6
        return s

    def __str__(self):
        vendor = self.vendor[1] if self.vendor[1] else "???"
        return "%s - %s : %s [ %s ]" %(self.ip, self.mac, self.name, vendor)

    def __setattr__(self, attr, val):
        if attr == "mac" and val is not None:
            val = utils.normalize(val)
            self.vendor = utils.vendor_lookup(val)
        return object.__setattr__(self, attr, val)
