# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Class that provides access to various network parameters
"""

import ethercut.utils as utils
import ethercut.shell as shell


class Network(object):
    """
    This class gives access to some parameters of a given network such as:
        -network address (in dotted and integer form)
        -netmask (in dotted and integer form)
        -network gateway (as a Target instance)
        -local hosts (list with all possible local hosts)

    +param:  ip      - An IPv4 address of the network
    +param:  netmask - Network mask (255.255.255.0 by default)
    """

    __slots__ = [
        # Network and netmask stored as dotted strings (x.x.x.x)
        "network", "netmask",
        ]

    def __init__(self, ip, netmask="255.255.255.0"):
        self.netmask = netmask
        self.network = utils.ntoa(utils.aton(ip) & self.mask32)

    @property
    def net32(self):
        """
        Returns the network byte integer representation of the network address.
        """
        return utils.aton(self.network)

    @property
    def mask32(self):
        """
        Returns the network byte integer representation of the netmask.
        """
        return utils.aton(self.netmask)

    @property
    def all_hosts(self):
        """
        Returns a list containing all the possible host on this network.
        """
        nhost = (0xffffffff ^ self.mask32)
        ret = []
        for i in xrange(1, nhost): # We will omit the broadcast address
            ret.append(utils.ntoa(self.net32 | i))
        return ret

    @property
    def broadcast(self):
        """
        Returns the broadcast address associated with this network.
        """
        return utils.ntoa(self.net32 | (0xffffffff ^ self.mask32))

    @property
    def gateway(self):
        """
        Returns the network gateway, None if not found.
        """
        # Execute netstat to get the routing table
        netst = shell.Shell().netstat("-nr")[0]
        netst = netst[2:].split("\n")
        for l in netst:
            # Look for a valid Route "U", and a gateway "G"
            if "UG" in l:
                return l.split()[1]
        return None

    @property
    def prefix_len(self):
        """
        Returns the address prefix len.

        e.g: for 255.255.255.0  --> /24
        """
        i = 0x80000000
        x = 0
        mask = self.mask32
        while mask & i:
            i >>= 1
            x += 1
        return "/%d" %x

    def __contains__(self, item):
        """
        Returns true if item belongs to this network.
        """
        if not utils.is_ip(item):
            return False
        # Use our netmask to check if the IP could belong to our network
        other_net = utils.aton(item) & self.mask32
        return self.net32 == other_net

    def __setattr__(self, attr, val):
        if attr in ["network", "netmask"]:
            if not utils.is_ip(val):  # Check that we introduced a valid address
                raise ValueError("%s needs to be a valid IP format address (x.x.x.x)" %attr)

        object.__setattr__(self, attr, val)

    def __str__(self):
        return "%s%s" %(self.network,self.prefix_len)
