# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Target: Represents an endpoint device on the network
"""

import time
import ethercut.utils as utils
import ethercut.exceptions as exceptions


class Target(object):
    """
    Represents a host on the network that we are attacking.
    Once a target's last-time-seen exceeds the stale value, it should't be considerated
    alive. You can verify this with the is_alive() method.

    +param:  ip    - Protocol address, it can be either an IPv4 or IPv6 address.
    +param:  mac   - Hardware address
    +param:  port  - Ports to sniff packets from (None for all ports)
    +param:  stale - Time the target is considered alive without being verificated (in seconds)
    +param:  perm  - If perm is True, the target will always be considered as alive
    """

    __slots__ = [ "mac", "ip", "vendor", "__lts", "stale", "perm" ]

    def __init__(self, ip=None, mac=None, stale=3, perm=False):
        # A target needs something to be identified, this can be either it's IP or it's MAC.
        # If none of this fields is specified, we should raise an error.
        if not ip and not mac:
            raise ValueError("A target needs either a MAC or an IP address to be identified")

        # Theese values are checked in __setattr__()
        self.vendor = (None, None)  # Set with mac
        self.ip   = ip
        self.mac  = mac

        # Last-time-seen and stale
        self.__lts = time.time()
        self.stale = stale
        self.perm  = perm

    def needs_update(self):
        """
        Use this method to check whether a target needs to be updated (mac or ip is missing).
        """
        return not bool(self.ip and self.mac)

    def seen(self):
        """
        Updates the last-time-seen of the target to the current time.
        """
        self.__lts = time.time()

    @property
    def lts(self):
        """
        Returns the time elapsed in seconds since the last time the target was verificated.
        """
        return time.time() - self.__lts

    def is_alive(self):
        """
        Returns True if the target's lts doesn't exceed the stale time.
        """
        alive = self.perm if self.perm else self.lts < self.stale and not self.needs_update()
        return alive

    def update(self, addr):
        """
        Updates the missing address with addr.
        """
        if not self.ip:
            self.ip = addr
        elif not self.mac:
            self.mac = addr

    def __setattr__(self, attr, val):
        if attr == "mac" and val:
            val = utils.normalize(val)
            self.vendor = utils.vendor_lookup(val)
        elif attr == "ip" and val:
            if not utils.is_ip(val) and not utils.is_ip6(val):
                raise ValueError("Invalid IP address '%s'" %val)
        return object.__setattr__(self, attr, val)

    def __repr__(self):
        """
        Complete representation of the Target
        """
        addr = self.ip if self.ip else "???"
        vendor = "[ %s ]"%self.vendor[1] if self.vendor[1] else "[ ??? ]"
        mac = self.mac if self.mac else "???"
        s = "%s - %s %s" %(addr, mac, vendor)
        return s

    def __str__(self):
        """
        Reduced representation of the Target
        """
        return self.ip

    def __eq__(self, other):
        # Compare two ips if one of the targets has no MAC
        if not self.mac or not other.mac:
            return self.ip == other.ip
        return self.mac == other.mac

    def __ne__(self, other):
        return not self.__eq__(other)


class TargetList(object):
    """
    List of targets
    """

    def __init__(self, targ=[]):
        if not isinstance(targ, list):
            targ = [targ]
        self.targets = targ
        self.macs    = [] # List containing the mac addresses of all the targets

    def get_alive(self):
        """
        Returns a list with all the alive hosts
        """
        return filter(lambda x: x.is_alive(), self.targets)

    def append(self, targ):
        """
        Adds a target to the list (if it is not already in it).
        """
        if targ.mac not in self.macs:
            self.targets.append(targ)
            self.macs.append(targ.mac)

    def get(self, targ):
        """
        Gets a target of the list that matches targ (None if not found)
        """
        ret = None
        for t in self.targets:
            if t == targ:
                ret = t
                break
        return ret

    def remove_lost(self):
        """
        Remove all lost targets from the list (returns all lost targets)
        """
        i = 0
        lost = []
        for t in self.targets:
            if not t.is_alive():
                lost.append(t)
                self.targets = self.targets[:i] + self.targets[i+1:]
            else:
                i+=1
        return lost

    def get_byip(self, ip):
        """
        Gets the first target whose IP matches ip (None if not found)
        """
        ret = None
        for t in self.targets:
            if t.ip == ip:
                ret = t
                break
        return ret

    def get_bymac(self, mac):
        """
        Gets the first target whose MAC matches mac (None if not found)
        """
        ret = None
        for t in self.targets:
            if t.mac == mac:
                ret = t
                break
        return ret

    def pop(self, targ):
        """
        Removes a target from the list and returns it. Returns None if the target wasn't found.
        """
        ret = None
        for i, t in enumerate(self.targets):
            if t == targ:
                self.targets = self.targets[:i] + self.targets[i+1:]
                self.macs.pop(self.macs.index(t.mac))
                ret = t
                break
        return ret

    def __iter__(self):
        return iter(self.targets)

    def __str__(self):
        """
        String representation of the truncated target list
        """
        s = " "
        for t in self.targets:
            if len(s) > 100:
                # Truncate and show the last item
                s += " ... , %s" %self.targets[-1]
                break
            s += "%s, " %t
        else:
            s = s[:-2] # Remove the last ", "

        return "[%s ]" %s

    def __repr__(self):
        """
        String representation of the whole target list
        """
        s = ", ".join(map(str, self.targets))
        return "[ %s ]" %s

    def __contains__(self, other):
        for t in self.targets:
            if t == other:
                return True
        return False

class TargetSpec(object):
    """
    Target specifications: this class holds all the information required for scanning and attacking
    the hosts.

    Specific target-port bindings must be done manually by assigning a key (ip or mac) to the member
    "specific" and a value (port)

    +param: s - "IP/MAC/PORT" string
    """

    __slots__ = [ "all", "ip", "mac", "port", "specific" ]

    def __init__(self, s=""):
        self.all     = False # All IP, MAC and ports
        self.port = None # None means "No specific port" (all ports)
        self.mac  = None # None means "No specific ip" (all ip)
        self.ip   = None # None means "No specific mac" (all mac)
        self.specific = {} # Specific target-port binds
        if s:
            self.compile_spec(s)

    def compile_spec(self, s):
        if s == "//": # Scan all the network
            self.all = True
            return

        try:
            ip, mac, port = s.split("/")
        except ValueError:
            exce

        # Expand the ports and ip and mac addresses
        self.port = utils.expand_port(port)
        self.ip   = utils.expand_ip(ip)
        self.mac  = utils.expand_mac(mac)

    def check(self, host):
        """
        Checks if a host (ip, mac, port) compiles this specifications
        """
        if self.specific: # If there are specific bindings

            if host[0] in self.specific and host[1] in self.mac: # Check if ip is in specific
                if host[2] in self.specific[host[0]]:
                    return True
                else:
                    return False

            elif host[1] in self.specific and host[0] in self.ip: # Check if mac is in specific
                if host[2] in self.specific[host[1]]:
                    return True
                else:
                    return False

        if self.all:
            return True

        elif ((self.ip is None or host[0] in self.ip) and
            (self.mac is None or host[1] in self.mac) and
            (self.port is None or host[2] in self.port)):
            return True

        else:
            return False
