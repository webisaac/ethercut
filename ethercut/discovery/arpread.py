# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
ARP cache reading module
"""

import ethercut.shell as shell
import ethercut.utils as utils
import ethercut.net.target as target
import ethercut.types.basethread as basethread

from ethercut.context import context


class ARPReader(basethread.BaseThread):
    """
    This class keeps track of the hosts that are in the ARP cache table.

    +param: iface - Name of the interface which the targets belong to
    +param: hosts - List of Target instances to look for in the cache
    +param: ts    - Delay between lookups in seconds (default 3)
    """

    def __init__(self, scanlist):
        super(ARPReader, self).__init__("ARP reader")
        self.ts    = 3
        self.iface = ctx.iface
        self.scanlist  = scanlist
        self.targetlist= ctx.targetlist

        # For update notifications
        self.prev = []

    def run(self):
        sh = shell.Shell()
        while self.running:
            # Get the list of targets (only those ones availables on our interface)
            arp = sh.arp("-nai %s" %self.iface.name)[0]
            for l in arp.split("\n"):
                if not l:
                    continue
                # Get the details of the hosts
                data = l.split()
                ip = data[1][1:-1] # Remove parenthesis
                mac= data[3]

                if ip not in self.scanlist or not utils.is_mac(mac):
                    continue # Skip this host (incomplete or not in scanlist)

                # Check if the host is already in the list
                targ = self.targetlist.get_bymac(mac)
                if not targ:
                    self.targetlist.append(target.Target(ip, mac))
                else:
                    targ.seen()

                # Don't continue if the thread was requested to terminate it's activity
                if not self.running:
                    break

    def stop(self):
        """
        To avoid writing extra code in the discovery stop() method
        """
        self.end()
