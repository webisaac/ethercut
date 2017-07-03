# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Target discovery package
"""

import time
import ethercut.types.ticker as ticker

from ethercut.context import ctx
from ethercut.types.colorstr import CStr

_prof_to_name = {
    0: "disabled",
    1: "ARP reader",
    2: "initial scan",
    3: "passive",
    4: "active"
}

_name_to_prof = {
    "disabled"    : 0,
    "ARP reader"  : 1,
    "initial scan": 2,
    "passive"     : 3,
    "active"      : 4
}


class Discovery(object):
    """
    This class is responsible of the target discovery.
    """

    def __init__(self):
        self.running = False
        self.targetlist = ctx.targetlist
        self.scanlist = []
        self.profile = None
        self.agent = None
        self.prev = [] # Keeps track of the previous alive targets
        self.updates = ticker.Ticker(1.0, self.show_updates, name="Target update")
        self.enabled = False

    def configure(self):
        """
        Configures the proper discovery profile
        """
        self.profile = ctx.opt.discovery.profile
        if ctx.opt.sniff.read or self.profile == 0:
            self.enabled = False
            ctx.ui.msg("Target discovery manager disabled")
        else:
            self.enabled = True
            self.scanlist = self.build_scan_list()
            # Configure the proper discovery agent
            if self.profile == 1:
                import ethercut.discovery.arpread as arpread
                self.agent = arpread.ARPReader(self.scanlist)

            elif self.profile == 2:
                import ethercut.discovery.scan as scan
                self.agent = scan.ActiveScan(self.scanlist, initial=True)

            elif self.profile == 3:
                import ethercut.discovery.scan as scan
                self.agent = scan.PassiveScan(self.scanlist)

            else:
                import ethercut.discovery.scan as scan
                self.agent = scan.ActiveScan(self.scanlist)

            if self.profile == 0 or self.profile == 2:
                self.update = False # Don't update after first round of new targets
            else:
                self.update = True

    def start(self):
        """
        Starts the discovery agent
        """
        if not self.enabled or self.running:
            return
        self.running = True
        self.updates.start()
        self.agent.start()

    def stop(self):
        """
        Stops the discovery agent
        """
        if not self.enabled or not self.running:
            return
        self.running = False
        self.updates.end()
        self.agent.stop()

    @staticmethod
    def build_scan_list():
        """
        Given the two target groups, generate a list of addresses to scan for
        """
        if ctx.target1.ip is None or ctx.target2.ip is None:
            ctx.ui.msg("Targeting the whole network (%s)" %CStr(str(ctx.network)).yellow)
            ctx.ui.msg("Ethercut needs to precompute all the possible hosts in the network, this could take a while...")
            ctx.ui.flush()
            start = time.time()
            scanlist = filter(lambda ip: ip != ctx.iface.ip and ip != ctx.gateway.ip, ctx.network.all_hosts)
            end = time.time()
            ctx.ui.msg("Done in %0.2fms" %(1000*(end-start)))
        else:
            # Start with target1
            scanlist = ctx.target1.ip
            # Merge target2
            for t in ctx.target2.ip:
                if t not in scanlist and t != ctx.iface.ip and t != ctx.gateway.ip:
                    scanlist.append(t)

            s = ""
            ln = 0
            for t in scanlist:
                if ln > 90:
                    # Truncate and show the last item
                    s += "\n\t"
                    ln = 0
                s += "%s | " %CStr(t).yellow
                # We have to add the length of the address, if we use len(s) it is going to sum
                # the ansi escapes to the length of the string
                ln += len(t)
            if s.endswith(", "):
                s = s[:-2] # Remove the last ", "
            ctx.ui.msg("Targeting %s hosts: \n\t%s" %(len(scanlist), s))

        return scanlist

    def show_updates(self):
        """
        Logs information about new and lost targets.
        """
        new   = []

        # Remove all lost targets
        lost = self.targetlist.remove_lost()

        for t in self.targetlist:
            if t not in self.prev:
                new.append(t)
        if new: # Print new targets
            ctx.ui.user_msg("[%s] New targets acquired:" %CStr("DISCOVERY").green)
            for t in new:
                ctx.ui.user_msg("\t[%s] %s" %(CStr("NEW").green, repr(t)))

        if lost: # Print lost targets
            ctx.ui.user_msg("[%s] Targets lost:" %CStr("DISCOVERY").green)
            for t in lost:
                ctx.ui.user_msg("\t[%s] %s" %(CStr("LOST").red, repr(t)))
        ctx.ui.flush()
        # Update previous list
        self.prev = self.targetlist.targets.values()

        if new and not self.update:
            self.updates.end(False)
