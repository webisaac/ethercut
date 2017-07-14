# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Master: Handles the program loop
"""

import pcap, Queue, logging
import contextlib
import ethercut.ui          as ui
import ethercut.log         as log
import ethercut.sniff       as sniff
import ethercut.utils       as utils
import ethercut.net.link    as link
import ethercut.discovery   as discovery
import ethercut.exceptions  as exceptions
import ethercut.net.target  as target
import ethercut.net.inject  as inject
import ethercut.net.network as network
import ethercut.decodermanager as decmanager
import ethercut.spoofermanager as spfmanager
import ethercut.platform as platform
import ethercut.koalafilter as koala
import ethercut.shell as shell


from ethercut.options import *
from ethercut.config import ethconf
from ethercut.context import ctx
from ethercut import NAME, PROGRAM, CONFILE, COPYRIGHT, AUTHOR
from ethercut.types.colorstr import CStr


class Master(object):

    name = NAME
    program = PROGRAM

    def __init__(self):

        # Load configuration file
        ethconf.load(CONFILE)

        # Register the decoders
        self.decoders = decmanager.DecoderManager()
        self.decoders.register()

        # Register the spoofers
        self.spoofers = spfmanager.SpooferManager()
        self.spoofers.register()

        # Add all options
        self.opt = Options()

        self.target1 = None
        self.target2 = None
        self.targetlist = ctx.targetlist = target.TargetList()
        self.iface = None
        self.original_mac = None
        self.network = None
        self.gateway = None
        self.injector = inject.Injector()
        self.discovery = discovery.Discovery()
        self.sniffer = sniff.Sniffer()
        self.filter = koala.KoalaFilter(self.decoders)

        # Initialize the user interface
        self.ui = ui.TextUI(self)

    def start(self):
        """
        Starts the whole thing
        """
        # Load spoofers and decoders
        if not self.opt.sniff.read:
            self.spoofers.load()
        self.decoders.load()

        # Starts the user interface
        self.ui.start()

    def show_summary(self):
        """
        Show a summary of the program status:
          -Spoofers and decoders successfuly loaded
          -Modules enabled (discovery, sniffer...)
        """
        spoof  = CStr(len(self.spoofers)).green if len(self.spoofers) > 0 else CStr(0).red
        decode = CStr(len(self.decoders)).green if len(self.decoders) > 0 else CStr(0).red
        disc = CStr("ON").green if self.discovery.active else CStr("OFF").red
        sniff = CStr("ON").green if self.sniffer.active else CStr("OFF").red
        summary = "[%s: %s - %s: %s - %s: %s - %s: %s]\n"%(CStr("spoofers").yellow,
                                                      spoof,
                                                      CStr("decoders").yellow,
                                                      decode,
                                                      CStr("discovery").yellow,
                                                      disc,
                                                      CStr("sniffer").yellow,
                                                      sniff)
        self.ui.user_msg(summary)

    def update_network(self):
        """
        Update the network details
        """
        if self.opt.core.use_mac:
            cfg = utils.get_iface(self.opt.core.iface)

            if cfg["inet"] is None:
                raise exceptions.EthercutException("Couldn't determine %s IP address, make sure it "+
                    "is connected and propertly configured")

            # Save the original mac to restore it later
            self.original_mac = cfg["hw"]
            self.ui.msg("Changing MAC address to: %s" %CStr(self.opt.core.use_mac).yellow)
            shell.Shell().change_mac(self.opt.core.iface, self.opt.core.use_mac)

        self.iface = link.Link(self.opt.core.iface)

        # Network
        self.network = network.Network(self.iface.ip, self.iface.netmask)

        # Try to find the network gateway
        gwip = self.opt.core.gateway or self.network.gateway
        gwhw = utils.arp_read(gwip)

        if gwip is None or gwhw is None:
            raise exceptions.EthercutException("Ethercut wasn't able to find the network gateway, "+
            "please check your network configuration")

        self.gateway = target.Target(gwip, gwhw)

        self.ui.msg("[%s] %s"%(CStr("IFACE").cyan, self.iface))
        self.ui.msg("[%s] %s" %(CStr("GATEWAY").cyan, repr(self.gateway)))

        # Update the context
        ctx.iface   = self.iface
        ctx.network = self.network
        ctx.gateway = self.gateway

    def update_targets(self):
        """
        Compile the target specifications and build the target list
        """
        self.targetlist.clear()
        self.target1 = self.opt.attack.target1
        self.target2 = self.opt.attack.target2

        # Add targets and bindings specified by the user with -T
        for t in self.opt.attack.targets:
            ip, mac, port = t
            if port:
                if mac: # Bind ports to MAC by default
                    if mac in self.target1:
                        self.target1.specific[mac] = port
                    if mac in self.target2:
                        self.target2.specific[mac] = port
                else: # Bind it to the ip
                    if ip in self.target1:
                        self.target1.specific[ip] = port
                    if ip in self.target2:
                        self.target2.specific[ip] = port

            if not self.opt.sniff.read:
                # Only add the target if it has mac and ip
                if (ip and mac and ip != self.gateway.ip and mac != self.gateway.mac and
                        ip != self.iface.ip and mac != self.iface.mac):
                    self.targetlist.append(target.Target(ip, mac, perm=True))

        if len(self.targetlist) > 0:
            self.ui.msg("Permanent targets:")
            for t in self.targetlist:
                self.ui.msg("\t%s"%repr(t))
        else:
            self.ui.msg("No permanent targets were added to the target list")

        ctx.targetlist = self.targetlist
        ctx.target1 = self.target1
        ctx.target2 = self.target2

    def shutdown(self):
        """
        Shuts the program down, terminate all daemons
        """
        self.ui.clean_exit()
