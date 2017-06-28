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
import ethercut.log         as log
import ethercut.sniff       as sniff
import ethercut.utils       as utils
import ethercut.context     as ctx
import ethercut.options     as options
import ethercut.net.link    as link
import ethercut.discovery   as discovery
import ethercut.exceptions  as exceptions
import ethercut.net.target  as target
import ethercut.net.inject  as inject
import ethercut.ui.text_ui  as ui
import ethercut.net.network as network
import ethercut.decodermanager as decmanager
import ethercut.spoofermanager as spfmanager

from ethercut.config import conf
from ethercut import NAME, PROGRAM, CONFILE, COPYRIGHT, AUTHOR
from ethercut.types.colorstr import CStr


class Master(object):

    name = NAME
    program = PROGRAM

    def __init__(self):
        # Get a default interface from pcap
        try:
            iface = pcap.lookupdev()
        except OSError:
            # Catch the exception, the user can still provide a working interface
            iface = None

        # Load configuration file
        conf.load(CONFILE)

        # Register the decoders
        self.decoders = decmanager.DecoderManager()
        self.decoders.register()

        # Register the spoofers
        self.spoofers = spfmanager.SpooferManager()
        self.spoofers.register()

        # Parse the program options
        self.opts = options.EthercutOptions(iface)
        self.opts.parse()
        self.opts.sanity_check() # Perform a sanity check on the options

        # Configure the logging subsystem
        if self.opts.core.log_file:
            handl = logging.FileHandler(self.opts.core.log_file, mode="w")
            handl.setFormatter(log.EthercutFormatter())
            log.log_ethcut.addHandler(handl)
            if self.opts.core.debug:
                log.log_ethcut.setLevel(logging.DEBUG)

        # Initialize network details

        self.iface = link.Link(self.opts.core.iface)
        self.original_mac = None
        if self.opts.core.use_mac:
            log.log_ethcut.debug("Changing mac address of %s to: %s" %(self.iface.name, self.opts.core.use_mac))
            self.original_mac = self.iface.mac
            self.shell.change_mac(self.iface.name, self.opts.core.use_mac)
            self.iface = link.Link(self.opts.core.iface)

        # Network
        self.network = network.Network(self.iface.ip, self.iface.netmask)

        # Try to find the network gateway
        if self.opts.core.gateway:
            gwip = self.opts.core.gateway
        else:
            gwip = self.network.gateway
        gwhw = utils.arp_read(gwip)
        if gwip is None or gwhw is None:
            raise exceptions.EthercutException("Ethercut wasn't able to find the network gateway")
        self.gateway = target.Target(gwip, gwhw)

        log.log_ethcut.debug("Compiling target specifications and building initial target list...")
        self.targetlist = target.TargetList()

        log.log_ethcut.debug("Target 1: %s" %self.opts.attack.target1)
        self.target1 = target.TargetSpec(self.opts.attack.target1)

        log.log_ethcut.debug("Target 2: %s" %self.opts.attack.target2)
        self.target2 = target.TargetSpec(self.opts.attack.target2)

        # Add targets and bindings specified by the user with -T
        for t in self.opts.attack.targets:
            ip, mac, port = t.split("/")
            port = utils.expand_port(port)
            if mac: # Bind ports to MAC by default
                if self.target1.all or self.target1.mac is None or mac in self.target1.mac:
                    self.target1.specific[mac] = port
                if self.target2.all or self.target2.mac is None or mac in self.target2.mac:
                    self.target2.specific[mac] = port
            elif ip: # Bind it to the ip
                if self.target1.all or self.target1.ip is None or ip in self.target1.ip:
                    self.target1.specific[ip] = port
                if self.target2.all or self.target2.ip is None or ip in self.target2.ip:
                    self.target2.specific[ip] = port
            else:
                log.log_ethcut.warning("Couldn't bind anything from %s" %t)

            # Only add the target if it has mac and ip
            if ip and mac and ip != self.gateway.ip and mac != self.gateway.mac:
                targ = target.Target(ip, mac, perm=True)
                self.targetlist.append(targ)
                log.log_ethcut.debug("Added permanent target to targetlist %s" %targ)

        # Initialize the user interface
        self.ui = ui.TextUI(self.opts.ui.verb)

        # Prepare the program context
        ctx.master = self
        ctx.opt    = self.opts
        ctx.iface  = self.iface
        ctx.network= self.network
        ctx.ui     = self.ui
        ctx.targetlist = self.targetlist
        ctx.target1 = self.target1
        ctx.target2 = self.target2
        ctx.gateway = self.gateway
        ctx.injector= self.injector = inject.Injector()
        ctx.sniffed_packets = self.sniffed_packets = Queue.Queue()

        # Initialize discovery and sniffer
        self.discovery = discovery.Discovery()
        self.sniffer = sniff.Sniffer()

    def start(self):
        """
        Starts the whole thing
        """
        # Start the UI
        self.ui.start()

        # Load spoofers and decoders
        log.log_ethcut.debug("Loading spoofers...")
        self.spoofers.load()
        log.log_ethcut.debug("Loading decoders...")
        self.decoders.load()

        self.show_summary()

        self.ui.user_msg("[%s] Attacking on: %s" %(CStr(self.iface.name).green, self.iface))
        self.ui.msg("[%s] %s\n" %(CStr("GATEWAY").green, repr(self.gateway)))
        self.ui.flush()
        self.injector.start()
        self.discovery.start()
        self.sniffer.start()
        self.spoofers.start_all()

    def shutdown(self):
        """
        Shuts the program down
        """
        self.ui.instant_msg("Shutting down, please wait...")
        self.spoofers.stop_all()
        self.discovery.stop()
        self.injector.stop()
        self.sniffer.end()

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
