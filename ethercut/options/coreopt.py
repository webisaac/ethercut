# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Core options
"""

import pcap
import ethercut.log as log
import ethercut.utils as utils
import ethercut.options.base as base
import ethercut.types.colorstr as cstr
import ethercut.exceptions as exceptions

from ethercut import VERSION
from ethercut.context import ctx

class CoreOptions(base.OptionGroup):

    __slots__ = [ "_iface", "_gateway", "_use_mac", "default_log" ]

    name = "core"

    # Default log file
    default_log = utils.get_default_file("ethercut_log", ".log")

    def __init__(self):
        base.OptionGroup.__init__(self)

        try:
            iface = pcap.lookupdev()
        except OSException:
            iface = None

        # Add arguments to parse
        self.add_arg("-i", "--interface", help="Use <iface> as our network interface [default: %s]" %cstr.CStr(iface).yellow,
                    dest="core.iface", metavar="<iface>", default=iface)
        self.add_arg("-m", "--change-mac", help="Change the interface mac address for <mac> before starting the attack",
                    dest="core.use_mac", metavar="<mac>")
        self.add_arg("-g", "--gateway", help="Use <gateway> as the network gateway address", dest="core.gateway",
                    metavar="<gateway>")
        #self.add_arg("--log-file", metavar="<logfile>", nargs="?", dest="core.log_file",
        #help="Log the messages in <logfile> [default: %s]"%cstr.CStr(self.default_log).yellow,
        #            const=self.default_log)
        #self.add_arg("-D", "--debug", help="Print debug messages (will enable logging)", dest="core.debug", action="store_const",
        #             const=True, default=False)
        self.add_arg("--no-colors", help="Disable colored output", dest="core.color", action="store_const",
                     const=False, default=True)
        # Version and help
        self.add_arg("-v", "--version", action="version", version="%s" %VERSION,
                        help="Show program's version number and exit")
        self.add_arg("-h", "--help", action="help", help="Show this message and exit")


    @property
    def iface(self):
        return self._iface

    @iface.setter
    def iface(self, val):
        if val is None:
            raise exceptions.EthercutException("Ethercut wasn't able to find a suitable network interface, "+
                "please check your network configuration")
        else:
            self._iface = val

    @property
    def use_mac(self):
        return None if not self._use_mac else self._use_mac.lower()

    @use_mac.setter
    def use_mac(self, val):
        if val is not None:
            if not utils.is_mac(val):
                raise exceptions.EthercutException("Invalid mac address sepcified as argument -m \"%s\"" %val)
        self._use_mac = val

    @property
    def gateway(self):
        return self._gateway

    @gateway.setter
    def gateway(self, val):
        if val is not None:
            if not utils.is_ip(val):
                raise exceptions.EthercutException("Invalid gateway address specified as argument -g \"%s\"" %val)
        self._gateway = val

    @property
    def color(self):
        return cstr.COLORS_ON

    @color.setter
    def color(self, val):
        cstr.COLORS_ON = val
