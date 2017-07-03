# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Sniffing options
"""

import ethercut.utils as utils
import ethercut.options.base as base
import ethercut.exceptions as exceptions

from ethercut.config import ethconf
from ethercut.types.colorstr import CStr

class SniffOptions(base.OptionGroup):

    __slots__ = [ "sniff", "_read", "_write", "filter", "_promisc",
                  "_decoders" ]

    name = "sniff"

    def __init__(self):
        super(SniffOptions, self).__init__()

        # Add arguments to parse
        self.add_arg("-s", "--sniff", help="Enables the sniffing module", dest="sniff.sniff", action="store_const",
                        const=True, default=False)
        default_file = utils.get_default_file("ethercut_cap", ".pcap")
        self.add_arg("-w", "--write-packets", help="Dump all sniffed packets in pcapfile <file> [default:%s]"
                    % CStr(default_file).yellow, metavar="<file>", nargs="?", dest="sniff.write", const=default_file)
        self.add_arg("-r", "--read-packets", help="Read packets from pcapfile <file> (will enable -s)", metavar="<file>",
                    nargs="?", dest="sniff.read")
        self.add_arg("-f", "--pcapfilter", help="Set this pcap filter <filter>", metavar="<filter>",
                    dest="sniff.filter", default="")
        self.add_arg("-p", "--promisc", help="Put the interface in promiscuous mode", dest="sniff.promisc",
                    action="store_const", const=True, default=False)
        self.add_arg("-d", "--decoder", help="Comma separated list of packet decoders to enable [default: %s]"
                    %CStr("None").yellow + " Available: %s (\"*\" for all)" %self.available_decoders(),
                    dest="sniff.decoders", default=[], metavar="<decoders>")

    @property
    def write(self):
        return self._write

    @write.setter
    def write(self, val):
        if val: # There isn't much sense to write in a file something that is already stored in a file...
            self._read = False
            self._promisc = False
            self.sniff = True
        self._write = val

    @property
    def read(self):
        return self._read

    @read.setter
    def read(self, val):
        if val: # Same as for write ;)
            self._write = False
            self._promisc = False
            self.sniff = True
        self._read = val

    @property
    def promisc(self):
        return self._promisc

    @promisc.setter
    def promisc(self, val):
        self._promisc = True if val and not (self.read or self.write) else False

    @property
    def decoders(self):
        return self._decoders

    @decoders.setter
    def decoders(self, val):
        decoders = []
        if val:
            for s in val.split(","):
                if s == "*":
                    decoders.append(s)
                    break
                elif s in ethconf.decoderlist:
                    decoders.append(s)
                else:
                    raise exceptions.EthercutException("Invalid decoder selected %s" %s)
        self._decoders = decoders

    @staticmethod
    def available_decoders():
        ret = ", ".join(CStr(x).green for x in ethconf.decoderlist)
        ret = ret or CStr("No decoders available").red
        return ret
