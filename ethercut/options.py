# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Program options from argparse
"""

from ethercut import VERSION
import ethercut.utils as utils
import ethercut.exceptions as exceptions
import ethercut.optbase as optbase
import ethercut.types.colorstr as cstr
from ethercut.config import conf

########################
##  Ethercut options  ##
########################

class EthercutOptions(optbase.BaseProgramOpts):

    desc = """
    TARGET1 and TARGET2 are specified as IP/MAC/PORT (use // for all hosts)
    """

    def __init__(self, iface):
        super(EthercutOptions, self).__init__(usg="%(prog)s [options] TARGET1 TARGET2",
                                              desc = self.desc)
        self.add_group("core", EthercutCoreOpt(iface))
        self.add_group("attack", EthercutAttackOpt())
        self.add_group("discovery", EthercutDiscoveryOpt())
        self.add_group("ui", EthercutUIOpt())
        self.add_group("sniff", EthercutSniffOpt())

class EthercutCoreOpt(optbase.BaseOptionGroup):

    __slots__ = [ "iface", "use_mac", "gateway",
                  "debug", "log_file", "default_log" ]

    # Default log file
    default_log = utils.get_default_file("ethercut_log", ".log")

    def __init__(self, iface):
        super(EthercutCoreOpt, self).__init__("Core")
        # Option initialization
        self.iface   = iface
        self.use_mac = None
        self.gateway = None
        self.log_file= None
        self.debug   = None

        # Add arguments to parse
        self.add_arg("-i", "--interface", help="Use <iface> as our network interface [default: %s]" %cstr.CStr(self.iface).yellow,
                    dest="core.iface", metavar="<iface>", default=self.iface)
        self.add_arg("-m", "--change-mac", help="Change the interface mac address for <mac> before starting the attack",
                    dest="core.use_mac", metavar="<mac>")
        self.add_arg("-g", "--gateway", help="Use <gateway> as the network gateway address", dest="core.gateway",
                    metavar="<gateway>")
        self.add_arg("-L", "--log-file", metavar="<logfile>", nargs="?", dest="core.log_file",
                    help="Log the messages in <logfile> [default: %s]"%cstr.CStr(self.default_log).yellow,
                    const=self.default_log)
        self.add_arg("-D", "--debug", help="Print debug messages (will enable logging)", dest="core.debug", action="store_const",
                     const=True, default=False)

        # Version and help
        self.add_arg("-v", "--version", action="version", version="%s" %VERSION,
                        help="Show program's version number and exit")
        self.add_arg("-h", "--help", action="help", help="Show this message and exit")

    def sanity_check(self):
        # Validate the interface
        if not self.iface:
            raise exceptions.EthercutException("Ethercut wasn't able to find a suitable network interface")
        # Validate the mac address
        if self.use_mac:
            if not utils.is_mac(self.use_mac):
                raise exceptions.EthercutException("Invalid mac address sepcified as argument \"%s\"" %self.use_mac)
        # Validate the gateway address
        if self.gateway:
            if not utils.is_ip(self.gateway):
                raise exceptions.EthercutException("Invalid gateway address \"%s\". It must be a valid IPv4 address"
                                                                                                    %self.gateway)
        if self.debug:
            if not self.log_file:
                self.log_file = utils.get_default_file("ethercut_log", ".log")


class EthercutAttackOpt(optbase.BaseOptionGroup):

    __slots__ = [ "target1", "target2", "cut", "unoffensive", "targets", "spoofers",
                  "full_duplex" ]

    def __init__(self):
        super(EthercutAttackOpt, self).__init__("Attack")
        self.cut     = None
        self.target1 = None
        self.target2 = None
        self.targets = None
        self.spoofers = None
        self.full_duplex = True
        self.unoffensive = None

        # Add arguments to parse
        self.add_hidden_arg("attack.target1", default="//")
        self.add_hidden_arg("attack.target2", default="//")
        self.add_arg("-T", "--target", help="Add specific targets to the program in the form IP/MAC/PORT. You can "+
                     "use this option to bind targets to specific ports aswell (e.g: 10.0.0.1//80 will bind 10.0.0.1 to "+
                     "port 80)", dest="attack.targets", metavar="<IP/MAC/PORT>")
        self.add_arg("-C", "--cut", help="Cut the connection of all targets (drop all packets)", action="store_const",
                    const=True, default=False, dest="attack.cut")
        #self.add_arg("-U", "--unoffensive", help="Don't filter the packets (use kernel's ip_forward)",
                    #action="store_const", const=True, default=False, dest="attack.unoffensive")
        self.add_arg("-M", "--mitm", dest="attack.spoofers", default="ARP", metavar="<spoofer>",
                    help="Comma separated list of <spoofer> to perform a mitm attack [default: %s]"%cstr.CStr("ARP").yellow
                    +" Available: %s (\"*\" for all)" %self.available_spoofers())

    def sanity_check(self):
            t1 = self.target1.split("/")
            if len(t1) != 3:
                raise exceptions.EthercutException("Unexpected number of \"/\" in TARGET1 (//): %s" %self.target1)
            t2 = self.target2.split("/")
            if len(t2) != 3:
                raise exceptions.EthercutException("Unexpected number of \"/\" in TARGET2 (//): %s" %self.target2)

            if not self.targets:
                self.targets = []
            else:
                tgts = self.targets.split(",")
                for t in tgts:
                    try:
                        ip, mac, port=t.split("/")
                        if ip and not utils.is_ip(ip):
                            raise ValueError
                        if mac and not utils.is_mac(mac):
                            raise ValueError
                    except ValueError:
                        raise exceptions.EthercutException("Invalid target in -T (IP/MAC/PORT): %s" %t)
                self.targets = tgts

            spflist = []
            for s in self.spoofers.split(","):
                if s == "*":
                    self.spoofers = ["*"]
                    break
                else:
                    if s not in conf.spooferlist:
                        raise exceptions.EthercutException("Invalid spoofer selected %s" %s)
                    spflist.append(s)
            self.spoofers = spflist

    def available_spoofers(self):
        ret = ", ".join(x for x in map(lambda x: cstr.CStr(x).green, conf.spooferlist.keys()))
        return ret


class EthercutDiscoveryOpt(optbase.BaseOptionGroup):

    __slots__ = [ "profile" ]

    def __init__(self):
        super(EthercutDiscoveryOpt, self).__init__("Discovery")
        self.profile = None

        # Add arguments to parse
        self.add_arg("-P", "--disc-profile", help="Set the discovery profile [default: 2] (0: Disable"+
                     ", 1: Watch ARP table, 2: Initial Scan, 3: Passive Discovery, 4: Active Discovery)",
                     type=int, default=2, dest="discovery.profile", metavar="<profile>")


class EthercutUIOpt(optbase.BaseOptionGroup):

    __slots__ = [ "color", "verb" ]

    def __init__(self):
        super(EthercutUIOpt, self).__init__("User Interface")
        self.color = True
        self.verb  = True

        # Add arguments to parse
        self.add_arg("--no-colors", help="Don't use colored output", action="store_const", const=False,
                    default=True, dest="ui.color")
        self.add_arg("-q", "--quiet", help="Print less output", action="store_const", const=False,
                    default=True, dest="ui.verb")

    def sanity_check(self):
        cstr.COLORS_ON = self.color # Set/Disable colored output

class EthercutSniffOpt(optbase.BaseOptionGroup):

    __slots__ = [ "sniff", "read", "write", "filter", "promisc",
                  "decoders" ]

    def __init__(self):
        super(EthercutSniffOpt, self).__init__("Sniffing")
        self.sniff = False
        self.read  = None
        self.write = None
        self.filter= ""
        self.promisc = False
        self.decoders = ""

        # Add arguments to parse
        self.add_arg("-s", "--sniff", help="Enables the sniffing module", dest="sniff.sniff", action="store_const",
                        const=True, default=False)
        default_file = utils.get_default_file("ethercut_cap", ".pcap")
        self.add_arg("-w", "--write-packets", help="Dump all sniffed packets in pcapfile <file> [default:%s]"
                    % cstr.CStr(default_file).yellow, metavar="<file>", nargs="?", dest="sniff.write", const=default_file)
        self.add_arg("-r", "--read-packets", help="Read packets from pcapfile <file> (will enable -s)", metavar="<file>",
                    nargs="?", dest="sniff.read")
        self.add_arg("-f", "--pcapfilter", help="Set this pcap filter <filter>", metavar="<filter>",
                    dest="sniff.filter", default="")
        self.add_arg("-p", "--promisc", help="Put the interface in promiscuous mode", dest="sniff.promisc",
                    action="store_const", const=True, default=False)
        self.add_arg("-d", "--decoder", help="Comma separated list of <decoder> packet decoders [default: %s]"
                    %cstr.CStr("NONE").yellow + " Available: %s (\"*\" for all)" %self.available_decoders(),
                    dest="sniff.decoders", default="", metavar="<decoder>")

    def available_decoders(self):
        ret = ", ".join(cstr.CStr(x).green for x in conf.decoderlist.keys())
        return ret

    def sanity_check(self):
        if self.write or self.read or self.promisc:
            self.sniff = True

        dclist = []
        for d in self.decoders.split(","):
            if d == "*":
                self.decoders = ["*"]
                break
            else:
                if d not in conf.decoderlist:
                    raise exceptions.EthercutException("Invalid decoder selected %s" %d)
                dclist.append(d)
        self.decoders = dclist
