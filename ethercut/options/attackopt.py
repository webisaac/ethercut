# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Attack options
"""

import ethercut.utils as utils
import ethercut.net.target as target
import ethercut.options.base as base
import ethercut.exceptions as exceptions

from ethercut.config import ethconf
from ethercut.context import ctx
from ethercut.types.colorstr import CStr


class AttackOptions(base.OptionGroup):

    __slots__ = [ "_target1", "_target2", "_targets",
                  "kill", "_spoofers", "kill", "full_duplex",
                  "unoffensive" ]

    name = "attack"

    def __init__(self):
        base.OptionGroup.__init__(self)
        self.full_duplex = True

        # Get a default spoofer
        default_spoofer = None if len(ethconf.spooferlist.keys()) == 0 else ethconf.spooferlist.keys()[0]

        # Add arguments to parse
        self.add_hidden_arg("attack.target1", default=None, nargs="?")
        self.add_hidden_arg("attack.target2", default=None, nargs="?")
        self.add_arg("-T", "--target", help="Add specific targets to the program in the form IP/MAC/PORT. You can "+
                     "use this option to bind targets to specific ports aswell (e.g: 10.0.0.1//80 will bind 10.0.0.1 to "+
                     "port 80)", dest="attack.targets", metavar="<IP/MAC/PORT>")
        self.add_arg("-U", "--unoffensive", help="Don't filter the packets (use kernel's ip_forward)",
                     action="store_const", const=True, default=False, dest="attack.unoffensive")
        self.add_arg("-S", "--spoofers", dest="attack.spoofers", default=default_spoofer, metavar="<spoofers>",
                    help="Comma separated list of spoofers to perform a mitm attack [default: %s]"%(CStr("%(default)s").yellow)
                    +" Available: %s (\"*\" for all)" %self.available_spoofers())
        self.add_arg("--kill", help="Kill the connection of all targets (drop all packets)", action="store_const",
                    const=True, default=False, dest="attack.kill")
        self.add_arg("--half-duplex", help="Only spoof from TARGET1 to TARGET2", action="store_const",
                     dest="attack.full_duplex", const=False, default=True)


    @property
    def target1(self):
        return self._target1

    @target1.setter
    def target1(self, val):
        try:
            self._target1 = target.TargetSpec(val)
        except exceptions.EthercutException as e:
            raise exceptions.EthercutException("%s (TARGET1)"%str(e))

    @property
    def target2(self):
        return self._target2

    @target2.setter
    def target2(self, val):
        try:
            self._target2 = target.TargetSpec(val)
        except exceptions.EthercutException as e:
            raise EthercutException("%s (TARGET2)"%str(e))

    @property
    def targets(self):
        return self._targets

    @targets.setter
    def targets(self, val):
        targets = []
        if val is not None:
            for t in val.split(","):
                try:
                    ip, mac, port = t.split("/")
                    port = utils.expand_port(port)
                    if ip and not utils.is_ip(ip):
                        raise exceptions.EthercutException("Invalid IP address")
                    if mac and not utils.is_mac(mac):
                        raise exceptions.EthercutException("Invalid MAC address")
                    targets.append((ip, mac, port))
                except ValueError:
                    raise exceptions.EthercutException("Unexpected number of \"/\" (//)")
                except exceptions.EthercutException as e:
                    raise exceptions.EthercutException("%s in -T %s" %(str(e), t))
        self._targets = targets

    @property
    def spoofers(self):
        return self._spoofers

    @spoofers.setter
    def spoofers(self, val):
        spoofers = []
        if val:
            for s in val.split(","):
                if s == "*":
                    spoofers.append(s)
                    break
                elif s in ethconf.spooferlist:
                    spoofers.append(s)
                else:
                    raise exceptions.EthercutException("Invalid spoofer selected %s" %s)
        self._spoofers = spoofers

    def available_spoofers(self):
        ret = ", ".join(x for x in map(lambda x: CStr(x).green, ethconf.spooferlist.keys()))
        ret = ret or CStr("No spoofers available").red
        return ret
