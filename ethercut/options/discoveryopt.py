# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Target discovery options
"""


import ethercut.options.base as base



class DiscoveryOptions(base.OptionGroup):

    __slots__ = [ "profile" ]

    name = "discovery"

    def __init__(self):
        super(DiscoveryOptions, self).__init__()

        # Add arguments to parse
        self.add_arg("-P", "--disc-profile", help="Set the discovery profile [default: 2] (0: Disable"+
                     ", 1: Watch ARP table, 2: Initial Scan, 3: Passive Discovery, 4: Active Discovery)",
                     type=int, default=2, dest="discovery.profile", metavar="<profile>", choices=[0,1,2,3,4])
