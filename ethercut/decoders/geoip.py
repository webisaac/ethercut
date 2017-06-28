# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
GeoDecoder: Looks up for globl IPs on a database and prints their location
"""

import ethercut.exceptions as exceptions
try:
    import geoip2.database
except ImportError:
    raise exceptions.EthercutException("geoip2 not available, GeoIP parser won't be laoded")

import ethercut.context as ctx
import ethercut.decoders.base as base

from ethercut.config import conf
from ethercut.types.colorstr import CStr
from scapy.layers.inet import IP


class GeoDecoder(base.Decoder):

    __slots__ = [ "reader", "known" ]

    name = "GEO"

    def __init__(self):
        super(GeoDecoder, self).__init__(filter=self.filter_func)
        self.reader = geoip2.database.Reader(conf.geoipdb)
        self.known = [] # List of known global IP addresses

    @staticmethod
    def filter_func(packet):
        if packet.haslayer(IP):
            return True
        else:
            return False

    def on_packet(self, packet):
        globl = None
        src = packet[IP].src
        dst = packet[IP].dst
        if src not in ctx.network:
            globl = src
            addresses = "%s >> "+dst
        elif dst not in ctx.network:
            globl = dst
            addresses = src+" >> %s"

        # Only global IP addresses can have location
        if not globl:
            return

        if globl not in self.known:
            self.known.append(globl)
            # Tries to read the location from the database
            try:
                response = self.reader.city(globl)
            except geoip2.errors.AddressNotFoundError:
                message = "Address not in database"
                globl = CStr(globl).red
            else:
                globl = CStr(globl).green
                message = "%s, %s. Lat: %s, Long: %s" %(response.subdivisions.most_specific.name,
                                                        response.country.name,
                                                        response.location.latitude,
                                                        response.location.longitude)
            ctx.ui.user_msg("[%s] %s [%s]"% (CStr(self.name).green,
                                             addresses%globl,
                                             message))
