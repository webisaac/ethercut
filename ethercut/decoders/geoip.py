# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
GeoDecoder: Looks up for global_ip IPs on a database and prints their location
"""

import ethercut.exceptions as exceptions
try:
    import geoip2.database
except ImportError:
    raise exceptions.EthercutException("geoip2 not available, GeoIP parser won't be laoded")

import ethercut.decoders.base as base
import ethercut.net.network as network

from ethercut.context import ctx
from ethercut.config import ethconf
from ethercut.types.colorstr import CStr


class GeoDecoder(base.Decoder):

    __slots__ = [ "reader", "known", "priv_net" ]

    name = "GEO"

    # Private networks
    priv_net = [ network.Network("10.0.0.0", "255.0.0.0"),
                 network.Network("172.16.0.0", "255.240.0.0"),
                 network.Network("192.168.0.0", "255.255.0.0"),
                 network.Network("169.254.0.0", "255.255.0.0") ]

    def __init__(self):
        super(GeoDecoder, self).__init__()
        self.reader = geoip2.database.Reader(ethconf.geoip_database)
        self.known = [] # List of known global IP addresses

    def on_packet(self, packet):
        global_ip = None
        src = packet.payload.src
        dst = packet.payload.dst
        for n in self.priv_net:
            if src in n:
                break
        else:
            global_ip = src
            addresses = "%s >> "+dst

        if not global_ip:
            for n in self.priv_net:
                if dst in n:
                    break
            else:
                global_ip = dst
                addresses = src+" >> %s"

        # Only global IP addresses can have location
        if not global_ip:
            return

        if global_ip not in self.known:
            self.known.append(global_ip)
            # Tries to read the location from the database
            try:
                response = self.reader.city(global_ip)
            except geoip2.errors.AddressNotFoundError:
                message = "Address not in database"
                global_ip = CStr(global_ip).red
            else:
                global_ip = CStr(global_ip).green
                message = "%s, %s. Lat: %s, Long: %s" %(response.subdivisions.most_specific.name,
                                                        response.country.name,
                                                        response.location.latitude,
                                                        response.location.longitude)
            ctx.ui.user_msg("[%s] %s [%s]"% (CStr(self.name).green,
                                             addresses%global_ip,
                                             message))
