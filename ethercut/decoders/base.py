# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license


"""
Base classes for all decoders
"""

class _Decoder_metaclass(type):
    def __new__(cls, name, supers, dct):
        if "__slots__" not in dct:
            dct["__slots__"] = []
        try:
            dct["_name"] = dct.pop("name")
        except KeyError:
            pass
        from ethercut.config import ethconf
        # Resolve the ports
        try:
            dct["ports"] = ethconf.decoderports.pop(0)
        except IndexError:
            pass

        newcls = super(_Decoder_metaclass, cls).__new__(cls, name, supers, dct)
        try:
            # Register the decoder to make it available to the user
            ethconf.decoderlist.register(newcls, dct["_name"])
        except KeyError:
            pass

        return newcls

class Decoder:

    __slots__ = [ "name", "ports" ]

    __metaclass__ = _Decoder_metaclass

    ports = []

    def __init__(self):
        self.name = self._name or self.__class__.__name__

    def decode(self, packet):
        """
        Runs the packet through the filter and if it matches it, calls on_packet()
        """
        if not self.ports or packet.sport in self.ports or packet.dport in self.ports:
            if self.filter(packet):
                self.on_packet(packet)

    def on_packet(self, packet):
        """
        This function is applied to every packet that matches the filter
        """
        pass

    def filter(self, packet):
        """
        Use this function to check if the packet meets the requisites to be parsed.
        Must return True if it does meet them and False otherwise.
        """
        return True
