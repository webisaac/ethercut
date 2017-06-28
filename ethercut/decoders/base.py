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
        newcls = super(_Decoder_metaclass, cls).__new__(cls, name, supers, dct)
        # Register the decoder
        from ethercut.config import conf
        if "_name" in dct and dct["_name"]:
            conf.decoderlist.register(dct["_name"], newcls)
        elif name != "Decoder":
            conf.decoderlist.register(name, newcls)
        return newcls

class Decoder:

    __slots__ = [ "name", "filter" ]

    __metaclass__ = _Decoder_metaclass

    name = ""

    def __init__(self, filter):
        self.name = self._name if self._name else self.__class__.__name__
        self.filter = filter

    def decode(self, packet):
        """
        Runs the packet through the filter and if it matches it, calls on_packet()
        """
        if self.filter(packet):
            self.on_packet(packet)

    def on_packet(self, packet):
        """
        This function is applied to every packet that matches the filter
        """
        pass
