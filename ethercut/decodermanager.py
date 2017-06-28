# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Class responsible of loading and managing the decoders
"""

import ethercut.context as ctx
import ethercut.exceptions as exceptions

from ethercut.config import conf


class DecoderManager(object):

    def __init__(self):
        self.chain = []

    def load(self):
        """
        Load all decoders selected by the user and place them in the chain
        """
        for d in ctx.opt.sniff.decoders:
            if d == "*":
                self.chain = map(lambda x: x(), conf.decoderlist.values())
                break
            else:
                try:
                    self.chain.append(conf.decoderlist[d]())
                except exceptions.EthercutException as e:
                    ctx.ui.warning(e.msg)

    def register(self):
        """
        Register all the decoders that will be available to the user to select
        """
        for x in map(lambda x: "ethercut.decoders.%s"%x, conf.decodermodules):
            __import__(x, globals(), locals(), [], 0)

    def decode(self, packet):
        """
        Starts the decoder chain and passes the packet through all decoders
        """
        for d in self.chain:
            d.decode(packet)
            ctx.ui.flush()  # Flushes all the messages printed by the decoders

    def __iter__(self):
        return iter(self.chain)

    def __len__(self):
        return len(self.chain)
