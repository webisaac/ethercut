# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Class responsible of loading and managing the decoders
"""

import ethercut.context as ctx

from ethercut.config import conf


class SpooferManager(object):

    def __init__(self):
        self.spoofers = []

    def load(self):
        """
        Load all spoofers selected by the user and place them in the list
        """
        for s in ctx.opt.attack.spoofers:
            self.spoofers.append(conf.spooferlist[s]())

    def register(self):
        """
        This function will register all the spoofers specified in the configuration file
        """
        for x in map(lambda x: "ethercut.mitm.%s" %x, conf.spoofermodules):
            __import__(x, globals(), locals(), [], 0)

    def start_all(self):
        """
        Starts all the spoofers in the list
        """
        for s in self.spoofers:
            s.start()

    def stop_all(self):
        """
        Stop all the spoofers in the list
        """
        for s in self.spoofers:
            s.stop()

    def __iter__(self):
        return iter(self.spoofers)

    def __len__(self):
        return len(self.spoofers)
