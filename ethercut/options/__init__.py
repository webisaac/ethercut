# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Program options package
"""

from ethercut.context import ctx
from ethercut.options.base import option_groups, global_parser

__all__ = [ "Options", "coreopt", "attackopt", "sniffopt",
            "discoveryopt" ]

##################################
##  Program options base class  ##
##################################

class Options(object):

    def __init__(self):
        self.parser = global_parser
        # Set the proper usage message and description
        self.parser.usage = "%(prog)s [options] [TARGET1] [TARGET2]"
        self.parser.description = "TARGET1 and TARGET2 are specified as IP/MAC/PORT (use // for all hosts)"
        self._groups = {}
        for k, v in option_groups.iteritems():
            self._groups[k] = v()

        ctx.opt = self

    def parse(self):
        """
        Parse the program options
        """
        self.parser.parse_args(namespace=self)
        # Set context values
        self.set()

    def set(self):
        """
        Performs the sanity check for all options and then set context values
        """
        for group in self._groups.values():
            group.set()

    def __getattr__(self, attr):
        if attr in self._groups:
            return self._groups[attr]
        else:
            raise AttributeError("No such group: %s" %attr)

    def __setattr__(self, attr, val):
        if "." in attr: # To make the namespace accessible to the members specified in "dest"
            mem, attr = attr.split(".")
            mem = getattr(self, mem)
            mem.__setattr__(attr, val)
        else:
            object.__setattr__(self, attr, val)
