# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Register list: A subclass of a dictionary that allows to register
functions using register() as a decorator
"""

class RegList(dict):
    def register(self, item, lookup=None):
        if lookup is not None:
            self[lookup] = item
        else:
            try:
                self[item.__name__] = item
            except AttributeError:
                raise ValueError("Item to be registered must have a __name__ method if no lookup is specified")
        return item # Return the item so this method can be used as a decorator
