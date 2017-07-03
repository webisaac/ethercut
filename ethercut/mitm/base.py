# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Base class for all spoofers
"""

class _Spoofer_metaclass(type):
    def __new__(cls, name, supers, dct):
        if "__slots__" not in dct:
            dct["__slots__"] = []
        try:
            dct["_name"] = dct.pop("name")
        except KeyError:
            pass
        newcls = super(_Spoofer_metaclass, cls).__new__(cls, name, supers, dct)
        # Register the spoofer
        from ethercut.config import ethconf
        if "_name" in dct and dct["_name"]:
            ethconf.spooferlist.register(newcls, dct["_name"])
        elif name != "Spoofer":
            ethconf.spooferlist.register(newcls, name)
        return newcls

class Spoofer:

    __slots__ = [ "name", "spoofer", "running" ]

    __metaclass__ = _Spoofer_metaclass

    name = ""

    def __init__(self, spoofer):
        self.name = self._name if self._name else self.__class__.__name__
        self.spoofer = spoofer
        self.running = False

    def start(self):
        """
        Starts the spoofing activity
        """
        if self.running:
            return
        self.running = True
        self.spoofer.start()

    def stop(self):
        """
        Stops the spoofing activity
        """
        if not self.running:
            return
        self.running = False
        self.spoofer.end()
