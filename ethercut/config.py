# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Ethercut configuration from ethcut.conf
"""


import ethercut.exceptions as exceptions

class ParserList(dict):
    """
    Registers a parser for a determined section
    """
    def register(self, parser):
        self[parser.__name__] = parser
        return parser # Return the parser to use this method as a decorator

class SpooferList(dict):
    def register(self, name, spoofer):
        self[name] = spoofer

class DecoderList(dict):
    def register(self, name, decoder):
        self[name] = decoder

class Config(object):
     # Parsed from configuration file
    parsers = ParserList()
    # SNIFFER
    snaplen = 65535
    promisc = False
    sniff_timeout = 0.1
    # SPOOFERS
    spoofermodules = []
    # DECODERS
    decodermodules = []
    # GEOIP
    geoipdb = ""

    # Configured at runtime
    spooferlist = SpooferList()
    decoderlist = DecoderList()

    def load(self, filename):
        """
        Loads a configuration file
        """
        ln = 1 # Line number
        section = None
        parser = None
        try:
            with open(filename, "r") as confile:
                for line in confile:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith("#"):
                        continue

                    if line.startswith("["): # New section
                        if not line.endswith("]"):
                            raise exceptions.EthercutException("Missing \"]\" in line %s of %s" %(ln, filename))
                        section = line[1:-1]
                        # Get the section parser
                        try:
                            parser = self.parsers[section]
                        except KeyError:
                            raise exceptions.EthercutException("Invalid section in line %s of %s"%(ln, filename))
                        continue

                    if not section:
                        raise exceptions.EthercutException("Entry out of a section in line %s of %s"
                                                                                            %(ln, filename))
                    # Trim comments
                    i = line.find("#")
                    if i >= 0:
                        line = line[:i]
                    try:
                        parser(self, line)
                    except AttributeError as e:
                        raise exceptions.EthercutException("Invalid entry in line %s of %s" %(ln, filename))
        except OSError:
            raise exceptions.EthercutException("Could't load configuration file %s" %confile)

#######################
##  Section parsers  ##
#######################

    @parsers.register
    def spoofers(self, entry):
        """
        Spoofers section, entry is the module where the spoofer is written
        """
        self.spoofermodules.append(entry)

    @parsers.register
    def sniff(self, entry):
        """
        Collect data for the sniffer
        """
        # Split the entry into field and value
        field, value = map(lambda x: x.strip(), entry.split("="))
        if field == "promisc": # Pcap complains if promisc is not boolean
            self.promisc = False if value == "0" else True
        else:
            self.__setattr__(field, type(field)(value))

    @parsers.register
    def decoders(self, entry):
        """
        Collect data from decoders
        """
        self.decodermodules.append(entry)

    @parsers.register
    def geoip(self, entry):
        """
        Collect data for the geoip2 module
        """
        field, value = [x.strip() for x in entry.split("=")]
        self.__setattr__(field, value)



conf = Config()
