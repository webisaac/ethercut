# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Ethercut configuration from ethcut.conf
"""

import ethercut.utils as utils
import ethercut.exceptions as exceptions
import ethercut.types.reglist as reglist


class EtherConfig(object):
    """
Ethercut configuration:

snaplen:  Snapshot len for sniffing pcap stream
sniff_timeout : Pcap timeout in sniffing thread
spoofermodules: Spoofer modules to be registered
decodermodules: Decoder modules to be registered
geoip_database: Path to Maxmind's database
    """
     # Parsed from configuration file
    __parsers = reglist.RegList()
    # SNIFFER
    snaplen = 65535
    sniff_timeout = 1
    # SPOOFERS
    spoofermodules = []
    # DECODERS
    decodermodules = []
    decoderports = []
    # GEOIP
    geoip_database = ""
    # Packet injector
    inject_workers = 4
    inject_timeout = 0.0

    # Configured at runtime
    spooferlist = reglist.RegList()
    decoderlist = reglist.RegList()

    def load(self, filename):
        """
        Loads a configuration file
        """
        ln = 0 # Line number
        section = None
        parser = None
        try:
            with open(filename, "r") as confile:
                for line in confile:
                    ln += 1
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
                            parser = self.__parsers[section]
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
                        line = line.strip()
                    try:
                        parser(self, line)
                    except AttributeError as e:
                        raise exceptions.EthercutException("Invalid entry in line %s of %s" %(ln, filename))
                    except exceptions.EthercutException as e:
                        raise exceptions.EthercutException("%s in line %s of %s"%(str(e), ln, filename))
        except OSError:
            raise exceptions.EthercutException("Could't load configuration file %s" %confile)

#######################
##  Section parsers  ##
#######################

    @__parsers.register
    def spoofers(self, entry):
        """
        Spoofers section, entry is the module where the spoofer is written
        """
        self.spoofermodules.append(entry)

    @__parsers.register
    def sniff(self, entry):
        """
        Collect data for the sniffer
        """
        # Split the entry into field and value
        field, value = map(lambda x: x.strip(), entry.split("="))
        self.__setattr__(field, type(self.__getattribute__(field))(value))

    @__parsers.register
    def decoders(self, entry):
        """
        Collect data from decoders
        """
        field, value = map(lambda x: x.strip(), entry.split("="))
        self.decodermodules.append(field)
        # Important! decoders will be loaded in the same order they are written in the conf file
        ports = None if value.lower() == "none" else utils.expand_port(value)
        self.decoderports.append(ports)


    @__parsers.register
    def geoip(self, entry):
        """
        Collect data for the geoip2 module
        """
        field, value = [x.strip() for x in entry.split("=")]
        self.__setattr__(field, value)



ethconf = EtherConfig()
