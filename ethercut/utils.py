# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Miscellaneous utility functions
"""

import socket
import re, struct
import ethercut.shell as shell
import ethercut.const as const
import ethercut.exceptions as exceptions


##########################
##  Address validators  ##
##########################

def is_ip(ip):
    """
    Returns True if ip is a legal IP address.
    """
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except (socket.error, TypeError):
        return False

def is_ip6(ip6):
    """
    Returns True if ip6 is a legal IP6 address.
    """
    try:
        socket.inet_pton(socket.AF_INET6, ip6)
        return True
    except (socket.error, TypeError):
        return False

_MAC_ADDR_REGEX = "([0-9A-Fa-f]{1,2}\:){5}[0-9A-Fa-f]{1,2}"
def is_mac(x):
    """
    Returns True if x is a valid MAC address.
    """
    return x and re.match(_MAC_ADDR_REGEX, x) is not None

def normalize(x):
    """
    Normalizes a network address.

    +param:  x - address to normalize

    NOTE: Currently only supports mac addresses.
    """
    if is_mac(x):
        return x.lower()
    raise ValueError("x must be a valid mac address: %s" %x)


#####################
##  Vendor lookup  ##
#####################

def vendor_lookup(mac):
    """
    Looks up in the vendor-list file for the manufacturer
    """
    if mac:
        try:
            with open("/usr/share/ethercut/vendor-list") as f:
                for l in f:
                    l = l.strip()
                    if not l or l.startswith("#"):
                        continue
                    if not l.startswith(mac.upper()[:8]):
                        continue
                    oui, shrt = l.split()[:2]
                    i = l.find("#")
                    if i < 0:
                        lng = shrt
                    else:
                        lng = l[i+2:]
                    ret = shrt, lng
                    break
                else:
                    ret = "Unknown", "Unknown"
            return ret
        except IOError as err:
            pass
    return None, None

###########################
##  Address conversions  ##
###########################

def aton(x):
    """
    Converts an IPv4 address in dotted form (x.x.x.x) to a network byte order integer
    """
    if is_ip(x):
        sa = socket.inet_pton(socket.AF_INET, x)
        return struct.unpack(">I", sa)[0]
    raise ValueError("x must be valid IP address")

def ntoa(x):
    """
    Converts a network byte order integer to an IP address in dotted form (x.x.x.x)
    """
    return socket.inet_ntop(socket.AF_INET, struct.pack(">I", x))

#########################
##  Address expansion  ##
#########################

def expand_mac(mac):
    """
    Returns a list of mac addresses by expanding the parameter mac
    """
    if not mac:
        ret = None
    else:
        ret = []
        macs = mac.split(",")
        for m in macs:
            try:
                if not is_mac(m):
                    raise ValueError()
                ret.append(m)
            except ValueError:
                raise exceptions.EthercutException("Invalid mac address \"%s\"" %m)

        # Remove repeated macs
        ret = list(set(ret))

    return ret

def expand_ip(ip):
    """
    Returns a list of ip addresses by expanding the parameter ip
    """
    if not ip:
        ret = None
    else:
        ret = []
        ips = ip.split(";") # Split individual ip addresses
        for i in ips:
            try:
                if "-" in i: # Expand range
                    if "," in i: # Ranges don't support ","
                        raise ValueError()

                    first, last = i.split("-")
                    fnet = aton(first)
                    last = ".".join(first.split(".")[:-1]) + ".%s" %last
                    lnet = aton(last)

                    for x in xrange(fnet, lnet+1):
                        ret.append(ntoa(x))

                elif "," in i: # Expand individual ips
                    if "-" in i: # Individual ips don't support ranges
                        raise ValueError()

                    lst = i.split(",")
                    ipaddr = lst[0]
                    if not is_ip(ipaddr):
                        raise ValueError()

                    # Get the prefix (x.x.x)
                    pref = ".".join(ipaddr.split(".")[:-1])
                    # Get the suffixes
                    sufx = map(int, [ipaddr.split(".")[-1]] + lst[1:])
                    for s in sufx:
                        if s > 255:
                            raise ValueError()
                        ret.append(pref+".%s" %s)

                else:
                    if not is_ip(i):
                        raise ValueError()
                    ret.append(i)

            except ValueError:
                raise exceptions.EthercutException("Invalid ip/range \"%s\"" %i)

            # Remove repeated ips
            ret = list(set(ret))

    return ret

def expand_port(port):
    """
    Returns a list of ports by expanding the parameter port
    """
    if not port: # "" means all ports
        ret = None
    else:
        ret = []
        ports = port.split(",") # Split individual ports
        for p in ports:
            try:
                if "-" in p: # Expand range ports
                    first, last = map(int, p.split("-"))
                    if last < first: # Bad range, first must be smaller
                        raise ValueError()

                    for i in xrange(first, last+1):
                        if i < 0 or i > 65535: # Port out of range
                            raise exceptions.EthercutException("Port out of range (0-65535) \"%s\"" %p)
                        ret.append(i)
                else:
                    intp = int(p)
                    if intp < 0 or intp > 65535: # Port out of range
                        raise exceptions.EthercutException("Port out of range (0-65535) \"%s\"" %p)
                    ret.append(intp)

            except ValueError:
                raise exceptions.EthercutException("Invalid port/range \"%s\"" %p)


        # Remove repeated ports
        ret = list(set(ret))
    return ret

#######################
##  Address parsing  ##
#######################

def arp_read(addr):
    """
    Reads the arp cache for a concrete address mac or ip address and returns the other one(*).
    Returns None if addr is not in the cache.

    (*)if addr is IP -> returns its MAC/ if addr is MAC -> returns its IP.
    """
    cache = shell.Shell().arp("-na")[0]
    cache = cache.split("\n")
    for l in cache:
        if re.search(addr, l):
            if is_ip(addr):
                return l.split()[3]
            if is_mac(addr):
                return l.split()[1][1:-1] # Skip parentheses
            else:
                raise ValueError("addr must be either a valid IP or MAC address")
    return None

def get_iface(iface):
    """
    Returns a dictionary containing relevant information about a given intreface parsing the
    output of ifconfig.
    Information will be stored as a dictionary as follows:
        {"iface": {"hw": "00:00:00:00:00:00", "inet": "192.168.2.37", ...}}
            hw: hardware address
            inet: IPv4 address
            bcast: broadcast address
            netmask: network mask
            inet6: IPv6 address
            mtu: maximum transmission unit

    NOTE: Currently only handles Linux ifconfig output
    """

    # Run ifconfig
    ifcnf = shell.Shell().ifconfig(iface)
    if not ifcnf[0]:
        raise ValueError("%s" %ifcnf[1])

    cnf = ifcnf[0].split("\n")

    ret = {"hw": None, "inet": None, "bcast": None, "netmask": None, "inet6": None, "mtu": None}

    if const.LINUX:
        for line in cnf:
            m = re.search("HWaddr[\s]+([0-9A-Fa-f]{1,2}\:){5}[0-9A-Fa-f]{1,2}", line)
            if m:
                ret["hw"] = m.group().split()[1]
            m = re.search("inet addr:[\s]*([0-9]{1,3}.){3}[0-9]{1,3}", line)
            if m:
                ret["inet"] = m.group()[10:].strip()
            m = re.search("Bcast:[\s]*([0-9]{1,3}.){3}[0-9]{1,3}", line)
            if m:
                ret["bcast"] = m.group()[6:].strip()
            m = re.search("Mask:[\s]*([0-9]{1,3}.){3}[0-9]{1,3}", line)
            if m:
                ret["netmask"] = m.group()[5:].strip()
            m = re.search("inet6 addr:[\s]*[0-9a-fA-F:]+/[0-9]+", line)
            if m:
                ret["inet6"] = m.group()[11:].strip()
            m = re.search("MTU:[\s]*[0-9]+", line)
            if m:
                ret["mtu"] = m.group()[4:].strip()
    elif const.DARWIN:
        for line in cnf:
            m = re.search("ether[\s]+([0-9A-Fa-f]{1,2}\:){5}[0-9A-Fa-f]{1,2}", line)
            if m:
                ret["hw"] = m.group().split()[1]
            m = re.search("inet[\s]([0-9]{1,3}.){3}[0-9]{1,3}", line)
            if m:
                ret["inet"] = m.group().split()[1].strip()
            m = re.search("broadcast[\s]([0-9]{1,3}.){3}[0-9]{1,3}", line)
            if m:
                ret["bcast"] = m.group().split()[1].strip()
            m = re.search("netmask[\s]0x[0-9a-f]{8}", line)
            if m:
                # In OSX, the netmask is in hex format, we need to change it to a dotted address
                netmask = int(m.group().split()[1].strip(), 0)
                ret["netmask"] = ntoa(netmask)
            m = re.search("inet6[\s][0-9a-fA-F:]+/[0-9]+", line)
            if m:
                ret["inet6"] = m.group().split()[1].strip()
            m = re.search("mtu[\s][0-9]+", line)
            if m:
                ret["mtu"] = m.group().split()[1].strip()

    return ret


##############################
##  File related functions  ##
##############################

def get_default_file(name, fmt=""):
    """
    Used for producing default file names
    """
    i = 0
    path = "%s%0.2d%s"
    while True:
        try:
            f = open(path %(name,i,fmt), "r")
            f.close()
            i += 1
        except IOError as e:
            if e.errno == 2: # No such file or directory
                return path %(name,i,fmt)
