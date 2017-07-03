# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Linux specific stuff
"""

############################
##  Kernel IP forwarding  ##
############################

def linux_enable_forward():
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")

def linux_disable_forward():
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("0")
def linux_check_forward():
    with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
        return f.read()
