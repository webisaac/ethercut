# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Darwin specific stuff
"""

import ethercut.shell as shell

############################
##  Kernel IP forwarding  ##
############################

def darwin_enable_forward():
    shell.Shell().execute("sysctl -w net.inet.ip.forwarding=1")

def darwin_disable_forward():
    shell.Shell().execute("sysctl -w net.inet.ip.forwarding=0")

def darwin_check_forward():
    shell.Shell().execute("sysctl net.inet.ip.forwarding ")[0].split(" ")[1]
