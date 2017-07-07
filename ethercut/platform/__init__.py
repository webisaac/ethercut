# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Platform dependencies
"""

from ethercut.const import LINUX, DARWIN


if LINUX:
    from ethercut.platform.linux import linux_enable_forward, linux_disable_forward, linux_check_forward
    enable_ip_forward = linux_enable_forward
    disable_ip_forward = linux_disable_forward
    check_ip_forward = linux_check_forward
elif DARWIN:
    from ethercut.platform.darwin import darwin_enable_forward, darwin_disable_forward, darwin_check_forward
    enable_ip_forward = darwin_enable_forward
    disable_ip_forward = darwin_disable_forward
    check_ip_forward = darwin_check_forward
