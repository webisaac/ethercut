# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Logging subsystem
"""

import logging

class EthercutFormatter(logging.Formatter):
    """
    Subclass of Formatter from logging module to print the messges with a custom format.
    """

    error_fmt = "[E] %(msg)s"
    warn_fmt  = "[W] %(msg)s"
    debug_fmt = "[D] %(msg)s"
    info_fmt  = "[I] %(msg)s"

    def __init__(self, fmt="[%(levelno)s] %(msg)s"):
        super(EthercutFormatter, self).__init__(fmt)

    def format(self, record):
        orig = self._fmt

        # Replace the original format with a custom one depending of the log level
        if record.levelno == logging.DEBUG:
            self._fmt = self.debug_fmt
        elif record.levelno == logging.INFO:
            self._fmt = self.info_fmt
        elif record.levelno == logging.WARNING:
            self._fmt = self.warn_fmt
        elif record.levelno == logging.ERROR:
            self._fmt = self.error_fmt

        # Call the superclass format method to format the message
        ret = super(EthercutFormatter, self).format(record)

        # Restore the original _fmt
        self._fmt = orig

        return ret
