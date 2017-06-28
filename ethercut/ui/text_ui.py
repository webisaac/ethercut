# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Text based user interface
"""

import sys
import ethercut.ui.base as base

from ethercut.types.colorstr import CStr


# Escape sequences
ESC = "\033["

# Save and restore cursor position
SAVEC = ESC+"s"
RESTC = ESC+"u"

# Erase to end of line
ERASE = ESC+"K"

# Clear the screen
CLEAR = "%s2J%sH"%(ESC, ESC)

#####################
##  Text based UI  ##
#####################

class TextUI(base.UI):
    """
    Text based user interface
    """

    def __init__(self, verb=True):
        super(TextUI, self).__init__(verb)

    def start(self):
        self.clear()
        self.instant_msg(CStr(self.banner).grey)

    def user_msg(self, msg):
        s = "%s%s\n" %(ERASE, msg)
        self.queue.put(s)

    def flush(self):
        while not self.queue.empty():
            msg = self.queue.get()
            sys.stdout.write(msg)

    def clear(self):
        # Flush the queue and clear the screen
        self.flush()
        sys.stdout.write(CLEAR)

    def update_progressbar(self, val):
        if not self.pbar:
            return
        self.pbar.update(val)

        self.instant_msg(CStr("\n"+str(self.pbar)+ESC+"2A").grey)

        # If the progress has finished, discard the progressbar
        if self.pbar.complete:
            self.pbar = None
            self.instant_msg(ESC+"1B")
