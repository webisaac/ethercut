# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Text based user interface
"""

import sys, time
import ethercut.ui.base as base
import ethercut.platform as platform

from ethercut.context import ctx
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

    def __init__(self, master):
        super(TextUI, self).__init__()
        self.instant_msg(CStr(self.banner).grey)
        self.master = master
        ctx.ui = self
        self.verb = True

    def start(self):
        self.user_msg("Welcome to ethercut, have fun and don't be evil!\n")

        ########  Ethercut configuration phase  ########

        self.msg("[ %s ]"%CStr("Modules loaded").green)

        loaded = ", ".join(CStr(x.name).yellow for x in self.master.spoofers)
        self.msg("Loaded %s spoofer%s [%s]" %(len(self.master.spoofers),
                                                    "" if len(self.master.spoofers) == 1 else "s",
                                                    loaded))
        loaded = ", ".join(CStr(x.name).yellow for x in self.master.decoders)
        self.msg("Loaded %s decoder%s [%s]" %(len(self.master.decoders),
                                                    "" if len(self.master.decoders) == 1 else "s",
                                                    loaded))
        self.msg("")
        self.flush()

        self.msg("[ %s ]"%CStr("Network parameters").green)
        if not self.master.opt.sniff.read:
            self.master.update_network()
            self.master.injector.configure()
        else:
            self.msg("No network parameters needed while reading form a file")

        self.msg("")
        self.flush()

        self.msg("[ %s ]"%CStr("TARGETs compiled").green)
        self.master.update_targets()
        self.msg("")
        self.flush()

        self.msg("[ %s ]"%CStr("Sniffer").green)
        self.master.sniffer.configure()
        self.msg("")
        self.flush()

        self.msg("[ %s ]" %CStr("Koala filter").green)
        self.master.filter.configure()
        self.msg("")
        self.flush()

        self.msg("[ %s ]" %CStr("Target discovery manager").green)
        self.master.discovery.configure()
        self.msg("")
        self.flush()

        ######## End of configuration phase ########

        ######## Ethercut startup!! ########

        print "Starting ethercut in 2...",
        sys.stdout.flush()
        time.sleep(1)
        print "1...",
        sys.stdout.flush()
        time.sleep(1)
        print "NOW!"
        self.clear()
        self.instant_msg(CStr(self.banner).grey)
        self.master.injector.start()
        self.master.discovery.start()
        self.master.sniffer.start()
        self.master.filter.start()
        self.master.spoofers.start_all()

    def clean_exit(self):
        self.instant_msg("Shutting down, please wait...") # Flush all messages
        self.master.discovery.stop()
        self.master.spoofers.stop_all()
        self.master.injector.stop()
        self.master.sniffer.end()
        self.master.filter.stop()
        self.user_msg("Filter stats:")
        self.user_msg("%s" %self.master.filter.stats)
        self.flush()

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
