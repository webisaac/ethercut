# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
User interface base class
"""

import Queue
from ethercut.ui.progressbar import ProgressBar
from ethercut import PROGRAM, COPYRIGHT, AUTHOR, VERSION, STATE

class UI(object):
    """
    Base class for a user interface.
    """

    def __init__(self):
        self.verb  = False
        self.queue = Queue.Queue()
        # Progress bar
        self.pbar = None
        # Banner and copyright
        self.copyright = "\n%s copyright © %s %s\n" % (PROGRAM, COPYRIGHT, AUTHOR)
        self.banner = self.get_banner() + self.copyright

    def user_msg(self, msg,  *args):
        """
        Pushes a message to the queue
        """
        pass

    def instant_msg(self, msg, *args):
        """
        Prints an inmediate message to the user
        """
        self.user_msg(msg, *args)
        self.flush()

    def msg(self, msg, *args):
        """
        Print a message only if the verbose flag is set
        """
        if self.verb:
            self.user_msg(msg, *args)

    def flush(self):
        """
        Prints all messages enqueued (and removes them from the queue)
        """
        pass

    def clear(self):
        """
        Clears the screen
        """
        pass

    def warning(self, msg, instant=False):
        """
        Prints a warning (immediatly if instant is True)
        """
        if instant:
            self.instant_msg(CStr("[W] "+msg).yellow)
        else:
            self.user_msg(CStr("[W] "+msg).yellow)

    def error(self, msg):
        """
        Prints an error message immediately
        """
        self.instant_msg(CStr("[E] "+msg).red)

    def progressbar(self, pmax, pname="Running"):
        """
        Creates a ProgressBar instance
        """
        if self.pbar:
            return # There is already a progress bar in course
        self.pbar = ProgressBar(pmax, pname)

    def update_progressbar(self, val):
        """
        Updates the progress bar state
        """
        pass

    def start(self):
        """
        Starts the user interface
        """
        pass

    def exit(self):
        """
        Clean exit for the ui
        """
        pass

    @staticmethod
    def get_banner():
        """
        Returns the banner as a string
        """
        s = ""
        with open("/media/ivan/8GB/gitproyects/ethercut/share/banner", "r") as f:
            for l in f:
                s+="%s"%l
        s = s.replace("%VERSION%", "v"+VERSION+" "+STATE)
        return s
