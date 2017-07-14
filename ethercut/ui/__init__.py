# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
User interface package
"""

import Queue
import sys, termios, time
import threading
import contextlib

import sys
sys.path.insert(0, "/media/ivan/8GB/gitproyects/ethercut")

from ethercut.context import ctx
from ethercut.types.colorstr import CStr
from ethercut.ui.progressbar import ProgressBar
from ethercut import PROGRAM, COPYRIGHT, AUTHOR, VERSION, STATE


#############################
##  ANSI escape sequences  ##
#############################

# Save and restore the cursor position
SAVEC = "\033[s"
RESTC = "\033[u"

# Erase from cursor to end of line
ERASE = "\033[K"

# Clear the screen
CLEAR = "\033[2J\033[H"

##########################
##  Text user interface ##
##########################

class TextUI(object):
    """
    Text based user interface
    """

    __slots__ = [ "quiet", "master", "progressbar",  "queue",
                  # Default terminal settings (will be restored at exit)
                  "old_tc",
                  # copyright notice and banner
                  "copyright", "banner",
                  # Thread synchronization
                  "_fblock", # Event flag to prevent threads to log messages while flushing
                  "_wrblock", # Writing block, when this event flag is cleared, only the thread which
                  "_pidblock" # pid matches _pidblock will be able to log messages, the rest will wait
                  ]

    copyright = "\n%s copyright © %s %s\n" % (PROGRAM, COPYRIGHT, AUTHOR)

    def __init__(self, master, quiet=False):
        self.quiet = quiet
        self.master = master
        self.progressbar =  None

        # Get the banner from the file
        self.banner = self.get_banner() + self.copyright

        # All the messages will be pushed into the queue, they will
        # be printed when flush() is called
        self.queue = Queue.Queue()

        # Event to synchronize output when a thread needs to log messages
        # without being mixed with other thread messages
        self._wrblock = threading.Event()
        self._wrblock.set()
        self._pidblock = None
        # Event to prevent threads to push messages into the queue while flushing
        self._fblock = threading.Event()
        self._fblock.set()

        self.instant_msg(CStr(self.banner).grey)

        # Disable terminal echoing and buffering

        fd = sys.stdin.fileno()

        # Save previous configuration and set a new one
        self.old_tc = termios.tcgetattr(fd)

        new = termios.tcgetattr(fd)
        new[3] &= ~(termios.ECHO | termios.ICANON)
        new[6][termios.VTIME] = 1
        termios.tcsetattr(fd, termios.TCSANOW, new)

        # Register the User interface in the context
        ctx.ui = self

    def user_msg(self, msg, nl=True):
        """
        Push a message into the queue
        """
        if not self._wrblock.isSet() and self._pidblock != threading.current_thread().ident:
            self._wrblock.wait()
        self._fblock.wait()
        # Use the EARSE sequence to wipe the previous text
        s = "%s%s" %(ERASE, msg)
        if nl: # Add the newline
            s += "\n"
        self.queue.put(s)

    def instant_msg(self, msg, nl=True):
        """
        Prints a user message instantly, flushes the queue just right
        after pushing the message into the queue.
        """
        self.user_msg(msg, nl)
        self.flush()

    def msg(self, msg, nl=True):
        """
        Push a message into the queue only if quiet attribute is False
        """
        if not self.quiet:
            self.user_msg(msg, nl)

    def flush(self):
        """
        Print all the queued messages
        """
        # XXX - We need to prevent other threads to log messages while flushing
        # the current queue
        self._fblock.clear()
        while not self.queue.empty():
            msg = self.queue.get()
            sys.stdout.write(msg)
        self._fblock.set()

    def clear(self):
        """
        Clears the Terminal screen
        """
        # Flush the queue and clear the screen
        self.flush()
        sys.stdout.write(CLEAR)

    @contextlib.contextmanager
    def block(self):
        """
        Use this function as a context manager to prevent other threads to push messages
        in the queue.
        """
        # Wait in case other thread is blocking the ui
        self._wrblock.wait()
        # Clear the block event and get the current thread pid
        self._wrblock.clear()
        self._pidblock = threading.current_thread().ident

        yield
        # Set the event and reset the pid
        self._wrblock.set()
        self._pidblock = None

    @staticmethod
    def get_banner():
        """
        Returns the banner as a string
        """
        s = ""
        with open("/media/ivan/8GB/gitproyects/ethercut/share/banner", "r") as f:
        #with open("/Volumes/8GB/gitproyects/ethercut/share/banner", "r") as f:
            for l in f:
                s+="%s"%l
        s = s.replace("%VERSION%", "v"+VERSION+" "+STATE)
        return s

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

        ######## End of startup ########

        ######## UI Loop ########

        while True:

            inp = sys.stdin.read(1)

            if inp == "h":
                self.help()

            if inp == "q":
                print "Shutting down..."
                break

        #########################

    def help(self):
        """
        Displays the user interface action keys
        """
        with self.block():
            self.user_msg("")
            self.user_msg("\t[ %s ]" %CStr("Help").blue)
            self.user_msg(" [q] Exit the program")
            self.user_msg(" [h] Shows this help screen")
            self.user_msg("")
            self.flush()

    @contextlib.contextmanager
    def progress(self, pmax, task="Progress"):
        """
        This context manager will create a progress bar
        """

        def print_bar(bar):
            self.instant_msg(CStr("\n%s\033[2A"%bar).grey)

        progressbar = ProgressBar(pmax, print_bar, task)
        try:

            yield progressbar

        except KeyboardInterrupt:
            pass
        finally:
            # If an exception has occurred, we have to make sure the progressbar
            # doesn't block
            progressbar.done.set()
            progressbar = None
            self.instant_msg("\033[1A")

    def error_msg(self, msg):
        """
        Prints an error message instantly
        """
        self.instant_msg("[%s] %s" %(CStr("ERROR").red, msg))

    def clean_exit(self):
        """
        Performs the necesary clean-up before terminating the user interface
        """
        # If a CTRL-C was requested, a thread may be waiting some flag to be set
        self._wrblock.set()
        self._fblock.set()

        # Flush all pending messages
        self.flush()
        print ""

        # Restore previous terminal settings
        fd = sys.stdin.fileno()
        termios.tcsetattr(fd, termios.TCSANOW, self.old_tc)
