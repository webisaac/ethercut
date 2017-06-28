# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Ticker: Special kind of basethread, this thread will call a function every amount seconds
"""

import threading
import ethercut.types.basethread as basethread

class Ticker(basethread.BaseThread):

    def __init__(self, ts, function, name="Ticker thread", *args):
        super(Ticker, self).__init__(name)
        self.ts = ts
        self.function = function
        self.args = args if args is not None else []
        self.event = threading.Event()

    def run(self):
        """
        Call function every ts seconds in a non-blocking way
        """
        self.event.clear() # Make sure the flag is cleared
        self.function(*self.args)
        while self.running:
            self.event.wait(self.ts)
            if not self.event.isSet():
                self.function(*self.args)

    def end(self, join=True):
        if not self.running:
            return
        self.running = False
        self.event.set()
        if join:
            threading.Thread.join(self) # Wait for the thread to exit cleanly
