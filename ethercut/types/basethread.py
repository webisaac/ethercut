# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Base class for Ethercut threads
"""

import threading


# Lock to synchronize the threads
thread_lock = threading.Lock()

class BaseThread(threading.Thread):

    def __init__(self, name="Ethercut Thread"):
        super(BaseThread, self).__init__(name=name)
        self.running = False
        self.lock    = thread_lock
        self.daemon  = True  # Every thread will be a daemon

    def start(self):
        """
        Start the thread's activity
        """
        if self.running: # Prevent the thread from starting twice
            return
        self.running = True
        threading.Thread.start(self) # Call the Thread's start method

    def run(self):
        """
        Main thread activity.
        Every subclass should implement its own run() method!
        """
        raise NotImplementedError

    def end(self, join=True):
        """
        Terminate the thread's activity by clearing the "running" flag
        """
        if not self.running: # Prevent from joining a thread when it is not active
            return
        self.running = False
        if join:
            threading.Thread.join(self) # Wait until the thread exits cleanly
