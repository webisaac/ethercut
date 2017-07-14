# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license


import threading

_PROG_BAR_SZ = 30


class ProgressBar(object):
    """
    Progress bar, shows the percentage completed of a determined progressing task.

    E.G:
    SCANNING FOR 255 HOSTS: [##                            ]  04.00% completed

    +param: pmax - Value of the task when it is finished
    +param: task - Name of the task
    """

    __slots__ = [ "pmax", "curr", "done", "sz", "task", "_printer",
                  "updated" ]

    def __init__(self, pmax, printer=None, task="Running"):
        self.pmax = pmax
        self.curr = 0
        self.done = threading.Event()
        self.sz = _PROG_BAR_SZ
        self.task = task

        # Printer function
        pf = printer or self.default_print
        self._printer = threading.Thread(name="ProgressBar printer", target=self._waiter, args=(pf,))
        self.updated = threading.Event()

        self._printer.start()

    def _waiter(self, printer):
        """
        Waits for an update to print the current progress
        """
        while not self.done.isSet():
            ret = self.updated.wait(1)
            if ret:
                self.updated.wait()
                printer(self.__str__())
                self.updated.clear() # Clear the flag and wait for another update

    def update(self, val):
        """
        Updates the status of the progress bar
        """
        if val > self.pmax:
            raise ValueError("Value is higher than the max value specified: %s" %self.pmax)

        self.curr = val
        if self.pmax == self.curr:
            self.done.set()
        self.updated.set()

    def default_print(self, s):
        print s

    def __str__(self):
        # Get the percentage and the progress
        pct  = (self.curr * 100) / self.pmax
        prog = (self.sz * pct) / 100
        if int(prog) > 0 and prog*10 / int(prog) > 50:
            prog = int(prog) + 1
        else:
            prog = int(prog)

        return "%s: [%s%s] %%%.2f" %(self.task, "#"*prog, " "*(self.sz-prog), pct)
