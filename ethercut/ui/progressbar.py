# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

_PROG_BAR_SZ = 30

class ProgressBar(object):
    """
    Progress bar, shows the percentage completed of a determined progressing task.

    E.G:
    SCANNING FOR 255 HOSTS: [##                            ]  04.00% completed

    +param: pmax - Value of the task when it is finished
    +param: task - Name of the task
    """

    def __init__(self, pmax, task="Running"):
        self.pmax = pmax
        self.curr = 0
        self.complete = False
        self.sz = _PROG_BAR_SZ
        self.task = task

    def update(self, val):
        """
        Updates the status of the progress bar
        """
        self.curr = val
        if self.curr > self.pmax:
            raise ValueError("New value is higher than the max value specified (%s)"%self.pmax)

        pct  = (self.curr * 100) / self.pmax # Get the percentage
        prog = (self.sz * pct) / 100 # Get the progress
        if int(prog) > 0 and prog*10 / int(prog) > 50:
            prog = int(prog) + 1
        else:
            prog = int(prog)

        self.percentage = pct
        self.progress = prog
        self.complete = self.pmax == self.curr

    def __str__(self):
        s = "%s: [%s%s] %.2f" %(self.task, "#"*self.progress, " "*(self.sz-self.progress), self.percentage)
        return s+"% completed"
