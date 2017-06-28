# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Shell command execution
"""

import subprocess

import ethercut.log       as log
import ethercut.platform  as platform
import ethercut.exceptions as exceptions


class Shell:
    """
    Class responsible of executing various shell commands and providing support for
    various OS (Linux, OSX).
    """

    def execute(self, cmd):
        """
        Executes a shell command and returns it's output as a tuple (outdata, errdata).

        Commands must be a single string containing the whole command:
            - "netstat -nr | grep en0"
        Or a list of arguments (the first argument is the name of the command):
            -["netstat", "-nr", "|", "grep", "en0"]

        See: https://docs.python.org/2/library/subprocess.html#subprocess.Popen
        for more info.
        """
        # Check the sanity of the command
        if isinstance(cmd, basestring):
            orig = cmd
            cmd = cmd.split()
        elif type(cmd, list):
            orig = " ".join(cmd)
        else:
            raise ValueError("cmd must be either a string or list of arguments")

        log.log_ethcut.debug("Running command \"%s\"" %orig)

        # The shell Pipeline must be treated specially
        try:
            if "|" in cmd:
                g1 = []
                for i, c in enumerate(cmd):
                    g2 = cmd[i+1:]
                    if "|" == c:
                        break
                    g1.append(c)
                p1 = subprocess.Popen(g1, stdout=subprocess.PIPE)
                p2 = subprocess.Popen(g2, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                p1.stdout.close() # Allow p1 to receive a SIGPIPE if p2 exits
                out = p2.communicate()
            else:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out = p.communicate()

            if out[1]: # Show command errors in debug mode
                log.log_ethcut.debug("Returned an error: %s" %out[1][:-1])
            return out
        except OSError as e:
            raise exceptions.EthercutException("Error executing %s", orig)

    def ifconfig(self, opts=""):
        """
        Executes ifconfig with opts as the command options
        """
        return self.execute("ifconfig "+opts)

    def netstat(self, opts=""):
        """
        Executes netstat with opts as the command options
        """
        return self.execute("netstat "+opts)

    def arp(self, opts=""):
        """
        Executes arp with opts as the command options
        """
        return self.execute("arp "+opts)

    def change_mac(self, iface, new):
        """
        Uses ifconfig to change the mac of iface. Supports OSX and Linux systems
        """
        if platform.DARWIN:
            self.ifconfig(iface+" ether "+new)
        elif platform.LINUX:
            self.ifconfig(iface+" hw ether "+new)
