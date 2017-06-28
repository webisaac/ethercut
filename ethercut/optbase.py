# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license


"""
Base classes for program options
"""

import argparse


class _CustomFormatter(argparse.HelpFormatter):
    """
    This subclass of argparse.HelpFormatter will display the output of the help text
    as -s, --long METAVAR instead of -s METAVAR, --long METAVAR
    It will also increase the max_help_position and width for a nicer output
    """
    def __init__(self, prog):
        argparse.HelpFormatter.__init__(self, prog, max_help_position=45, width=127)

    def _format_action_invocation(self, action):
        if not action.option_strings:
            metavar, = self._metavar_formatter(action, action.dest)(1)
            return metavar
        else:
            parts = []
            # If the Optional doesn't take a value, format is:
            #   -s, --long
            if action.nargs == 0:
                parts.extend(action.option_strings)
            else:
                default = action.dest.upper()
                args_string = self._format_args(action, default)
                for option_string in action.option_strings:
                    parts.append("%s" %option_string)
                parts[-1] += " %s" %args_string
            return ", ".join(parts)

_customformatter = lambda prog: _CustomFormatter(prog)
_global_parser = argparse.ArgumentParser(usage="%(prog)s [options]", conflict_handler="resolve",
                                 formatter_class=_customformatter)

###############################
##  Option group base class  ##
###############################

class BaseOptionGroup(object):

    __slots__ = [ "name", "_parser" ]

    def __init__(self, name="Base Options"):
        self.name = name
        self._parser = _global_parser.add_argument_group(title=name)

    def add_arg(self, *args, **kargs):
        """
        Calls add_argument() to add an argument to the group
        """
        self._parser.add_argument(*args, **kargs)

    def add_hidden_arg(self, *args, **kargs):
        """
        Adds an argument that won't show up in the help display
        """
        self._parser.add_argument(help=argparse.SUPPRESS, *args, **kargs)

    def sanity_check(self):
        """
        If a subclass needs to perform sanity checks to the arguments, it should override this
        method.
        """
        pass


##################################
##  Program options base class  ##
##################################

class BaseProgramOpts(object):

    def __init__(self, usg="%(prog)s [options]", desc=None):
        self.parser = _global_parser
        # Set the proper usage message and description
        self.parser.usage = usg
        self.parser.description = desc
        self._groups = {}

    def add_group(self, name, grp):
        self._groups[name] = grp


    def parse(self):
        """
        Parse the program options
        """
        self.parser.parse_args(namespace=self)

    def sanity_check(self):
        """
        Performs the sanity check for all options
        """
        for group in self._groups.values():
            group.sanity_check()

    def __getattr__(self, attr):
        if attr in self._groups:
            return self._groups[attr]
        else:
            raise AttributeError("No such group: %s" %attr)

    def __setattr__(self, attr, val):
        if "." in attr: # To make the namespace accessible to the members specified in "dest"
            mem, attr = attr.split(".")
            mem = getattr(self, mem)
            mem.__setattr__(attr, val)
        else:
            object.__setattr__(self, attr, val)
