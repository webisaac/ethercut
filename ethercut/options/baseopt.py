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
global_parser = argparse.ArgumentParser(usage="%(prog)s [options]", conflict_handler="resolve",
                                 formatter_class=_customformatter)

# To register all option groups
option_groups = {}

###############################
##  Option group base class  ##
###############################

class _OptionGroup_metaclass(type):
    def __new__(cls, name, base, dct):
        try:
            dct["_name"] = dct.pop("name")
        except KeyError:
            pass
        newcls = type.__new__(cls, name, base, dct)
        # Register the class
        if "_name" in dct:
            option_groups[dct["_name"]] = newcls
        return newcls

class OptionGroup:

    __slots__ = [ "name", "_parser" ]

    __metaclass__ = _OptionGroup_metaclass

    def __init__(self):
        self.name = self._name
        self._parser = global_parser.add_argument_group(title=self.name.upper())

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

    def set(self):
        """
        Set some context values from the options
        """
        pass
