# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Colored string (with ANSI escapes)
"""

from ethercut.const import DARWIN, LINUX

# COLORS
RED    = "\033[91m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
BLUE   = "\033[94m"
CYAN   = "\033[36m"
MAGENTA= "\033[95m"
WHITE  = "\033[97m"
GREY   = "\033[90m"
BLACK  = "\033[30m"

# Reset to default color
RESET  = "\033[0m"

name2color = { "RED"    : RED,
               "GREEN"  : GREEN,
               "YELLOW" : YELLOW,
               "BLUE"   : BLUE,
               "CYAN"   : CYAN,
               "MAGENTA": MAGENTA,
               "WHITE"  : WHITE,
               "GREY"   : GREY,
               "BLACK"  : BLACK,
             }

# Set this variable to False to disable colored output
COLORS_ON = True


class CStr(str):
    """
    Colored string
    """

    def __new__(cls, string):
        return str.__new__(cls, str(string))

    @property
    def red(self):
        if not COLORS_ON:
            return self
        return RED+self+RESET
    @property
    def green(self):
        if not COLORS_ON:
            return self
        return GREEN+self+RESET
    @property
    def yellow(self):
        if not COLORS_ON:
            return self
        return YELLOW+self+RESET
    @property
    def blue(self):
        if not COLORS_ON:
            return self
        return BLUE+self+RESET
    @property
    def cyan(self):
        if not COLORS_ON:
            return self
        return CYAN+self+RESET
    @property
    def magenta(self):
        if not COLORS_ON:
            return self
        return MAGENTA+self+RESET
    @property
    def white(self):
        if not COLORS_ON:
            return self
        return WHITE+self+RESET
    @property
    def grey(self):
        if not COLORS_ON:
            return self
        return GREY+self+RESET
    @property
    def black(self):
        if not COLORS_ON:
            return self
        return BLACK+self+RESET
    def custom(self, r, g, b):
        if not COLORS_ON:
            return self
        return ";".join([r,g,b])+self+RESET
    def bg(self, color):
        if not COLORS_ON:
            return self
        try:
            return name2color[color.upper()]+self+RESET
        except KeyError:
            raise ValueError("valid colors: RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, WHITE, GREY, BLACK")
    def custombg(self, r, g, b):
        if not COLORS_ON:
            return self
        return BG%";".join([r,g,b])+self+RESET
