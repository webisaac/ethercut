# coding: utf-8

# ETHERCUT SUITE
# Author: Ivan 'evilgroot' Luengo
# Email: evilgroot@gmail.com

# This project is released under a GPLv3 license

"""
Colored string (with ANSI escapes)
"""

# Foreground and background
FG = "\033[38;2;%sm"
BG = "\033[48;2;%sm"

# COLORS
RED    = "255;0;0"
GREEN  = "0;252;0"
YELLOW = "205;205;0"
BLUE   = "0;0;238"
CYAN   = "0;255;255"
MAGENTA= "205;0;205"
WHITE  = "255;255;255"
GREY   = "127;127;127"
BLACK  = "0;0;0"

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
        return str.__new__(cls, str(string)+RESET)
    @property
    def red(self):
        if not COLORS_ON:
            return self
        return FG%RED+self
    @property
    def green(self):
        if not COLORS_ON:
            return self
        return FG%GREEN+self
    @property
    def yellow(self):
        if not COLORS_ON:
            return self
        return FG%YELLOW+self
    @property
    def blue(self):
        if not COLORS_ON:
            return self
        return FG%BLUE+self
    @property
    def cyan(self):
        if not COLORS_ON:
            return self
        return FG%CYAN+self
    @property
    def magenta(self):
        if not COLORS_ON:
            return self
        return FG%MAGENTA+self
    @property
    def white(self):
        if not COLORS_ON:
            return self
        return FG%WHITE+self
    @property
    def grey(self):
        if not COLORS_ON:
            return self
        return FG%GREY+self
    @property
    def black(self):
        if not COLORS_ON:
            return self
        return FG%BLACK+self
    def custom(self, r, g, b):
        if not COLORS_ON:
            return self
        return FG%";".join([r,g,b])+self
    def bg(self, color):
        if not COLORS_ON:
            return self
        try:
            return FG%name2color[color.upper()]+self
        except KeyError:
            raise ValueError("valid colors: RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, WHITE, GREY, BLACK")
    def custombg(self, r, g, b):
        if not COLORS_ON:
            return self
        return BG%";".join([r,g,b])+self
