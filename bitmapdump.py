#!/usr/bin/env python
# encoding: utf-8

__author__ = "SYA-KE"
__copyright__ = ""
__credits__ = ["SYA-KE"]
__license__ = "MIT"
__version__ = "1.0.0"
__maintainer__ = "SYA-KE"
__email__ = ""
__status__ = ""

import sys
import os

from scapy.plist import PacketList

def _bitmapdump(self, lfilter=None, banner=True, slice_bytes=0, charcode=True, delimiter=os.linesep):
    """Same as nsummary(), except that packets are also bitmapdumped
   lfilter: a truth function that decides whether a packet must be displayed
   banner: whether a packet banner must be displayed or not"""
    for i in range(len(self.res)):
        p = self._elt2pkt(self.res[i])
        if lfilter is not None and not lfilter(p):
            continue
        if banner:
            print "%s %s %s" % (conf.color_theme.id(i,fmt="%04i"),
            p.sprintf("%.time%"),self._elt2sum(self.res[i]))
        bitmapdump(p, s=slice_bytes, c=charcode, d=delimiter)

PacketList.bitmapdump = _bitmapdump

@conf.commands.register
def bitmapdump(x, s=0, c=True, d=""):
    """Draw psudo bitmap to xterm-256color"""
    indexcolor = [16+i for i in range(217)]+\
    [0,233,235,236,238,240,242,243,245,247,248,250,252,253,255,15]+\
    [7,8,1,5,2,6]+[0 for i in range(16)]+[231]
    x=str(x)
    l = len(x)
    p = sys.stdout.write
    for i,ch in enumerate(x,1):
        if s and i%s == 0:
            print ""
        p("\x1b[48;5;%02dm" % indexcolor[ord(ch)])
        if c:
            p(ord(ch) > 0x1F and ord(ch) < 0x7F and ch or ".")
        else:
            p(" ")
        p("\x1b[0m")
    print ""

if __name__ == "__main__":
    from scapy.main import interact
    from scapy.all import sniff
    my=sniff(prn=bitmapdump)
    interact(mydict=locals(),mybanner="***SYA-KE scapy!***")
