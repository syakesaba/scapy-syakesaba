#!/usr/bin/env python
# -*- coding: utf-8 -*-
from scapy.all import *
from scapy.utils import *

from espeak import espeak#apt-get install espeak python-espeak

load_contrib('http')

def f(p):
 l=p.lastlayer()
 if isinstance(l,Raw) or 'Option' in l.name:
  l=l.underlayer
 espeak.synth(l.name)
 return

sniff(lfilter=lambda p:not espeak.is_playing(),prn=f)
