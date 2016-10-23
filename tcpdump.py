#!/usr/bin/env python
# encoding: utf-8
from scapy.all import *
conf.color_theme = scapy.themes.DefaultTheme()
sniff(prn=repr)
