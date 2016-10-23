#!/usr/bin/env python
# encoding: utf-8
 
#IPv6 over IPv4 は考えない
#IPv4 over IPv6 は考えないとすると
 
from scapy.all import *
def sniffCallback(pkt):
    if IP in pkt:
        print pkt[IP].src,"=>",pkt[IP].dst
    elif IPv6 in pkt:
        print pkt[IPv6].src,"=>",pkt[IPv6].dst
sniff(prn=sniffCallback)
#sniff(offline="TCP_example.cap",prn=sniffCallback)
#sniff(lfilter=lambda pkt:IP in pkt or IPv6 in pkt,prn=sniffCallback)
 
 
 
 
#20[16:52:48 root@dyske ~/caps]$ ./a.py
#WARNING: No route found for IPv6 destination :: (no default route?)
#192.168.1.8 => 8.8.8.8
#8.8.8.8 => 192.168.1.8
#^C21[16:52:55 root@dyske ~/caps]$
