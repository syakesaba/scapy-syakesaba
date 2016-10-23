#!/usr/bin/env python
# encoding: utf-8

# Sample Simple script using http.py
# See https://github.com/invernizzi/scapy-http

from scapy.all import *
load_contrib("http")
import socket


dnscache = {}
def resolvIP(ip):
    try:
        if ip in dnscache:
            return dnscache[ip]
        host = socket.gethostbyaddr(ip)[0]
        dnscache.update({ip:host})
        return host
    except:
        return ip

def printCookie(pkt,resolv=True):
    l3 = pkt[TCP].underlayer
    print
    if resolv:
        print resolvIP(l3.src),"===================>",resolvIP(l3.dst)
    else:
        print l3.src,"===================>",l3.dst
    print pkt.Cookie,
    print

cookieFilter = lambda pkt: HTTPRequest in pkt and "Cookie" in pkt[HTTPRequest].fields


if __name__ == "__main__":
    sniff(iface="eth1",lfilter=cookieFilter,prn=printCookie)
