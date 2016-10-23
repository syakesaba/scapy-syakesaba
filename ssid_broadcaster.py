#!/usr/bin/env python
# encoding: utf-8

"""
    -*- coding: utf-8 -*-
    inject.py
    Provided by Package: eapeak

    Author: Spencer McIntyre <smcintyre [at] securestate [dot] com>

    Copyright 2011 SecureState

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
    MA 02110-1301, USA.


    modified by sya-ke
"""

from struct import pack, unpack
from random import randint
from time import sleep
import threading
from scapy.sendrecv import sniff
from scapy.sendrecv import sendp
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11Elt

def getHwAddr(ifname):                                    # Return the MAC address associated with a network interface, available only on Linux
    """
    Return the MAC address associated with a network interface, available only on Linux
    """
    from socket import socket, AF_INET, SOCK_DGRAM
    from fcntl import ioctl
    from struct import pack
    s = socket(AF_INET, SOCK_DGRAM)
    info = ioctl(s.fileno(), 0x8927,  pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

PRIVACY_NONE = 0
PRIVACY_WEP = 1
PRIVACY_WPA = 2

class SSIDBroadcaster(threading.Thread):
    """
    This object is a thread-friendly SSID broadcaster
    It's meant to be controlled by the Wireless State Machine
    """
    def __init__(self, interface, essid, bssid = None,\
                beacon_interval=0.15,channel=6,priv=PRIVACY_NONE):
        threading.Thread.__init__(self)
        self.interface = interface
        self.essid = essid
        if bssid is None:
            bssid = getHwAddr(interface)
        self.bssid = bssid.lower()
        self.broadcast_interval = beacon_interval
        self.channel = "\x06"
        self.setPrivacy(PRIVACY_NONE)
        self.sequence = randint(1200, 2000)

    def shutdown(self):
        self.__shutdown__ = True

    def run(self):
        """
        This is the thread routine that broadcasts the SSID.
        """
        self.__shutdown__ = False
        while not self.__shutdown__:
            if self.beacon.getlayer(Dot11).SC >= 0xFFF:
                self.beacon.getlayer(Dot11).SC = 1
            else:
                self.beacon.getlayer(Dot11).SC += 1
            sendp(self.beacon, iface=self.interface, verbose=False)
            sleep(self.broadcast_interval)

    def setBeacon(self, beacon):
        self.beacon = beacon

    def setWEP(self):
        WEPBIT=0x1000

    def setPrivacy(self, value):
        """
        Configure the privacy settings for None, WEP, and WPA
        """
        if value == PRIVACY_NONE:
            self.beacon = \
RadioTap()/\
Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/\
Dot11Beacon(cap='ESS+short-preamble+short-slot')/\
#
Dot11Elt(ID="SSID",info=self.essid)/\
Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/\
Dot11Elt(ID="DSset",info=self.channel)/\
Dot11Elt(ID=42, info="\x04")/\
Dot11Elt(ID=47, info="\x04")/\
Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
        elif value == PRIVACY_WEP:
            self.beacon = \
RadioTap()/\
Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/\
Dot11Beacon(cap='ESS+privacy+short-preamble+short-slot')/\
Dot11Elt(ID="SSID",info=self.essid)/\
Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/\
Dot11Elt(ID="DSset",info=self.channel)/\
Dot11Elt(ID=42, info="\x04")/\
Dot11Elt(ID=47, info="\x04")/\
Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
        elif value == PRIVACY_WPA:
            self.beacon = \
RadioTap()/\
Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/\
Dot11Beacon(cap='ESS+privacy+short-preamble+short-slot')/\
Dot11Elt(ID="SSID",info=self.essid)/\
Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/\
Dot11Elt(ID="DSset",info=self.channel)/\
Dot11Elt(ID=221, info="\x00\x50\xf2\x01\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x01")/\
Dot11Elt(ID=42, info="\x00")/\
Dot11Elt(ID=50, info="\x30\x48\x60\x6c")/\
Dot11Elt(ID=221, info="\x00\x50\xf2\x02\x01\x01\x84\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00")

    def sendBeacon(self):
        """
        Convenience function for sending beacons without starting a thread
        """
        self.beacon.getlayer(Dot11).SC = self.__unfuckupSC__()
        sendp(self.beacon, iface=self.interface, verbose=False)

    @staticmethod
    def sendBeaconEx(essid, interface, privacy = PRIVACY_NONE, bssid = None, channel = 6):
        """
        Convenience function for sending beacons without a thread or creating an instance
        """
        if not bssid:
            bssid = getHwAddr(interface)
        channel = chr(channel)
        sequence = randint(1200, 2000)
        if privacy in [PRIVACY_NONE, 'none', 'NONE']:
            beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid, SC=sequence)/Dot11Beacon(cap='ESS+short-preamble+short-slot')/Dot11Elt(ID="SSID",info=essid)/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
        elif privacy in [PRIVACY_WEP, 'wep', 'WEP']:
            beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid, SC=sequence)/Dot11Beacon(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID",info=essid)/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
        elif privacy in [PRIVACY_WPA, 'wpa', 'WPA']:
            beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid, SC=sequence)/Dot11Beacon(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID",info=essid)/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=channel)/Dot11Elt(ID=221, info="\x00\x50\xf2\x01\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x01")/Dot11Elt(ID=42, info="\x00")/Dot11Elt(ID=50, info="\x30\x48\x60\x6c")/Dot11Elt(ID=221, info="\x00\x50\xf2\x02\x01\x01\x84\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00")
        else:
            raise Exception('Invalid privacy setting')
        sendp(beacon, iface=interface, verbose=False)

if __name__ == "__main__":
    import sys
    print "Starting SSID Broadcaster...AUTH=NONE"
    b=SSIDBroadcaster(interface="wlan0", essid="ESSID", bssid=None)
    b.start()
    raw_input("Press Enter:::")
    b.__shutdown__ = True
    print "waiting for thread die"
    while b.isAlive():
        pass
    del b

    print "Starting SSID Broadcaster...AUTH=WEP"
    b=SSIDBroadcaster(interface="wlan0", essid="ESSID", bssid=None)
    b.setPrivacy(PRIVACY_WEP)
    b.start()
    raw_input("Press Enter:::")
    b.__shutdown__ = True
    print "waiting for thread die"
    while b.isAlive():
        pass
    del b

    print "Starting SSID Broadcaster...AUTH=WPA"
    b=SSIDBroadcaster(interface="wlan0", essid="ESSID", bssid=None)
    b.setPrivacy(PRIVACY_WPA)
    b.start()
    raw_input("Press Enter:::")
    b.__shutdown__ = True
    print "waiting for thread die"
    while b.isAlive():
        pass
    del b
