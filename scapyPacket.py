#!/usr/bin/env python
# encoding: utf-8
import sys,os
import time
DEBUG=True
def dPrint(s):
    if DEBUG:
        sys.stderr.write(s)
    else:
        pass

try:
    from scapy.all import *
except:
    raise Exception("[#] Cannot import scapy.all")
    exit(-1)

dPrint("Successfully loaded scapy!\n")

class T0114:

    def __init__(self):    
        self.total = 0
        self.allPackets = PacketList()
        self.otherPackets = PacketList()
        self.targetLayer=[UDP,TCP,IP,IPv6,ICMP,ARP,Ether]
        self.nameIni={"UDP":"U","TCP":"T","IP":"4","IPv6":"6","ICMP":"I","Ether":"E"}
        self.counter=dict([[layer.name,0] for layer in self.targetLayer])
        self.counter.update({"RARP":0})

    def p(self,pkt):
        self.total = self.total + 1
        self.allPackets.append(pkt)
        n = "?"
        for layer in self.targetLayer:
            if layer in pkt:
                if layer.name == "ARP":
                    if self.isRARP(layer):
                        self.counter["RARP"] = self.counter["RARP"] + 1
                        n = "A"
                    else:
                        self.counter["ARP"] = self.counter["ARP"] + 1
                        n = "R"
                else:
                    self.counter[layer.name] = self.counter[layer.name] + 1
                    n = self.nameIni[layer.name][:1]
                dPrint(n)
                return
        self.otherPackets.append(pkt)

    def isRARP(self,arpPkt):
        return True if arpPkt.op in range(4,8) else False

    def pp(self):
        for keys in self.counter:
            print "%s Packet : %d" % (keys,self.counter[keys])

if __name__ == "__main__":
    my = T0114()
    dPrint("[*] To Stop, Press Ctrl+C ")
    print ""
    sniff(prn=my.p)
    print ""
    print "Read %d Packets!" % my.total
    my.pp()
    print "              "
    print "#Other Packets"
    my.otherPackets
    interact(mydict={"my":my},mybanner="Entering Testing Interact mode. Test Object 'my' ")
