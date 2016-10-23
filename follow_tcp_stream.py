#!/usr/bin/env python
# encoding: utf-8
from scapy.all import config
from scapy.all import IP,TCP,IPv6,Padding
from scapy.all import TCP_SERVICES,UDP_SERVICES
TCP_PORTS={TCP_SERVICES[service]:service for service in TCP_SERVICES.keys()}
UDP_PORTS={UDP_SERVICES[service]:service for service in UDP_SERVICES.keys()}
import socket

def _search_3way_handshake_of_tcp_stream(tcp_stream):
    """Search TCP 3 Way Handshake in TCP Stream.(returns first seen)"""
    handshakes_init = []
    #get a "SYN"
    for synpacket in tcp_stream.filter(lambda p: p[TCP].flags & 0x02):
        S = synpacket
        #get the coresponding "SYN ACK"
        synackpackets = tcp_stream.filter(
            lambda p: p[TCP].flags & 0x12 and p[TCP].ack == S.seq + 1
        )
        for synackpacket in synackpackets:
            SA = synackpacket
            #get the coresponding "ACK"
            ackpackets = tcp_stream.filter(
                lambda p: p[TCP].flags & 0x10 and p[TCP].ack == SA.seq + 1
            )
            if ackpackets:
                A = ackpackets[0]
                return PacketList([S,SA,A],name="TCP3WayHandShake of %s - " % repr(tcp_stream))

_calc_tcp_pay_len = lambda pkt:\
                        TCP in pkt and type(pkt[TCP].payload) != Padding and \
                        pkt[TCP].payload and len(pkt[TCP].payload) or 0

def _search_4way_teardown_of_tcp_stream(tcp_stream):
    """Search TCP 4 Way Teardown Session in TCP Stream.(returns first seen)"""
    for F1 in tcp_stream.filter(lambda p: p[TCP].flags & 0x1):
        addjust = _calc_tcp_pay_len(F1)
        ackpackets1 = tcp_stream.filter(
            lambda p: p[TCP].flags & 0x10 and \
                        p[TCP].ack == F1[TCP].seq + 1 + addjust
        )
        for A1 in ackpackets1:
            FA = False
            if A1[TCP].flags & 0x1:
                FA = True
                ackpackets2 = [A1]
            else:
                ackpackets2 = tcp_stream.filter(
                    lambda p: p[TCP].flags & 0x1 and \
                                p[TCP].seq == A1[TCP].seq and \
                                p[TCP].ack == A1[TCP].ack
                )
            for F2 in ackpackets2:
                ackpackets2 = tcp_stream.filter(
                    lambda p: p[TCP].flags & 0x10 and \
                                p[TCP].seq == F2[TCP].ack and \
                                p[TCP].ack == F2[TCP].seq + 1
                )
                if ackpackets2:
                    A2 = ackpackets2[0]
                    if FA:
                        return PacketList([F1,A1,A2],name="TCP4WayTeardown of %s - " % repr(tcp_stream))
                    return PacketList([F1,A1,F2,A2],name="TCP4WayTeardown of %s - " % repr(tcp_stream))


class NoAddressException(Exception):
    def __init__(self, pkt):
        self.pkt = pkt
    def __str__(self):
        return "Invalid Packet %s (No IP Address)" % repr(self.pkt)

@config.conf.commands.register
def follow_tcp_stream(pkt,pktlist,quick=False,resolv=False):
    """Follow TCP stream of one packet."""
    assert pkt in pktlist,\
        "Packet %s is not listed in PacketList %s" % (repr(pkt), repr(pktlist))
    assert TCP in pkt, "TCP is not in Packet %s" % repr(pkt)
    #Pairwise TCP port
    followme = pkt[TCP] #the first TCP layer will be picked automatically
    srcport = followme.sport
    dstport = followme.dport
    #Pairwise IP Address
    # the closest under layer will be picked. (IPv6()/IP()/TCP() then IP())
    L3 = IP
    try:
        #try underlayer
        foot = followme.underlayer
        srcip = foot.src
        dstip = foot.dst
        if type(foot) == IPv6:
            L3 = IPv6
    except:
        #try other, but upper layer
        if IPv6 in pkt:
            srcip = pkt[IPv6].src
            dstip = pkt[IPv6].dst
            L3 = IPv6
        elif IP in pkt:
            srcip = pkt[IP].src
            dstip = pkt[IP].dst
        else:
            raise NoAddressException(followme)
    if resolv:
        #resolv ip,port => host,service
        try:
            srchost = socket.gethostbyaddr(srcip)[0]
        except socket.herror:
            srchost = srcip
        srcservice = srcport
        if srcport in TCP_PORTS:
            srcservice = TCP_PORTS[srcport]
        try:
            dsthost = socket.gethostbyaddr(dstip)[0]
        except socket.herror:
            dsthost = dstip
        dstservice = dstport
        if dstport in TCP_PORTS:
            dstservice = TCP_PORTS[dstport]
    ip_pair = (srcip,dstip)
    port_pair = (srcport,dstport)

    #Select pkts from pktlist where ip and port pair are matched.
    #This will save much time ;)

    possible_stream = pktlist.filter(\
       lambda p:\
            TCP in p and \
            p[TCP].sport in port_pair and p[TCP].dport in port_pair and\
            p[L3].src in ip_pair and p[L3].dst in ip_pair
        )

    #<Possible TCP Stream Between ?:? - ?:? : TCP:22 UDP:5 ICMP:0 Other:3>
    if resolv:
        possible_stream = PacketList(possible_stream,
        name="Possible TCP Stream Between %s:%s - %s:%s"
        % (srchost, srcservice, dsthost, dstservice) )
    else:
        possible_stream = PacketList(possible_stream,
        name="Possible TCP Stream Between %s:%s - %s:%s"
        % (srcip, srcport, dstip, dstport) )

    #you looks busy, fed this.
    if quick:
        return possible_stream

    tcp_stream = []

    syn = _search_3way_handshake_of_tcp_stream(possible_stream)
    fin = _search_4way_teardown_of_tcp_stream(possible_stream)

    if syn and fin:
        tcp_stream += syn
        client_next_seq = syn[-1].seq
        server_next_seq = syn[-1].ack
        while True:
            print client_next_seq,"=>",server_next_seq
            nexts = possible_stream.filter(
                lambda p:p.seq in (client_next_seq,server_next_seq) and \
                    not p in tcp_stream and not p in fin
            )
            if not nexts:
                break
            for some in nexts:
                tcp_stream.append(some)
                if some[L3].src == srcip:
                    client_next_seq += _calc_tcp_pay_len(some)
                elif some[L3].src == dstip:
                    server_next_seq += _calc_tcp_pay_len(some)
        tcp_stream += fin

    #<TCP Stream Between ?:? - ?:? : TCP:22 UDP:5 ICMP:0 Other:3>
    if resolv:
        tcp_stream = PacketList(tcp_stream,
        name="TCP Stream Between %s:%s - %s:%s"
        % (srchost, srcservice, dsthost, dstservice) )
    else:
        tcp_stream = PacketList(tcp_stream,
        name="TCP Stream Between %s:%s - %s:%s"
        % (srcip, srcport, dstip, dstport) )

    return tcp_stream

if __name__ == "__main__":
    from scapy.main import interact
    interact(mydict=locals(),mybanner="***SYA-KE scapy!***")
