from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.l2 import Ether


def basic_sniffer(packet):
    ethernet = packet.getlayer(Ether)
    if ethernet:
        print("Ethernet Header:"f"\nDestination MAC address: {ethernet.dst}"
              f"\nSource MAC address: {ethernet.src}"f"\nProtocol type: {ethernet.type}")
    ip = packet.getlayer(IP)
    print('***************************************************************')
    if ip:
        print("IP Header:"f"\nVersion: {ip.version}"f"\nHeader Length: {ip.ihl * 4}"
              f"\nTTL: {ip.ttl}"f"\nSource IP: {ip.src}"f"\nDestination IP: {ip.dst}")
    tcp = packet.getlayer(TCP)
    print('***************************************************************')
    if tcp:
        print("TCP Header:"f"\nSource Port: {tcp.sport}"f"\nDestination Port: {tcp.dport}"
              f"\nSequence Number: {tcp.seq}"f"\nAcknowledgment Number: {tcp.ack}"
              f"\nHeader Length: {tcp.dataofs * 4}""\nFlags: {tcp.flags}")

    udp = packet.getlayer(UDP)
    print('***************************************************************')
    if udp:
        print("UDP Header:"f"Source Port: {udp.sport}"f"Destination Port: {udp.dport}"f"Length: {udp.len}")

    icmp = packet.getlayer(ICMP)
    print('***************************************************************')
    if icmp:
        print("ICMP Header:"f"\nType: {icmp.type}"f"\nCode: {icmp.code}")
sniff(prn=basic_sniffer)