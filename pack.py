import socket
import struct
import binascii
import struct
import time
import sys
from scapy.all import wrpcap

def capture_packets():
    #Make a socket. 
    #1st parameter is IP version 4 
    #2nd is capturing the RAW socket
    #3rd is the protocol of the packet
    #PF_PACKET Linux 
    #AF_INET windows
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    pkts = []
    #Loop to capture packets
    #while true:
    for lp in range(1000):
        packet = s.recvfrom(65565)
        print(packet) #Test remove me when working!
        print("Captured Packet: " + binascii.hexlify(packet[0]).decode('utf-8'))
        ethernet_header = packet[0][0:14]
        eth_header = struct.unpack("!6s6s2s", ethernet_header)
        print ("Destination MAC:" + binascii.hexlify(eth_header[0]) + " Source MAC:" + binascii.hexlify(eth_header[1]) + " Type:" + binascii.hexlify(eth_header[2]))
        ipheader = packet[0][14:34]
        ip_header = struct.unpack("!12s4s4s", ipheader)
        print ("Source IP:" + socket.inet_ntoa(ip_header[1]) + " Destination IP:" + socket.inet_ntoa(ip_header[2]))
        pkts.append(packet[0])

    wrpcap("temp.pcap", pkts)

capture_packets()