import pcapy
import socket
from struct import unpack

def print_packet(pktlen, data, timestamp):
    if not data:
        return

    # Extract the Ethernet header
    eth_length = 14
    eth_header = data[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])

    # Extract the IP header
    if eth_protocol == 8:
        ip_header = data[eth_length:20+eth_length]
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        print('IP: Version: {}, Header Length: {}, TTL: {}, Protocol: {}, Source Address: {}, Destination Address: {}'.format(version, ihl, ttl, protocol, s_addr, d_addr))

    # Extract the TCP header
    if protocol == 6:
        tcp_header = data[eth_length+iph_length:20+eth_length+iph_length]
        tcph = unpack('!HHLLBBHHH', tcp_header)

        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4

        print('TCP: Source Port: {}, Dest Port: {}, Sequence: {}, Acknowledgement: {}, Header Length: {}'.format(source_port, dest_port, sequence, acknowledgement, tcph_length))

    # Extract the UDP header
    elif protocol == 17:
        udp_header = data[eth_length+iph_length:8+eth_length+iph_length]
        udph = unpack('!HHHH', udp_header)

        source_port = udph[0]
        dest_port = udph[1]
        length = udph[2]
        checksum = udph[3]

        print('UDP: Source Port: {}, Dest Port: {}, Length: {}, Checksum: {}'.format(source_port, dest_port, length, checksum))

    # Extract the ICMP header
    elif protocol == 1:
        icmp_header = data[eth_length+iph_length:4+eth_length+iph_length]
        icmph = unpack('!BBH', icmp_header)

        type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]

        print('ICMP: Type: {}, Code: {}, Checksum: {}'.format(type, code, checksum))

cap = pcapy.open_offline('temp.pcap')
while True:
    (header, packet) = cap.next()
    print_packet(header.getlen(), packet, header.getts())
