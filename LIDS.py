import pcapy
from scapy.all import *
import platform
import netifaces

interfaces = netifaces.interfaces()
print("Available interfaces:")
for iface in interfaces:
    print(iface)

# Ask the user to select an interface
iface_selected = input("Enter the name of the interface you want to use (or press Enter for eth0): ")
# If no interface is selected, use eth0 by default
if iface_selected == "":
    iface_selected = "eth0"
# Check if the selected interface is available
if iface_selected not in interfaces:
    print("Error: Interface not found.")
else:
    # Open the capture object using the selected interface
    cap = pcapy.open_live(iface_selected, 65536, 1, 0)
    print(f"Using interface {iface_selected} for packet capture.")
    
#if platform.system() == "Windows":
    #cap = pcapy.open_live('Wi-Fi', 1000, 1, 0)

#elif platform.system() == "Linux":
#Linux

dump_file = PcapWriter("IDS_Temp.pcap", append=True, sync=True)
# loop to capture packets
while True:
    # read a single packet
    (header, packet) = cap.next()
    
    pkt = IP(packet)

    # extract the source and destination IP addresses
    src_ip = pkt.src
    dst_ip = pkt.dst

    # extract the protocol field to determine if it's TCP or UDP
    if pkt.haslayer(TCP):
        # extract TCP-specific fields
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        tcp_flags = pkt[TCP].flags
        payload_len = len(pkt[TCP].payload)
        # set other protocol-specific fields to None
        udp_len = None

    elif pkt.haslayer(UDP):
        # extract UDP-specific fields
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        payload_len = len(pkt[UDP].payload)
        # set other protocol-specific fields to None
        tcp_flags = None
        udp_len = pkt[UDP].len

    else:
        # packet is not TCP or UDP, set fields to None
        src_port = None
        dst_port = None
        tcp_flags = None
        udp_len = None
        payload_len = None

    # extract the IP packet fields
    ip_len = pkt.len
    ttl = pkt.ttl

    # check if TCP layer exists
    if TCP in pkt:
        syn_flag = pkt[TCP].flags.S
        fin_flag = pkt[TCP].flags.F
        ack_flag = pkt[TCP].flags.A
        rst_flag = pkt[TCP].flags.R
        urg_flag = pkt[TCP].flags.U
        psh_flag = pkt[TCP].flags.P
    else:
        syn_flag = None
        fin_flag = None
        ack_flag = None
        rst_flag = None
        urg_flag = None
        psh_flag = None

    # print the extracted fields
    print("Source IP: ", src_ip)
    print("Destination IP: ", dst_ip)
    print("Source Port: ", src_port)
    print("Destination Port: ", dst_port)
    print("IP Length: ", ip_len)
    print("TCP Flags: ", tcp_flags)
    print("UDP Length: ", udp_len)
    print("Payload Length: ", payload_len)
    print("TTL: ", ttl)
    print("SYN Flag: ", syn_flag)
    print("FIN Flag: ", fin_flag)
    print("ACK Flag: ", ack_flag)
    print("RST Flag: ", rst_flag)
    print("URG Flag: ", urg_flag)
    print("PSH Flag: ", psh_flag)
    
    # write the packet to the output pcap file
    dump_file.write(packet)