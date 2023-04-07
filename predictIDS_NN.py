from keras.models import load_model
import numpy as np
from scapy.all import rdpcap
from scapy.layers.inet import TCP, UDP, IP, raw

def packetFeatures(packet):
    # packet features
    src_port = None
    dst_port = None
    ip_len = None
    tcp_flags = None
    udp_len = None
    payload_len = None
    ttl = None
    syn_flag = None
    fin_flag = None
    ack_flag = None
    rst_flag = None
    urg_flag = None
    psh_flag = None
    src_ip = None
    dst_ip = None
    ip_version = None
    protocol = None
    frag_flag = None
    frag_offset = None
    tcp_win_size = None
    icmp_type = None
    icmp_code = None
    if IP in packet:
        ip_version = packet[IP].version
        protocol = packet[IP].proto
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        frag_flag = int(packet[IP].flags == 'MF' or packet[IP].flags == 'DF+MF')
        frag_offset = packet[IP].frag
        ttl = packet[IP].ttl
        if protocol == 6:  # TCP
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            ip_len = len(packet[IP])
            tcp_flags = packet[TCP].flags
            tcp_win_size = packet[TCP].window
            syn_flag = int(packet[TCP].flags & 0x02 != 0)
            fin_flag = int(packet[TCP].flags & 0x01 != 0)
            ack_flag = int(packet[TCP].flags & 0x10 != 0)
            rst_flag = int(packet[TCP].flags & 0x04 != 0)
            urg_flag = int(packet[TCP].flags & 0x20 != 0)
            psh_flag = int(packet[TCP].flags & 0x08 != 0)
        elif protocol == 17:  # UDP
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            ip_len = len(packet[IP])
            udp_len = len(packet[UDP])
        elif protocol == 1:  # ICMP
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
        else:  # Other protocols
            ip_len = len(packet[IP])
    if raw in packet:
        payload_len = len(packet[raw])
    return [src_port, dst_port, ip_len, tcp_flags, udp_len, payload_len, ttl, syn_flag, fin_flag, ack_flag, rst_flag, urg_flag, psh_flag, src_ip, dst_ip, ip_version, protocol, frag_flag, frag_offset, tcp_win_size, icmp_type, icmp_code]

# Load the model from the file
model = load_model('model.h5')
packets = rdpcap('temp.pcap')

X = []
for packet in packets:
    features = packetFeatures(packet)  # Use the same function that was used for training to extract features
    X.append(features)

X = np.array(X, dtype=np.float32)
X = np.expand_dims(X, axis=1)
predictions = model.predict(X)
print(predictions)