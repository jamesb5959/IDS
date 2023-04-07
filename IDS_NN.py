import numpy as np
import ipaddress
from keras.models import Sequential
from keras.layers import Dense, Dropout, LSTM
from sklearn.model_selection import train_test_split
from scapy.all import rdpcap
from scapy.layers.inet import TCP, UDP, IP, raw
from keras.utils import to_categorical

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
        src_ip = int(ipaddress.IPv4Address(packet[IP].src))
        dst_ip = int(ipaddress.IPv4Address(packet[IP].dst))
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

# Load normal packets
normal_packets = rdpcap('temp.pcap')
X_normal = []
y_normal = []
for packet in normal_packets:
    features = packetFeatures(packet)
    X_normal.append(features)
    y_normal.append(0)  # Label as 0 for normal

# Load malicious packets
malicious_packets = rdpcap('temp.pcap')
X_malicious = []
y_malicious = []
for packet in malicious_packets:
    features = packetFeatures(packet)
    X_malicious.append(features)
    y_malicious.append(1)  # Label as 1 for malicious

# Concatenate data
X = np.concatenate([X_normal, X_malicious], axis=0)
y = np.concatenate([y_normal, y_malicious], axis=0)

X = np.array(X, dtype=np.float32)  # Cast input data to float32
y = np.array(y)

X = np.expand_dims(X, axis=1)

np.save('X.npy', X)
np.save('y.npy', y)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

y_train = to_categorical(y_train, num_classes=2)
y_test = to_categorical(y_test, num_classes=2)

model = Sequential()
model.add(LSTM(128, input_shape=(1, X.shape[2]), return_sequences=True))
model.add(Dropout(0.2))
model.add(LSTM(64))
model.add(Dropout(0.2))
model.add(Dense(2, activation='softmax'))

model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

# Train
model.fit(X_train, y_train, epochs=50, batch_size=32, validation_data=(X_test, y_test))
model.save('model.h5')