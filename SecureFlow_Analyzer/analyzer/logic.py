'''
Here is where the logic will be placed, in more detail the functions analyzing the pcap file and returning their results.
'''
# Scapy
from scapy.all import *
from scapy.layers.inet import *

from collections import Counter


def get_capture(file_path):
    return rdpcap(file_path)

#--------------------PROTOCOL DISTRIBUTION---------------------
def get_protocols(capture):
    '''
    This is a docstring for get_protocols.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.

    Returns:
    A dictionary with keys and values as PROTOCOLS utilized and OCCURENCES of each respectively.
    '''
    proto_nums = {
        1: "ICMP",
        0: "IP",
        2: "IGMP",
        4: "IPIP",
        6: "TCP",
        8: "EGP",
        9: "IGP",
        17: "UDP",
        58: "IPv6-ICMP",
        41: "IPv6",
        43: "IPv6-Route",
        44: "IPv6-Frag",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "IPv6-ICMP",
        88: "EIGRP",
        89: "OSPFIGP",
        94: "IPIP",
        97: "EtherIP",
        103: "PIM",
        112: "VRRP",
        115: "L2TP",
        118: "STP",
        121: "SMP",
        124: "PIPE",
        132: "SCTP",
        133: "FC",
        137: "MPLS",
        138: "MPLS-MCAST",
        139: "UDPLite",
        140: "MPLS-UDPLite",
        142: "MP",
        254: "RAW"
    }

    proto_counter = Counter()
    proto_list = []

    for pkt in capture:
        # Check if packet has IP layer
        if IP in pkt:
            ip_layer = pkt[IP]
            # Check IP version & append perceeding protocol
            if ip_layer.version == 4:
                proto_list.append(proto_nums[int(ip_layer.proto)])
            elif ip_layer.version == 6:
                proto_list.append(proto_nums[int(ip_layer.nh)])

    # Count the occurrences of each protocol in the list
    proto_counter.update(proto_list)
    return dict(proto_counter)

#--------------------BANDWIDTH UTILIZATION---------------------

#--------------------CONVERSATIONS---------------------
    # IPs Communicating
    # Bytes + Packets  Exchanged
    # Duration of communication
def get_convos(capture):
    '''
    This is a docstring for extract_ip_conv_pairs.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.

    Returns:
    {   
        1:{
            pair: (IP, IP),
            packets: int,
            bytes: int,
            duration: float
        },
        2:{...},
        ...
    }
    '''

    conversations = {}

    for packet in capture:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            payload_bytes = len(packet)
            timestamp = float(packet.time)

            # Ensure the pair is unique by sorting the IPs
            ip_pair = tuple(sorted([src_ip, dst_ip]))
            
            # Add 1st conversation
            if len(conversations) == 0:
                conversations[0] = {
                        'pair': ip_pair,
                        'packets': 1,
                        'bytes': payload_bytes,
                        'start_time': timestamp,
                        'end_time': timestamp
                    }
            else:    
                # Update or initialize attributes
                for k, v in conversations.items():
                    if v['pair'] == ip_pair:
                        v['packets'] += 1
                        v['bytes'] += payload_bytes
                        v['end_time'] = timestamp
                        break
                else:
                    conversations[max(conversations.keys())+1] = {
                        'pair': ip_pair,
                        'packets': 1,
                        'bytes': payload_bytes,
                        'start_time': timestamp,
                        'end_time': timestamp
                    }

    return conversations

#--------------------IP GEOLOCATION MAPPING---------------------

#--------------------TCP Stream---------------------