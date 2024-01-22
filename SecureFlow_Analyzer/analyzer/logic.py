'''
Here is where the logic will be placed, in more detail the functions analyzing the pcap file and returning their results.
'''
# Scapy
from scapy.all import *
from scapy.layers.inet import *

from collections import Counter


def get_capture(file_path):
    return rdpcap(file_path)

'''
    Returns a dictionary with keys and values as PROTOCOLS utilized and OCCURENCES of each respectively.
'''
def get_protocols(capture):
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