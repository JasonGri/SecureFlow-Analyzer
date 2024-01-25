'''
Here is where the logic will be placed, in more detail the functions analyzing the pcap file and returning their results.
'''
from django.conf import settings
# Scapy
from scapy.all import *
from scapy.layers.inet import *

from collections import Counter

# Plotting
import pandas as pd
import matplotlib.pyplot as plt


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

def visualize_protocols(proto_dict):

    data = pd.DataFrame(list(proto_dict.items()), columns=['protocol', 'occurrence'])
    
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']
        
    # BAR GRAPH
    fig1, ax1 = plt.subplots()

    data.plot.bar(x='protocol', y='occurrence', color=colors, legend=False, ax=ax1)

    fig1.set_facecolor('#f8f9fa')
    ax1.set_facecolor('#f8f9fa')
    
    ax1.set_yscale('log')

    ax1.set_xlabel('Protocol')
    ax1.set_ylabel('Number of Occurrences')
    ax1.set_title('Bar Chart')
    ax1.tick_params(axis='x', rotation=45)
    plt.tight_layout()
    plt.savefig(os.path.join(settings.MEDIA_ROOT, 'images/proto_dirb_bar.png'))

    # PIE PLOT
    fig2, ax2 = plt.subplots()

    fig2.set_facecolor('#f8f9fa')
    ax2.set_facecolor('#f8f9fa')

    #FIXME: Utilize explode for better representation
    # explode = (0, 0.1, 0, 0)

    ax2.pie(data['occurrence'], labels=data['protocol'], colors=colors, autopct='%1.1f%%', startangle=90)
    ax2.set_title('Pie Chart')

    plt.tight_layout()
    plt.savefig(os.path.join(settings.MEDIA_ROOT, 'images/proto_dirb_pie.png'))

#--------------------BANDWIDTH UTILIZATION---------------------
def get_top_talkers(capture):
    '''
    This is a docstring for top_talkers.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.

    Returns:
    A dictionary with keys as IP ADDRESS where BYTES originated from as values.
    '''
    traffic = Counter()

    for pkt in capture:
        if IP in pkt:
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            payload = ip_layer.len

            traffic.update({src_ip: payload})
    
    # Convert Counter to dictionary
    traffic = dict(traffic)

    # Sort based on num of bytes
    sorted_traffic = dict(sorted(traffic.items(), key=lambda x: x[1], reverse=True))

    # Get the 10 IPs with most communication traffic, and sort it from least to most
    top_ten = dict(list(sorted_traffic.items())[:10][::-1])
    
    return top_ten

def visualize_top_talkers(band_dict):

    data = pd.DataFrame(list(band_dict.items()), columns=['IP', 'Bytes'])
    print(data)

    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']

    fig, ax = plt.subplots()

    ax.barh(data['IP'], data['Bytes'], color=colors)

    fig.set_facecolor('#f8f9fa')
    ax.set_facecolor('#f8f9fa')

    ax.set_xlabel('Bytes')
    ax.set_xscale('log')
    byte_ticks = [1, 1e3, 1e6, 1e9, 1e12]
    byte_labels = ['1B', '1KB', '1MB', '1GB', '1TB']

    ax.set_xticks(byte_ticks)
    ax.set_xticklabels(byte_labels)

    ax.set_ylabel('IP Addresses')
    ax.set_title('Horizontal Bar Chart')

    plt.tight_layout()
    plt.savefig(os.path.join(settings.MEDIA_ROOT, 'images/band_util_hbar.png'))

def bandwidth_timeseries(capture):
    
    # Extract bytes per time instance
    traffic = Counter()
    for pkt in capture:
        if IP in pkt:
            ip_layer = pkt[IP]

            payload = ip_layer.len
            timestamp = float(ip_layer.time)

            traffic.update({datetime.fromtimestamp(timestamp):payload})
    
    traffic = dict(traffic)

    # Plotting the timeseries chart
    data = pd.DataFrame(list(traffic.items()), columns=['Date', 'Bytes'])
    data['Date'] = pd.to_datetime(data['Date'])


    fig, ax = plt.subplots()
    ax.plot(data['Date'], data['Bytes'], marker='o')
 
    fig.set_facecolor('#f8f9fa')
    ax.set_facecolor('#f8f9fa')

    ax.set_xlabel('Date')
    ax.tick_params(axis='x', rotation=45)
    ax.set_ylabel('Bytes')
    ax.set_title('Time Series Chart')

    plt.tight_layout()
    plt.savefig(os.path.join(settings.MEDIA_ROOT, 'images/band_util_tseries.png'))

#--------------------CONVERSATIONS---------------------
    # IPs Communicating
    # Bytes + Packets  Exchanged
    # Duration of communication
def get_convos(capture):
    '''
    This is a docstring for get_convos.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.

    Returns:
    {   
        1:{
            socket_pair: (IP:port, IP:port),
            packets: int,
            bytes: int,
            proto: str,
            start_time: float,
            end_time: float,
            duration: float
        },
        2:{...},
        ...
    }
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

    conversations = {}

    for packet in capture:
        if IP in packet:
            # Gather values
            ip_layer = packet[IP]

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            timestamp = float(packet.time)
            payload_bytes = ip_layer.len

            if ip_layer.version == 4:
                protocol = proto_nums[int(ip_layer.proto)] 
            elif ip_layer.version == 6:
                protocol = proto_nums[int(ip_layer.nh)]

            if packet.haslayer(UDP) or packet.haslayer(TCP):
                src_port = packet.sport
                dst_port = packet.dport

            # Direction doesn't matter 
            # socket_pair = tuple(sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"]))

            # Direction matters    
            socket_pair = (f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}")
            
            # Add 1st conversation
            if len(conversations) == 0:
                conversations[0] = {
                        'pair': socket_pair,
                        'packets': 1,
                        'bytes': payload_bytes,
                        'proto': protocol,
                        'start_time': timestamp,
                        'end_time': timestamp
                    }
            else:    
                # Update or initialize attributes
                for k, convo in conversations.items():
                    if convo['pair'] == socket_pair:
                        convo['packets'] += 1
                        convo['bytes'] += payload_bytes
                        convo['end_time'] = timestamp
                        break
                else:
                    conversations[max(conversations.keys())+1] = {
                        'pair': socket_pair,
                        'packets': 1,
                        'bytes': payload_bytes,
                        'proto': protocol,
                        'start_time': timestamp,
                        'end_time': timestamp
                    }

     # Add duration in milliseconds for each conversation
    for k, convo in conversations.items():
        duration = round((convo['end_time'] - convo['start_time']) * 1000, 3)
        convo['duration'] = duration 

    return conversations

#--------------------IP GEOLOCATION MAPPING---------------------

#--------------------TCP Stream---------------------