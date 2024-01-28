'''
Here is where the logic will be placed, in more detail the functions analyzing the pcap file and returning their results.
'''
from django.conf import settings
from .constants import *

# Scapy
from scapy.all import *
from scapy.layers.inet import *

from collections import Counter

# Plotting
import pandas as pd
import plotly.express as px

from datetime import datetime

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
    proto_nums = PROTOCOL_NUMS

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

    data = pd.DataFrame(list(proto_dict.items()), columns=['Protocols', 'Occurrences'])

    # Plot Bar chart
    fig1 = px.bar(data, x='Protocols', y='Occurrences', color='Protocols', log_y=True)

    fig1.update_layout(plot_bgcolor=PLOT_BG_COLOR, paper_bgcolor=PAPER_BG_COLOR, font_color=CHART_FONT_COLOR, margin=dict(l=20, r=20, t=20, b=20))

    # Plot Pie Chart
    fig2 = px.pie(data, values='Occurrences', names='Protocols', color='Protocols')

    fig2.update_layout(plot_bgcolor=PLOT_BG_COLOR,  paper_bgcolor=PAPER_BG_COLOR, font_color=CHART_FONT_COLOR, margin=dict(l=20, r=20, t=20, b=20))

    return fig1.to_html(), fig2.to_html()

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

    # Plot Horizontal Bar Chart
    fig = px.bar(data, x=data['Bytes'], y=data['IP'], orientation='h', color='IP') 

    fig.update_layout(plot_bgcolor=PLOT_BG_COLOR, paper_bgcolor=PAPER_BG_COLOR, font_color=CHART_FONT_COLOR, margin=dict(l=20, r=20, t=20, b=20), showlegend=False)

    return fig.to_html()

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

    fig = px.line(data, x=data['Date'], y=data['Bytes'], markers='o')

    fig.update_layout(plot_bgcolor=PLOT_BG_COLOR, paper_bgcolor=PAPER_BG_COLOR, font_color=CHART_FONT_COLOR, margin=dict(l=20, r=20, t=20, b=20))

    return fig.to_html()

#--------------------CONVERSATIONS---------------------
def get_convos(capture):
    '''
    This is a docstring for get_convos.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.

    Returns:
    {   
        1:{
            socket_pair: (IP:port, IP:port),
            src_ip: str,
            dst_ip: str,
            src_port: int,
            dst_port: int, 
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

    proto_nums = PROTOCOL_NUMS
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
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port, 
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
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port, 
                        'packets': 1,
                        'bytes': payload_bytes,
                        'proto': protocol,
                        'start_time': timestamp,
                        'end_time': timestamp
                    }

    for k, convo in conversations.items():
        # Convert duration to milliseconds    
        duration = abs(convo['end_time'] - convo['start_time']) * 1000
        convo['duration'] = duration


    return conversations

#--------------------IP GEOLOCATION MAPPING---------------------
