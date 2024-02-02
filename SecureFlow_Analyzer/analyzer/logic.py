'''
Here is where the logic will be placed, in more detail the functions analyzing the pcap file and returning their results.
'''
from django.conf import settings
from .constants import *

# Scapy
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.layers.dns import *

from collections import Counter

# Plotting
import pandas as pd
import plotly.express as px

from datetime import datetime
import os
import ipinfo
import requests

def get_capture(file_path):
    return rdpcap(file_path)

#**************************ANALYSIS****************************
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
        if IP in pkt or IPv6 in pkt:
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
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
    This is a docstring for get_top_talkers.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.

    Returns:
    A dictionary with keys as IP ADDRESS where BYTES originated from as values.
    '''
    traffic = Counter()

    for pkt in capture:
        if IP in pkt or IPv6 in pkt:
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            src_ip = ip_layer.src

            if ip_layer.version == 4:
                payload = ip_layer.len  
            elif ip_layer.version == 6:
                payload = ip_layer.plen 

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

def get_traffic(capture):
    '''
    This is a docstring for get_traffic.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.

    Returns:
    A dictionary with keys as DATETIME objects and values as BYTES.
    '''
    # Extract bytes per time instance
    traffic = Counter()
    for pkt in capture:
        if IP in pkt or IPv6 in pkt:
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            timestamp = float(ip_layer.time)

            if ip_layer.version == 4:
                payload = ip_layer.len  
            elif ip_layer.version == 6:
                payload = ip_layer.plen 

            traffic.update({datetime.fromtimestamp(timestamp):payload})
    
    return dict(traffic)

def visualize_traffic(traffic_dict):
    
    data = pd.DataFrame(list(traffic_dict.items()), columns=['Date', 'Bytes'])
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

    for pkt in capture:
        if IP in pkt or IPv6 in pkt:
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]

            if pkt.haslayer(UDP) or pkt.haslayer(TCP):
                # Gather values
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                src_port = pkt.sport
                dst_port = pkt.dport
                timestamp = float(pkt.time)

                if ip_layer.version == 4:
                    protocol = proto_nums[int(ip_layer.proto)]
                    payload_bytes = ip_layer.len 
                elif ip_layer.version == 6:
                    protocol = proto_nums[int(ip_layer.nh)]
                    payload_bytes = ip_layer.plen

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
access_token = os.getenv('IP_ACCESS_TKN')

handler = ipinfo.getHandler(access_token)

def get_coordinates(capture):
    '''
    This is a docstring for get_coordinates.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.

    Returns:
    A dictionary with keys as IP ADDRESSES and values as COORDINATES.
    '''

    ip_coords = {}

    for pkt in capture:
        if IP in pkt or IPv6 in pkt:
            ip_addr = pkt[IP].src if IP in pkt else pkt[IPv6].src
            
            details = handler.getDetails(ip_addr)
            # Convert Details object to dict 
            details_core = vars(details)['details']

            # Add IP only if it exists publicly
            if 'bogon' not in details_core:
                # Get only addresses that exist in database
                if details_core['latitude'] != None:
                    location = details_core['loc']
                    ip_coords[ip_addr] = location
    return ip_coords

#**************************ANOMALIES*********************************
#---------------------Insecure/ Vulnerable Services------------------
# Initialize services dict
services_dict = {service:[] for service in VULN_PORT_NUMS.values()}

def get_vuln_services(capture):
    '''
    This is a docstring for get_vuln_services.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.

    Returns:
    A dictionary with keys as SERVICE NAMES and values as LISTS OF SOCKET PAIRS.
    '''
    for pkt in capture:
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]

                # dst port to get the host initiating the communication with a vuln service/ protocol
                dst_port = ip_layer.dport 

                # Check if port in vulnerable ones
                if dst_port in VULN_PORT_NUMS.keys():
                    service = VULN_PORT_NUMS[dst_port]

                    # Gather info
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    src_port = ip_layer.sport
                    socket_pair = f"{src_ip}:{src_port} > {dst_ip}:{dst_port}"

                    # Add only unique socket pairs
                    if socket_pair not in services_dict[service]:
                        services_dict[service].append(socket_pair)


    # Remove services not utilized
    filtered_serv_dict = {serv: sum_lst for serv, sum_lst in services_dict.items() if sum_lst}

    return filtered_serv_dict

#---------------------Malicious Domains------------------
# Fetch data each time before analysis (UP-TO-DATE)
def fetch_data(url):

    response = requests.get(url)
    data = response.text

    return data

def is_dom_suspicious(capture, data):
    '''
    This is a docstring for is_dom_suspicious.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.
    - data: A string of multiple known malicious domains. 

    Returns:
    A list comprised of dictionaries with src_ip, dst_ip, domain_name, and datetime of the incident.
    '''
    sus_entries = []
    domain_lines = data.strip().split('\n')
    dom_lst = [line.split(' ')[-1] for line in domain_lines]

    for pkt in capture:
        # Check to see if it is a QUERY
        if pkt.haslayer(DNSQR):
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            # Extract domain name
            # Decode and remove trailing dot of FQDN
            try:
                domain = pkt[DNSQR].qname.decode('utf-8')[:-1]
            except UnicodeDecodeError:
                domain = pkt[DNSQR].qname.decode('latin-1')[:-1]

            # Check if domain is malicious
            for mal_dom in dom_lst:
                if domain == mal_dom:
                    timestamp = float(ip_layer.time)
                    date_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                    
                    entry = {"src_ip": ip_layer.src, "dst_ip": ip_layer.dst, "domain_name": domain, "date_time": date_time}

                    if entry not in sus_entries:
                        sus_entries.append(entry)

    return sus_entries
