'''
Here is where the logic will be placed, in more detail the functions analyzing the pcap file and returning their results.
'''
from django.conf import settings
from .constants import *
from .utils import *

# Scapy
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.layers.dns import *
from scapy.layers.http import *

from collections import Counter

# Plotting
import pandas as pd
import plotly.express as px

# General
from datetime import datetime
import os
import ipinfo
from ipaddress import IPv6Address, IPv6Network 
from decimal import Decimal
import csv

@timeit
def get_capture(file_path):
    return rdpcap(file_path)

#**************************ANALYSIS****************************
#--------------------PROTOCOL/ SERVICE DISTRIBUTION---------------------
@timeit
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

@timeit
def get_services(capture):
    '''
    This is a docstring for get_services.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.

    Returns:
    A dictionary with keys and values as SERVICES utilized and OCCURENCES of each respectively.
    '''
    service_counter = Counter()
    service_list = []

    for pkt in capture:
        # Check if packet has TCP or UDP layer for a service port
        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]

            src_port = resolve_service(ip_layer.sport)
            dst_port = resolve_service(ip_layer.dport)

            # In case the services was not resolved from the port number add "Unresolved"
            service_list.append(src_port if type(src_port) != int else 'Unresolved')

            service_list.append(dst_port if type(dst_port) != int else 'Unresolved')
    
    
    # Count the occurrences of each service in the list
    service_counter.update(service_list)
    return dict(service_counter)

@timeit
def visualize_protocols(proto_dict):

    data = pd.DataFrame(list(proto_dict.items()), columns=['Protocols', 'Occurrences'])

    # # Plot Bar chart
    # fig1 = px.bar(data, x='Protocols', y='Occurrences', color='Protocols', log_y=True)

    # fig1.update_layout(plot_bgcolor=PLOT_BG_COLOR, paper_bgcolor=PAPER_BG_COLOR, font_color=CHART_FONT_COLOR, margin=dict(l=20, r=20, t=20, b=20))

    # Plot Pie Chart
    fig2 = px.pie(data, values='Occurrences', names='Protocols', color='Protocols')

    fig2.update_layout(plot_bgcolor=PLOT_BG_COLOR,  paper_bgcolor=PAPER_BG_COLOR, font_color=CHART_FONT_COLOR, margin=dict(l=20, r=20, t=20, b=20))

    return fig2.to_html()

@timeit
def visualize_services(service_dict):

    data = pd.DataFrame(list(service_dict.items()), columns=['Services', 'Occurrences'])

    # Plot Bar chart
    fig1 = px.bar(data, x='Services', y='Occurrences', color='Services', log_y=True)

    fig1.update_layout(plot_bgcolor=PLOT_BG_COLOR, paper_bgcolor=PAPER_BG_COLOR, font_color=CHART_FONT_COLOR, margin=dict(l=20, r=20, t=20, b=20))

    return fig1.to_html()

#--------------------BANDWIDTH UTILIZATION---------------------
@timeit
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

@timeit
def visualize_top_talkers(band_dict):

    data = pd.DataFrame(list(band_dict.items()), columns=['IP', 'Bytes'])

    # Plot Horizontal Bar Chart
    fig = px.bar(data, x=data['Bytes'], y=data['IP'], orientation='h', color='IP') 

    fig.update_layout(plot_bgcolor=PLOT_BG_COLOR, paper_bgcolor=PAPER_BG_COLOR, font_color=CHART_FONT_COLOR, margin=dict(l=20, r=20, t=20, b=20), showlegend=False)

    return fig.to_html()

@timeit
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
            timestamp = float(pkt.time)

            if ip_layer.version == 4:
                payload = ip_layer.len  
            elif ip_layer.version == 6:
                payload = ip_layer.plen 

            traffic.update({datetime.fromtimestamp(timestamp):payload})
    
    return dict(traffic)

@timeit
def visualize_traffic(traffic_dict):
    
    data = pd.DataFrame(list(traffic_dict.items()), columns=['Date', 'Bytes'])
    data['Date'] = pd.to_datetime(data['Date'])

    fig = px.line(data, x=data['Date'], y=data['Bytes'], markers='o')

    fig.update_layout(plot_bgcolor=PLOT_BG_COLOR, paper_bgcolor=PAPER_BG_COLOR, font_color=CHART_FONT_COLOR, margin=dict(l=20, r=20, t=20, b=20))

    return fig.to_html()

#--------------------CONVERSATIONS---------------------
@timeit
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
access_token = "feecfe8b0c116a"

handler = ipinfo.getHandler(access_token)

@timeit
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

#**********************ANOMALIES*************************
#----------------------Insecure/ Vulnerable Services---------
@timeit
def get_vuln_services(capture):
    '''
    This is a docstring for get_vuln_services.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.

    Returns:
    A dictionary with keys as SERVICE NAMES and values as LISTS OF ENTRY.
    '''
    # Initialize services dict
    services_dict = {service: [] for service in VULN_PORT_NUMS.values()}

    for pkt in capture:
        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            # dst port to get the host initiating the communication with a vuln service/ protocol
            dst_port = pkt.dport

            # Check if port in vulnerable ones
            if dst_port in VULN_PORT_NUMS.keys():
                service = VULN_PORT_NUMS[dst_port]

                # Gather info
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                src_port = pkt.sport
                timestamp = float(pkt.time)
                date_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

                entry = {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port, "date_time": date_time, }

                # Add only unique socket pairs
                if entry not in services_dict[service]:
                    services_dict[service].append(entry)
    
    # Remove services not utilized
    filtered_serv_dict = {serv: sum_lst for serv, sum_lst in services_dict.items() if sum_lst}
    
    return filtered_serv_dict

#---------------------Malicious Domains------------------
@timeit
def parse_dom_data(url):
    data = fetch_data(url)
    domain_lines = data.strip().split('\n')
    dom_set = {line.split(' ')[-1] for line in domain_lines} # set for faster iteration
    
    return dom_set

@timeit
def is_dom_suspicious(capture, dom_set):
    '''
    This is a docstring for is_dom_suspicious.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.
    - data: A string of multiple known malicious domains. 

    Returns:
    A list comprised of dictionaries with src_ip, dst_ip, domain_name, and datetime of the incident.
    '''
    sus_entries = []

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
            for mal_dom in dom_set:
                if domain == mal_dom:
                    timestamp = float(pkt.time)
                    date_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                    
                    entry = {"src_ip": ip_layer.src, "dst_ip": ip_layer.dst, "domain_name": domain, "date_time": date_time}

                    if entry not in sus_entries:
                        sus_entries.append(entry)

    return sus_entries

#---------------------Malicious IPs------------------
@timeit
def is_ip_suspicious(capture, data4, data6):
    sus_entries = []
    # Parse data into set for faster iteration
    mal_ipv4 = set(data4.splitlines()) # IPv4 addresses
    mal_ipv6 = set([line.split(';')[0].strip() for line in data6.splitlines()]) # IPv6 address prefixes
    mal_ipv6.remove('')
    mal_ipv6_nets = [IPv6Network(ipv6_prefix) for ipv6_prefix in mal_ipv6] # IPv6 Networks

    for pkt in capture:
        # Handles IPv4 addresses
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            if src_ip in mal_ipv4 or dst_ip in mal_ipv4:

                mal_ip = src_ip if src_ip in mal_ipv4 else dst_ip
                entry = {"mal_ip": mal_ip, "src_ip": src_ip, "dst_ip": dst_ip} # Handles cases like ICMP where no port number concept exists
                    # Get port numbers
                if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                    # Resolve service names if they exist
                    src_port = resolve_service(pkt.sport)
                    dst_port = resolve_service(pkt.dport)
                
                    entry = {"mal_ip": mal_ip, "src_ip": src_ip, "dst_ip": dst_ip, 'src_port': src_port, 'dst_port': dst_port}

                if entry not in sus_entries:
                    sus_entries.append(entry)

        # Handles IPv6 Addresses
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]
            src_ip = IPv6Address(ip_layer.src)
            dst_ip = IPv6Address(ip_layer.dst)

            for net in mal_ipv6_nets:
                if src_ip in net or dst_ip in net:

                    mal_ip = src_ip if src_ip in net else dst_ip
                    entry = {"mal_ip": str(mal_ip), "src_ip": str(src_ip), "dst_ip": str(dst_ip)} # Handles cases like ICMP where no port number concept exists
                
                    # Get port numbers
                    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                        # Resolve service names if they exist
                        src_port = resolve_service(pkt.sport)
                        dst_port = resolve_service(pkt.dport)
                    
                        entry = {"mal_ip": str(mal_ip), "src_ip": str(src_ip), "dst_ip": str(dst_ip), 'src_port': src_port, 'dst_port': dst_port}

                    if entry not in sus_entries:
                        sus_entries.append(entry)

    return sus_entries

#---------------------(D)DoS Attacks-----------------
# Ping-of-Death
@timeit
def get_offsets(capture):
    '''
    Parameters:
        - capture: The Scapy's PacketList obj from the uploaded PCAP file.

    Returns:
    Dictionary with IPv4 identification nums as keys & list of offets as values
    '''
    offset_dict = {}
    for pkt in capture:
        # Check if packet has ip layer 
        if IP in pkt:
            ip_layer = pkt[IP]

            # Check if packet has MF(more fragments flag) && next proto is ICMP
            if ip_layer.flags == 1 and ip_layer.proto == 1:
                frag_offset = ip_layer.frag

                if ip_layer.id not in offset_dict:
                    offset_dict[ip_layer.id] = [frag_offset]
                else:
                    offset_dict[ip_layer.id].append(frag_offset)

    for id, offset_lst in offset_dict.items():
        # Calculate the offset interval to add the final offset that does not contain MF flag
        offset_interval = {offset_lst[i + 1] - offset_lst[i] for i in range(len(offset_lst) - 1)}.pop()
        # Add final offset
        offset_lst.append(offset_lst[-1] + offset_interval)
    
    return offset_dict

@timeit
def get_total_size(capture, offsets):
    '''
    Parameters:
        - capture: The Scapy's PacketList obj from the uploaded PCAP file.
        - offsets: Dictionary IPv4 IDS and list of offsets
        
    Returns:
    Dictionary with IPv4 identification nums as keys & int of total packet size as value.
    '''
    frag_sums = {}
    for pkt in capture:
        if IP in pkt:
            ip_layer = pkt[IP]

            # Iterate through the IPv4 Identification numbers
            for id, offset_lst in offsets.items():
                # Match the Identification
                if ip_layer.id == id:
                    # Iterate through the offsets for that id
                    for offset in offset_lst:
                        # Match the offset
                        if ip_layer.frag == offset:
                            # Get payload size
                            payload_size = len(ip_layer.payload)

                            # Initiate/ Update the byte sums 
                            if id not in frag_sums:
                                frag_sums[id] = payload_size
                            else:
                                frag_sums[id] += payload_size

    for id, sum in frag_sums.items():
        # Add IP & Ether headers
        frag_sums[id] += (20 + 14)
    
    return frag_sums

@timeit
def PoD_detect(capture, size_sums, alerts):
    '''
    Parameters:
        - capture: The Scapy's PacketList obj from the uploaded PCAP file.
        - size_sums: Dictionary with IPv4 Ids and int of total packet size.

    Updates:
    List with alert messages including Src, Dst IP addreses and Time of the incident.
    '''   
    # Check for oversized un-fragmented ICMP packets
    for pkt in capture:
        if pkt.haslayer(ICMP):
            # Check for Echo Request explicitly
            if pkt[ICMP].type == 8:
                pkt_size = len(pkt)

                # Check if it exceeds maximum packet size
                if pkt_size > 65535:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    timestamp = float(pkt.time)
                    date_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                    alert_msg = {'type':'Ping of Death','src_ip':src_ip,'dst_ip':dst_ip, 'start_time':date_time, 'size': pkt_size}

                    alerts.append(alert_msg)

    # Iterate through fragmented packet sums
    for id, sum in size_sums.items():
        # Check if it exceeds maximum packet size
        if sum > 65535:
            for pkt in capture:
                # Check for ICMP in packet 
                if ICMP in pkt:
                    ip_layer = pkt[IP]
                    # Check for the Echo Request only(dont add all the IPv4 fragments or the ICMP replies) AND a fragmented request to be exact
                    if ip_layer.id == id and pkt[ICMP].type == 8 and ip_layer.flags == 1:

                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        timestamp = float(pkt.time)
                        date_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                        alert_msg = {'type':'Ping of Death','src_ip':src_ip,'dst_ip':dst_ip, 'start_time':date_time, 'size': sum}

                        alerts.append(alert_msg)

# Flood Attacks
def grouping(pkt, current_group, current_group_start_time, grouped_packets, time_threshold):
    '''
    This is a docstring for grouping.

    Parameters:
    - pkt: Scapy's Packet obj.
    - current_group: Scapy's PacketList obj
    - current_group_start_time: A float for timestamp
    - grouped_packets: An empty list for storing PacketList objs
    - time_threshold: An integer representing seconds. 

    Returns:
    A list comprised of PacketList() objects each containing ICMP Echo Requests in time_threshold groups.
    '''   

    if current_group_start_time is None:
        # 1st Initialization
        current_group.append(pkt)
        current_group_start_time = pkt.time
    # Perform floating operations with Decimal to avoid precision errors
    elif Decimal(pkt.time) - Decimal(current_group_start_time) > time_threshold:
        # Threshold is exceeded
        grouped_packets.append(current_group)  # Group to list of groups
        current_group = PacketList()  # Create new group
        current_group.append(pkt)  # Add that pkt to new group
        current_group_start_time = pkt.time  # Initialize time of new group
    else:
        # Threshold not exceeded
        current_group.append(pkt)

    return current_group, current_group_start_time, grouped_packets

@timeit
def time_group(capture, time_threshold):
    '''
    This is a docstring for time_group.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.
    - time_threshold: An integer representing seconds. 

    Returns:
    A list comprised of PacketList() objects each containing groups based on protocols and time_threshold.
    '''   
    grouped_packets = []

    # Sort packets based on timestamp
    sorted_packets = sorted(capture, key=lambda x: x.time)

    current_group = PacketList()
    current_group_start_time = None

    for pkt in sorted_packets:
        # Check for ICMP packets
        if ICMP in pkt:
            icmp_layer = pkt[ICMP]
            # Filter for Echo Request ICMP packets
            if icmp_layer.type == 8:
               current_group, current_group_start_time, grouped_packets = grouping(pkt, current_group, current_group_start_time, grouped_packets, time_threshold)
        # Check for UDP packets
        if UDP in pkt:
            current_group, current_group_start_time, grouped_packets = grouping(pkt, current_group, current_group_start_time, grouped_packets, time_threshold)
        # Check for TCP packets
        if TCP in pkt:
            tcp_layer = pkt[TCP]
            # Filter for SYN tcp packets
            if tcp_layer.flags == 'S':
                current_group, current_group_start_time, grouped_packets = grouping(pkt, current_group, current_group_start_time, grouped_packets, time_threshold)
        
    # Append last group
    grouped_packets.append(current_group)
    
    return grouped_packets        

@timeit
def flood_detect(time_groups, pkt_threshold):
    '''
    This is a docstring for flood_detect.

    Parameters:
    - time_groups: List of PacketList() objects.
    - pkt_threshold: An integer representing number of packets threshold. 

    Returns:
    A dictionary comprised of dictionaries with type_of_attack, src_ip, dst_ip, dst_port, and datetime of the incident, (num of packets).
    '''
    potential_floods = {}
    for group in time_groups:
        group_num = time_groups.index(group)
        for pkt in group:
            if IP in pkt:
                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                timestamp = float(pkt.time)
                date_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

                # Destination port is almost always specific
                dst_port = ip_layer.dport if TCP in pkt else None

                proto = PROTOCOL_NUMS[ip_layer.proto]


                # Set potential flood identifier
                flood_id = f'{src_ip}{dst_ip}{group_num}' # Takes into account src, dst, and time

                # Add flood entry if it doesnt exist
                if flood_id not in potential_floods:
                    potential_floods[flood_id] = {'type':f'{proto} Flood', 'src_ip': src_ip, 'dst_ip': dst_ip, 'dst_ports': [dst_port],'start_time': date_time, 'count': 1}
                else:
                    # Increase pkt counter otherwise
                    potential_floods[flood_id]['count'] += 1
                    # Add dst_port if it isnt in list
                    port_lst =potential_floods[flood_id]['dst_ports'] 
                    if dst_port not in port_lst:
                        port_lst.append(dst_port)

    # Gather all keys of the values that do not surpass the threshold   
    entries_to_remove = []
    for id, flood in potential_floods.items():
        if flood['count'] < pkt_threshold:
            # Remove flood entry withing threshold
            entries_to_remove.append(id)
        # Need to check for port scan cases(1:N) and remove them
        if len(flood['dst_ports']) > 1: 
            entries_to_remove.append(id)

    # Remove those entries
    for id in entries_to_remove:
        potential_floods.pop(id, None)
    

    return potential_floods

@timeit
def generate_alerts(entries, alerts):
    '''
    Updates:
    The alerts list FOR NOW
    '''
    for id, entry in entries.items():
        alert_msg = entry
        alerts.append(alert_msg)
    
#---------------------Port Scans-----------------
@timeit
def port_scan_detect(time_groups, port_threshold):
    '''
    This is a docstring for port_scan_detect.

    Parameters:
    - time_groups: List of PacketList() objects.
    - port_threshold: An integer representing number of ports threshold. 

    Returns:
    A dictionary comprised of dictionaries with src_ip, dst_ip, dst_ports(list), and datetime of the incident.
    '''
    port_scans = {}

    # Group ports targeted by IPs initiating SYN requests 
    for group in time_groups:
        group_num = time_groups.index(group)
        for pkt in group:
            if TCP in pkt:
                ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                dst_port = ip_layer.dport
                timestamp = float(pkt.time)
                date_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

                tcp_layer = pkt[TCP]
                # If TCP SYN request is sent add dst port to lst
                if tcp_layer.flags == 0x02:

                    # Set potential flood identifier
                    scan_id = f'{src_ip}{dst_ip}{group_num}'
                    # Add src ip and its trageted destination ports
                    if scan_id not in port_scans:
                        port_scans[scan_id] = {'src_ip':src_ip, 'dst_ip': dst_ip, 'dst_ports':[dst_port], 'start_time': date_time }
                    else:
                        port_lst =  port_scans[scan_id]['dst_ports']
                        if dst_port not in port_lst:
                            port_lst.append(dst_port)


    # Gather all keys of the values that do not surpass the threshold 
    entries_to_remove = []
    for id, details in port_scans.items():
        if len(details['dst_ports']) <= port_threshold:
            entries_to_remove.append(id)

    # Remove those entries
    for id in entries_to_remove:
        port_scans.pop(id, None)

    return port_scans

#---------------------HTTP Inspection-----------------
@timeit
def check_agent(file_path, agent):

    with open(os.path.join(settings.STATICFILES_DIRS[0], file_path), newline='') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        
        for row in csv_reader:
            if row['http_user_agent'] == agent:
                return {'name': row['http_user_agent'], 'description':row['metadata_description'], 'category': row['metadata_category'], 'severity': row['metadata_severity']}

    return None


def get_path(packet):
    path = packet[HTTPRequest].Path 

    return path.decode('utf-8', errors='replace')

def get_url(packet):    
    host = packet[HTTPRequest].Host
    path = packet[HTTPRequest].Path

    url = host.decode('utf-8', errors='replace') + path.decode('utf-8', errors='replace')

    return url

def get_method(packet):
    method = packet[HTTPRequest].Method

    return method.decode('utf-8', errors='replace')

def get_agent(packet):
    agent = packet[HTTPRequest].User_Agent
    if agent != None:
        return agent.decode('utf-8', errors='replace')

# Scapy by default only includes ports 80 and 8080 for http
bind_layers(TCP, HTTP, sport=5000)
bind_layers(TCP, HTTP, dport=5000)
bind_layers(TCP, HTTP, sport=8000)
bind_layers(TCP, HTTP, dport=8000)

@timeit
def http_inspect(capture, dom_set):
    # Capture a packet list of all TCP communications
    # tcp_sessions = sniff(offline=capture, session=TCPSession)

    http_entries = {}

    for pkt in capture:

        if pkt.haslayer(HTTPRequest):

            # # Prepare neutral entry
            # entry = {'method':None, 'agent':None, 'url':None, 'file':None, 'creds':None}

            # Gather HTTP info
            method = get_method(pkt)
            url = get_url(pkt)
            agent = get_agent(pkt)
            path = get_path(pkt)

            entry = {'info':{'method':method, 'agent':agent, 'url':url}, 'mal':{'method':None, 'agent':None, 'url':None, 'file':None, 'credentials':None}}

            # Check for potentially dangerous HTTP Methods
            if method in SUS_METHODS:
                entry['mal']['method'] = method

            # Check for malicious user agents
            entry['mal']['agent'] = check_agent(AGENTS_CSV, agent)

            # Check for malicious domain in URL
            for dom in dom_set:
                if dom in url:
                    entry['mal']['url'] = (dom, url)

            # Check for potentially dangerous file requested
            for ext in FILE_EXTENSIONS:
                if ext in path:
                    # Get file name
                    file = path[path.rfind('/')+1:]
                    entry['mal']['file'] = file

            # Check for credentials       
            if method == 'POST':
                payload = pkt[Raw].load.decode('utf-8', errors='replace')

                # Username/ Password possibly related keywords
                keywords = {"uname", "username", "user", "pass", "password", "login", "Email"}

                for keyword in keywords:
                    if keyword in payload:
                        # TODO: Provide a more parsed version
                        entry['mal']['credentials'] = payload

            # If the malicious part of the entry has at least one suspicious value add it to the dict
            if any(val != None for val in entry['mal'].values()):
                timestamp = float(pkt.time)
                socket_pair = f'{pkt[IP].src}:{pkt[TCP].sport}-->{pkt[IP].dst}:{pkt[TCP].dport} at {timestamp}'
                # Identifier of sockeet pair and timestamp
                id = socket_pair
                http_entries[id] = entry

    
    return http_entries


#---------------------DGA Detection-----------------
@timeit
def detect_dga(capture, nx_threshold):
    '''
    This is a docstring for detect_dga.

    Parameters:
    - capture: The Scapy's PacketList obj from the uploaded PCAP file.
    - nx_threshold: An integer representing number of nx domains allowed.  

    Returns:
    A dictionary comprised of IP addresses and theire repsective occurence counts.
    '''
    sus_ips_count = Counter()
    sus_ips_lst = []

    for pkt in capture:
        if pkt.haslayer(DNS):
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]

            dns_layer = pkt[DNS]

            # Check if its 1. query, 2. response code non-existent domain
            if dns_layer.qr == 1 and dns_layer.rcode == 3:
                
                # Get the IP it attempts to contact
                dst_ip = ip_layer.dst

                sus_ips_lst.append(dst_ip)
    
    sus_ips_count.update(sus_ips_lst)

    sus_ips_dict = {}
    # Filter IPs base on threshold
    for ip, count in sus_ips_count.items():
        if count >= nx_threshold:
            sus_ips_dict[ip] = count


    return sus_ips_dict
