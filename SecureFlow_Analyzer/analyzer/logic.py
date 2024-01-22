'''
Here is where the logic will be placed, in more detail the functions analyzing the pcap file and returning their results.
'''
# Scapy
from scapy.all import *
from scapy.layers.inet import *

def get_capture(file_path):
    return rdpcap(file_path)
