from django import forms
from django.core.validators import FileExtensionValidator


class PcapFileForm(forms.Form):
    pcap_file = forms.FileField(label="Please enter your .cap, .pcap, .pcapng file for analysis:",validators=[FileExtensionValidator( ['cap','pcap', 'pcapng'] ) ])

    dos_pkt_thres = forms.IntegerField(label="Packet Threshold", min_value=1)
    dos_time_thres = forms.FloatField(label="Time Threshold", min_value=0)

    scan_port_thres = forms.IntegerField(label="Port Threshold", min_value=0, max_value=65535)
    scan_time_thres = forms.FloatField(label="Time Threshold", min_value=0)

