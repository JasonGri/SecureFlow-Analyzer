from django import forms
from django.core.validators import FileExtensionValidator


class PcapFileForm(forms.Form):
    pcap_file = forms.FileField(label="Please enter your .cap, .pcap, .pcapng file for analysis:",validators=[FileExtensionValidator( ['cap','pcap', 'pcapng'] ) ])
