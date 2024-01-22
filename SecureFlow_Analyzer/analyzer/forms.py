from django import forms



class PcapFileForm(forms.Form):
    pcap_file = forms.FileField(label="Please enter your .pcap file for analysis:")
