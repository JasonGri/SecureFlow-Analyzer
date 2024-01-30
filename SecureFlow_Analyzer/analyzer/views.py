from django.shortcuts import render, redirect
from django.core.files.storage import default_storage

import concurrent.futures
import json

from .forms import PcapFileForm
from .logic import *

def index(req):
    if req.method == 'POST':
        form = PcapFileForm(req.POST, req.FILES)

        if form.is_valid():
            # Save the uploaded file to the media directory
            pcap_file = req.FILES['pcap_file']
            file_path = 'media/' + default_storage.save(f'pcap_files/{pcap_file.name}', pcap_file) # second half only returns the relative file path

            # Extract PacketList from pcap
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(get_capture, file_path)
                capture = future.result()
        

            #TODO: Run analysis and assign results to context
            protocols = get_protocols(capture)
            convos = get_convos(capture)
            top_talkers = get_top_talkers(capture)
            ip_coords = get_coordinates(capture)

            proto_graph_bar, proto_graph_pie = visualize_protocols(protocols)
            band_util_hbar = visualize_top_talkers(top_talkers)
            band_util_tseries = bandwidth_timeseries(capture)

            #TODO: Run anomaly detection and assign results to context

            context = {
                'analysis':{
                    'protocols': protocols,
                    'proto_graph_bar': proto_graph_bar,
                    'proto_graph_pie': proto_graph_pie,
                    'band_util_hbar': band_util_hbar,
                    'band_util_tseries': band_util_tseries,
                    'conversations': convos,
                    'ip_coords': ip_coords
                },
                'anomaly':{}
            }

            #Sets context in session for transfer to other views
            req.session['context'] = context

            return redirect('analyzer:results')

    else:
        form = PcapFileForm()
                
    return render(req, 'analyzer/index.html', {'form': form})

def results(req):
    return render(req, "analyzer/results.html")

def analysis(req):

    context = req.session['context'].get('analysis')

    return render(req, "analyzer/analysis.html", context)

def anomaly(req):

    context = req.session['context'].get('anomaly')

    return render(req, "analyzer/anomaly.html", context)