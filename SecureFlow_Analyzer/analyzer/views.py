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

            # Extract specific threshold values if provided
            dos_pkt_thres = form.cleaned_data['dos_pkt_thres']
            dos_time_thres = form.cleaned_data['dos_time_thres']
            scan_port_thres = form.cleaned_data['scan_port_thres']
            scan_time_thres = form.cleaned_data['scan_time_thres']

            # Extract PacketList from pcap
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(get_capture, file_path)
                capture = future.result()
        

            #TODO: Run analysis and assign results to context
            protocols = get_protocols(capture)
            services = get_services(capture)
            convos = get_convos(capture)
            top_talkers = get_top_talkers(capture)
            band_traffic = get_traffic(capture)
            ip_coords = get_coordinates(capture)


            context = {
                'analysis':{
                    'protocols': protocols,
                    'services': services,
                    'conversations': convos,
                    'ip_coords': ip_coords
                },
                'anomaly':{
                    'dos_pkt_thres' : dos_pkt_thres,
                    'dos_time_thres' : dos_time_thres,
                    'scan_port_thres' : scan_port_thres,
                    'scan_time_thres' : scan_time_thres,
                }
            }

            # Make sure not to plot an empty dict
            if len(protocols) != 0:
                proto_graph_pie = visualize_protocols(protocols)
                context['analysis']['proto_graph_pie'] = proto_graph_pie

            if len(services) !=0:
                serv_graph_bar = visualize_services(services)
                context['analysis']['serv_graph_bar'] = serv_graph_bar

            if len(top_talkers) != 0:
                band_util_hbar = visualize_top_talkers(top_talkers)
                context['analysis']['band_util_hbar'] = band_util_hbar

            if len(band_traffic) != 0:
                band_util_tseries = visualize_traffic(band_traffic)
                context['analysis']['band_util_tseries'] = band_util_tseries

            #TODO: Run anomaly detection and assign results to context
            vuln_services = get_vuln_services(capture)
            context['anomaly']['vuln_services'] = vuln_services

            mal_doms = fetch_data(MALICIOUS_DOMAINS_URL)
            sus_dom_entries = is_dom_suspicious(capture, mal_doms)
            context['anomaly']['sus_dom_entries'] = sus_dom_entries

            mal_ipv4 = fetch_data(MALICIOUS_IP_URL)
            mal_ipv6 = fetch_data(MALICIOUS_IPV6_URL)
            sus_ip_entries = is_ip_suspicious(capture, mal_ipv4, mal_ipv6)
            context['anomaly']['sus_ip_entries'] = sus_ip_entries
            
            dos_alerts = []
            # PoD
            offset_dict = get_offsets(capture)
            frag_sums = get_total_size(capture, offset_dict)
            PoD_detect(capture, frag_sums, dos_alerts)
            # Flood Attacks
            groups = time_group(capture, dos_time_thres)
            floods = flood_detect(groups, dos_pkt_thres)
            generate_alerts(floods, dos_alerts)

            context['anomaly']['dos_alerts'] = dos_alerts
            
            # Port Scans
            scan_alerts = []
            groups = time_group(capture, scan_time_thres)
            scans = port_scan_detect(groups, scan_port_thres)
            generate_alerts(scans, scan_alerts)

            context['anomaly']['scan_alerts'] = scan_alerts

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