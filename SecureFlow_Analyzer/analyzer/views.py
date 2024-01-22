from django.shortcuts import render, redirect
from django.core.files.storage import default_storage

from .forms import PcapFileForm

def index(req):
    if req.method == 'POST':
        form = PcapFileForm(req.POST, req.FILES)

        if form.is_valid():
            # Save the uploaded file to the media directory
            pcap_file = req.FILES['pcap_file']
            file_path = 'media/' + default_storage.save(f'pcap_files/{pcap_file.name}', pcap_file) # second half only returns the relative file path

            
            return render(req, 'analyzer/results.html')

    else:
        form = PcapFileForm()
                
    return render(req, 'analyzer/index.html', {'form': form})

def results(req):
    return render(req, "analyzer/results.html")