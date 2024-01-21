from django.shortcuts import render


def index(req):
    return render(req, 'analyzer/index.html')

def results(req):
    return render(req, "analyzer/results.html")