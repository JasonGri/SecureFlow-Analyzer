from django.urls import path

from . import views

app_name = "analyzer" # App-specific url namespace
urlpatterns = [
    # /analyzer/
    path("", views.results, name="results")
]