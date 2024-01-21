from django.contrib import admin
from django.urls import path, include

from django.conf import settings
from django.conf.urls.static import static

from analyzer import views

urlpatterns = [
    # Analyzer URLs
    path('analyzer/', include("analyzer.urls")),
    # Homepage URL
    path('', views.index, name="index"),
    # Admin panel URL
    path('admin/', admin.site.urls),
]



if settings.DEBUG:
  urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)