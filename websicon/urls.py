from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', TemplateView.as_view(template_name='home.html'), name='home'),
    path('accounts/', include('accounts.urls')),
    path('dashboard/', TemplateView.as_view(template_name='dashboard.html'), name='dashboard'),
    path('whois/', include('whois_tool.urls')),
    path('nslookup/', include('dns_tool.urls')),
    path('ping/', include('ping_tool.urls')),
    path('sicon/', include('sicon_tool.urls')),
]