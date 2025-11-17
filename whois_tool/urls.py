from django.urls import path
from . import views

urlpatterns = [
    path('', views.whois_lookup, name='whois_lookup'),
    path('api/', views.whois_api, name='whois_api'),
]