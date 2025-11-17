from django.urls import path
from . import views

urlpatterns = [
    path('', views.nslookup_tool, name='nslookup'),
    path('api/', views.nslookup_api, name='nslookup_api'),
]