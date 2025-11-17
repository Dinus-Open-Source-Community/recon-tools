from django.urls import path
from . import views

urlpatterns = [
    path('', views.ping_tool, name='ping_tool'),
    path('api/', views.ping_api, name='ping_api'),
]