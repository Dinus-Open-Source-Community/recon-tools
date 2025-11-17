from django.urls import path
from . import views

urlpatterns = [
    path('', views.sicon_tool, name='sicon_tool'),
    path('shared/<uuid:share_token>/', views.shared_scan_page, name='shared_scan_page'),
    path('api/scans/start/', views.start_scan_api, name='start_scan'),
    path('api/scans/', views.list_scans_api, name='list_scans'),
    path('api/scans/<str:scan_id>/', views.scan_status_api, name='scan_status'),
    path('api/scans/<str:scan_id>/share/', views.create_share_link_api, name='create_share_link'),
    path('api/scans/<str:scan_id>/revoke/', views.revoke_share_link_api, name='revoke_share_link'),
    path('api/scans/shared/<uuid:share_token>/', views.shared_scan_api, name='shared_scan'),
    path('api/health/', views.health_check_api, name='health_check'),
]