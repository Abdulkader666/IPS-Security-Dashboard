# monitor/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('',             views.dashboard,  name='dashboard'),   # الصفحة الرئيسية
    path('api/alerts/',  views.api_alerts, name='api_alerts'),  # JSON API
]
