from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("scan/", views.scan, name="scan"),
    path("report/<int:pk>/", views.report, name="report"),
    path("history/", views.history, name="history"),
]
