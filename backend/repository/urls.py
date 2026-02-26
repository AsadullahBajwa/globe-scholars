from django.urls import path
from . import views

urlpatterns = [
    # Upload
    path('upload/', views.ScholarlyWorkUploadView.as_view(), name='work-upload'),
    
    # List and Detail
    path('', views.ScholarlyWorkListView.as_view(), name='work-list'),
    path('<int:pk>/', views.ScholarlyWorkDetailView.as_view(), name='work-detail'),
    
    # Download and Delete
    path('<int:pk>/download/', views.ScholarlyWorkDownloadView.as_view(), name='work-download'),
    path('<int:pk>/delete/', views.ScholarlyWorkDeleteView.as_view(), name='work-delete'),
    
    # Reactions
    path('<int:pk>/react/', views.ReactToWorkView.as_view(), name='work-react'),
    
    # Conversion Status
    path('<int:pk>/conversion-status/', views.ConversionStatusView.as_view(), name='conversion-status'),
]