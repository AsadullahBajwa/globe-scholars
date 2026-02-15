from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

urlpatterns = [
    # Auth
    path('signup/',        views.SignupView.as_view(),       name='signup'),
    path('login/',         views.LoginView.as_view(),        name='login'),
    path('logout/',        views.LogoutView.as_view(),       name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(),       name='token-refresh'),

    # Own profile
    path('profile/',       views.ProfileView.as_view(),      name='profile'),

    # Scholars
    path('scholars/',      views.ScholarListView.as_view(),  name='scholar-list'),
    path('scholars/<int:pk>/',        views.ScholarDetailView.as_view(),   name='scholar-detail'),
    path('scholars/<int:pk>/export/', views.ProfileExportView.as_view(),   name='scholar-export'),
]