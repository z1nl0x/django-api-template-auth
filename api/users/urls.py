from django.urls import path

from .import views

urlpatterns = [
    path('register', views.user_register_view),
    path('login', views.user_login_view),
    path('profile', views.user_detail_view),
    path('logout', views.user_logout_view),
]
