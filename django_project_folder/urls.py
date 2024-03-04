"""
URL configuration for django_project_folder project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from netflix_rest_api_app.views import RegistrationView, LoginAPIView, UserAPIView, RefreshAPIView, LogoutAPIView,EmailRequestForPasswordResetView,PasswordResetView,GoogleLoginApi

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/register/', RegistrationView.as_view()),
    path('auth/login/', LoginAPIView.as_view()),
    path('user/', UserAPIView.as_view()),
    path('auth/refresh', RefreshAPIView.as_view()),
    path('auth/logout', LogoutAPIView.as_view()),
    path('emailRequest/', EmailRequestForPasswordResetView.as_view()),
    path('auth/passwordReset/', PasswordResetView.as_view()),
    path("auth/login/google/", GoogleLoginApi.as_view(), 
         name="login-with-google")

]
