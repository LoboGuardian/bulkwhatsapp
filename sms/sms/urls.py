

from django.urls import path,include
from django.contrib import admin
from smsapp import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.user_login, name='login'),
    path('dashboard/', views.user_dashboard, name='dashboard'),
   
    path('reset-password/', views.initiate_password_reset, name='initiate_password_reset'),
    path('otp-verification/<str:email>/<str:token>/', views.verify_otp, name='otp_verification'),
    path('change-password/<str:email>/<str:token>/', views.change_password, name='change_password'),
    path('whitelist/<int:whitelist_id>/',views.print_whitelist_file_data,name='whitelist'),   
]

