
from django.urls import path
from .views import registerView, loginView, VerifyEmailView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,

)


urlpatterns = [
  #regester and login urls
    path('auth/register/', registerView.as_view(), name='register'),
    path('auth/login/', loginView.as_view(), name='login'),
  path('auth/verify-email/', VerifyEmailView.as_view(), name='verify-email'),

    
     # JWT token urls 

    path('auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),




]