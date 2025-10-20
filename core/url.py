
from django.urls import path
from .views import registerView, loginView


urlpatterns = [
  #regester and login urls
    path('register/', registerView.as_view(), name='register'),
    path('login/', loginView.as_view(), name='login'),


]