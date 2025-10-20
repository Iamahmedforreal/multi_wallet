from django.db import models
from django.contrib.auth.models import  AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone
import uuid


""" this class is used  to makee custom user model"""
class UserManager(BaseUserManager):
    """this method used every time we need to create a new user"""
    def create_user(self, phone_number=None, email=None, password=None):
        if not phone_number and not email:
            raise ValueError("User must have either a phone number or email")
        user = self.model(
            phone_number=phone_number,
            email=self.normalize_email(email),
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
  
    def create_superuser(self, phone_number=None, email=None, password=None):
        user = self.create_user(phone_number, email, password)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user
    
class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    phone_number = models.CharField(max_length=15, unique=True, null=True, blank=True)
    email = models.EmailField(unique=True, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.phone_number if self.phone_number else self.email
    
