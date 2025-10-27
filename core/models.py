from django.db import models
from django.contrib.auth.models import  AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone
import uuid
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey


""" this class is used  to makee custom user model"""
class UserManager(BaseUserManager):
    """this method used every time we need to create a new user"""
    def create_user(self, username , email=None, phone_number=None, password=None , first_name=None, last_name=None , **extra_fields):
        if not username:
            raise ValueError("Username is required")
        user = self.model(
            username=username,
            phone_number=phone_number,
            email=self.normalize_email(email),
            first_name= first_name,
            last_name= last_name,
            **extra_fields
          
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
    first_name = models.CharField(max_length=30, null=True, blank=True)
    last_name = models.CharField(max_length=30, null=True, blank=True)
    username = models.CharField(max_length=150, unique=True, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    last_login = models.DateTimeField(null=True, blank=True)
    account_locked = models.BooleanField(default=False)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    fail_login_attempts = models.IntegerField(default=0)
    is_deleted = models.BooleanField(default=False)
    
    date_joined = models.DateTimeField(default=timezone.now)
    referral_code = models.CharField(max_length=32, unique=True, null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'phone_number']

    def __str__(self):
        return self.phone_number if self.phone_number else self.email
    
class AuditLog(models.Model):
    ACTION_CHOICES = (
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('PASSWORD_CHANGE', 'Password Change'),
        ('FAILED_LOGIN', 'Failed Login Attempt'),
    )

    # Who performed the action
    user = models.ForeignKey('User', on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)  # Changed from user_ip to ip_address
    user_agent = models.TextField(null=True, blank=True)  # Added user_agent field
    
    # What action was performed
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    success = models.BooleanField(default=True)  # Added success field
    
    # When the action was performed
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # On which model/object the action was performed
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True)
    object_id = models.UUIDField(null=True)
    content_object = GenericForeignKey('content_type', 'object_id')
    
    # Additional details
    changes = models.JSONField(null=True, blank=True)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, default='SUCCESS')
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['action']),
            models.Index(fields=['user']),
            models.Index(fields=['content_type', 'object_id']),
        ]

    def __str__(self):
        return f"{self.action} by {self.user} at {self.timestamp}"
