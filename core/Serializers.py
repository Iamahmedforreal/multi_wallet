from rest_framework import serializers 
from .models import User
from django.db import transaction
from django.contrib.auth import authenticate
from django.core.validators import EmailValidator 
import re
import logging
logger = logging.getLogger('auth')
from django.contrib.auth.password_validation import validate_password
import secrets
from .models import User 
from django.utils import timezone
from datetime import timedelta
from .utils import send_verification_to_user




class registerSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True , required=True , min_length=8 , help_text="Password must be at least 8 characters long")
    confirm_password = serializers.CharField(write_only=True , required=True)
    first_name = serializers.CharField(required=True , max_length=150 , min_length=5 , trim_whitespace=True)
    last_name = serializers.CharField(required=True , max_length=150 , min_length=5 , trim_whitespace=True)
    email = serializers.EmailField(required=True , validators=[EmailValidator()])


    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username' , 'email', 'password', 'confirm_password', 'phone_number']
        extra_kwargs = {
            'phone_number': {
                             'help_text': 'Format: +[country code][number] (E.164)'},
        }
    
    
    """ this method is used to validate the phone number """
    def validate_phone_number(self, value):
         """
        Validate phone number format (E.164)
        Format: +[1-9]\d{1,14}
        Examples: +1234567890, +441234567890
        """
         
         if not re.match(r'^\+[1-9]\d{1,14}$', value):
             raise serializers.ValidationError("Phone number must be in E.164 format (e.g., +1234567890)")
         if User.objects.filter(phone_number=value , is_deleted=False).exists():
             raise serializers.ValidationError("Phone number already in use")
         
         return value
        
    """ this method is used to validate the email"""    
    def validate_email(self, data):

    #make the email lowercase
        data = data.lower()
        """ we checking if the email already exists"""

        if User.objects.filter(email=data , is_deleted=False).exists():
            logger.warning(f"Attempt to register with existing email: {data}")
            raise serializers.ValidationError("Email already in use")
        
        return data
    
    def validate_password(self, data):
         """
        Validate password strength
        Requirements:
        - At least 8 characters
        - At least 1 uppercase letter
        - At least 1 lowercase letter
        - At least 1 digit
        - At least 1 special character
        """
         

         """Use Django's built-in password validators"""
         try:
             validate_password(data)
         except Exception as e:
                raise serializers.ValidationError(str(e))
         
         """ Additional custom validations """
         if re.search(r'[A-Z]', data) is None:
            raise serializers.ValidationError("Password must contain at least one uppercase letter")
         if re.search(r'[a-z]', data) is None:
            raise serializers.ValidationError("Password must contain at least one lowercase letter")
         if re.search(r'[!@#$%^&*(),.?":{}|<>]', data) is None:
            raise serializers.ValidationError("Password must contain at least one special character")
         
         """ check for common passwords """

         common_passwords = ['password', '12345678', 'qwert"y', 'abc12345']
         if data.lower() in common_passwords:
                raise serializers.ValidationError("Password is too common")
        
         return data
    
    def validate(self, data):
        """ this method is used to validate the object level validation """


        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError("Password and Confirm Password do not match")
        
        """ Validate first_name and last_name are not white space """
        if not data.get('first_name'):
            raise serializers.ValidationError("First name is required")
        
        if not data.get('last_name'):
            raise serializers.ValidationError("Last name is required")
        
        return data
    

    def create(self, validated_data):

        validated_data.pop('confirm_password')
        
        try:
          with transaction.atomic():
            user = User.objects.create_user(
                    username=validated_data['username'],
                    phone_number=validated_data['phone_number'],
                    email=validated_data['email'].lower(),
                    password=validated_data['password'],
                    first_name=validated_data['first_name'].strip(),
                    last_name=validated_data['last_name'].strip(),
                    # Create inactive user until they verify their email
                    is_active=False,
                    is_deleted=False,
                )
            
            """ Generate a unique referral code for the user """
            user.referral_code = secrets.token_urlsafe(8)
            user.save()

            # Send verification email asynchronously
            try:
                send_verification_to_user(user)
            except Exception:
                # If sending fails, continue registration but user remains inactive
                logger.exception('Failed to enqueue verification email for user %s', user.id)


            """ Log user creation """
            logger.info(
                    f'User registered: {user.phone_number}',
                    extra={'user_id': str(user.id)}
                )
            
            return user
        except Exception as e:
            logger.error(f'Registration error: {str(e)}')
            raise serializers.ValidationError(
               str(e)
            )
        from datetime import timedelta




class loginSerializer(serializers.Serializer):
    """Authenticate user with security checks"""
    username = serializers.CharField(required=True, help_text="Enter your phone number")
    password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            raise serializers.ValidationError("Username and password are required.")

        # Find user
        try:
            user = User.objects.get(username=username, is_deleted=False)
        except User.DoesNotExist:
            logger.warning(f"Login attempt with non-existent username: {username}")
            raise serializers.ValidationError("Invalid username or password.")

        # Check if active
        if not user.is_active:
            logger.warning(f"Login attempt to inactive account: {username}")
            raise serializers.ValidationError("Account is inactive. Please contact support.")

        # Check if locked
        if user.account_locked_until and timezone.now() < user.account_locked_until:
            logger.warning(f"Login attempt to locked account: {username}")
            raise serializers.ValidationError("Account is locked. Try again later.")
        elif user.account_locked_until and timezone.now() >= user.account_locked_until:
            # Unlock if lock time expired
            user.fail_login_attempts = 0
            user.account_locked_until = None
            user.save()

        # Verify password
        if not user.check_password(password):
            user.fail_login_attempts += 1
            if user.fail_login_attempts >= 5:
                user.account_locked_until = timezone.now() + timedelta(minutes=10)
                user.save()
                logger.error(f"Account locked due to failed attempts: {username}")
                raise serializers.ValidationError("Account locked due to multiple failed attempts. Try again later.")
            user.save()
            logger.warning(f"Failed login attempt {user.fail_login_attempts} for username: {username}")
            raise serializers.ValidationError("Invalid username or password.")

        # Reset failed attempts on success
        if user.fail_login_attempts > 0:
            user.fail_login_attempts = 0
            user.account_locked_until = None
        user.last_login = timezone.now()
        user.save()

        data['user'] = user
        return data

    
class userSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'phone_number', 'email', 'first_name', 'last_name', 'date_joined', 'referral_code']
        read_only_fields = ['id', 'date_joined', 'referral_code']

class changePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True , min_length=8)
    confirm_new_password = serializers.CharField(write_only=True, required=True)
    class Meta:
        fields = ['old_password', 'new_password', 'confirm_new_password']

    def validate_new_password(self, data):
        try:
            validate_password(data)
        except Exception as e:
            raise serializers.ValidationError(str(e))
        
        if re.search(r'[A-Z]', data) is None:
            raise serializers.ValidationError("Password must contain at least one uppercase letter")
        if re.search(r'[a-z]', data) is None:
            raise serializers.ValidationError("Password must contain at least one lowercase letter")
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', data) is None:
            raise serializers.ValidationError("Password must contain at least one special character")
    
        return data
    
    """ this method is for checking old password"""
    def validate_old_password(self, data):
        user = self.context['request'].user
        if not user.check_password(data):
            raise serializers.ValidationError("Old password is incorrect")
        return data
    
    """ this method is for checking new password and confirm new password"""
    def validate(self, data):
       if data['new_password'] != data['confirm_new_password']:
              raise serializers.ValidationError("New password and Confirm new password do not match")
       return data
       


        
                
            
    