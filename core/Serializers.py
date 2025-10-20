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




class registerSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True , required=True , min_length=8 , help_text="Password must be at least 8 characters long")
    confirm_password = serializers.CharField(write_only=True , required=True)
    first_name = serializers.CharField(required=True , max_length=150 , min_length=5 , trim_whitespace=True)
    last_name = serializers.CharField(required=True , max_length=150 , min_length=5 , trim_whitespace=True)
    email = serializers.EmailField(required=True , validators=[EmailValidator()])


    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'confirm_passworf', 'phone_number']
        extra_kwargs = {
            'phone_number': {'required': True,
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
                    phone_number=validated_data['phone_number'],
                    email=validated_data['email'].lower(),
                    password=validated_data['password'],
                    first_name=validated_data['first_name'].strip(),
                    last_name=validated_data['last_name'].strip(),
                    is_active=True,
                    is_deleted=False,
                )
            
            """ Generate a unique referral code for the user """
            user.referral_code = secrets.token_urlsafe(8)
            user.save()


            """ Log user creation """
            logger.info(
                    f'User registered: {user.phone_number}',
                    extra={'user_id': str(user.id)}
                )
            
            return user
        except Exception as e:
            logger.error(f'Registration error: {str(e)}')
            raise serializers.ValidationError(
                "Registration failed. Please try again."
            )
        

                
class loginSerializer(serializers.Serializer):
    phone_number = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['phone_number', 'password']

    def validate(self, data):
        phone_number = data.get('phone_number')
        password = data.get('password')

        if phone_number and password:
            user = authenticate(phone_number=phone_number, password=password)
            if not user:
                raise serializers.ValidationError("Invalid credentials username or password")
            if not user.is_active:
                raise serializers.ValidationError("User account is disabled")
            data['user'] = user
            return data
        else:
            raise serializers.ValidationError("Both username and password are required")
        


