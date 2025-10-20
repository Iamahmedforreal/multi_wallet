from rest_framework import serializers 
from .models import User
from django.db import transaction
from django.contrib.auth import authenticate
from django.core.validators import EmailValidator 

class registerSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True , required=True , min_length=8 , helper_text="Password must be at least 8 characters long")
    confirm_password = serializers.CharField(write_only=True , required=True)
    first_name = serializers.CharField(required=True , max_length=150 , min_length=5 , trim_whitespace=True)
    last_name = serializers.CharField(required=True , max_length=150 , min_length=5 , trim_whitespace=True)
    email = serializers.EmailField(required=True , Validators=[EmailValidator()])


    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'confirm_passworf', 'phone_number']
        extra_kwargs = {
            'phone_number': {'required': True,
                             'help_text': 'Format: +[country code][number] (E.164)'},
        }
    
    """ this method is used to validate the password and confirm password """

    def validate(self, data):
        if data['password' ] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return data
    
    """ this method is used to validate the phone number """
    def validate_phone_number(self, value):
        if User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("Phone number already in use")
        return value
            
    
    def create(self, validated_data):
        validated_data.pop('confirm_password')
        first_name = validated_data.pop('first_name')
        last_name = validated_data.pop('last_name')
        
        with transaction.atomic():
            user = User.objects.create_user(**validated_data)
            return user
        
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
        


