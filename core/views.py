from django.shortcuts import render
from .models import User
from .Serializers import registerSerializer, loginSerializer, userSerializer , changePasswordSerializer
from rest_framework.views import APIView 
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework import permissions
from .models import AuditLog
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
import logging
logger = logging.getLogger('auth')
from django.db import transaction
from .throttles import loginThrottle
from .utils import verify_verification_token
from django.core import signing




class registerView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        serializer = registerSerializer(data=request.data)
        if  serializer.is_valid(raise_exception=True):
            user = serializer.save()

            AuditLog.objects.create(
                user=user,
                action='User Registration',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
            )

       

        return Response({
            "message": "User registered successfully",
        }, status=201)
    
    """method to get client ip address"""
    @staticmethod
    def get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    

class loginView(APIView):
    permission_classes = [permissions.AllowAny]
    throttle_classes = [loginThrottle]
    
    def post(self, request):
        serializer = loginSerializer(data=request.data)
        if not serializer.is_valid():
            """ Log failed login attempt """
            AuditLog.objects.create(
                user=None,
                action='Failed Login Attempt',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=False

            )
            return Response(serializer.errors, status=400)
        
        user = serializer.validated_data['user']
        
        """ Log successful login """
        AuditLog.objects.create(
            user=user,
            action='Successful Login',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )        

        refresh = RefreshToken.for_user(user)
        access = refresh.access_token 

        return Response({
            "message": "Login successful",
            "refresh": str(refresh),
            "access": str(access),
            "user": userSerializer(user).data
        }, status=200)
    
    @staticmethod
    def get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    """ Logout View """
class logoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """ Log logout action if logout is successful"""
        try:
            AuditLog.objects.create(
                user=request.user,
                action='Logout',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
            )
            return Response({"message": "Logout successful"}, status=200)
        except Exception as e:
            logger.exception("Failed to write AuditLog for logout")
            return Response({"error": str(e)}, status=400)
        
    """method to get client ip address"""
    @staticmethod
    def get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
class changePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    """ View to change user password """
    def post(self , request):
        serializer  = changePasswordSerializer(data=request.data , context={'request':request})
        if not serializer.is_valid():
            return Response(serializer.errors ,status=400)
        
        user = request.user
        new_password = serializer.validated_data['new_password']

        """ Change the user's password and log the action """
        try:
            with transaction.atomic():
                user.set_password(serializer.validated_data['new_password'])
                user.save()
                AuditLog.objects.create(
                    user=user,
                    action='Password Change',
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                )
        except Exception as e:
            logger.exception("Failed to write AuditLog for password change")
            return Response({"error": str(e)}, status=400)
        return Response({"message":"Password changed successfully"}, status=200)


class VerifyEmailView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        token = request.query_params.get('token')
        if not token:
            return Response({"error": "Missing token"}, status=400)

        try:
            payload = verify_verification_token(token)
        except signing.SignatureExpired:
            return Response({"error": "Token expired"}, status=400)
        except signing.BadSignature:
            return Response({"error": "Invalid token"}, status=400)
        except Exception as e:
            return Response({"error": str(e)}, status=400)

        user_id = payload.get('user_id')
        try:
            user = User.objects.get(id=user_id, is_deleted=False)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)

        if user.is_verified:
            return Response({"message": "Account already verified"}, status=200)

        user.is_active = True
        user.is_verified = True
        user.save()

        # Log verification
        try:
            AuditLog.objects.create(
                user=user,
                action='Email Verified',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
            )
        except Exception:
            pass

        return Response({"message": "Email verified successfully"}, status=200)

       