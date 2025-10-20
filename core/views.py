from django.shortcuts import render
from .models import User
from .Serializers import registerSerializer, loginSerializer
from rest_framework.views import APIView 
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework import permissions

class registerView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        serializer = registerSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        refresh = RefreshToken.for_user(serializer.instance)
        access = refresh.access_token

        return Response({
            "message": "User registered successfully",
            "refresh": str(refresh),
            "access": str(access)
        }, status=201)

class loginView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        serializer = loginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        return Response({
            "message": "Login successful",
            "refresh": str(refresh),
            "access": str(access)
        }, status=200)

