from django.shortcuts import render

# Lib used to create the generic views
from rest_framework import generics

from .models import User
from .serializers import UserSerializer

# Lib used to hash the password
from django.contrib.auth.hashers import make_password

from rest_framework.response import Response

# Lib used to raise errors on authentication
from rest_framework.exceptions import AuthenticationFailed

# Create your views here.

class RegisterUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        password = serializer.validated_data.get('password')

        if password is not None:
            hashed_pswd = make_password(password)
            serializer.save(password=hashed_pswd)

            return Response({
                'message': 'Usuário criado com sucesso!'
            })

user_register_view = RegisterUserView.as_view()