from django.shortcuts import render

# Creating the communication with enviroment variables
import environ
env = environ.Env()
environ.Env.read_env()

# Lib used to create the generic views
from rest_framework import generics

# User model and serializer
from .models import User
from .serializers import UserSerializer

# Lib used to hash the password
from django.contrib.auth.hashers import make_password

from rest_framework.response import Response

# Lib used to raise errors on authentication
from rest_framework.exceptions import AuthenticationFailed

# JWT lib for managing the tokens and datetime for managing dates
import jwt, datetime


# User views bellow.


# View used for registering users
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


# View used for login users
class LoginUserView(generics.GenericAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed({'message': 'Usuário não encontrado!'})
        
        if not user.check_password(password):
            raise AuthenticationFailed({'message': 'Senha ou Usuário incorretos!'})
        
        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, env('SECRET_JWT'), algorithm='HS256')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token
        }

        return response

user_login_view = LoginUserView.as_view()


class SingleUserView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Usuário não autenticado!')
        
        try:
            payload = jwt.decode(token, env('SECRET_JWT'), algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Usuário não autenticado!')
        
        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)

        return Response(serializer.data)
 
user_detail_view = SingleUserView.as_view()


# View used for logout users
class LogoutUserView(generics.GenericAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'Logout realizado com sucesso!'
        }

        return response
    
user_logout_view = LogoutUserView.as_view()