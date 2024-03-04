from django.shortcuts import render
from rest_framework.views import APIView
from netflix_rest_api_app.serializers import CustomUserSerializer 
from rest_framework.exceptions import APIException, AuthenticationFailed
from rest_framework import serializers
from netflix_rest_api_app.models import CustomUser
import jwt, datetime
from rest_framework.response import Response
from rest_framework.authentication import get_authorization_header
from rest_framework import status
import json
from netflix_rest_api_app.exceptions import CustomAPIException
from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import uuid
from django.contrib.auth.hashers import make_password
#from .mixins import PublicApiMixin, ApiErrorsMixin
from django.conf import settings
from urllib.parse import urlencode
from django.shortcuts import redirect
from .utils import google_get_access_token, google_get_user_info


#class GoogleLoginApi(PublicApiMixin, ApiErrorsMixin, APIView):
class GoogleLoginApi(APIView):
    class InputSerializer(serializers.Serializer):
            code = serializers.CharField(required=False)
            error = serializers.CharField(required=False)

    def get(self, request, *args, **kwargs):
        
        input_serializer = self.InputSerializer(data=request.GET)
        input_serializer.is_valid(raise_exception=True)

        validated_data = input_serializer.validated_data

        code = validated_data.get('code')
        error = validated_data.get('error')

        print(code,'1111111111111111111111111111111111d111111')


        login_url = f'{settings.BASE_FRONTEND_URL}/login'
    
        if error or not code:
            params = urlencode({'error': error})
            return redirect(f'{login_url}?{params}')

        redirect_uri = f'{settings.BASE_FRONTEND_URL}/google'
        print(code,'codeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee')
        print(redirect_uri,'11111111111111111111111112222222222222222222222')


        access_token = google_get_access_token(code=code, 
                                               redirect_uri=redirect_uri)
        print(access_token,'access tokennnnnnnnnnnnnnnnnnnnnnnnn')
        user_data = google_get_user_info(access_token=access_token)
        print(user_data,'user dataaaaaaaaaaaaaaaaaaaaaaaaa')

        if CustomUser.objects.filter(email=user_data['email']).exists():
        
            user = CustomUser.objects.get(email=user_data['email'])
            print(user,'userrrrrrrrrrrrrrrrrrrrrrrrr')
            '''create access token'''
            id  = user.id
            access_token = jwt.encode({
            'user_id': id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=1800),
            'iat': datetime.datetime.utcnow()
        }, 'access_secret', algorithm='HS256')
            
            '''create refresh token '''

            refresh_token = jwt.encode({
            'user_id': id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
            'iat': datetime.datetime.utcnow()
        }, 'refresh_secret', algorithm='HS256')

            response = Response()
            '''place refresh token inside cookie and hide it http only'''
            response.set_cookie(key='refreshToken', value= str(refresh_token), httponly=True)
            #response.set_cookie(key='refreshToken', value=refresh_token)
            '''place the access token as dictionary inside response data'''
            response.data = {
                'access_token': str(access_token),
                'id':id,
                'username':user.username,
                'email':user.email
            }
            return response
        else:
            print('came into excepttttttttttttttttttttttttttt')
            email = user_data['email']
            print('came here alsooooooooooooooooooooooooooooo')
            username = user_data['given_name']
            #last_name = user_data.get('family_name', '')
            print('sssssssssssssssssssssssssssssssssssssssssssssssssss')
            user = CustomUser.objects.create(
                username=username,
                email=email,
                #registration_method='google',
                #phone_no=None,
                #referral=None
            )
            print('yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy')
            '''create access token'''
            id  = user.id
            access_token = jwt.encode({
            'user_id': id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=1800),
            'iat': datetime.datetime.utcnow()
        }, 'access_secret', algorithm='HS256')
            
            '''create refresh token '''

            refresh_token = jwt.encode({
            'user_id': id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
            'iat': datetime.datetime.utcnow()
        }, 'refresh_secret', algorithm='HS256')

        #saved_user = CustomUserSerializer(user)
        #print(saved_user)   

            response = Response()
            '''place refresh token inside cookie and hide it http only'''
            response.set_cookie(key='refreshToken', value= str(refresh_token), httponly=True)
            #response.set_cookie(key='refreshToken', value=refresh_token)
            '''place the access token as dictionary inside response data'''
            response.data = {
                'access_token': str(access_token),
                'id':id,
                'username':user.username,
                'email':user.email
            }
            # response_data = {
            #     'user': CustomUserSerializer(user).data,
            #     'access_token': str(access_token),
            #     'refresh_token': str(refresh_token)
            # }
            return response


# #class GoogleLoginApi(PublicApiMixin, ApiErrorsMixin, APIView):
# class GoogleLoginApi(APIView):
#     class InputSerializer(serializers.Serializer):
#             code = serializers.CharField(required=False)
#             error = serializers.CharField(required=False)

#     def get(self, request, *args, **kwargs):
        
#         input_serializer = self.InputSerializer(data=request.GET)
#         input_serializer.is_valid(raise_exception=True)

#         validated_data = input_serializer.validated_data

#         code = validated_data.get('code')
#         error = validated_data.get('error')

#         print(code,'1111111111111111111111111111111111d111111')


#         login_url = f'{settings.BASE_FRONTEND_URL}/login'
    
#         if error or not code:
#             params = urlencode({'error': error})
#             return redirect(f'{login_url}?{params}')

#         redirect_uri = f'{settings.BASE_FRONTEND_URL}/google'
#         print(code,'codeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee')
#         print(redirect_uri,'11111111111111111111111112222222222222222222222')


#         access_token = google_get_access_token(code=code, 
#                                                redirect_uri=redirect_uri)
#         print(access_token,'access tokennnnnnnnnnnnnnnnnnnnnnnnn')
#         user_data = google_get_user_info(access_token=access_token)
#         print(user_data,'user dataaaaaaaaaaaaaaaaaaaaaaaaa')
        
#         try:
#             user = CustomUser.objects.get(email=user_data['email'])
#             print(user,'userrrrrrrrrrrrrrrrrrrrrrrrr')
#             '''create access token'''
#             id  = user.id
#             access_token = jwt.encode({
#             'user_id': id,
#             'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=1800),
#             'iat': datetime.datetime.utcnow()
#         }, 'access_secret', algorithm='HS256')
            
#             '''create refresh token '''

#             refresh_token = jwt.encode({
#             'user_id': id,
#             'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
#             'iat': datetime.datetime.utcnow()
#         }, 'refresh_secret', algorithm='HS256')

#             response = Response()
#             '''place refresh token inside cookie and hide it http only'''
#             response.set_cookie(key='refreshToken', value= str(refresh_token), httponly=True)
#             #response.set_cookie(key='refreshToken', value=refresh_token)
#             '''place the access token as dictionary inside response data'''
#             response.data = {
#                 'access_token': str(access_token),
#                 'id':id,
#                 'username':user.username,
#                 'email':user.email
#             }
#             # response_data = {
#             #     'user': CustomUserSerializer(user).data,
#             #     'access_token': str(access_token),
#             #     'refresh_token': str(refresh_token)
#             # }
#             return Response(response)
#         except CustomUser.DoesNotExist:
#             print('came into excepttttttttttttttttttttttttttt')
#             email = user_data['email']
#             print('came here alsooooooooooooooooooooooooooooo')
#             username = user_data['given_name']
#             #last_name = user_data.get('family_name', '')

#             user = CustomUser.objects.create(
#                 username=username,
#                 email=email,
#                 #registration_method='google',
#                 #phone_no=None,
#                 #referral=None
#             )
         
#             '''create access token'''
#             id  = user.id
#             access_token = jwt.encode({
#             'user_id': id,
#             'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=1800),
#             'iat': datetime.datetime.utcnow()
#         }, 'access_secret', algorithm='HS256')
            
#             '''create refresh token '''

#             refresh_token = jwt.encode({
#             'user_id': id,
#             'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
#             'iat': datetime.datetime.utcnow()
#         }, 'refresh_secret', algorithm='HS256')

#         #saved_user = CustomUserSerializer(user)
#         #print(saved_user)   

#             response = Response()
#             '''place refresh token inside cookie and hide it http only'''
#             response.set_cookie(key='refreshToken', value= str(refresh_token), httponly=True)
#             #response.set_cookie(key='refreshToken', value=refresh_token)
#             '''place the access token as dictionary inside response data'''
#             response.data = {
#                 'access_token': str(access_token),
#                 'id':id,
#                 'username':user.username,
#                 'email':user.email
#             }
#             # response_data = {
#             #     'user': CustomUserSerializer(user).data,
#             #     'access_token': str(access_token),
#             #     'refresh_token': str(refresh_token)
#             # }
#             return Response(response)

class PasswordResetView(APIView):
    def post(self,request,*args, **kwargs):
        id = email=request.data['id']
        new_password = email=request.data['password']
        print(id)
        exact_id = id.split('xxx')[1]
        user = CustomUser.objects.get(id=exact_id)

        if user:
            hashed_password = make_password(new_password)
            user.password = hashed_password
            user.save()
        else:
            raise CustomAPIException(detail='Incorrect url', status_code=status.HTTP_400_BAD_REQUEST)

        
        dict_response ={}  
        dict_response['response']         = f'Password reset successfully '
        json_data = json.dumps(dict_response)

        return Response(json_data, status=status.HTTP_201_CREATED)



# Create your views here.
class EmailRequestForPasswordResetView(APIView):
    def post(self,request,*args, **kwargs):
        if CustomUser.objects.filter(email=request.data['email']).exists():
            user = CustomUser.objects.get(email=request.data['email'])
            welcome_message = "Hi "+ user.username
        else :
            raise CustomAPIException(detail='Unauthenticated user!.Please sign up', status_code=status.HTTP_401_UNAUTHORIZED)


        uniqueId = str(uuid.uuid4()).replace('-','')+'xxx'+f"{user.id}"
        print(uniqueId)
        
        link_app = f"http://localhost:3000/resetPassword/{uniqueId}"
        print(link_app)
        context = {
            "welcome_message": welcome_message, 
            "link_app": link_app
        }
        print(context)

        # import base64

        # def encode_image_to_base64(image_path):
        #     with open(image_path, "rb") as image_file:
        #         encoded_string = base64.b64encode(image_file.read()).decode("utf-8")
        #     return encoded_string

        # image_path_1 = 'static/netflix_rest_api_app/1_emailimage1_1.png'
        # image_path_2 = 'static/netflix_rest_api_app/2_emailimage2.png'
        # base64_encoded_image_1 = encode_image_to_base64(image_path_1)
        # base64_encoded_image_2 = encode_image_to_base64(image_path_2)
        # context['base64_encoded_image_1'] = base64_encoded_image_1
        # context['base64_encoded_image_2'] = base64_encoded_image_2
        #print(base64_encoded_image,'encoded imageeeeeeeeeeeeeeee')

        
        '''below commented lines are very important for email sending commented as of now'''

            

        html_message = render_to_string("netflix_rest_api_app/email.html", context=context)
        plain_message = strip_tags(html_message)

        message = EmailMultiAlternatives(
            subject = 'Complete your password reset request', 
            body = plain_message,
            from_email = None ,
            to= [user.email]
        )
       
        message.attach_alternative(html_message, "text/html")
        message.send()
        # subject = 'Complete your password reset request'
        # #body = plain_message
        # from_email = None
        # to= 'sundarapandyasastha@gmail.com'
        # send_mail(subject,plain_message,from_email,[to],html_message=html_message)

        dict_response ={}
        dict_response['id']               = uniqueId
        dict_response['response']         = f'Password reset mail sent successfully '
        dict_response['username']         = user.username
        dict_response['email']            = user.email

        json_data = json.dumps(dict_response)

        return Response(json_data, status=status.HTTP_201_CREATED)

class RegistrationView(APIView):
    def post(self, request, *args, **kwargs):

        ser_val_obj = CustomUserSerializer(data = request.data)
        print(ser_val_obj)
        dict_response = {} 
        if ser_val_obj.is_valid():
 
            saved_user = ser_val_obj.save()
  
        else:
            # Handle validation errors
            return Response(ser_val_obj.errors, status=status.HTTP_400_BAD_REQUEST)

    
        dict_response['id']               = saved_user.id
        #dict_response['response']         = f'Registration successful {saved_user.username}'
        dict_response['username']         = saved_user.username
        dict_response['email']            = saved_user.email

        json_data = json.dumps(dict_response)
        return Response(json_data, status=status.HTTP_201_CREATED)
  

class LoginAPIView(APIView):

    '''login request comes in'''

    def post(self, request):
        '''check with email in db becoz of email uniqueness'''
       
        user = CustomUser.objects.filter(email=request.data['email']).first()
       
        #s = CustomUserSerializer(user)
        
        if not user:
            raise CustomAPIException(detail='Unauthenticated user!.Please sign up', status_code=status.HTTP_401_UNAUTHORIZED)

        if not user.check_password(request.data['password']):
            print('1111111111111111111111111111111122222222222222222222222')
            raise CustomAPIException(detail='You have entered a invalid password.Please enter a valid password', status_code=status.HTTP_400_BAD_REQUEST)

        '''create access token'''
        id  = user.id
        access_token = jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=1800),
        'iat': datetime.datetime.utcnow()
    }, 'access_secret', algorithm='HS256')
        
        '''create refresh token '''

        refresh_token = jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow()
    }, 'refresh_secret', algorithm='HS256')

        '''send/ return  both token to front end client'''

        response = Response()
        '''place refresh token inside cookie and hide it http only'''
        response.set_cookie(key='refreshToken', value=refresh_token, httponly=True)
        #response.set_cookie(key='refreshToken', value=refresh_token)
        '''place the access token as dictionary inside response data'''
        response.data = {
            'access_token': access_token,
            'id':id,
            'username':user.username,
            'email':user.email
        }
        
        return response


class UserAPIView(APIView):
  

    def get(self, request):
        print(request)
        auth = get_authorization_header(request).split()
        print(auth)
        if auth and len(auth) == 2:
            token = auth[1].decode('utf-8')
            try:
                payload = jwt.decode(token, 'access_secret', algorithms='HS256')
                id = payload['user_id']
            except:
                raise AuthenticationFailed('unauthenticated')

            user = CustomUser.objects.filter(pk=id).first()

            return Response(CustomUserSerializer(user).data)

        raise AuthenticationFailed('unauthenticated')


class RefreshAPIView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refreshToken')

        try:
            payload = jwt.decode(refresh_token, 'refresh_secret', algorithms='HS256')

            id = payload['user_id']
        except:
            raise AuthenticationFailed('unauthenticated')
        
        access_token = jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
        'iat': datetime.datetime.utcnow()
    }, 'access_secret', algorithm='HS256')
        

        return Response({
            'token': access_token
        })


class LogoutAPIView(APIView):
    def post(self, _):
        response = Response()
        response.delete_cookie(key="refreshToken")
        response.data = {
            'message': 'success'
        }
        return response            


        






