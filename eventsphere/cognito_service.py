# cognito_service.py
import boto3
from botocore.exceptions import ClientError
from django.conf import settings

class CognitoService:
    def __init__(self):
        self.client = boto3.client('cognito-idp', region_name=settings.AWS_REGION)
    
    def sign_up(self, username, password, email):
        try:
            response = self.client.sign_up(
                ClientId=settings.AWS_COGNITO_CLIENT_ID,
                Username=username,
                Password=password,
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                ],
                SecretHash=self.get_secret_hash(username),
            )
            return response
        except ClientError as e:
            raise e

    def confirm_sign_up(self, username, code):
        try:
            response = self.client.confirm_sign_up(
                ClientId=settings.AWS_COGNITO_CLIENT_ID,
                Username=username,
                ConfirmationCode=code,
                SecretHash=self.get_secret_hash(username),
            )
            return response
        except ClientError as e:
            raise e

    def get_secret_hash(self, username):
        import hmac
        import hashlib
        import base64
        
        message = username + settings.AWS_COGNITO_CLIENT_ID
        dig = hmac.new(str(settings.AWS_COGNITO_CLIENT_SECRET).encode('utf-8'),
                       msg=message.encode('utf-8'),
                       digestmod=hashlib.sha256).digest()
        return base64.b64encode(dig).decode()

    def get_user(self, access_token):
        try:
            response = self.client.get_user(
                AccessToken=access_token
            )
            return response
        except ClientError as e:
            raise e
    
    def authenticate_user(self, username, password):
        try:
            response = self.client.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password,
                    'SECRET_HASH': self.get_secret_hash(username)
                },
                ClientId=settings.AWS_COGNITO_CLIENT_ID
            )
            return response['AuthenticationResult']
        except ClientError as e:
            raise e
