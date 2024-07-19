from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from .cognito_service import CognitoService

cognito_service = CognitoService()

class CognitoAuthenticationMiddleware(MiddlewareMixin):
    EXCLUDE_PATHS = [
        '/signup/',
        '/signin/',
        '/verify/',
    ]

    def process_request(self, request):
        if any(request.path == path for path in self.EXCLUDE_PATHS):
            return None  # Skip token validation for excluded paths

        if 'HTTP_AUTHORIZATION' in request.META:
            access_token = request.META['HTTP_AUTHORIZATION'].split(' ')[1]
            try:
                user_info = cognito_service.get_user(access_token)
                request.user_info = user_info
            except Exception as e:
                return JsonResponse({'success': False, 'error': 'Invalid access token'}, status=401)
        else:
            return JsonResponse({'success': False, 'error': 'Authorization header is required'}, status=401)
