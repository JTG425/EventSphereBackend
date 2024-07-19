from functools import wraps
from django.http import JsonResponse
from .cognito_service import CognitoService

cognito_service = CognitoService()

def cognito_authentication_required(view_func):
    @wraps(view_func)
    def _wrapped_view(view_instance, request, *args, **kwargs):
        if 'HTTP_AUTHORIZATION' in request.META:
            access_token = request.META['HTTP_AUTHORIZATION'].split(' ')[1]
            try:
                user_info = cognito_service.get_user(access_token)
                request.user_info = user_info
                return view_func(view_instance, request, *args, **kwargs)
            except Exception as e:
                return JsonResponse({'success': False, 'error': 'Invalid access token'}, status=401)
        else:
            return JsonResponse({'success': False, 'error': 'Authorization header is required'}, status=401)
    return _wrapped_view
