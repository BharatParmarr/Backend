# myapp/backends.py
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User


class EmailOrUsernameModelBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        print('1', username, password)
        if '@' in username:
            kwargs = {'email': username}
        else:
            kwargs = {'username': username}
        try:
            user = User.objects.get(**kwargs)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
