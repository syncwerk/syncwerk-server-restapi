import logging

from django.conf import settings
from django.contrib.auth.forms import SetPasswordForm
from rest_framework import serializers

from restapi.auth import authenticate
from .models import DESKTOP_PLATFORMS
from .utils import get_token_v1, get_token_v2
from restapi.profile.models import Profile

from restapi.utils.two_factor_auth import has_two_factor_auth, \
        two_factor_auth_enabled, verify_two_factor_token

logger = logging.getLogger(__name__)

def all_none(values):
    for value in values:
        if value is not None:
            return False
    return True

def all_not_none(values):
    for value in values:
        if value is None:
            return False
    return True

class ThirdPartyTokenSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def __init__(self, *a, **kw):
        super(ThirdPartyTokenSerializer, self).__init__(*a, **kw)

    def validate(self, attrs):
        login_id = attrs.get('username')
        password = attrs.get('password')

        platform = 'apiv3'
        device_id = 'apiv3'
        device_name = 'apiv3'
        client_version = '3'
        platform_version = '3'

        username = Profile.objects.get_username_by_login_id(login_id)
        if username is None:
            username = login_id

        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                if not user.is_active:
                    raise serializers.ValidationError('User account is disabled.')
            else:
                raise serializers.ValidationError('Unable to login with provided credentials.')
        else:
            raise serializers.ValidationError('Must include "username" and "password"')


        # Now user is authenticated
        token = get_token_v2(self.context['request'], username, platform, device_id, device_name,
                                client_version, platform_version)
        return token.key

class AuthTokenSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    
    # There fields are used by TokenV2
    platform = serializers.CharField(required=False)
    device_id = serializers.CharField(required=False)
    device_name = serializers.CharField(required=False)

    # These fields may be needed in the future
    client_version = serializers.CharField(required=False, default='')
    platform_version = serializers.CharField(required=False, default='')

    def __init__(self, *a, **kw):
        super(AuthTokenSerializer, self).__init__(*a, **kw)
        self.two_factor_auth_failed = False

    def validate(self, attrs):
        login_id = attrs.get('username')
        password = attrs.get('password')

        platform = attrs.get('platform', None)
        device_id = attrs.get('device_id', None)
        device_name = attrs.get('device_name', None)
        client_version = attrs.get('client_version', None)
        platform_version = attrs.get('platform_version', None)

        v2_fields = (platform, device_id, device_name)

        # Decide the version of token we need
        if all_none(v2_fields):
            v2 = False
        elif all_not_none(v2_fields):
            v2 = True
        else:
            raise serializers.ValidationError('invalid params')

        username = Profile.objects.get_username_by_login_id(login_id)
        if username is None:
            username = login_id

        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                if not user.is_active:
                    raise serializers.ValidationError('User account is disabled.')
            else:
                raise serializers.ValidationError('Unable to login with provided credentials.')
        else:
            raise serializers.ValidationError('Must include "username" and "password"')

        if platform in DESKTOP_PLATFORMS:
            if not user.permissions.can_connect_with_desktop_clients():
                raise serializers.ValidationError('Not allowed to connect to desktop client.')
        elif platform == 'android':
            if not user.permissions.can_connect_with_android_clients():
                raise serializers.ValidationError('Not allowed to connect to android client.')
        elif platform == 'ios':
            if not user.permissions.can_connect_with_ios_clients():
                raise serializers.ValidationError('Not allowed to connect to ios client.')
        else:
            logger.info('%s: unrecognized device' % login_id)

        self._two_factor_auth(self.context['request'], user)

        # Now user is authenticated
        if v2:
            token = get_token_v2(self.context['request'], username, platform, device_id, device_name,
                                 client_version, platform_version)
        else:
            token = get_token_v1(username)
        return token.key

    def _two_factor_auth(self, request, user):
        if not has_two_factor_auth() or not two_factor_auth_enabled(user):
            return
        token = request.META.get('HTTP_X_SYNCWERK_OTP', '')
        if not token:
            self.two_factor_auth_failed = True
            msg = 'Two factor auth token is missing.'
            raise serializers.ValidationError(msg)
        if not verify_two_factor_token(user.username, token):
            self.two_factor_auth_failed = True
            msg = 'Two factor auth token is invalid.'
            raise serializers.ValidationError(msg)

class AccountSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    is_staff = serializers.BooleanField(default=False)
    is_active = serializers.BooleanField(default=True)

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128)
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)

    set_password_form_class = SetPasswordForm

    def __init__(self, *args, **kwargs):
        self.old_password_field_enabled = getattr(
            settings, 'OLD_PASSWORD_FIELD_ENABLED', True
        )
        self.logout_on_password_change = getattr(
            settings, 'LOGOUT_ON_PASSWORD_CHANGE', False
        )
        super(PasswordChangeSerializer, self).__init__(*args, **kwargs)

        if not self.old_password_field_enabled:
            self.fields.pop('old_password')

        self.request = self.context.get('request')
        self.user = getattr(self.request, 'user', None)

    def validate_old_password(self, value):
        invalid_password_conditions = (
            self.old_password_field_enabled,
            self.user,
            not self.user.check_password(value)
        )

        if all(invalid_password_conditions):
            raise serializers.ValidationError('Invalid password')
        return value

    def validate(self, attrs):
        self.set_password_form = self.set_password_form_class(
            user=self.user, data=attrs
        )

        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        return attrs

    def save(self):
        self.set_password_form.save()
        if not self.logout_on_password_change:
            from django.contrib.auth import update_session_auth_hash
            update_session_auth_hash(self.request, self.user)

class PaginagtionSerializer(serializers.Serializer):
    page = serializers.IntegerField(required=False, default=1, min_value=1)
    per_page = serializers.IntegerField(required=False, default=10, min_value=1, max_value=1000)




