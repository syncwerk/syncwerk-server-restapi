import logging

from constance import config

from django.contrib.sites.models import Site
from django.contrib.sites.requests import RequestSite
from django.utils.decorators import method_decorator
from django.utils.http import int_to_base36, base36_to_int
from django.utils.translation import ugettext as _
from django.views.decorators.debug import sensitive_post_parameters

from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from restapi.auth.forms import PasswordResetForm, SetPasswordForm
from restapi.auth.tokens import default_token_generator
from restapi.base.accounts import User
from restapi.options.models import UserOptions

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.serializers import PasswordChangeSerializer, AuthTokenSerializer
from restapi.api3.utils import api_error, api_response, get_request_domain, send_html_email, is_user_password_strong

sensitive_post_parameters_m = method_decorator(
    sensitive_post_parameters(
        'password', 'old_password', 'new_password1', 'new_password2'
    )
)

logger = logging.getLogger(__name__)

from drf_yasg.utils import swagger_auto_schema, no_body
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema
from rest_framework import parsers


class PasswordReset(APIView):
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Reset password request',
        operation_description='Send reset password request',
        tags=['user'],
        manual_parameters=[
            openapi.Parameter(
                name='email',
                in_="formData",
                type='string',
                description='Email for requesting reset password',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Request success.',
                examples={
                    'application/json': {
                        "message": "New password has been saved.",
                        "data": {
                            "token": "a new login token."
                        }
                    }
                },
            ),
            403: openapi.Response(
                description='Mail send failed.',
                examples={
                    'application/json': {
                        "message": "Failed to send email, please check your email address.",
                        "data": None
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error.',
                examples={
                    'application/json': {
                        "detail": "Internal server error"
                    }
                }
            )
        }
    )
    def post(self, request, format=None):
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            user = form.users_cache
            token = default_token_generator.make_token(user)
            site_name = request.META['HTTP_HOST']
            email_template_name = 'api3/registration/password_reset_email.html'

            c = {
                'email': user.username,
                'uid': int_to_base36(user.id),
                'user': user,
                'token': token,
                'request_domain': get_request_domain(request)
            }

            try:
                send_html_email(_("Reset Password on %s") % site_name,
                                email_template_name, c, None, [user.username],request=request)
            except Exception, e:
                logger.error(str(e))
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, _(u'Failed to send email, please contact administrator.'))
            return api_response(msg='We have sent a password reset email to your mailbox.')
        errors = form.errors
        return api_error(status.HTTP_403_FORBIDDEN, msg=_(u'Failed to send email, please check your email address.'), data=errors)


class ConfirmPasswordReset(APIView):
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Check reset password token',
        operation_description='Check if the reset password token is valid or not',
        tags=['user'],
        manual_parameters=[
            openapi.Parameter(
                name='uidb36',
                in_="path",
                type='string',
                description='uidb36 string',
                required=True,
            ),
            openapi.Parameter(
                name='token',
                in_="path",
                type='string',
                description='Token string',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Reset password token is valid.',
                examples={
                    'application/json': {
                        "message": "Token valid.",
                        "data": None
                    }
                },
            ),
            404: openapi.Response(
                description='Token invalid.',
                examples={
                    'application/json': {
                        "message": "Failed to reset password: this link is no longer available.",
                        "data": None
                    }
                }
            ),
        }
    )
    def get(self, request, uidb36, token, format=None):
        assert uidb36 is not None and token is not None  # checked by URLconf
        try:
            uid_int = base36_to_int(uidb36)
            user = User.objects.get(id=uid_int)
        except (ValueError, User.DoesNotExist):
            user = None

        if default_token_generator.check_token(user, token):
            return api_response(msg='Token valid.')
        return api_error(status.HTTP_404_NOT_FOUND, msg='Failed to reset password: this link is no longer available.')

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Reset password',
        operation_description='Reset user password',
        tags=['user'],
        manual_parameters=[
            openapi.Parameter(
                name='uidb36',
                in_="path",
                type='string',
                description='uidb36 string',
                required=True,
            ),
            openapi.Parameter(
                name='token',
                in_="path",
                type='string',
                description='Token string',
                required=True,
            ),
            openapi.Parameter(
                name='new_password1',
                in_="formData",
                type='string',
                description='New password that user wants to change to.',
                required=True,
            ),
            openapi.Parameter(
                name='new_password2',
                in_="formData",
                type='string',
                description='Confirm new password',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Reset password success.',
                examples={
                    'application/json': {
                        "message": "Successfully reset password",
                        "data": None
                    }
                },
            ),
            404: openapi.Response(
                description='Reset password failed due to invalid provided password.',
                examples={
                    'application/json': {
                        "message": "Failed to reset password. Please check back your provided password.",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='Reset password failed due to invalid token.',
                examples={
                    'application/json': {
                        "message": "Failed to reset password: this link is no longer available.",
                        "data": None
                    }
                }
            ),
        }
    )
    def post(self, request, uidb36, token, format=None):
        assert uidb36 is not None and token is not None  # checked by URLconf
        try:
            uid_int = base36_to_int(uidb36)
            user = User.objects.get(id=uid_int)
        except (ValueError, User.DoesNotExist):
            user = None

        if default_token_generator.check_token(user, token):
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                return api_response(msg='Successfully reset password.')
            errors = form.errors
            return api_error(status.HTTP_400_BAD_REQUEST, msg=_(u'Failed to reset password, please check your entered password.'), data=errors)
        return api_error(status.HTTP_404_NOT_FOUND, msg='Failed to reset password: this link is no longer available.')


class PasswordChangeView(GenericAPIView):
    """ Calls Django Auth SetPasswordForm save method.

    Accepts the following POST parameters: new_password1, new_password2
    Returns the success/fail message.
    """
    authentication_classes = (TokenAuthentication, )
    serializer_class = PasswordChangeSerializer
    permission_classes = (IsAuthenticated,)
    parser_classes = (parsers.JSONParser, )

    @sensitive_post_parameters_m
    def dispatch(self, *args, **kwargs):
        return super(PasswordChangeView, self).dispatch(*args, **kwargs)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Change password',
        operation_description='Change user password',
        tags=['user'],
        request_body=openapi.Schema(
            type='object',
            properties={
                'old_password': openapi.Schema(
                    type='string',
                    description='User current password'
                ),
                'new_password1': openapi.Schema(
                    type='string',
                    description='New password that user wants to change to'
                ),
                'new_password2': openapi.Schema(
                    type='string',
                    description='Confirm new password'
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description='Changed password successfully.',
                examples={
                    'application/json': {
                        "message": "New password has been saved.",
                        "data": {
                            "token": "a new login token."
                        }
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
                    }
                }
            ),
            401: openapi.Response(
                description='Unauthenticated / unauthorized.',
                examples={
                    'application/json': {
                        "detail": "Invalid token"
                    }
                }
            )
        }
    )
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid(raise_exception=False):
            # Check old password
            old_password = serializer.data.get("old_password")
            if not self.request.user.check_password(old_password):
                return api_error(status.HTTP_400_BAD_REQUEST, 'Old password is incorrect.', serializer.errors)
            return api_error(status.HTTP_400_BAD_REQUEST, '', serializer.errors)

        if bool(config.USER_STRONG_PASSWORD_REQUIRED) is True:
            # print serializer
            new_password1 = serializer.data.get('new_password1')
            result, message = is_user_password_strong(new_password1)
            if not result:

                return api_error(code=400, msg=message, data={
                    'password1': [{'message': message}]
                })

        serializer.save()
        UserOptions.objects.unset_force_passwd_change(
            request.user.username)

        # Re-generate new token
        context = {'request': request}
        data = {
            'username': request.user.username,
            'password': serializer.data.get("new_password1")
        }
        serializer = AuthTokenSerializer(data=data, context=context)
        resp = {}
        if serializer.is_valid():
            key = serializer.validated_data
            resp['token'] = key

        return api_response(status.HTTP_200_OK, 'New password has been saved.', data=resp)
