import synserv
from constance import config
from registration import signals

from django.utils.translation import ugettext as _

from rest_framework.views import APIView
from rest_framework import status
from rest_framework import parsers
from rest_framework import renderers

from django.conf import settings
from django.contrib.sites.models import Site
from django.contrib.sites.requests import RequestSite

from restapi.api3.forms import RegistrationForm
from restapi.api3.utils import api_error, api_response
from restapi.api3.throttling import ScopedRateThrottle, AnonRateThrottle, UserRateThrottle

from restapi.base.accounts import User
from restapi.auth import login
from restapi.profile.models import Profile, DetailedProfile

from restapi.utils import send_html_email

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema


def get_request_domain(request=None):
    return '{}s://{}'.format(request.scheme, request.META['HTTP_HOST'])


def send_user_activation_email(request, activation_key, email):
    """Send email when add new user."""
    syncwerk_host = get_request_domain(request)
    c = {
        'activation_key': activation_key,
        'request_domain': syncwerk_host,
    }
    send_html_email(_(u'Account activation on Syncwerk'),
                    'api3/registration/user_activation_email.html', c, None, [email],request=request)


def send_admin_user_activation_email(request, email_for_activation):
    """Notify admins when a new user is registered"""
    admins = User.objects.get_superusers()
    admin_emails = []
    for admin in admins:
        admin_emails.append(admin.email)
    syncwerk_host = get_request_domain(request)
    c = {
        'user_email': email_for_activation,
        'request_domain': syncwerk_host,
    }
    send_html_email(_(u'Account activation on Syncwerk'),
                    'api3/sysadmin/admin_active_user.html', c, None, admin_emails,request=request)


class AccountRegistration(APIView):
    throttle_classes = (AnonRateThrottle, )
    permission_classes = ()
    parser_classes = (parsers.FormParser,
                      parsers.MultiPartParser, )
    renderer_classes = (renderers.JSONRenderer,)
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='User registration',
        operation_description='User registers a new account',
        tags=['user'],
        manual_parameters=[
            openapi.Parameter(
                name='email',
                in_="formData",
                type='string',
                description='User email for registration',
            ),
            openapi.Parameter(
                name='password1',
                in_="formData",
                type='string',
                description='Password for the created account',
            ),
            openapi.Parameter(
                name='password2',
                in_="formData",
                type='string',
                description='Confirm password',
            ),
        ],
        responses={
            200: openapi.Response(
                description='User registration successfully',
                examples={
                    'application/json': {
                        "message": "User registered successfully.",
                        "data": None
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request',
                examples={
                    'application/json': {
                        "message": "",
                        "data": "{\"email\": [{\"message\": \"Error message\", \"code\": \"Error code\"}]}"
                    }
                },
            ),
        }
    )
    def post(self, request):
        form_class = RegistrationForm
        form = form_class(request.data)
        print form.is_valid()
        if form.is_valid():
            # Do the register
            email, password = request.data.get(
                'email'), request.data.get('password1')
            username = email
            response_message = ''
            if Site._meta.installed:
                site = Site.objects.get_current()
            else:
                site = RequestSite(request)

            from registration.models import RegistrationProfile
            if bool(config.ACTIVATE_AFTER_REGISTRATION) is True:
                # since user will be activated after registration,
                # so we will not use email sending, just create acitvated user
                new_user = RegistrationProfile.objects.create_active_user(username, email,
                                                                          password, site,
                                                                          send_email=False)
                # login the user
                new_user.backend = settings.AUTHENTICATION_BACKENDS[0]

                # login(request, new_user)
                response_message = 'User registered successfully.'
            else:
                # create inactive user, user can be activated by admin, or through activated email
                new_user = RegistrationProfile.objects.create_inactive_user(username, email,
                                                                            password, site,
                                                                            send_email=False)
                if config.REGISTRATION_SEND_MAIL:
                    # Send a Syncwerk email for activation
                    activation_key = RegistrationProfile.objects.filter(
                        emailuser_id=new_user.id).first().activation_key
                    send_user_activation_email(
                        request, activation_key, new_user.email)
                else:
                    send_admin_user_activation_email(request, new_user.email)
                response_message = 'Registration sucessfully. Please check your email for activating your account.'

            # userid = kwargs['userid']
            # if userid:
            #     ccnet_threaded_rpc.add_binding(new_user.username, userid)

            if settings.REQUIRE_DETAIL_ON_REGISTRATION:
                name = request.data.get('name', '')
                department = request.data.get('department', '')
                telephone = request.data.get('telephone', '')
                note = request.data.get('note', '')
                Profile.objects.add_or_update(new_user.username, name, note)
                DetailedProfile.objects.add_detailed_profile(new_user.username,
                                                             department,
                                                             telephone)

            # signals.user_registered.send(sender=self.__class__,
            #                              user=new_user,
            #                              request=request)
            return api_response(msg=response_message)
        else:
            return api_error(msg="", data=form.errors.as_json(), code=status.HTTP_400_BAD_REQUEST)


class AccountActivationViaEmail(APIView):
    """ User activation
    """
    throttle_classes = (AnonRateThrottle, )
    permission_classes = ()
    parser_classes = (parsers.FormParser,
                      parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Account email activation',
        operation_description='Activate user account via email',
        tags=['user'],
        manual_parameters=[
            openapi.Parameter(
                name='activation_key',
                in_="path",
                type='string',
                description='The activation key sent to user via email',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Account activation successfully',
                examples={
                    'application/json': {
                        "message": "Account is successfully activated. Please login.",
                        "data": None
                    }
                },
            ),
            403: openapi.Response(
                description='Account activation failed',
                examples={
                    'application/json': {
                        "message": "Account activation failed.",
                        "data": None
                    }
                },
            ),
        }
    )
    def get(self, request, activation_key):
        from registration.models import RegistrationProfile
        activated = RegistrationProfile.objects.activate_user(activation_key)
        if activated:
            signals.user_activated.send(sender=self.__class__,
                                        user=activated,
                                        request=request)
            return api_response(code=200, msg=_('Account is successfully activated. Please login.'))
        else:
            return api_error(code=403, msg=_('Account activation failed.'))
