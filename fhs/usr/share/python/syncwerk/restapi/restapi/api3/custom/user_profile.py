import logging
import re
import json
import string
import random

from datetime import datetime

from django.utils.translation import ugettext as _
from django.utils import timezone
from django.db import transaction, connections

from constance import config

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from restapi.api3.base import APIView
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response, get_request_domain, send_html_email
from restapi.api3.models import EmailChangingRequest, CcnetUser

from restapi.avatar.templatetags.avatar_tags import api_avatar_url, get_default_avatar_url
from restapi.avatar.settings import AVATAR_DEFAULT_SIZE
from restapi.base.accounts import User
from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.profile.models import Profile, DetailedProfile
from restapi.utils import is_valid_username

logger = logging.getLogger(__name__)


from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

def generate_change_email_request_token(length=64):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))

class UserProfileView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)


    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get user profile by email',
        operation_description='Get user profile with specific email',
        tags=['user'],
        manual_parameters=[
            openapi.Parameter(
                name='email',
                in_="path",
                type='string',
                description='Email of the user that you want to get profile.',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Retrieve user profile successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "profile": [
                                {
                                    "department": "test",
                                    "telephone": ""
                                }
                            ],
                            "avatar_size": 80,
                            "name": "test1@grr.la",
                            "is_default_avatar": True,
                            "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                            "contact_email": "test1@grr.la"
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / unauthorized.',
                examples={
                    'application/json': {
                        "detail": "Invalid token"
                    }
                }
            ),
            404: openapi.Response(
                description='User not found.',
                examples={
                    'application/json': {
                        "detail": "User not found"
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error"
                    }
                }
            )
        }
    )
    def get(self, request, email, format=None):
        """ Get profile detail by specific User's email
        ---
        # YAML

        type:
          Authorization:
            required: true
            type: string
          email:
            required: true
            type: string

        parameters:
            - name: Authorization
              required: true
              type: string
              paramType: header
            - name: email
              description: User email
              required: true
              type: string
              paramType: path

        responseMessages:
            - code: 400
              message: BAD_REQUEST
            - code: 401
              message: UNAUTHORIZED
            - code: 404
              message: NOT_FOUND
            - code: 500
              message: INTERNAL_SERVER_ERROR

        consumes:
            - application/json
        produces:
            - application/json
        """
        if is_valid_username(email):
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                user = None
        else:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid email.')

        if user is None:
            return api_error(status.HTTP_404_NOT_FOUND, 'User does not exist.')
        else:
            nickname = email2nickname(user.username)
            contact_email = Profile.objects.get_contact_email_by_user(user.username)
            d_profile = DetailedProfile.objects.get_detailed_profile_by_user(
                user.username)
            avatar_size = AVATAR_DEFAULT_SIZE
            try:
                avatar_url, is_default, date_uploaded = api_avatar_url(email, avatar_size)
            except Exception as e:
                logger.error(e)
                avatar_url = get_default_avatar_url()

        resp = {
            'name': nickname,
            'contact_email': contact_email,
            'avatar_url': '%s%s' % (config.SERVICE_URL, avatar_url),
            'avatar_size': avatar_size,
            'is_default_avatar': is_default,
            'profile': None
        }
        if d_profile:
            resp['profile'] = {
                'department': d_profile.department,
                'telephone': d_profile.telephone
            },
        return api_response(data=resp)

class UserProfileChangeEmailView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    # This is for sending the new request for changing user email
    def post(self, request):
        new_email_to_change_to = request.POST.get('new_email', None)
        if new_email_to_change_to is None or new_email_to_change_to.strip() == '':
            return api_error(code=400, msg=_('Please provide the email that you want to change to.'))
        if not re.match("\\S+@[a-zA-Z0-9\u00E4\u00F6\u00FC\u00C4\u00D6\u00DC\u00df._-]+\\.[a-zA-Z0-9\u00E4\u00F6\u00FC\u00C4\u00D6\u00DC\u00df._-]+", new_email_to_change_to.strip()):
            return api_error(code=400, msg=_('Invalid email. Please check again'))
        if new_email_to_change_to.strip() == request.user.email:
            return api_error(code=400, msg=_('The new email must be different than the current email.'))
        # Check if the new email is belongs to existed user or not
        try:
            CcnetUser.objects.get(email=new_email_to_change_to.strip())
            return api_error(code=400, msg=_('The email is existed. Please choose a different one.'))
        except CcnetUser.DoesNotExist:
            pass
        # Check if the new email is belongs to another request or not
        try:
            EmailChangingRequest.objects.get(
                new_email= new_email_to_change_to.strip(),
            )
            return api_error(code=400, msg=_('The email is already requested by a different user. Please choose a different one.'))
        except EmailChangingRequest.DoesNotExist:
            pass
        # Check if the current user have a request which is in progress
        try:
            inprogress_request = EmailChangingRequest.objects.get(
                user_id= request.user.email,
                request_completed= False
            )
            if inprogress_request is not None:
                return api_error(code=400, msg=_('You already have a request that is in progress.'))
        except Exception as e:
            pass
        # User have no on going request. Time to populate the request info
        email_change_request_info = EmailChangingRequest()
        email_change_request_info.new_email = new_email_to_change_to
        email_change_request_info.new_email_confirmed = False
        email_change_request_info.request_completed = False
        email_change_request_info.user_id = request.user.email
        email_change_request_info.request_token = generate_change_email_request_token()
        email_change_request_info.request_token_expire_time = timezone.now() + timezone.timedelta(hours=1)
        email_change_request_info.save()
        # Send confirmation email to the user new email
        email_content = {
            # 'new_email': email_change_request_info.new_email,
            # 'current_email': email_change_request_info.user_id,
            'confirmation_link': '{}/email-change-confirmation/{}/{}'.format(get_request_domain(request), email_change_request_info.user_id, email_change_request_info.request_token)
        }
        send_html_email('Request for changing email',
            'api3/change_email_request_confirmation.html', email_content, None, [email_change_request_info.new_email],request=request)
        result = {
            "id": email_change_request_info.id,
            "new_email": email_change_request_info.new_email,
            "is_expired": email_change_request_info.request_token_expire_time < timezone.now() ,
            "new_email_confirmed": email_change_request_info.new_email_confirmed,
            "request_completed": email_change_request_info.request_completed,
        }
        return api_response(code=200, data=result, msg=_('Email change request submitted. Please check the inbox of your new email to continue.'))

class UserProfileChangeEmailRequestEntryView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    # This is for resending confirmation email to the new email address
    def put(self, request, request_id):

        if request_id is None:
            return api_error(code=400, msg=_('Please include "request_id" in your request.'))
        
        # Check if the current request is the correct user
        try:
            inprogress_request = EmailChangingRequest.objects.get(
                user_id= request.user.email,
                request_completed= False,
                new_email_confirmed=False,
                id=request_id
            )
            if inprogress_request is None:
                return api_error(code=400, msg=_('Invalid request.'))
        except Exception as e:
            return api_error(code=400, msg=_('Invalid request.'))
        # The request is correct. Regenerate token and infos. Then save and send email
        inprogress_request.request_token = generate_change_email_request_token()
        inprogress_request.request_token_expire_time = timezone.now() + timezone.timedelta(hours=1)
        try:
            inprogress_request.save()
        except Exception as e:
            logger.error(e)
            return api_error(code=500, msg=_('Internal server error.'))

        email_content = {
            'confirmation_link': '{}/email-change-confirmation/{}/{}'.format(get_request_domain(request), inprogress_request.user_id, inprogress_request.request_token)
        }
        send_html_email('Request for changing email',
            'api3/change_email_request_confirmation.html', email_content, None, [inprogress_request.new_email],request=request)
        result = {
            "id": inprogress_request.id,
            "new_email": inprogress_request.new_email,
            "is_expired": inprogress_request.request_token_expire_time < timezone.now() ,
            "new_email_confirmed": inprogress_request.new_email_confirmed,
            "request_completed": inprogress_request.request_completed,
        }
        return api_response(code=200, data=result, msg=_('Confirmation email resend successfully. Please check the inbox of your new email to continue.'))

    def delete(self, request, request_id):
        if request_id is None:
            return api_error(code=400, msg=_('Please include "request_id" in your request.'))
        try:
            inprogress_request = EmailChangingRequest.objects.get(
                user_id= request.user.email,
                id=request_id
            )
            if inprogress_request is None:
                return api_error(code=400, msg=_('Invalid request.'))
        except Exception as e:
            return api_error(code=400, msg=_('Invalid request.'))
        # Confirmed. Let's delete it
        inprogress_request.delete()
        return api_response(code=200, data=None, msg=_('Email change request was canceled successfully.'))

class UserProfileChangeEmailConfirmView(APIView):
    def post(self, request):
        json_data = json.loads(request.body)
        request_token = json_data['request_token'] or None
        request_owner = json_data['request_owner'] or None

        if request_owner is None or request_token is None:
            return api_error(code=400, msg=_('Invalid request.'))
        
        # Check if there's a correspond request with that information
        try:
            inprogress_request = EmailChangingRequest.objects.get(
                request_token = request_token,
                user_id = request_owner,
                request_completed = False,
                new_email_confirmed = False,
            )
            if inprogress_request is None:
                return api_error(code=400, msg=_('Invalid request.'))
        except Exception as e:
            return api_error(code=400, msg=_('Invalid request.'))
        
        # Update information
        inprogress_request.new_email_confirmed = True
        inprogress_request.request_token = None
        inprogress_request.request_token_expire_time = None
        try:
            inprogress_request.save()
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'), data=e)
        return api_response(code=200, msg=_('Email confirmed. Please now wait for system admin to trigger the change.'))      
