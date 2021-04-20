from constance import config

from datetime import datetime

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status
from django.utils.translation import ugettext as _
from django.utils import timezone

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.models import CcnetUser, EmailChangingRequest, EmailUser, LDAPUsers, BBBPrivateSetting
from restapi.api3.custom.available_features import getAvailableFeatures

from restapi.avatar.templatetags.avatar_tags import api_avatar_url, get_default_avatar_url
from restapi.avatar.settings import AVATAR_DEFAULT_SIZE
from restapi.options.models import UserOptions
from restapi.profile.models import Profile, DetailedProfile
from restapi.profile.forms import DetailedProfileForm
from restapi.views import get_owned_repo_list

from synserv import syncwerk_api

from constance import config

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema
from rest_framework import parsers


class ProfileView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication, )
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.JSONParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='User profile',
        operation_description='Get current user profile',
        tags=['user'],
        manual_parameters=[
            openapi.Parameter(
                name='avatar_size',
                in_="query",
                type='string',
                description='Size of the avatar',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Retrieve user profile successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "avatar_size": [
                                80
                            ],
                            "language": "en",
                            "default_repo": {
                                "id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                "name": "My Folder"
                            },
                            "is_default_avatar": False,
                            "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                            "owned_repos": [
                                {
                                    "id": "5162d1dd-428d-4a6f-9d44-c60ad57abebb",
                                    "name": "tgregr"
                                },
                                {
                                    "id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                                    "name": "test wiki 4"
                                },
                                {
                                    "id": "bacd10c8-032b-4696-9b04-37b2a75c06e7",
                                    "name": "Minh Nguyen"
                                },
                                {
                                    "id": "32c13cd4-3752-46bc-b1cf-cff4d50a671f",
                                    "name": "test wiki"
                                },
                                {
                                    "id": "7e79e4cc-c964-422c-83f6-6c7aa9e7cde0",
                                    "name": "Test wiki 3"
                                },
                                {
                                    "id": "c2cc6bcb-5c79-4163-b0a2-ce216df70ebb",
                                    "name": "test wiki 2"
                                },
                                {
                                    "id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                    "name": "My Folder"
                                },
                                {
                                    "id": "3935599b-e3d8-4068-8e3c-b0f4e6e03ba3",
                                    "name": "test111"
                                },
                                {
                                    "id": "9687e465-8a3e-466a-97ad-080ef595514c",
                                    "name": "addafolder"
                                },
                                {
                                    "id": "f393fa2e-cde0-485a-9572-472ec0ad507a",
                                    "name": "deqwfeqwf"
                                }
                            ],
                            "email": "admin@alpha.syncwerk.com",
                            "nickname": "",
                            "login_id": "",
                            "contact_email": "",
                            "department": "",
                            "telephone": "",
                        }
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request',
                examples={
                    'application/json': {
                        "message": "",
                        "data": "{}"
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
            )
        }
    )
    def get(self, request):
        username = request.user.username
        ccnet_user_info = CcnetUser.objects.get(email=username)
        profile = Profile.objects.get_profile_by_user(username)
        d_profile = DetailedProfile.objects.get_detailed_profile_by_user(
            username)

        init_dict = {}
        if profile:
            init_dict['nickname'] = profile.nickname
            init_dict['login_id'] = profile.login_id
            init_dict['contact_email'] = profile.contact_email
        if d_profile:
            init_dict['department'] = d_profile.department
            init_dict['telephone'] = d_profile.telephone
        init_dict['language'] = ccnet_user_info.language if ccnet_user_info.language != None and ccnet_user_info.language != '' else "en"

        avatar_size = int(request.GET.get('avatar_size', AVATAR_DEFAULT_SIZE))
        try:
            avatar_url, is_default, date_uploaded = api_avatar_url(
                username, avatar_size)
        except Exception as e:
            logger.error(e)
            avatar_url = get_default_avatar_url()

        init_dict['email'] = username
        init_dict['avatar_url'] = '%s%s' % (config.SERVICE_URL, avatar_url)
        init_dict['avatar_size'] = avatar_size,
        init_dict['is_default_avatar'] = is_default

        default_repo_id = UserOptions.objects.get_default_repo(username)
        if default_repo_id:
            default_repo = syncwerk_api.get_repo(default_repo_id)
        else:
            default_repo = None

        owned_repos = get_owned_repo_list(request)
        owned_repos = filter(lambda r: not r.is_virtual, owned_repos)

        if default_repo:
            init_dict['default_repo'] = {
                'id': default_repo.id,
                'name': default_repo.name
            }

        repos = []
        for r in owned_repos:
            repos.append({
                'id': r.id,
                'name': r.name
            })

        init_dict['owned_repos'] = repos

        # Get user quota
        init_dict['space_usage'] = syncwerk_api.get_user_self_usage(request.user.email)
        init_dict['space_quota'] = syncwerk_api.get_user_quota(request.user.email)    

        # Get profile permission
        available_feature_dict = getAvailableFeatures()
        # LDAP User can not change password and email
        update_profile_permission = {
            'UPDATE_PASSWORD': True if ccnet_user_info.source == EmailUser.source else False,
            'CHANGE_EMAIL': True if ccnet_user_info.source == EmailUser.source else False,
        }        
        
        init_dict['update_profile_permission'] = update_profile_permission

        # Get the current email request
        try:
            current_email_changing_request = EmailChangingRequest.objects.get(
                user_id=request.user.email,
                request_completed=False
            )
            print current_email_changing_request.request_token_expire_time
            if current_email_changing_request is not None:
                init_dict['email_change_request'] = {
                    "id": current_email_changing_request.id,
                    "new_email": current_email_changing_request.new_email,
                    "is_expired": None if current_email_changing_request.request_token_expire_time is None else datetime.strptime(current_email_changing_request.request_token_expire_time, "%Y-%m-%d %H:%M:%S.%f") < timezone.now(),
                    "new_email_confirmed": current_email_changing_request.new_email_confirmed,
                    "request_completed": current_email_changing_request.request_completed,
                }
            else:
                init_dict['email_change_request'] = None
        except Exception as e:
            init_dict['email_change_request'] = None    

        return api_response(data=init_dict)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Update profile',
        operation_description='Update current user profile',
        tags=['user'],
        request_body=openapi.Schema(
            type='object',
            properties={
                'nickname': openapi.Schema(
                    type='string',
                    description='Nickname of the user'
                ),
                'intro': openapi.Schema(
                    type='string',
                    description='Self introduction'
                ),
                'department': openapi.Schema(
                    type='string',
                    description='User department name'
                ),
                'telephone': openapi.Schema(
                    type='string',
                    description='User phone number'
                ),
            }
        ),
        responses={
            200: openapi.Response(
                description='Update profile successfully.',
                examples={
                    'application/json': {
                        "message": "Successfully edited profile.",
                        "data": None
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request',
                examples={
                    'application/json': {
                        "message": "",
                        "data": "{}"
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
            )
        }
    )
    def post(self, request):
        username = request.user.username
        form_class = DetailedProfileForm
        form = form_class(request.data)
        if form.is_valid():
            form.save(username=username)
            return api_response(msg=_('Successfully edited profile.'), )
        else:
            return api_error(status.HTTP_400_BAD_REQUEST, _('Failed to edit profile'))

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Update language',
        operation_description='Update current user language',
        tags=['user'],
        request_body=openapi.Schema(
            type='object',
            properties={
                'language': openapi.Schema(
                    description='Language code. Default to "en"',
                    type='string'
                )
            },
        ),
        responses={
            200: openapi.Response(
                description='Update user language successfully.',
                examples={
                    'application/json': {
                        "message": "User language updated.",
                        "data": None
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
            )
        }
    )
    def put(self, request):
        username = request.user.username
        new_lang = request.data.get('language', 'en')
        ccnet_user = CcnetUser.objects.get(email=username)
        ccnet_user.language = new_lang
        ccnet_user.save(using='ccnet')
        return api_response(code=200, msg=_('User language updated.'))

class ProfileBBBSettingView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication, )
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def post(self, request):
        bbb_server_url = request.POST.get('bbb_server_url', '')
        bbb_server_secret = request.POST.get('bbb_server_secret', '')
        is_active = request.POST.get('bbb_is_active', 'false')

        try:
            existing_bbb_config = BBBPrivateSetting.objects.get(
                user_id=request.user.email
            )
        except BBBPrivateSetting.DoesNotExist:
            # not found => create one
            existing_bbb_config = None
        
        if existing_bbb_config is None:
            new_bbb_config = BBBPrivateSetting()

            new_bbb_config.bbb_server = bbb_server_url
            new_bbb_config.bbb_secret = bbb_server_secret
            new_bbb_config.is_active = True if is_active == 'true' else False
            new_bbb_config.user_id = request.user.email

            new_bbb_config.save()
        else:
            # found - update existing
            existing_bbb_config.bbb_server = bbb_server_url
            existing_bbb_config.bbb_secret = bbb_server_secret
            existing_bbb_config.is_active = True if is_active == 'true' else False
            existing_bbb_config.updated_at = datetime.now()

            existing_bbb_config.save()

        return api_response(code=200, msg=_('BBB configuration updated.'))
