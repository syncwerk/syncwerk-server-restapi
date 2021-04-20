# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.utils.translation import ugettext as _

from synserv import syncwerk_api

from restapi.options.models import UserOptions
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response
from restapi.base.accounts import User
from restapi.views import get_system_default_repo_id

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class AdminDefaultLibrary(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    def create_default_repo(self, username):

        default_repo_id = syncwerk_api.create_repo(name=_("My Library"),
                desc=_("My Library"), username=username, passwd=None)

        sys_repo_id = get_system_default_repo_id()
        if not sys_repo_id or not syncwerk_api.get_repo(sys_repo_id):
            return None

        dirents = syncwerk_api.list_dir_by_path(sys_repo_id, '/')
        for dirent in dirents:
            obj_name = dirent.obj_name
            syncwerk_api.copy_file(sys_repo_id, '/', obj_name,
                    default_repo_id, '/', obj_name, username, 0)

        UserOptions.objects.set_default_repo(username, default_repo_id)

        return default_repo_id

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get info of common user\'s default folder',
        operation_description='''Get info of common user\'s default folder''',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='user_email',
                in_='path',
                type='string',
                description='user email',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrived successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "user_email": "",
                            "exists": True,
                            "repo_id": "folder id"
                        }
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": 'Token invalid'
                    }
                }
            ),
            404: openapi.Response(
                description='Not found',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error",
                        "data": None
                    }
                }
            ),
        }
    )
    def get(self, request):
        # argument check
        user_email = request.GET.get('user_email', None)
        if not user_email:
            error_msg = 'user_email invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            User.objects.get(email=user_email)
        except User.DoesNotExist:
            error_msg = 'User %s not found.' % user_email
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # get default library info
        try:
            default_repo_id = UserOptions.objects.get_default_repo(user_email)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        default_repo_info = {}
        default_repo_info['user_email'] = user_email
        if default_repo_id and syncwerk_api.get_repo(default_repo_id) is not None:
            default_repo_info['exists'] = True
            default_repo_info['repo_id'] = default_repo_id
        else:
            default_repo_info['exists'] = False

        # return Response(default_repo_info)
        return api_response(data=default_repo_info)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Create a default folder for a common user.',
        operation_description='''Create a default folder for a common user.''',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='user_email',
                in_='formData',
                type='string',
                description='user email',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='User default folder created successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "user_email": "",
                            "exists": True,
                            "repo_id": "folder id"
                        }
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": 'Token invalid'
                    }
                }
            ),
            403: openapi.Response(
                description='Operation not permitted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error",
                        "data": None
                    }
                }
            ),
        }
    )
    def post(self, request):
        # argument check
        user_email = request.POST.get('user_email', None)
        if not user_email:
            error_msg = 'user_email invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            common_user = User.objects.get(email=user_email)
        except User.DoesNotExist:
            error_msg = 'User %s not found.' % user_email
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if not common_user.permissions.can_add_repo():
            error_msg = 'Permission denied, %s can not create library.' % user_email
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # create default library for common use
        try:
            default_repo_id = UserOptions.objects.get_default_repo(user_email)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        default_repo_info = {}
        default_repo_info['user_email'] = user_email
        default_repo_info['exists'] = True

        try:
            if default_repo_id and syncwerk_api.get_repo(default_repo_id) is not None:
                default_repo_info['repo_id'] = default_repo_id
            else:
                new_default_repo_id = self.create_default_repo(user_email)
                default_repo_info['repo_id'] = new_default_repo_id
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # return Response(default_repo_info)
        return api_response(data=default_repo_info)
