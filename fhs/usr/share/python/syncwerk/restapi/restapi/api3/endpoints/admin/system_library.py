# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from synserv import syncwerk_api

from restapi.views import get_system_default_repo_id
from restapi.utils import gen_file_upload_url, normalize_dir_path

from restapi.api3.authentication import TokenAuthentication
from restapi.api2.throttling import UserRateThrottle
# from restapi.api2.utils import api_error

from restapi.api3.utils import api_error, api_response


logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class AdminSystemLibrary(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get system folder info',
        operation_description='''Get system folder info''',
        tags=['admin-folders'],
        responses={
            200: openapi.Response(
                description='Folder info retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "name": "folder name",
                            "id": "folder id",
                            "description": "folder description",
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid",
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
    def get(self, request, format=None):
        try:
            repo = syncwerk_api.get_repo(get_system_default_repo_id())
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(code=status.HTTP_500_INTERNAL_SERVER_ERROR, msg=error_msg)

        result = {}
        result['name'] = repo.repo_name
        result['id'] = repo.repo_id
        result['description'] = repo.desc

        return api_response(data=result)


class AdminSystemLibraryUploadLink(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get system folder upload link',
        operation_description='''Get link for upload files / folder to the system folder''',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='from',
                in_="query",
                type='string',
                description='"web" or "api". Default to "web"',
            ),
            openapi.Parameter(
                name='path',
                in_="query",
                type='string',
                description='upload path. Default to "/"',
            ),
        ],
        responses={
            200: openapi.Response(
                description='List retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "upload_link": "https://alpha.syncwerk.com/seafhttp/upload-aj/cac8ae03-4e30-422a-b50f-75ceac7052df"
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
                        "detail": "Token invalid",
                    }
                }
            ),
            404: openapi.Response(
                description='Folder not found',
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
        req_from = request.GET.get('from', 'web')
        if req_from not in ('web', 'api'):
            error_msg = 'from invalid.'
            return api_error(code=status.HTTP_400_BAD_REQUEST, msg=error_msg)

        # recourse check
        try:
            repo_id = syncwerk_api.get_system_default_repo_id()
            repo = syncwerk_api.get_repo(repo_id)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(code=status.HTTP_500_INTERNAL_SERVER_ERROR, msg=error_msg)

        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(code=status.HTTP_404_NOT_FOUND, msg=error_msg)

        parent_dir = request.GET.get('path', '/')
        parent_dir = normalize_dir_path(parent_dir)
        dir_id = syncwerk_api.get_dir_id_by_path(repo_id, parent_dir)
        if not dir_id:
            error_msg = 'Folder %s not found.' % parent_dir
            return api_error(code=status.HTTP_404_NOT_FOUND, msg=error_msg)

        token = syncwerk_api.get_fileserver_access_token(repo_id,
                                                         'dummy', 'upload', 'system', use_onetime=False)

        if not token:
            error_msg = 'Internal Server Error'
            return api_error(code=status.HTTP_500_INTERNAL_SERVER_ERROR, msg=error_msg)

        if req_from == 'api':
            url = gen_file_upload_url(token, 'upload-api')
        else:
            url = gen_file_upload_url(token, 'upload-aj')

        result = {}
        result['upload_link'] = url
        return api_response(data=result)
