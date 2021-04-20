import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from restapi.views import check_folder_permission

from synserv import syncwerk_api, get_repo
from pyrpcsyncwerk import RpcsyncwerkError

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class FileRestore(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Restore file',
        operation_description='''Restore file from trash''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='p',
                in_="formData",
                type='string',
                description='path of the file to be restored',
            ),
            openapi.Parameter(
                name='commit_id',
                in_="formData",
                type='string',
                description='commit id',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Folder restored successfully',
                examples={
                    'application/json': {
                        "message": "File restored successfully.",
                        "data": None
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
            403: openapi.Response(
                description='Operation not permitted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='File not found',
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
    def put(self, request, repo_id, format=None):
        
        path = request.data.get('p', None)
        commit_id = request.data.get('commit_id', None)

        if not path:
            error_msg = 'path invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not commit_id:
            error_msg = 'commit_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not syncwerk_api.get_repo(repo_id):
            error_msg = 'library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if not syncwerk_api.get_file_id_by_commit_and_path(repo_id, commit_id, path):
            error_msg = 'file %s not found.' % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if check_folder_permission(request, repo_id, '/') != 'rw':
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        username = request.user.username
        try:
            syncwerk_api.revert_file(repo_id, commit_id, path, username)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return api_response(msg='File restored successfully.')
