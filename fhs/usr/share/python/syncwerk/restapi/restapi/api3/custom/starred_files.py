import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.utils import api_error, api_response, prepare_starred_files
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle

from restapi.base.models import UserStarredFiles
from restapi.utils.star import star_file, unstar_file
from restapi.views import check_folder_permission

from pyrpcsyncwerk import RpcsyncwerkError
import synserv
from synserv import syncwerk_api

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema


class StarredFileView(APIView):
    """
    Support uniform interface for starred file operation,
    including add/delete/list starred files.
    """

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get list favorite files',
        operation_description='''Get all favorite files of the current users''',
        tags=['files'],
        responses={
            200: openapi.Response(
                description='Favorite file list retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "file_name": "02 \u307f\u3061\u3057\u308b\u3079.flac",
                                "icon_path": "24/music.png",
                                "oid": "9366dc42410ccec2475c94e3d6f533540aa9dbee",
                                "mtime_relative": "<time datetime=\"2019-02-01T08:20:37\" is=\"relative-time\" title=\"Fri, 1 Feb 2019 08:20:37 +0000\" >2019-02-01</time>",
                                "repo": "bacd10c8-032b-4696-9b04-37b2a75c06e7",
                                "org": -1,
                                "path": "/02 \u307f\u3061\u3057\u308b\u3079.flac",
                                "size": 167051678,
                                "repo_id": "bacd10c8-032b-4696-9b04-37b2a75c06e7",
                                "mtime": 1549009237,
                                "dir": False,
                                "repo_name": "Minh Nguyen"
                            }
                        ]
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
        # list starred files
        personal_files = UserStarredFiles.objects.get_starred_files_by_username(
            request.user.username)
        starred_files = prepare_starred_files(personal_files)
        # return Response(starred_files)
        return api_response(data=starred_files)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Mark file as favorite',
        operation_description='''Mark a specific file as favorite''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="formData",
                type='string',
                description='repo id that the file is in.',
                required=True,
            ),
            openapi.Parameter(
                name='p',
                in_="formData",
                type='string',
                description='path to the file to be marked as favorite.',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Marked file as favorite successfully.',
                examples={
                    'application/json': {
                        "message": "",
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
    def post(self, request, format=None):
        
        # add starred file
        repo_id = request.POST.get('repo_id', '')
        path = request.POST.get('p', '')

        if not (repo_id and path):
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'Library ID or path is missing.')

        if check_folder_permission(request, repo_id, path) is None:
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied')

        try:
            file_id = syncwerk_api.get_file_id_by_path(repo_id, path)
        except RpcsyncwerkError as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal error')

        if not file_id:
            return api_error(status.HTTP_404_NOT_FOUND, "File not found")

        if path[-1] == '/':     # Should not contain '/' at the end of path.
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid file path.')

        star_file(request.user.username, repo_id, path, is_dir=False,
                  org_id=-1)

        # resp = Response('success', status=status.HTTP_201_CREATED)
        # resp['Location'] = reverse('starredfiles')

        # return resp
        return api_response(code=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Remove file from favorite',
        operation_description='''Remove file from favorite files''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="query",
                type='string',
                description='repo id that the file is in.',
                required=True,
            ),
            openapi.Parameter(
                name='p',
                in_="query",
                type='string',
                description='path to the favorite file to be removed.',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Removed file from favorite successfully.',
                examples={
                    'application/json': {
                        "message": "",
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
    def delete(self, request, format=None):
        
        # remove starred file
        repo_id = request.GET.get('repo_id', '')
        path = request.GET.get('p', '')

        if not (repo_id and path):
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'Library ID or path is missing.')

        if check_folder_permission(request, repo_id, path) is None:
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied')

        try:
            file_id = syncwerk_api.get_file_id_by_path(repo_id, path)
        except RpcsyncwerkError as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal error')

        if not file_id:
            return api_error(status.HTTP_404_NOT_FOUND, "File not found")

        if path[-1] == '/':     # Should not contain '/' at the end of path.
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid file path.')

        unstar_file(request.user.username, repo_id, path)
        # return Response('success', status=status.HTTP_200_OK)
        return api_response()
