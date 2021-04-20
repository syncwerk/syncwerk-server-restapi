import os
import logging
from constance import config

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from django.utils.translation import ugettext as _

from synserv import syncwerk_api
from pyrpcsyncwerk import RpcsyncwerkError

from restapi.api3.utils import api_error, api_response, gen_shared_upload_link, send_upload_link_audit_signal
from restapi.api3.constants import EventLogActionType
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.permissions import CanGenerateUploadLink

from restapi.share.models import UploadLinkShare
from restapi.views import check_folder_permission
from restapi.utils.timeutils import datetime_to_isoformat_timestr

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)

def _get_upload_link_info(uls):
    data = {}
    token = uls.token

    repo_id = uls.repo_id
    try:
        repo = syncwerk_api.get_repo(repo_id)
    except Exception as e:
        logger.error(e)
        repo = None

    path = uls.path
    if path:
        obj_name = '/' if path == '/' else os.path.basename(path.rstrip('/'))
    else:
        obj_name = ''

    if uls.ctime:
        ctime = datetime_to_isoformat_timestr(uls.ctime)
    else:
        ctime = ''

    data['repo_id'] = repo_id
    data['repo_name'] = repo.repo_name if repo else ''
    data['path'] = path
    data['obj_name'] = obj_name
    data['view_cnt'] = uls.view_cnt
    data['ctime'] = ctime
    data['link'] = gen_shared_upload_link(token)
    data['token'] = token
    data['username'] = uls.username
    data['mtime'] = repo.last_modify if repo else None
    data['size'] = repo.size if repo else 0
    data['encrypted'] = repo.encrypted if repo else False
    return data

class UploadLinks(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, CanGenerateUploadLink)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.JSONParser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get all upload links',
        operation_description='''Get all upload links of the user''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='folder id for filter upload link'
            ),
            openapi.Parameter(
                name="p",
                in_="query",
                type='string',
                description='path for filter upload link',
                required=True
            ),
        ],
        responses={
            200: openapi.Response(
                description='Successfully retrieve result.',
                examples={
                    'application/json': {
                    "message": "",
                    "data": [
                        {
                            "username": "admin@alpha.syncwerk.com",
                            "view_cnt": 0,
                            "ctime": "2019-02-18T06:53:55+00:00",
                            "encrypted": False,
                            "mtime": 1550461334,
                            "token": "65f58d7c4b984b178e93",
                            "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                            "link": "u/d/65f58d7c4b984b178e93/",
                            "obj_name": "/",
                            "path": "/",
                            "size": 0,
                            "repo_name": "test wiki 4"
                        }
                    ]
                }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
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
        # get all upload links
        username = request.user.username
        upload_link_shares = UploadLinkShare.objects.filter(username=username)

        repo_id = request.GET.get('repo_id', None)
        if repo_id:
            repo = syncwerk_api.get_repo(repo_id)
            if not repo:
                error_msg = 'Library %s not found.' % repo_id
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            # filter share links by repo
            upload_link_shares = filter(lambda ufs: ufs.repo_id==repo_id, upload_link_shares)

            path = request.GET.get('path', None)
            if path:
                try:
                    dir_id = syncwerk_api.get_dir_id_by_path(repo_id, path)
                except RpcsyncwerkError as e:
                    logger.error(e)
                    error_msg = 'Internal Server Error'
                    return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

                if not dir_id:
                    error_msg = 'folder %s not found.' % path
                    return api_error(status.HTTP_404_NOT_FOUND, error_msg)

                if path[-1] != '/':
                    path = path + '/'

                # filter share links by path
                upload_link_shares = filter(lambda ufs: ufs.path==path, upload_link_shares)

        result = []
        for uls in upload_link_shares:
            link_info = _get_upload_link_info(uls)
            result.append(link_info)

        if len(result) == 1:
            result = result
        else:
            result.sort(lambda x, y: cmp(x['obj_name'], y['obj_name']))

        # return Response(result)
        return api_response(data=result)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Create upload link',
        operation_description='''Create upload link for specific folder''',
        tags=['shares'],
        request_body=openapi.Schema(
            type="object",
            properties={
                "repo_id": openapi.Schema(
                    type='string',
                    description='folder id'
                ),
                "path": openapi.Schema(
                    type='string',
                    description='path of folder for creating upload link'
                ),
                "password": openapi.Schema(
                    type='string',
                    description='password if you want ot create a protected uplaod link'
                ),
            }
        ),
        responses={
            200: openapi.Response(
                description='Create upload link success.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "username": "admin@alpha.syncwerk.com",
                            "view_cnt": 0,
                            "ctime": "2019-02-18T07:01:50+00:00",
                            "encrypted": False,
                            "mtime": 1550461334,
                            "token": "b2e3f939706740dbae66",
                            "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                            "link": "u/d/b2e3f939706740dbae66/",
                            "obj_name": "/",
                            "path": "/",
                            "size": 0,
                            "repo_name": "test wiki 4"
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
                        "detail": "Token invalid"
                    }
                }
            ),
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='File / folder not found',
                examples={
                    'application/json': {
                        "message": "File / folder not found",
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
        repo_id = request.data.get('repo_id', None)
        if not repo_id:
            error_msg = 'repo_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        path = request.data.get('path', None)
        print 'this is the path'
        print path
        if not path:
            error_msg = 'path invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        password = request.data.get('password', None)
        if password and len(password) < config.SHARE_LINK_PASSWORD_MIN_LENGTH:
            error_msg = _('Password is too short')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            dir_id = syncwerk_api.get_dir_id_by_path(repo_id, path)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if not dir_id:
            error_msg = 'folder %s not found.' % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if check_folder_permission(request, repo_id, path) != 'rw':
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        username = request.user.username
        uls = UploadLinkShare.objects.get_upload_link_by_path(username, repo_id, path)
        if not uls:
            uls = UploadLinkShare.objects.create_upload_link_share(username,
                repo_id, path, password)

        link_info = _get_upload_link_info(uls)

        send_upload_link_audit_signal(request, EventLogActionType.CREATE_UPLOAD_LINK.value, repo_id, path)
        # return Response(link_info)
        return api_response(data=link_info)

class UploadLink(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, CanGenerateUploadLink)
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Upload link info',
        operation_description='''Get specific upload link info''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name="token",
                in_="path",
                type='string',
                description='upload link token'
            ),
        ],
        responses={
            200: openapi.Response(
                description='Retrive info successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "username": "admin@alpha.syncwerk.com",
                            "view_cnt": 0,
                            "ctime": "2019-02-18T07:01:50+00:00",
                            "encrypted": False,
                            "mtime": 1550461334,
                            "token": "b2e3f939706740dbae66",
                            "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                            "link": "u/d/b2e3f939706740dbae66/",
                            "obj_name": "/",
                            "path": "/",
                            "size": 0,
                            "repo_name": "test wiki 4"
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
                    }
                }
            ),
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='Not found',
                examples={
                    'application/json': {
                        "message": "Not found",
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
    def get(self, request, token):
        try:
            uls = UploadLinkShare.objects.get(token=token)
        except UploadLinkShare.DoesNotExist:
            error_msg = 'token %s not found.' % token
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        link_info = self._get_upload_link_info(uls)
        # return Response(link_info)
        return api_response(data=link_info)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Remove upload link',
        operation_description='''Remove an upload link''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name="token",
                in_="path",
                type='string',
                description='upload link token'
            ),
        ],
        responses={
            200: openapi.Response(
                description='Upload link was deleted successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
                    }
                }
            ),
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='Not found',
                examples={
                    'application/json': {
                        "message": "Not found",
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
    def delete(self, request, token):
        try:
            uls = UploadLinkShare.objects.get(token=token)
        except UploadLinkShare.DoesNotExist:
            return Response({'success': True})

        username = request.user.username
        if not uls.is_owner(username):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # Get variable
        repo_id = uls.repo_id
        path = uls.path

        try:
            uls.delete()
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)
        send_upload_link_audit_signal(request, EventLogActionType.DELETE_UPLOAD_LINK.value, repo_id, path)
        # return Response({'success': True})
        return api_response()
