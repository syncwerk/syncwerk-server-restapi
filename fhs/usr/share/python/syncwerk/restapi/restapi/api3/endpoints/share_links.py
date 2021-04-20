import os
import logging
from constance import config
from dateutil.relativedelta import relativedelta

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from django.utils import timezone
from django.utils.translation import ugettext as _

from synserv import syncwerk_api
from pyrpcsyncwerk import RpcsyncwerkError

from restapi.api3.utils import api_error, api_response, gen_shared_link, translate_time, send_share_link_audit_signal
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.permissions import CanGenerateShareLink
from restapi.api3.constants import EventLogActionType
from restapi.share.models import FileShare, OrgFileShare
from restapi.utils import is_org_context
from restapi.views import check_folder_permission
from restapi.utils.timeutils import datetime_to_isoformat_timestr

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema
from restapi.api3.utils.file import check_permission_share_public_link

logger = logging.getLogger(__name__)


def get_share_link_info(fileshare):
    data = {}
    token = fileshare.token

    repo_id = fileshare.repo_id
    try:
        print repo_id
        print fileshare
        repo = syncwerk_api.get_repo(repo_id)
    except Exception as e:
        logger.error(e)
        repo = None

    path = fileshare.path
    if path:
        obj_name = '/' if path == '/' else os.path.basename(path.rstrip('/'))
    else:
        obj_name = ''

    if fileshare.expire_date:
        expire_date = translate_time(fileshare.expire_date)
    else:
        expire_date = ''

    if fileshare.ctime:
        ctime = datetime_to_isoformat_timestr(fileshare.ctime)
    else:
        ctime = ''

    data['username'] = fileshare.username
    data['repo_id'] = repo_id
    data['repo_name'] = repo.repo_name if repo else ''

    data['path'] = path
    data['obj_name'] = obj_name
    data['is_dir'] = True if fileshare.s_type == 'd' else False

    data['token'] = token
    data['link'] = gen_shared_link(token, fileshare.s_type)
    data['view_cnt'] = fileshare.view_cnt
    data['ctime'] = ctime
    data['expire_date'] = expire_date
    data['is_expired'] = fileshare.is_expired()
    data['permissions'] = fileshare.get_permissions()
    data['mtime'] = repo.last_modify if repo else None
    data['size'] = repo.size if repo else 0
    data['encrypted'] = repo.encrypted if repo else False
    return data

class ShareLinks(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, CanGenerateShareLink)
    throttle_classes = (UserRateThrottle,)
    parser_classes=(parsers.JSONParser,)

    def _generate_obj_id_and_type_by_path(self, repo_id, path):

        file_id = syncwerk_api.get_file_id_by_path(repo_id, path)
        if file_id:
            return (file_id, 'f')

        dir_id = syncwerk_api.get_dir_id_by_path(repo_id, path)
        if dir_id:
            return (dir_id, 'd')

        return (None, None)

    def _check_permissions_arg(self, request):
        permissions = request.data.get('permissions', None)
        if permissions is not None:
            if isinstance(permissions, dict):
                perm_dict = permissions
            elif isinstance(permissions, basestring):
                import json
                try:
                    perm_dict = json.loads(permissions)
                except ValueError:
                    error_msg = 'permissions invalid: %s' % permissions
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
            else:
                error_msg = 'permissions invalid: %s' % permissions
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
        else:
            perm_dict = None

        can_preview = True
        can_download = True
        if perm_dict is not None:
            can_preview = perm_dict.get('can_preview', True)
            can_download = perm_dict.get('can_download', True)

        if can_preview and can_download:
            perm = FileShare.PERM_VIEW_DL
        if can_preview and not can_download:
            perm = FileShare.PERM_VIEW_ONLY
        return perm

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='User share link',
        operation_description='''Get all share links of the current user''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='folder id for filter share link'
            ),
            openapi.Parameter(
                name="p",
                in_="query",
                type='string',
                description='path for filter share link',
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
                                "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                                "ctime": "2019-02-18T04:47:07+00:00",
                                "mtime": 1550461334,
                                "expire_date": "",
                                "token": "8fb7733e12f54ee4be0e",
                                "view_cnt": 0,
                                "link": "d/8fb7733e12f54ee4be0e/",
                                "size": 0,
                                "obj_name": "/",
                                "path": "/",
                                "is_dir": True,
                                "permissions": {
                                    "can_edit": False,
                                    "can_download": True
                                },
                                "is_expired": False,
                                "encrypted": False,
                                "repo_name": "test wiki 4"
                            }
                        ]
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
        # get all share links
        username = request.user.username
        fileshares = FileShare.objects.filter(username=username)

        repo_id = request.GET.get('repo_id', None)
        if repo_id:
            repo = syncwerk_api.get_repo(repo_id)
            if not repo:
                error_msg = 'Library %s not found.' % repo_id
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            # filter share links by repo
            fileshares = filter(lambda fs: fs.repo_id == repo_id, fileshares)

            path = request.GET.get('path', None)
            if path:
                try:
                    obj_id, s_type = self._generate_obj_id_and_type_by_path(repo_id, path)
                except RpcsyncwerkError as e:
                    logger.error(e)
                    error_msg = 'Internal Server Error'
                    return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

                if not obj_id:
                    if s_type == 'f':
                        error_msg = 'file %s not found.' % path
                    elif s_type == 'd':
                        error_msg = 'folder %s not found.' % path
                    else:
                        error_msg = 'path %s not found.' % path

                    return api_error(status.HTTP_404_NOT_FOUND, error_msg)

                # if path invalid, filter share links by repo
                if s_type == 'd' and path[-1] != '/':
                    path = path + '/'

                fileshares = filter(lambda fs: fs.path == path, fileshares)

        links_info = []
        for fs in fileshares:
            link_info = get_share_link_info(fs)
            links_info.append(link_info)

        if len(links_info) == 1:
            result = links_info
        else:
            dir_list = filter(lambda x: x['is_dir'], links_info)
            file_list = filter(lambda x: not x['is_dir'], links_info)

            dir_list.sort(lambda x, y: cmp(x['obj_name'], y['obj_name']))
            file_list.sort(lambda x, y: cmp(x['obj_name'], y['obj_name']))

            result = dir_list + file_list

        # return Response(result)
        return api_response(data=result)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Create share link',
        operation_description='''Create share link for specific file / folder''',
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
                    description='ath of file / folder to share'
                ),
                "password": openapi.Schema(
                    type='string',
                    description='password if you want ot create a protected share'
                ),
                "expire_days": openapi.Schema(
                    type='number',
                    description='share link will expires after this number of day'
                ),
                "permission": openapi.Schema(
                    type='string',
                    description='permission of the share. "r", "w" or "rw"'
                ),
            }
        ),
        responses={
            200: openapi.Response(
                description='Create share link success.',
                examples={
                    'application/json': {
                        "message": "Create share link successfully.",
                        "data": {
                            "username": "admin@alpha.syncwerk.com",
                            "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                            "ctime": "2019-02-18T04:52:09+00:00",
                            "mtime": 1550461334,
                            "expire_date": "",
                            "token": "394fcbf0dad742019773",
                            "view_cnt": 0,
                            "link": "d/394fcbf0dad742019773/",
                            "size": 0,
                            "obj_name": "/",
                            "path": "/",
                            "is_dir": True,
                            "permissions": {
                                "can_edit": False,
                                "can_download": True
                            },
                            "is_expired": False,
                            "encrypted": False,
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
        if not path:
            error_msg = 'path invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        password = request.data.get('password', None)
        if password and len(password) < config.SHARE_LINK_PASSWORD_MIN_LENGTH:
            error_msg = _('Password is too short.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            expire_days = int(request.data.get('expire_days', 0))
        except ValueError:
            expire_days = 0

        if expire_days <= 0:
            expire_date = None
        else:
            expire_date = timezone.now() + relativedelta(days=expire_days)

        perm = self._check_permissions_arg(request)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            obj_id, s_type = self._generate_obj_id_and_type_by_path(repo_id, path)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if not obj_id:
            if s_type == 'f':
                error_msg = 'file %s not found.' % path
            elif s_type == 'd':
                error_msg = 'folder %s not found.' % path
            else:
                error_msg = 'path %s not found.' % path

            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if not check_folder_permission(request, repo_id, path):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        if not check_permission_share_public_link(request.user): 
            error_msg = 'You dont have permission.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        username = request.user.username
        if s_type == 'f':
            fs = FileShare.objects.get_file_link_by_path(username, repo_id, path)
            if not fs:
                fs = FileShare.objects.create_file_link(username, repo_id, path,
                                                        password, expire_date,
                                                        permission=perm)

        elif s_type == 'd':
            fs = FileShare.objects.get_dir_link_by_path(username, repo_id, path)
            if not fs:
                fs = FileShare.objects.create_dir_link(username, repo_id, path,
                                                       password, expire_date,
                                                       permission=perm)

        if is_org_context(request):
            org_id = request.user.org.org_id
            OrgFileShare.objects.set_org_file_share(org_id, fs)

        link_info = get_share_link_info(fs)

        send_share_link_audit_signal(request, EventLogActionType.CREATE_SHARE_LINK.value, repo_id, path, perm)
        # return Response(link_info)
        return api_response(data=link_info, msg='Create share link successfully.')

class ShareLink(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, CanGenerateShareLink)
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Share link info',
        operation_description='''Get specific share link info''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name="token",
                in_="path",
                type='string',
                description='share link token'
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
                            "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                            "ctime": "2019-02-18T04:52:09+00:00",
                            "mtime": 1550461334,
                            "expire_date": "",
                            "token": "394fcbf0dad742019773",
                            "view_cnt": 0,
                            "link": "d/394fcbf0dad742019773/",
                            "size": 0,
                            "obj_name": "/",
                            "path": "/",
                            "is_dir": True,
                            "permissions": {
                                "can_edit": False,
                                "can_download": True
                            },
                            "is_expired": False,
                            "encrypted": False,
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
    def get(self, request, token):
        try:
            fs = FileShare.objects.get(token=token)
        except FileShare.DoesNotExist:
            error_msg = 'token %s not found.' % token
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        link_info = get_share_link_info(fs)
        # return Response(link_info)
        return api_response(data=link_info)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Remove share link',
        operation_description='''Remove a share link''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name="token",
                in_="path",
                type='string',
                description='share link token'
            ),
        ],
        responses={
            200: openapi.Response(
                description='Share link was deleted successfully.',
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
    def delete(self, request, token):
        try:
            fs = FileShare.objects.get(token=token)
        except FileShare.DoesNotExist:
            # return Response({'success': True})
            return api_response()

        username = request.user.username
        if not fs.is_owner(username):
            error_msg = _('Permission denied.')
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # Get variable
        repo_id = fs.repo_id
        path = fs.path
        perm = fs.permission

        try:
            fs.delete()
        except Exception as e:
            logger.error(e)
            error_msg = _('Internal Server Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)
        # return Response({'success': True})

        send_share_link_audit_signal(request, EventLogActionType.DELETE_SHARE_LINK.value, repo_id, path, perm)
                
        return api_response(msg=_('Share link was deleted successfully.'))
