import os

from django.utils.translation import ugettext as _
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from synserv import syncwerk_api, get_repo

from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.share.models import FileShare, UploadLinkShare
from restapi.utils import is_org_context
from restapi.utils.timeutils import datetime_to_isoformat_timestr

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_response, api_error

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class RepoDownloadSharedLinks(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get folder download links',
        operation_description='''Get all download links for a specific folder''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
        ],
        responses={
            200: openapi.Response(
                description='List retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "share_type": "d",
                                "view_count": 1,
                                "name": "/",
                                "creator_name": "admin",
                                "create_by": "admin@alpha.syncwerk.com",
                                "token": "394fcbf0dad742019773",
                                "create_time": "2019-02-18T04:52:09+00:00",
                                "path": "/",
                                "size": ""
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
    def get(self, request, repo_id, format=None):
        
        repo = get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        org_id = None
        if is_org_context(request):
            org_id = request.user.org.org_id

        # check permission
        if org_id:
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        if request.user.username != repo_owner or repo.is_virtual:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        shared_links = []
        fileshares = FileShare.objects.filter(repo_id=repo_id)
        for fs in fileshares:
            size = None
            shared_link = {}
            if fs.is_file_share_link():
                path = fs.path.rstrip('/') # Normalize file path
                if syncwerk_api.get_file_id_by_path(repo.id, fs.path) is None:
                    continue

                obj_id = syncwerk_api.get_file_id_by_path(repo_id, path)
                size = syncwerk_api.get_file_size(repo.store_id, repo.version, obj_id)
            else:
                path = fs.path
                if path[-1] != '/': # Normalize dir path
                    path += '/'

                if syncwerk_api.get_dir_id_by_path(repo.id, fs.path) is None:
                    continue

            shared_link['create_by'] = fs.username
            shared_link['creator_name'] = email2nickname(fs.username)
            shared_link['create_time'] = datetime_to_isoformat_timestr(fs.ctime)
            shared_link['token'] = fs.token
            shared_link['path'] = path
            shared_link['name'] = os.path.basename(path.rstrip('/')) if path != '/' else '/'
            shared_link['view_count'] = fs.view_cnt
            shared_link['share_type'] = fs.s_type
            shared_link['size'] = size if size else ''
            shared_links.append(shared_link)

        # return Response(shared_links)
        return api_response(data=shared_links)


class RepoDownloadSharedLink(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Remove folder download link',
        operation_description='''Remove a specific download links of the folder''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='token',
                in_="path",
                type='string',
                description='token of the download link',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Download shared link deleted successfully.',
                examples={
                    'application/json': {
                        "message": "Download shared link deleted successfully.",
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
            404: openapi.Response(
                description='Folder / link not found',
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
    def delete(self, request, repo_id, token, format=None):
        repo = get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        org_id = None
        if is_org_context(request):
            org_id = request.user.org.org_id

        # check permission
        if org_id:
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        if request.user.username != repo_owner or repo.is_virtual:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            link = FileShare.objects.get(token=token)
        except FileShare.DoesNotExist:
            error_msg = 'Link %s not found.' % token
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        link.delete()
        # result = {'success': True}
        # return Response(result)
        return api_response(msg=_('Download shared link deleted successfully.'))


class RepoUploadSharedLinks(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get folder upload links',
        operation_description='''Get all upload links for a specific folder''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
        ],
        responses={
            200: openapi.Response(
                description='List retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "view_count": 0,
                                "name": "/",
                                "creator_name": "admin",
                                "create_by": "admin@alpha.syncwerk.com",
                                "token": "b2e3f939706740dbae66",
                                "create_time": "2019-02-18T07:01:50+00:00",
                                "path": "/"
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
    def get(self, request, repo_id, format=None):
        repo = get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        org_id = None
        if is_org_context(request):
            org_id = request.user.org.org_id

        # check permission
        if org_id:
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        if request.user.username != repo_owner or repo.is_virtual:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        shared_links = []
        fileshares = UploadLinkShare.objects.filter(repo_id=repo_id)
        for fs in fileshares:
            shared_link = {}
            path = fs.path
            if path[-1] != '/': # Normalize dir path
                path += '/'

            if syncwerk_api.get_dir_id_by_path(repo.id, fs.path) is None:
                continue

            shared_link['create_by'] = fs.username
            shared_link['creator_name'] = email2nickname(fs.username)
            shared_link['create_time'] = datetime_to_isoformat_timestr(fs.ctime)
            shared_link['token'] = fs.token
            shared_link['path'] = path
            shared_link['name'] = os.path.basename(path.rstrip('/')) if path != '/' else '/'
            shared_link['view_count'] = fs.view_cnt
            shared_links.append(shared_link)

        # return Response(shared_links)
        return api_response(data=shared_links)


class RepoUploadSharedLink(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Remove folder upload link',
        operation_description='''Remove a specific upload link of the folder''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='token',
                in_="path",
                type='string',
                description='token of the download link',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Upload shared link deleted successfully.',
                examples={
                    'application/json': {
                        "message": "Upload shared link deleted successfully.",
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
            404: openapi.Response(
                description='Folder / link not found',
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
    def delete(self, request, repo_id, token, format=None):
        repo = get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        org_id = None
        if is_org_context(request):
            org_id = request.user.org.org_id

        # check permission
        if org_id:
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        if request.user.username != repo_owner or repo.is_virtual:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            link = UploadLinkShare.objects.get(token=token)
        except FileShare.DoesNotExist:
            error_msg = 'Link %s not found.' % token
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        link.delete()
        # result = {'success': True}
        # return Response(result)
        return api_response(msg=_('Upload shared link has been deleted successfully.'))
