# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from django.utils.translation import ugettext as _

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from synserv import syncwerk_api
from pyrpcsyncwerk import RpcsyncwerkError

from restapi.utils import is_valid_username
from restapi.utils.timeutils import timestamp_to_isoformat_timestr

from restapi.api3.authentication import TokenAuthentication
from restapi.api2.throttling import UserRateThrottle

from restapi.api3.utils import api_error, api_response

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

def get_trash_repo_info(repo):

    result = {}
    result['name'] = repo.repo_name
    result['id'] = repo.repo_id
    result['owner'] = repo.owner_id
    result['delete_time'] = timestamp_to_isoformat_timestr(repo.del_time)
    result['encrypted'] = repo.encrypted

    return result


class AdminTrashLibraries(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get system trash folders',
        operation_description='''Get system trash folders''',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='owner',
                in_="query",
                type='string',
                description='email of the owner for filtering',
            ),
            openapi.Parameter(
                name='page',
                in_="query",
                type='string',
                description='page. Default to 1',
            ),
            openapi.Parameter(
                name='per_page',
                in_="query",
                type='string',
                description='number of items per page. Default to 100',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Folders list retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "page_info": {
                                "current_page": 1,
                                "has_next_page": False
                            },
                            "repos": [
                                {
                                    "owner": "admin@alpha.syncwerk.com",
                                    "encrypted": False,
                                    "delete_time": "2019-02-11T06:56:43+00:00",
                                    "name": "fewfwefewf",
                                    "id": "e1828259-dcdf-44ee-b509-4397ba79dcf5"
                                },
                                {
                                    "owner": "admin@alpha.syncwerk.com",
                                    "encrypted": False,
                                    "delete_time": "2019-01-24T03:09:19+00:00",
                                    "name": "test111",
                                    "id": "025f707d-2442-427f-abe1-8077dc91d4eb"
                                }
                            ]
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
        # list by owner
        search_owner = request.GET.get('owner', '')
        if search_owner:
            if not is_valid_username(search_owner):
                error_msg = 'owner invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            repos = syncwerk_api.get_trash_repos_by_owner(search_owner)

            return_repos = []
            for repo in repos:
                result = get_trash_repo_info(repo)
                return_repos.append(result)
            data = {"search_owner": search_owner, "repos": return_repos}
            return api_response(data=data)

        # list by page
        try:
            current_page = int(request.GET.get('page', '1'))
            per_page = int(request.GET.get('per_page', '100'))
        except ValueError:
            current_page = 1
            per_page = 100

        start = (current_page - 1) * per_page
        limit = per_page + 1

        repos_all = syncwerk_api.get_trash_repo_list(start, limit)

        if len(repos_all) > per_page:
            repos_all = repos_all[0:per_page]
            has_next_page = True
        else:
            has_next_page = False

        return_results = []
        for repo in repos_all:
            repo_info = get_trash_repo_info(repo)
            return_results.append(repo_info)

        page_info = {
            'has_next_page': has_next_page,
            'current_page': current_page
        }
        data = {"page_info": page_info, "repos": return_results}
        return api_response(data=data)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Permantly deleted all folders of specific owner',
        operation_description='''Permantly deleted all folders of specific owner''',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='owner',
                in_="formData",
                type='string',
                description='email of the owner',
            ),
        ],
        responses={
            200: openapi.Response(
                description='All folders deleted successfully',
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
        owner = request.data.get('owner', '')
        try:
            if owner:
                if not is_valid_username(owner):
                    error_msg = 'owner invalid.'
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

                syncwerk_api.empty_repo_trash_by_owner(owner)
            else:
                syncwerk_api.empty_repo_trash()
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return api_response(msg=_("Cleaned trash successfully."))

class AdminTrashLibrary(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Restore deleted folder',
        operation_description='''Restore a deleted folder''',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the deleted folder to be restored',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Folder restored successfully',
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
    def put(self, request, repo_id, format=None):
        try:
            syncwerk_api.restore_repo_from_trash(repo_id)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return api_response(msg=_('Restored folder successfully.'))

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Permanently remove a folder.',
        operation_description='''Permanently remove a folder''',
        operation_id='admin_trash_library_delete',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the deleted folder to be removed permanently',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Folder removed successfully',
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
    def delete(self, request, repo_id, format=None):
        try:
            syncwerk_api.del_repo_from_trash(repo_id)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return api_response(msg=_('Permanently removed folder successfully.'))
