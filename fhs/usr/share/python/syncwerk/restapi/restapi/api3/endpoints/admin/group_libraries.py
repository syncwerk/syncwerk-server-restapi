# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
import synserv
from synserv import syncwerk_api, ccnet_api

from restapi.utils import is_org_context
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

def get_group_repo_info(repo):
    result = {}
    result['repo_id'] = repo.repo_id
    result['name'] = repo.repo_name
    result['size'] = repo.size
    result['shared_by'] = repo.user
    result['permission'] = repo.permission
    result['group_id'] = repo.group_id
    result['encrypted'] = repo.encrypted

    return result


class AdminGroupLibraries(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - List group folders',
        operation_description='''List group folders''',
        tags=['admin-groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='id of the group',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Group folder list retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "folders": [
                                {
                                    "repo_id": "de138e58-9e0e-4e79-907c-f2a8ad003f5e",
                                    "name": "share to group admin",
                                    "permission": "rw",
                                    "encrypted": False,
                                    "group_id": 1,
                                    "shared_by": "test10@grr.la",
                                    "size": 0
                                }
                            ],
                            "group_id": 1,
                            "group_name": "1"
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
            404: openapi.Response(
                description='Group not found',
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
    def get(self, request, group_id, format=None):
        group_id = int(group_id)
        group = ccnet_api.get_group(group_id)
        if not group:
            error_msg = 'Group %d not found.' % group_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if is_org_context(request):
            org_id = request.user.org.org_id
            repos = syncwerk_api.get_org_group_repos(org_id, group_id)
        else:
            repos = syncwerk_api.get_repos_by_group(group_id)

        group_repos_info = []
        for repo in repos:
            repo_info = get_group_repo_info(repo)
            group_repos_info.append(repo_info)

        group_libraries = {
            'group_id': group_id,
            'group_name': group.group_name,
            'folders': group_repos_info
        }

        # return Response(group_libraries)
        return api_response(data=group_libraries)


class AdminGroupLibrary(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Unshare folder from group',
        operation_description='''Unshare folder from group''',
        tags=['admin-groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='id of the group',
            ),
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder to be unshared',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Group folder unshared successfully',
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
            404: openapi.Response(
                description='Group / Folder not found',
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
    def delete(self, request, group_id, repo_id, format=None):
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        group_id = int(group_id)
        group = ccnet_api.get_group(group_id)
        if not group:
            error_msg = 'Group %d not found.' % group_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            if is_org_context(request):
                org_id = request.user.org.org_id
                synserv.del_org_group_repo(repo_id, org_id, group_id)
            else:
                repo_owner = syncwerk_api.get_repo_owner(repo_id)
                syncwerk_api.unset_group_repo(repo_id, group_id, repo_owner)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # return Response({'success': True})
        return api_response()
