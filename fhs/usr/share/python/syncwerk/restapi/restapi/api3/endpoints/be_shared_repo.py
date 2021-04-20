# Copyright (c) 2012-2016 Seafile Ltd.
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

import synserv
from synserv import syncwerk_api

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response
from restapi.utils import is_valid_username, is_org_context

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class BeSharedRepo(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication )
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Unshare a folder',
        operation_description='''Unshare a specific folder''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='share_type',
                in_='query',
                type='string',
                description='type of the share',
                required=True,
                enum=['personal','group','public']
            ),
            openapi.Parameter(
                name='from',
                in_='query',
                type='string',
                description='if share type is "personal", this will be the email of the share owner',
            ),
            openapi.Parameter(
                name='group_id',
                in_='query',
                type='string',
                description='if share type is "group", this will be the id of the group',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Remove shared folder successfully',
                examples={
                    'application/json': {
                        "message": "Delete shared folder successfully",
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
    def delete(self, request, repo_id, format=None):
        
        if not syncwerk_api.get_repo(repo_id):
            return api_error(status.HTTP_400_BAD_REQUEST, 'Library does not exist')

        username = request.user.username
        share_type = request.GET.get('share_type', None)
        if share_type == 'personal':

            from_email = request.GET.get('from', None)
            if not is_valid_username(from_email):
                return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid argument')

            if is_org_context(request):
                org_id = request.user.org.org_id
                synserv.syncwserv_threaded_rpc.org_remove_share(org_id,
                                                               repo_id,
                                                               from_email,
                                                               username)
            else:
                synserv.remove_share(repo_id, from_email, username)

        elif share_type == 'group':

            from_email = request.GET.get('from', None)
            if not is_valid_username(from_email):
                return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid argument')

            group_id = request.GET.get('group_id', None)
            group = synserv.get_group(group_id)
            if not group:
                return api_error(status.HTTP_400_BAD_REQUEST, 'Group does not exist')

            if not synserv.check_group_staff(group_id, username) and \
                not syncwerk_api.is_repo_owner(username, repo_id):
                return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied')

            if synserv.is_org_group(group_id):
                org_id = synserv.get_org_id_by_group(group_id)
                synserv.del_org_group_repo(repo_id, org_id, group_id)
            else:
                syncwerk_api.unset_group_repo(repo_id, group_id, from_email)

        elif share_type == 'public':

            if is_org_context(request):
                org_repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
                is_org_repo_owner = True if org_repo_owner == username else False

                if not request.user.org.is_staff and not is_org_repo_owner:
                    return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied')

                org_id = request.user.org.org_id
                synserv.syncwserv_threaded_rpc.unset_org_inner_pub_repo(org_id,
                                                                       repo_id)
            else:
                if not syncwerk_api.is_repo_owner(username, repo_id) and \
                    not request.user.is_staff:
                    return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied')

                synserv.unset_inner_pub_repo(repo_id)
        else:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid argument')

        # return Response({'success': True}, status=status.HTTP_200_OK)
        return api_response(msg='Delete be shared library successfully.')
