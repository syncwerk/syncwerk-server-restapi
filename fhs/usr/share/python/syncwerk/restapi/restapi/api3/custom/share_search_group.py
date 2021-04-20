from constance import config

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from django.conf import settings

import synserv
from synserv import ccnet_api
from synserv import syncwerk_api

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response

from restapi.utils import is_org_context
from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.group.utils import is_group_member, is_group_admin, \
    is_group_owner, is_group_admin_or_owner

try:
    from restapi.settings import CLOUD_MODE
except ImportError:
    CLOUD_MODE = False

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

def get_group_info(group_id):
    group = ccnet_api.get_group(group_id)
    isoformat_timestr = timestamp_to_isoformat_timestr(group.timestamp)
    group_info = {
        "id": group.id,
        "name": group.group_name,
        "owner": group.creator_name,
        "created_at": isoformat_timestr,
    }

    return group_info

class ShareSearchGroup(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def _can_use_global_address_book(self, request):

        return request.user.permissions.can_use_global_address_book()

    def list_group_shared_items(self, request, repo_id, path):
        username = request.user.username
        if is_org_context(request):
            org_id = request.user.org.org_id
            if path == '/':
                share_items = syncwerk_api.list_org_repo_shared_group(org_id,
                        username, repo_id)
            else:
                share_items = syncwerk_api.get_org_shared_groups_for_subdir(org_id,
                        repo_id, path, username)
        else:
            if path == '/':
                share_items = syncwerk_api.list_repo_shared_group_by_user(username, repo_id)
            else:
                share_items = syncwerk_api.get_shared_groups_for_subdir(repo_id,
                                                                       path, username)
        ret = []
        for item in share_items:
            ret.append(item.group_id)
        return ret

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Search groups to share',
        operation_description='''Search groups from to share''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='folder id for filtering the search',
            ),
            openapi.Parameter(
                name='p',
                in_="query",
                type='string',
                description='path of the folder for filtering the search.',
            ),
            openapi.Parameter(
                name='q',
                in_="query",
                type='string',
                description='query for search',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Result retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "owner": "admin@alpha.syncwerk.com",
                                "created_at": "2019-01-23T10:50:47+00:00",
                                "id": 1,
                                "name": "1"
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
        

        # argument check
        q = request.GET.get('q', None)
        if not q:
            error_msg = 'q invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, 'Library %s not found.' % repo_id)

        path = request.GET.get('p', '/')
        if syncwerk_api.get_dir_id_by_path(repo.id, path) is None:
            return api_error(status.HTTP_404_NOT_FOUND, 'Folder %s not found.' % path)

        shared_group = self.list_group_shared_items(request, repo_id, path)

        # permission check
        # if not self._can_use_global_address_book(request):
        #     error_msg = 'Permission denied.'
        #     return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        if CLOUD_MODE:
            if is_org_context(request):
                org_id = request.user.org.org_id
                groups = ccnet_api.get_org_groups(org_id, -1, -1)
            elif config.ENABLE_GLOBAL_ADDRESSBOOK:
                username = request.user.username
                groups = ccnet_api.get_personal_groups_by_user(username)
            else:
                username = request.user.username
                groups = synserv.get_personal_groups_by_user(username)
        else:
            # groups = ccnet_api.get_all_groups(-1, -1)
            username = request.user.username
            groups = synserv.get_personal_groups_by_user(username)

        result = []
        for group in groups:
            group_name = group.group_name
            if not group_name:
                continue
            if group.id in shared_group:
                continue
            # if is_group_owner(group.id, request.user.email) is False:
            #     continue
            if q.lower() in group_name.lower():
                group_info = get_group_info(group.id)
                result.append(group_info)

        # return Response(result)
        return api_response(data=result)
