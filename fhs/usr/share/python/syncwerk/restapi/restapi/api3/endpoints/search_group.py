from constance import config

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from django.conf import settings

import synserv
from synserv import ccnet_api

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response

from restapi.utils import is_org_context
from restapi.utils.timeutils import timestamp_to_isoformat_timestr

from drf_yasg.utils import swagger_auto_schema, no_body
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

try:
    from restapi.settings import CLOUD_MODE
except ImportError:
    CLOUD_MODE = False

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

class SearchGroup(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def _can_use_global_address_book(self, request):

        return request.user.permissions.can_use_global_address_book()

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Search group',
        operation_description='Search all groups',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='q',
                in_="query",
                type='string',
                description='Query string',
                required=True,
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
                                "owner": "admin@alpha.syncwerk.com",
                                "created_at": "2019-02-15T08:17:22+00:00",
                                "id": 4,
                                "name": "Group 3"
                            },
                            {
                                "owner": "admin@alpha.syncwerk.com",
                                "created_at": "2019-01-24T03:41:48+00:00",
                                "id": 3,
                                "name": "3"
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
        }
    )
    def get(self, request, format=None):
        # argument check
        q = request.GET.get('q', None)
        if not q:
            error_msg = 'q invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # permission check
        if not self._can_use_global_address_book(request):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        if CLOUD_MODE:
            if is_org_context(request):
                org_id = request.user.org.org_id
                groups = ccnet_api.get_org_groups(org_id, -1, -1)
            elif config.ENABLE_GLOBAL_ADDRESSBOOK:
                groups = ccnet_api.get_all_groups(-1, -1)
            else:
                username = request.user.username
                groups = synserv.get_personal_groups_by_user(username)
        else:
            groups = ccnet_api.get_all_groups(-1, -1)

        result = []
        for group in groups:
            group_name = group.group_name
            if not group_name:
                continue

            if q.lower() in group_name.lower():
                group_info = get_group_info(group.id)
                result.append(group_info)

        # return Response(result)
        return api_response(data=result)
