# Copyright (c) 2012-2016 Seafile Ltd.
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from synserv import ccnet_api

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response
from restapi.group.models import GroupMessage
from .utils import api_check_group
from restapi.group.utils import is_group_admin_or_owner

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

json_content_type = 'application/json; charset=utf-8'

class GroupDiscussion(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Remove a group discussion',
        operation_description='''Remove a group discussion''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='group id',
            ),
            openapi.Parameter(
                name='discuss_id',
                in_="path",
                type='string',
                description='id of the discussion to be removed',
            ),
        ],
        responses={
            204: openapi.Response(
                description='Discussion removed successfully.',
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
                        "message": "Internal server error",
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
    @api_check_group
    def delete(self, request, group_id, discuss_id, format=None):
        
        username = request.user.username
        group_id = int(group_id)

        try:
            discussion = GroupMessage.objects.get(pk=discuss_id)
        except GroupMessage.DoesNotExist:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Discussion id %s not found.' % discuss_id)

        # perm check
        if not is_group_admin_or_owner(group_id, username) and \
            discussion.from_email != username:
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

        discussion.delete()

        # return Response(status=204)
        return api_response(code=status.HTTP_204_NO_CONTENT)
