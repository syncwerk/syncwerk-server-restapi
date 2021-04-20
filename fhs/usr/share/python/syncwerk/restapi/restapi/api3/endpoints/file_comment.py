# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from synserv import syncwerk_api

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.permissions import IsRepoAccessible
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response, user_to_dict
from restapi.avatar.settings import AVATAR_DEFAULT_SIZE
from restapi.base.models import FileComment

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class FileCommentView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, IsRepoAccessible)
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get a comment',
        operation_description='''Get a specific comment''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='folder id.',
            ),
            openapi.Parameter(
                name='pk',
                in_="path",
                type='string',
                description='comment id.',
            ),
            openapi.Parameter(
                name='avatar_size',
                in_="query",
                type='string',
                description='size of the avatar thumbnail.',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Comment retrived successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
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
    def get(self, request, repo_id, pk, format=None):
        try:
            o = FileComment.objects.get(pk=pk)
        except FileComment.DoesNotExist:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Wrong comment id')

        try:
            avatar_size = int(request.GET.get('avatar_size',
                                              AVATAR_DEFAULT_SIZE))
        except ValueError:
            avatar_size = AVATAR_DEFAULT_SIZE

        comment = o.to_dict()
        comment.update(user_to_dict(o.author, request=request,
                                    avatar_size=avatar_size))

        # return Response(comment)
        return api_response(data=comment)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Remove a comment',
        operation_description='''Remove a specific comment. Only comment owner or repo owner can perform this operation''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='folder id.',
            ),
            openapi.Parameter(
                name='pk',
                in_="path",
                type='string',
                description='comment id.',
            ),
        ],
        responses={
            204: openapi.Response(
                description='Comment removed successfully.',
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
    def delete(self, request, repo_id, pk, format=None):
        
        try:
            o = FileComment.objects.get(pk=pk)
        except FileComment.DoesNotExist:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Wrong comment id')

        username = request.user.username
        if username != o.author and \
           not syncwerk_api.is_repo_owner(username, repo_id):
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

        o.delete()

        # return Response(status=204)
        return api_response(code=status.HTTP_204_NO_CONTENT)
