# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from django.db.models import Count
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from synserv import syncwerk_api
from pyrpcsyncwerk import RpcsyncwerkError

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.permissions import IsRepoAccessible
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response
from restapi.base.models import FileComment

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class FileCommentsCounts(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, IsRepoAccessible)
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Count files comment in a folder',
        operation_description='''Count all comments of all file under certain parent dir''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='folder id.',
            ),
            openapi.Parameter(
                name='p',
                in_="path",
                type='string',
                description='path to the file.',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Comment count retrived successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "item_name": "file name",
                                'total': 10
                            },
                            {
                                "item_name": "file name 2",
                                'total': 99
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

    def get(self, request, repo_id, format=None):
        
        path = request.GET.get('p', '/')
        if not path:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Wrong path.')

        try:
            obj_id = syncwerk_api.get_dir_id_by_path(repo_id,
                                                    path)
        except RpcsyncwerkError as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Internal error.')
        if not obj_id:
            return api_error(status.HTTP_404_NOT_FOUND, 'Parent dir not found.')

        ret = []
        qs = FileComment.objects.get_by_parent_path(repo_id, path).values(
            'item_name').annotate(total=Count('item_name'))
        for e in qs:
            ret.append({e['item_name']: e['total']})
        # return Response(ret)
        return api_response(data=ret)
'''
>>> print qs.query
SELECT "base_filecomment"."item_name", COUNT("base_filecomment"."item_name") AS "total" FROM "base_filecomment" WHERE "base_filecomment"."repo_id_parent_path_md5" = c80beeeb8e48566a394d000f6c8492ac GROUP BY "base_filecomment"."item_name"
'''
