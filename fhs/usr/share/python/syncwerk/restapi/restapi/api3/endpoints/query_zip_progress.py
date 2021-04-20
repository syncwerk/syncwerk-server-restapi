# Copyright (c) 2012-2016 Seafile Ltd.
import logging
import json

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response

from synserv import syncwerk_api

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)

class QueryZipProgressView(APIView):

    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Query zip process',
        operation_description='''Getting the current status of the zipping process''',
        tags=['shares', 'folders'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_="query",
                type='string',
                description='zipping token.',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Status retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": "{\"zipped\":2,\"total\":2}"
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

        token = request.GET.get('token', None)
        if not token:
            error_msg = 'token invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            progress = syncwerk_api.query_zip_progress(token)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # return Response(json.loads(progress))
        return api_response(data=progress)
