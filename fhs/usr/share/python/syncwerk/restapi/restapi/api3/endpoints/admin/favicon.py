# Copyright (c) 2012-2016 Seafile Ltd.
import os
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response
from restapi.settings import RESTAPI_DATA_ROOT, MEDIA_ROOT

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

CUSTOM_FAVICON_PATH = 'custom/favicon.ico'


class AdminFavicon(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle, )
    permission_classes = (IsAdminUser,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Change page favicon',
        operation_description='''Change page favicon''',
        tags=['admin-system'],
        manual_parameters=[
            openapi.Parameter(
                name='favicon',
                in_="formData",
                type='file',
                description='image file for setting as favicon',
            ),
        ],
        responses={
            200: openapi.Response(
                description='favicon update successfully',
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
    def post(self, request):
        favicon_file = request.FILES.get('favicon', None)
        if not favicon_file:
            error_msg = 'favicon invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not os.path.exists(RESTAPI_DATA_ROOT):
            os.makedirs(RESTAPI_DATA_ROOT)

        custom_dir = os.path.join(RESTAPI_DATA_ROOT,
                                  os.path.dirname(CUSTOM_FAVICON_PATH))

        if not os.path.exists(custom_dir):
            os.makedirs(custom_dir)

        try:
            custom_favicon_file = os.path.join(RESTAPI_DATA_ROOT,
                                               CUSTOM_FAVICON_PATH)

            # save favicon file to custom dir
            with open(custom_favicon_file, 'w') as fd:
                fd.write(favicon_file.read())

            custom_symlink = os.path.join(MEDIA_ROOT,
                                          os.path.dirname(CUSTOM_FAVICON_PATH))

            # create symlink for custom dir
            if not os.path.exists(custom_symlink):
                os.symlink(custom_dir, custom_symlink)

        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return api_response(msg='Changed favicon successfully.')


class AdminFavIconReset(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle, )
    permission_classes = (IsAdminUser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Reset favicon to default',
        operation_description='''Reset favicon to default''',
        tags=['admin-system'],
        responses={
            200: openapi.Response(
                description='favicon reset successfully',
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
    def post(self, request):
        try:
            # remove default logo to custom folder
            os.remove(os.path.join(MEDIA_ROOT, CUSTOM_FAVICON_PATH))
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return api_response(msg='Reset favicon successfully.')
