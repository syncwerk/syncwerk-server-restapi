# Copyright (c) 2012-2016 Seafile Ltd.
import os
import logging
from PIL import Image

from django.utils.translation import ugettext as _

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

CUSTOM_LOGO_PATH = 'custom/mylogo.png'


class AdminLogo(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle, )
    permission_classes = (IsAdminUser,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Change page logo',
        operation_description='''Change page logo''',
        tags=['admin-system'],
        manual_parameters=[
            openapi.Parameter(
                name='logo',
                in_="formData",
                type='file',
                description='image file for setting as page logo',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Page logo update successfully',
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
        logo_file = request.FILES.get('logo', None)
        if not logo_file:
            error_msg = 'logo invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not os.path.exists(RESTAPI_DATA_ROOT):
            os.makedirs(RESTAPI_DATA_ROOT)

        custom_dir = os.path.join(
            RESTAPI_DATA_ROOT, os.path.dirname(CUSTOM_LOGO_PATH))
        if not os.path.exists(custom_dir):
            os.makedirs(custom_dir)

        try:
            # save logo file to custom dir
            custom_logo_file = os.path.join(RESTAPI_DATA_ROOT, CUSTOM_LOGO_PATH)
            image = Image.open(logo_file)
            image.save(custom_logo_file)

            # create symlink for custom dir
            custom_symlink = os.path.join(
                MEDIA_ROOT, os.path.dirname(CUSTOM_LOGO_PATH))
            if not os.path.exists(custom_symlink):
                os.symlink(custom_dir, custom_symlink)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return api_response(msg='Changed logo successfully.')


class SetDefaultAdminLogo(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle, )
    permission_classes = (IsAdminUser,)
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Reset page logo to default',
        operation_description='''Reset page logo to default''',
        tags=['admin-system'],
        responses={
            200: openapi.Response(
                description='Page logo update successfully',
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
            # copy default logo to custom folder
            os.remove(os.path.join(MEDIA_ROOT, CUSTOM_LOGO_PATH));
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return api_response(msg='Reset logo successfully.')
