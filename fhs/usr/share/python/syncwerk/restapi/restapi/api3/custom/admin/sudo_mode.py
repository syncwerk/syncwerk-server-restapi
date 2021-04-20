import logging
import json
import os

from django.utils.translation import ugettext as _

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.views import APIView

from restapi.base.sudo_mode import sudo_mode_check, update_sudo_mode_ts
from restapi.auth.forms import AuthenticationForm

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema


class SudoMode(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get sudo status',
        operation_description='''Get sudo mode to see if the user need to input the password again''',
        tags=['admin-sudo'],
        responses={
            200: openapi.Response(
                description='Sudo status retrieved',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "sudo_result": False
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
    def get(self, request):
        check_result = sudo_mode_check(request)
        return api_response(code=200, data={
            'sudo_result': check_result
        })

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Submit password to unlock admin area',
        operation_description='''Submit password to unlock admin area. You will not required to do this with in 10 minutes after unlocking by default''',
        tags=['admin-sudo'],
        manual_parameters=[
            openapi.Parameter(
                name='password',
                in_="formData",
                type='string',
                description='password for authenticating',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Admin area unlocked',
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
        password = request.POST.get('password')
        login = request.user.email
        form = AuthenticationForm(data={
            "password": password,
            "login": login
        })
        if form.is_valid():
            update_sudo_mode_ts(request)
            return api_response(code=200, msg='')
        return api_error(code=403, msg='', data=form.errors)
