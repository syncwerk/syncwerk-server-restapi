from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser

from restapi.role_permissions.utils import get_available_roles

from restapi.api3.utils import api_error, api_response
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.permissions import IsSystemAdminOrTenantAdmin

from django.conf import settings

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema


class Roles(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsSystemAdminOrTenantAdmin, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get available role list',
        operation_description='''Get available role list''',
        tags=['admin-system'],
        responses={
            200: openapi.Response(
                description='Role list retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "admin_roles": [
                                "daily_admin",
                                "default_admin",
                                "audit_admin",
                                "system_admin"
                            ],
                            "user_roles": [
                                "default",
                                "employee",
                                "guest"
                            ]
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
        role_list = get_available_roles()
        admin_role_list = settings.ENABLED_ADMIN_ROLE_PERMISSIONS.keys()
        return api_response(data={'user_roles': role_list, 'admin_roles': admin_role_list})
