import synserv

from django.utils.translation import ugettext as _
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.views import APIView

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response

from synserv import ccnet_api

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class Accounts(APIView):
    """ List all accounts.
    Administrator permission is required.
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - List accounts',
        operation_description='''Admin accounts''',
        tags=['admin-accounts'],
        manual_parameters=[
            openapi.Parameter(
                name='start',
                in_='query',
                type='string',
                description='offset. Default is 0',
            ),
            openapi.Parameter(
                name='limit',
                in_='query',
                type='string',
                description='limit. Default is 100',
            ),
            openapi.Parameter(
                name='scope',
                in_='query',
                type='string',
                description='LDAP, LDAPIMPORT or DB',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Account retrived successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": []
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
                        "detail": 'Token invalid'
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
        # list accounts
        start = int(request.GET.get('start', '0'))
        limit = int(request.GET.get('limit', '100'))
        # reading scope user list
        scope = request.GET.get('scope', None)

        accounts_ldapimport = []
        accounts_ldap = []
        accounts_db = []
        if scope:
            scope = scope.upper()
            if scope == 'LDAP':
                accounts_ldap = ccnet_api.get_emailusers('LDAP', start, limit)
            elif scope == 'LDAPIMPORT':
                accounts_ldapimport = ccnet_api.get_emailusers('LDAPImport', start, limit)
            elif scope == 'DB':
                accounts_db = ccnet_api.get_emailusers('DB', start, limit)
            else:
                return api_error(status.HTTP_400_BAD_REQUEST, "%s is not a valid scope value" % scope)
        else:
            # old way - search first in LDAP if available then DB if no one found
            accounts_ldap = synserv.get_emailusers('LDAP', start, limit)
            if len(accounts_ldap) == 0:
                accounts_db = synserv.get_emailusers('DB', start, limit)

        accounts_json = []
        for account in accounts_ldap:
            accounts_json.append({'email': account.email, 'source' : 'LDAP'})

        for account in accounts_ldapimport:
            accounts_json.append({'email': account.email, 'source' : 'LDAPImport'})

        for account in accounts_db:
            accounts_json.append({'email': account.email, 'source' : 'DB'})

        return api_response(data=accounts_json)
