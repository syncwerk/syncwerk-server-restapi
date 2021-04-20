import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.utils.translation import ugettext as _

from synserv import syncwerk_api
from pyrpcsyncwerk import RpcsyncwerkError

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response

from restapi.utils import is_org_context

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)

class RepoPassword(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication )
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Grant encrypted folder access',
        operation_description='''Grant access to encrypted folder''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='password',
                in_="formData",
                type='string',
                description='password of the encrypted folder',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Access granted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request / incorrect password',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None,
                        "error_code": ""
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
            404: openapi.Response(
                description='Folder not found',
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
    def post(self, request, repo_id):
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        password = request.data.get('password', None)
        if not password:
            error_msg = 'password invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            syncwerk_api.set_passwd(repo_id, request.user.username, password)
            # return Response({'success': True})
            return api_response()
        except RpcsyncwerkError as e:
            if e.msg == 'Bad arguments':
                error_msg = 'Bad arguments'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg, error_code='bad_argument')
            elif e.msg == 'Incorrect password':
                error_msg = _(u'Wrong password')
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg, error_code='incorrect_password')
            elif e.msg == 'Internal server error':
                error_msg = _(u'Internal server error')
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)
            else:
                error_msg = _(u'Decrypt library error')
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg, error_code='decrypt_library_error')

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Change folder password',
        operation_description='''Change password of an encrypted folder''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='old_password',
                in_="formData",
                type='string',
                description='old password of the encrypted folder',
            ),
            openapi.Parameter(
                name='new_password',
                in_="formData",
                type='string',
                description='new password of the encrypted folder',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Change folder password successfully.',
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
                        "data": None,
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
            404: openapi.Response(
                description='Folder not found',
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
    def put(self, request, repo_id):
        

        # argument check
        old_password = request.data.get('old_password', None)
        if not old_password:
            error_msg = 'old_password invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        new_password = request.data.get('new_password', None)
        if not new_password:
            error_msg = 'new_password invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if is_org_context(request):
            repo_owner = syncwerk_api.get_org_repo_owner(repo.id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo.id)

        username = request.user.username
        if username != repo_owner:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # change password
        try:
            syncwerk_api.change_repo_passwd(repo_id, old_password, new_password, username)
        except RpcsyncwerkError as e:
            if e.msg == 'Incorrect password':
                error_msg = _(u'Wrong old password')
                return api_error(status.HTTP_403_FORBIDDEN, error_msg, error_code='incorrect_password')
            else:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # return Response({'success': True})
        return api_response(msg='Successfully changed library password.')
