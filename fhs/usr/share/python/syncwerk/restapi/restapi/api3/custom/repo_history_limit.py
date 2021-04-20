import logging
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication

from restapi.api3.base import APIView
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from restapi.utils import is_org_context, ALLOW_EDIT_HISTORY_KEEP_DAY

from pyrpcsyncwerk import RpcsyncwerkError
import synserv
from synserv import syncwerk_api

from constance import config

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)

HTTP_520_OPERATION_FAILED = 520

class RepoHistoryLimit(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.JSONParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get folder history limit',
        operation_description='''Get folder history limit settings''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "keep_days": 3650
                        }
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
    def get(self, request, repo_id, format=None):

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # check permission
        if is_org_context(request):
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        username = request.user.username
        # no settings for virtual repo
        if repo.is_virtual or username != repo_owner:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            keep_days = syncwerk_api.get_repo_history_limit(repo_id)
            # return Response({'keep_days': keep_days})
            return api_response(status.HTTP_200_OK, '', {'keep_days': keep_days,'can_edit':ALLOW_EDIT_HISTORY_KEEP_DAY})
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Update folder history limit',
        operation_description='''Update folder history limit setting''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
        ],
        request_body=openapi.Schema(
            type='object',
            properties={
                'keep_days':openapi.Schema(
                    type='number',
                    description='''- -1: keep all histories \n
- 0: do not keep history
- any other integer number equal or less than 90: keep history for that number of days''',
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='History limit updated successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "keep_days": 90
                        }
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
            520: openapi.Response(
                description='Operation failed',
                examples={
                    'application/json': {
                        "message": "Failed to set folder history limit",
                        "data": None
                    }
                }
            ),
        }
    )
    def put(self, request, repo_id, format=None):

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # check permission
        if is_org_context(request):
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        username = request.user.username
        # no settings for virtual repo
        if repo.is_virtual or \
            not config.ENABLE_REPO_HISTORY_SETTING or \
            username != repo_owner:

            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # check allow edit keep_days
        if not ALLOW_EDIT_HISTORY_KEEP_DAY:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)
            
        # check arg validation
        keep_days = request.data.get('keep_days', None)
        if not keep_days:
            error_msg = 'keep_days invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            keep_days = int(keep_days)
        except ValueError:
            error_msg = 'keep_days invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            # days <= -1, keep full history
            # days = 0, not keep history
            # days > 0, keep a period of days
            res = syncwerk_api.set_repo_history_limit(repo_id, keep_days)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if res == 0:
            new_limit = syncwerk_api.get_repo_history_limit(repo_id)
            # return Response({'keep_days': new_limit})
            return api_response(status.HTTP_200_OK, '', {'keep_days': new_limit})
        else:
            error_msg = 'Failed to set library history limit.'
            return api_error(status.HTTP_520_OPERATION_FAILED, error_msg)
