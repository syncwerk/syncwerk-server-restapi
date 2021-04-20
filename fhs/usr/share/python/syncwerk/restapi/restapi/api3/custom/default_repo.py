from django.utils.translation import ugettext as _

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from restapi.api3.base import APIView
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from restapi.options.models import UserOptions
from restapi.views import create_default_library

import synserv
from synserv import get_repo, syncwerk_api

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema
from rest_framework import parsers


class DefaultRepoView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.JSONParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Default folder',
        operation_description='Get user default folder',
        tags=['user'],
        responses={
            200: openapi.Response(
                description='Default folder info retrieve successfully. \n - "repo_id" will be null if "exists" is falsy.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "exists": True,
                            "repo_id": "id of the default folder"
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / unauthorized.',
                examples={
                    'application/json': {
                        "detail": "Invalid token"
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error"
                    }
                }
            )
        }
    )
    def get(self, request, format=None):
        username = request.user.username
        repo_id = UserOptions.objects.get_default_repo(username)
        if repo_id is None or (get_repo(repo_id) is None):
            json = {
                'exists': False,
            }
            # return Response(json)
            return api_response(data=json)
        else:
            return self.default_repo_info(repo_id)

    def default_repo_info(self, repo_id):
        repo_json = {
            'exists': False,
        }

        if repo_id is not None:
            repo_json['exists'] = True
            repo_json['repo_id'] = repo_id

        # return Response(repo_json)
        return api_response(data=repo_json)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Update default folder',
        operation_description='Update user default folder',
        tags=['user'],
        request_body=openapi.Schema(
            type='object',
            properties={
                'repo_id': openapi.Schema(
                    type='string',
                    description='Folder id of the folder that user wants to set as default'
                )
            },
        ),
        responses={
            200: openapi.Response(
                description='Update default folder successfully.',
                examples={
                    'application/json': {
                        "message": "Successfully set <folder name> as default folder.",
                        "data": None
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
                    }
                }
            ),
            401: openapi.Response(
                description='Unauthenticated / unauthorized.',
                examples={
                    'application/json': {
                        "detail": "Invalid token"
                    }
                }
            ),
            403: openapi.Response(
                description='Current user do not have permission to perform the operation.',
                examples={
                    'application/json': {
                        "message": "You do not have permission to create library."
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error"
                    }
                }
            )
        }
    )
    def post(self, request, format=None):
        repo_id = request.data.get('repo_id', None)

        if not repo_id:
            if not request.user.permissions.can_add_repo():
                return api_error(status.HTTP_403_FORBIDDEN,
                                 'You do not have permission to create library.')

            username = request.user.username

            repo_id = UserOptions.objects.get_default_repo(username)
            if repo_id and (get_repo(repo_id) is not None):
                return self.default_repo_info(repo_id)

            repo_id = create_default_library(request)

            return self.default_repo_info(repo_id)
        else:
            repo = syncwerk_api.get_repo(repo_id)
            if repo is None:
                return api_error(status.HTTP_400_BAD_REQUEST, 'Failed to set default library.')
            if repo.encrypted:
                return api_error(status.HTTP_400_BAD_REQUEST, 'Can not set encrypted library as default library.')
            username = request.user.username
            UserOptions.objects.set_default_repo(username, repo.id)
            return api_response(msg=_('Successfully set "%s" as your default library.') % repo.name)
