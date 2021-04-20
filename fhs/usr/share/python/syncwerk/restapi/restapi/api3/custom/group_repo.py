from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response, api_group_check

import synserv
from synserv import syncwerk_api

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class GroupRepo(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Delete a group folder',
        operation_description='''Delete a specific folder of the group''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='group id',
            ),
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder to be deleted.',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Folder deleted successfully.',
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
    @api_group_check
    def delete(self, request, group, repo_id, format=None):
        
        username = request.user.username
        group_id = group.id

        if not group.is_staff and not syncwerk_api.is_repo_owner(username, repo_id):
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

        if synserv.is_org_group(group_id):
            org_id = synserv.get_org_id_by_group(group_id)
            synserv.del_org_group_repo(repo_id, org_id, group_id)
        else:
            syncwerk_api.unset_group_repo(repo_id, group_id, username)

        # return HttpResponse(json.dumps({'success': True}), status=200,
        #                     content_type=json_content_type)
        return api_response()
