import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from django.utils.translation import ugettext as _

from synserv import syncwerk_api

from pyrpcsyncwerk import RpcsyncwerkError

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.base import APIView
from restapi.api3.utils import api_error, api_response
from restapi.base.templatetags.restapi_tags import email2nickname, \
    email2contact_email
from restapi.utils.timeutils import timestamp_to_isoformat_timestr

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class DeletedRepos(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)
    parser_classes= (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get deleted folders',
        operation_description='''Get all deleted folders of the current user''',
        tags=['folders'],
        responses={
            200: openapi.Response(
                description='Deleted folder list retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "owner_name": "admin",
                                "encrypted": False,
                                "owner_email": "admin@alpha.syncwerk.com",
                                "del_timestamp": 1550228824,
                                "size": 0,
                                "owner_contact_email": "admin@alpha.syncwerk.com",
                                "repo_id": "fc22da80-58e6-4cd9-b045-9240c94a4d63",
                                "del_time": "2019-02-15T11:07:04+00:00",
                                "org_id": None,
                                "head_commit_id": "7df45cae640b3e37a53b9c76336904a953113edf",
                                "repo_name": "dddde"
                            },
                            {
                                "owner_name": "admin",
                                "encrypted": False,
                                "owner_email": "admin@alpha.syncwerk.com",
                                "del_timestamp": 1548299359,
                                "size": 0,
                                "owner_contact_email": "admin@alpha.syncwerk.com",
                                "repo_id": "025f707d-2442-427f-abe1-8077dc91d4eb",
                                "del_time": "2019-01-24T03:09:19+00:00",
                                "org_id": None,
                                "head_commit_id": "a8703cabeb13b817bb152da6c231a42f506683a7",
                                "repo_name": "test111"
                            }
                        ]
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
        trashs_json = []
        email = request.user.username

        trash_repos = syncwerk_api.get_trash_repos_by_owner(email)
        for r in trash_repos:
            trash = {
                "repo_id": r.repo_id,
                "owner_email": email,
                "owner_name": email2nickname(email),
                "owner_contact_email": email2contact_email(email),
                "repo_name": r.repo_name,
                "org_id": r.org_id,
                "head_commit_id": r.head_id,
                "encrypted": r.encrypted,
                "del_time": timestamp_to_isoformat_timestr(r.del_time),
                "size": r.size,
                'del_timestamp': r.del_time
            }
            trashs_json.append(trash)
        return api_response(data=trashs_json)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Restore deleted folder',
        operation_description='''Restore a deleted folder''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="formData",
                type='string',
                description='id of the folder to be restored.',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Folder restored successfully.',
                examples={
                    'application/json': {
                        "message": "Folder restored successfully.",
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
        
        post_data = request.POST
        repo_id = post_data.get('repo_id', '')
        username = request.user.username
        if not repo_id:
            error_msg = _("repo_id can not be empty.")
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
        owner = syncwerk_api.get_trash_repo_owner(repo_id)
        if owner is None:
            error_msg = _("Folder is not found in trash.")
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
        if owner != username:
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

        try:
            syncwerk_api.restore_repo_from_trash(repo_id)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = _("Internal Server Error")
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)
        return api_response(msg=_('Folder restored successfully.'))
