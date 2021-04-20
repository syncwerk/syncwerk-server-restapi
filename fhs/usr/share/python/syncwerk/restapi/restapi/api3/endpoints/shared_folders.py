# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

import synserv
from synserv import syncwerk_api, ccnet_api

from restapi.api3.utils import api_error, api_response
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.profile.models import Profile
from restapi.utils import is_org_context
from restapi.base.templatetags.restapi_tags import email2nickname

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)

class SharedFolders(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get all shared subfolders',
        operation_description='''Get all shared subfolders of the current user''',
        tags=['shares'],
        responses={
            200: openapi.Response(
                description='List retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "share_permission": "rw",
                                "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                "share_type": "personal",
                                "contact_email": "test1@grr.la",
                                "folder_name": "efe",
                                "path": "/efe",
                                "user_name": "test1@grr.la",
                                "user_email": "test1@grr.la"
                            },
                            {
                                "share_permission": "rw",
                                "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                "share_type": "personal",
                                "contact_email": "bsynnott3@artisteer.com",
                                "folder_name": "efewf",
                                "path": "/fefe/efewf",
                                "user_name": "Bibbye Synnott",
                                "user_email": "bsynnott3@artisteer.com"
                            },
                            {
                                "share_permission": "rw",
                                "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                "share_type": "personal",
                                "contact_email": "ulibero4@infoseek.co.jp",
                                "folder_name": "frtgr",
                                "path": "/frtgr",
                                "user_name": "Uriah Libero",
                                "user_email": "ulibero4@infoseek.co.jp"
                            }
                        ]
                    }
                },
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
        shared_repos = []
        username = request.user.username

        try:
            if is_org_context(request):
                org_id = request.user.org.org_id
                shared_repos += syncwerk_api.get_org_share_out_repo_list(
                    org_id, username, -1, -1)
                shared_repos += synserv.syncwserv_threaded_rpc.get_org_group_repos_by_owner(
                    org_id, username)
            else:
                shared_repos += syncwerk_api.get_share_out_repo_list(
                    username, -1, -1)
                shared_repos += syncwerk_api.get_group_repos_by_owner(username)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        returned_result = []
        shared_repos.sort(lambda x, y: cmp(x.repo_name, y.repo_name))
        for repo in shared_repos:
            if not repo.is_virtual:
                continue

            result = {}
            result['repo_id'] = repo.origin_repo_id
            result['path'] = repo.origin_path
            result['folder_name'] = repo.name
            result['share_type'] = repo.share_type
            result['share_permission'] = repo.permission

            if repo.share_type == 'personal':
                result['user_name'] = email2nickname(repo.user)
                result['user_email'] = repo.user
                result['contact_email'] = Profile.objects.get_contact_email_by_user(
                    repo.user)

            if repo.share_type == 'group':
                group = ccnet_api.get_group(repo.group_id)
                result['group_id'] = repo.group_id
                result['group_name'] = group.group_name

            returned_result.append(result)

        # return Response(returned_result)
        return api_response(data=returned_result)
