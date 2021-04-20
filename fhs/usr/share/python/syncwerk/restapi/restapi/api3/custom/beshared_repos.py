from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.permissions import IsRepoAccessible
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response

import synserv
import json
from synserv import syncwerk_api, get_personal_groups_by_user, get_group_repoids, get_repo, get_commits, check_permission

try:
    from restapi.settings import CLOUD_MODE
except ImportError:
    CLOUD_MODE = False

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema


class BeSharedRepos(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication )
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get all user\'s shared folders',
        operation_description='''Get all folders shared to current user''',
        tags=['shares'],
        responses={
            200: openapi.Response(
                description='List retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
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
    def get(self, request, format=None):
        username = request.user.username
        shared_repos = []
        shared_repos += syncwerk_api.get_share_in_repo_list(username, -1, -1)
        
        joined_groups = get_personal_groups_by_user(username)
        for grp in joined_groups:
            # Get group repos, and for each group repos...
            for r_id in get_group_repoids(grp.id):
                # No need to list my own repo
                if syncwerk_api.is_repo_owner(username, r_id):
                    continue
                # Convert repo properties due to the different collumns in Repo
                # and SharedRepo
                r = get_repo(r_id)
                if not r:
                    continue
                r.repo_id = r.id
                r.repo_name = r.name
                r.repo_desc = r.desc
                cmmts = get_commits(r_id, 0, 1)
                last_commit = cmmts[0] if cmmts else None
                r.last_modified = last_commit.ctime if last_commit else 0
                r._dict['share_type'] = 'group'
                r.user = syncwerk_api.get_repo_owner(r_id)
                r.user_perm = check_permission(r_id, username)
                shared_repos.append(r)

        if not CLOUD_MODE:
            shared_repos += synserv.list_inner_pub_repos(username)

        # return HttpResponse(json.dumps(shared_repos, cls=RpcsyncwerkObjEncoder),
        #                     status=200, content_type=json_content_type)
        return api_response(data=shared_repos)
