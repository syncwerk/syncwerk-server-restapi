from django.template.defaultfilters import filesizeformat

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response, api_group_check
from restapi.api3.constants import EventLogActionType
from restapi.base.templatetags.restapi_tags import email2nickname, translate_restapi_time
from restapi.group.views import is_group_staff
from restapi.signals import repo_created, repo_deleted, repo_update_signal
from restapi.utils import is_org_context

import synserv
from synserv import syncwerk_api, is_group_user

from constance import config

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema


class GroupRepos(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.JSONParser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Create new group folder',
        operation_description='''Create new folder for group''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='group id',
            ),
        ],
        request_body=openapi.Schema(
            type='object',
            properties={
                'name': openapi.Schema(
                    type='string',
                    description='name of the new folder'
                ),
                'desc': openapi.Schema(
                    type='string',
                    description='description of the new folder'
                ),
                'permission': openapi.Schema(
                    type='string',
                    description='"r" or "rw"'
                ),
                'passwd': openapi.Schema(
                    type='string',
                    description='password for the folder if you want to create an encrypted folder. This field should be null rather than empty string for an unencrypted folder.'
                ),
            }
        ),
        responses={
            200: openapi.Response(
                description='Folder created successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "owner_nickname": "admin",
                            "permission": "rw",
                            "encrypted": False,
                            "mtime_relative": "<time datetime=\"2019-02-19T08:42:59\" is=\"relative-time\" title=\"Tue, 19 Feb 2019 08:42:59 +0000\" >1 second ago</time>",
                            "mtime": 1550565779,
                            "owner": "admin@alpha.syncwerk.com",
                            "id": "bb966ac2-ec76-4940-96fa-7e0fdec41a32",
                            "size": 0,
                            "name": "fefefe",
                            "share_from_me": True,
                            "desc": "",
                            "size_formatted": "0\u00a0bytes"
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
    @api_group_check
    def post(self, request, group, format=None):
        
        # add group repo
        username = request.user.username
        repo_name = request.data.get("name", None)
        repo_desc = request.data.get("desc", '')
        passwd = request.data.get("passwd", None)

        # to avoid 'Bad magic' error when create repo, passwd should be 'None'
        # not an empty string when create unencrypted repo
        if not passwd:
            passwd = None

        if (passwd is not None) and (not config.ENABLE_ENCRYPTED_FOLDER):
            return api_error(status.HTTP_403_FORBIDDEN,
                             'NOT allow to create encrypted library.')

        permission = request.data.get("permission", 'r')
        if permission != 'r' and permission != 'rw':
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid permission')

        org_id = -1
        if is_org_context(request):
            org_id = request.user.org.org_id
            repo_id = syncwerk_api.create_org_repo(repo_name, repo_desc,
                                                  username, passwd, org_id)
            repo = syncwerk_api.get_repo(repo_id)
            syncwerk_api.add_org_group_repo(repo_id, org_id, group.id,
                                           username, permission)
        else:
            repo_id = syncwerk_api.create_repo(repo_name, repo_desc,
                                              username, passwd)
            repo = syncwerk_api.get_repo(repo_id)
            syncwerk_api.set_group_repo(repo.id, group.id, username, permission)

        library_template = request.data.get("library_template", '')
        repo_created.send(sender=None,
                          org_id=org_id,
                          creator=username,
                          repo_id=repo_id,
                          repo_name=repo_name,
                          library_template=library_template)
        repo_update_signal.send(sender=request.user,
                                    request=request,
                                    action_type=EventLogActionType.ADDED_DIR.value,
                                    repo_id=repo_id,
                                    repo_name=repo_name)
        group_repo = {
            "id": repo.id,
            "name": repo.name,
            "desc": repo.desc,
            "size": repo.size,
            "size_formatted": filesizeformat(repo.size),
            "mtime": repo.last_modified,
            "mtime_relative": translate_restapi_time(repo.last_modified),
            "encrypted": repo.encrypted,
            "permission": permission,
            "owner": username,
            "owner_nickname": email2nickname(username),
            "share_from_me": True,
        }

        # return Response(group_repo, status=200)
        return api_response(data=group_repo)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Create group folders',
        operation_description='''Get all folders of the group''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='group id',
            ),
            openapi.Parameter(
                name='from',
                in_="query",
                type='string',
                description='"web" means only folders created on web will be retrieved. This field should not be provided by default.',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Folder created successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "repos": [
                                {
                                    "owner_nickname": "admin",
                                    "permission": "rw",
                                    "encrypted": False,
                                    "mtime_relative": "<time datetime=\"2019-02-19T08:42:59\" is=\"relative-time\" title=\"Tue, 19 Feb 2019 08:42:59 +0000\" >1 second ago</time>",
                                    "mtime": 1550565779,
                                    "owner": "admin@alpha.syncwerk.com",
                                    "id": "bb966ac2-ec76-4940-96fa-7e0fdec41a32",
                                    "size": 0,
                                    "name": "fefefe",
                                    "share_from_me": True,
                                    "desc": "",
                                    "size_formatted": "0\u00a0bytes"
                                },
                                {
                                    "owner_nickname": "admin",
                                    "permission": "rw",
                                    "encrypted": False,
                                    "mtime_relative": "<time datetime=\"2019-02-14T08:34:13\" is=\"relative-time\" title=\"Thu, 14 Feb 2019 08:34:13 +0000\" >5 days ago</time>",
                                    "mtime": 1550133253,
                                    "owner": "admin@alpha.syncwerk.com",
                                    "id": "5162d1dd-428d-4a6f-9d44-c60ad57abebb",
                                    "size": 1630,
                                    "name": "tgregr",
                                    "share_from_me": True,
                                    "desc": "",
                                    "size_formatted": "1.6\u00a0KB"
                                }
                            ],
                            "is_staff": True
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
    @api_group_check
    def get(self, request, group, format=None):
        
        username = request.user.username

        if group.is_pub:
            if not request.user.is_staff and not is_group_user(group.id, username):
                return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

        if is_org_context(request):
            org_id = request.user.org.org_id
            repos = syncwerk_api.get_org_group_repos(org_id, group.id)
        else:
            repos = syncwerk_api.get_repos_by_group(group.id)

        repos.sort(lambda x, y: cmp(y.last_modified, x.last_modified))
        group.is_staff = is_group_staff(group, request.user)

        repos_json = []
        for r in repos:
            repo = {
                "id": r.id,
                "name": r.name,
                "desc": r.desc,
                "size": r.size,
                "size_formatted": filesizeformat(r.size),
                "mtime": r.last_modified,
                "mtime_relative": translate_restapi_time(r.last_modified),
                "encrypted": r.encrypted,
                "permission": r.permission,
                "owner": r.user,
                "owner_nickname": email2nickname(r.user),
                "share_from_me": True if username == r.user else False,
            }
            repos_json.append(repo)

        req_from = request.GET.get('from', "")
        if req_from == 'web':
            # return Response({"is_staff": group.is_staff, "repos": repos_json})
            resp = {"is_staff": group.is_staff, "repos": repos_json}
            return api_response(data=resp)
        else:
            # return Response(repos_json)
            resp = {"repos": repos_json}
            return api_response(data=resp)
