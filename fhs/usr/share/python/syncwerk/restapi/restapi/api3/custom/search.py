import stat
import fnmatch

from django.template.defaultfilters import filesizeformat

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from synserv import syncwerk_api

from restapi.base.templatetags.restapi_tags import translate_restapi_time

from restapi.api3.base import APIView
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class SearchFiles(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    def search_files_in_folder(self, repo_info, path, allowed_file_ext_list, search_query):
        dirents = syncwerk_api.list_dir_by_path(
            repo_info.id, path)
        result = []
        for dirent in dirents:
            if stat.S_ISDIR(dirent.mode):
                sub_path = path+dirent.obj_name+'/'
                result += self.search_files_in_folder(
                    repo_info, sub_path, allowed_file_ext_list, search_query)
            else:
                if len(allowed_file_ext_list) >= 0:
                    for ext in allowed_file_ext_list:
                        if fnmatch.fnmatch(dirent.obj_name, '*.'+ext) and search_query.lower() in dirent.obj_name.lower():
                            f = {
                                'name': dirent.obj_name,
                                'type': 'file',
                                'parent_dir': path,
                                'repo': {
                                    "type": "repo",
                                    "id": repo_info.id,
                                    "name": repo_info.name,
                                    "mtime": repo_info.last_modify,
                                    "mtime_relative": translate_restapi_time(repo_info.last_modify),
                                    "size": repo_info.size,
                                    "size_formatted": filesizeformat(repo_info.size),
                                    "encrypted": repo_info.encrypted,
                                    "head_commit_id": repo_info.head_cmmt_id,
                                    "version": repo_info.version,
                                    'desc': repo_info.desc
                                }
                            }
                            result.append(f)
                elif search_query.lower() in dirent.obj_name.lower():
                    f = {
                        'name': dirent.obj_name,
                        'type': 'file',
                        'parent_dir': path,
                        'repo': {
                            "type": "repo",
                            "id": repo_info.id,
                            "name": repo_info.name,
                            "mtime": repo_info.last_modify,
                            "mtime_relative": translate_restapi_time(repo_info.last_modify),
                            "size": repo_info.size,
                            "size_formatted": filesizeformat(repo_info.size),
                            "encrypted": repo_info.encrypted,
                            "head_commit_id": repo_info.head_cmmt_id,
                            "version": repo_info.version,
                            'desc': repo_info.desc
                        }
                    }
                    result.append(f)
        return result

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Search files',
        operation_description='''Search file in all users file''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name='s',
                in_='query',
                type='string',
                description='''Search query''',
            ),
            openapi.Parameter(
                name='ext',
                in_='query',
                type='string',
                description='''only filter the files with those extensions. Support multiple file extenstions, separate by comma. Leave this empty for all file types''',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Result retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "repo": {
                                    "encrypted": False,
                                    "mtime_relative": "<time datetime=\"2019-02-14T08:34:13\" is=\"relative-time\" title=\"Thu, 14 Feb 2019 08:34:13 +0000\" >6 days ago</time>",
                                    "mtime": 1550133253,
                                    "id": "5162d1dd-428d-4a6f-9d44-c60ad57abebb",
                                    "desc": None,
                                    "name": "tgregr",
                                    "type": "repo",
                                    "version": 1,
                                    "head_commit_id": "10f6c325a0d602667f6d11281f2e2aed8c8ff6a0",
                                    "size": 1630,
                                    "size_formatted": "1.6\u00a0KB"
                                },
                                "type": "file",
                                "name": "support-de.html",
                                "parent_dir": "/"
                            },
                            {
                                "repo": {
                                    "encrypted": False,
                                    "mtime_relative": "<time datetime=\"2019-02-14T08:34:13\" is=\"relative-time\" title=\"Thu, 14 Feb 2019 08:34:13 +0000\" >6 days ago</time>",
                                    "mtime": 1550133253,
                                    "id": "5162d1dd-428d-4a6f-9d44-c60ad57abebb",
                                    "desc": None,
                                    "name": "tgregr",
                                    "type": "repo",
                                    "version": 1,
                                    "head_commit_id": "10f6c325a0d602667f6d11281f2e2aed8c8ff6a0",
                                    "size": 1630,
                                    "size_formatted": "1.6\u00a0KB"
                                },
                                "type": "file",
                                "name": "support-en.html",
                                "parent_dir": "/"
                            }
                        ]
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": 'Token invalid'
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
        
        search_query = request.GET.get('s', '')
        allowed_file_ext = request.GET.get('ext', '')
        allowed_file_ext_list = allowed_file_ext.split(",")
        email = request.user.username
        owned_repos = syncwerk_api.get_owned_repo_list(
            email, ret_corrupted=True)
        result = []
        for repo in owned_repos:
            if repo.encrypted:
                continue
            result += self.search_files_in_folder(repo,
                                                  '/', allowed_file_ext_list, search_query)
        return api_response(code=200, data=result)
