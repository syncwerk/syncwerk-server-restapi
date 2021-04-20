import logging
import posixpath
import stat

from rest_framework import status
from rest_framework.views import APIView

from django.contrib.auth.hashers import check_password

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response, get_file_size

from restapi.share.models import FileShare

from pyrpcsyncwerk import RpcsyncwerkError
import synserv
from synserv import syncwerk_api, syncwserv_threaded_rpc, get_repo

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)


class SharedDirView(APIView):
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get download folder content',
        operation_description='''Get all contents in a shared download link''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_="path",
                type='string',
                description='token of the download link',
            ),
            openapi.Parameter(
                name='p',
                in_="query",
                type='string',
                description='subfolder path',
            ),
            openapi.Parameter(
                name='password',
                in_="query",
                type='string',
                description='if the link is password protected, then this is the password for access it.',
            ),
        ],
        responses={
            200: openapi.Response(
                description='List retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "dir_name": "test wiki 4",
                            "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                            "share_link_audit": False,
                            "thumbnail_size": 48,
                            "traffic_over_limit": False,
                            "is_expired": False,
                            "password_protected": False,
                            "dir_list": [
                                {
                                    "mtime": 1549880708,
                                    "type": "dir",
                                    "last_modified": "<time datetime=\"2019-02-11T10:25:08\" is=\"relative-time\" title=\"Mon, 11 Feb 2019 10:25:08 +0000\" >7 days ago</time>",
                                    "obj_name": "fffff"
                                }
                            ],
                            "token": "984fa5293de84507b036",
                            "ENABLE_THUMBNAIL": False,
                            "mode": "list",
                            "expire_date": "",
                            "file_list": [
                                {
                                    "type": "file",
                                    "last_modified": "<time datetime=\"2019-02-18T03:42:05\" is=\"relative-time\" title=\"Mon, 18 Feb 2019 03:42:05 +0000\" >7 hours ago</time>",
                                    "mtime": 1550461325,
                                    "obj_name": "qqq.md",
                                    "encoded_thumbnail_src": None,
                                    "is_img": None,
                                    "file_size": 0,
                                    "is_video": None
                                }
                            ],
                            "path": "/",
                            "permissions": {
                                "can_edit": False,
                                "can_download": True
                            },
                            "shared_by": {
                                "user_login_id": "",
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                "user_name": "admin",
                                "user_email": "admin@alpha.syncwerk.com"
                            },
                            "zipped": [
                                [
                                    "test wiki 4",
                                    "/"
                                ]
                            ],
                            "parent_dir": "/",
                            "repo_name": "test wiki 4"
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
    def get(self, request, token, format=None):
        
        fileshare = FileShare.objects.get_valid_dir_link_by_token(token)
        if not fileshare:
            return api_error(status.HTTP_400_BAD_REQUEST, "Invalid token")

        repo_id = fileshare.repo_id
        repo = get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_400_BAD_REQUEST, "Invalid token")

        if fileshare.is_encrypted():
            password = request.GET.get('password', '')

            if not password:
                return api_error(status.HTTP_403_FORBIDDEN, "Password is required")

            if not check_password(password, fileshare.password):
                return api_error(status.HTTP_403_FORBIDDEN, "Invalid Password")

        req_path = request.GET.get('p', '/')

        if req_path[-1] != '/':
            req_path += '/'

        if req_path == '/':
            real_path = fileshare.path
        else:
            real_path = posixpath.join(fileshare.path, req_path.lstrip('/'))

        if real_path[-1] != '/':         # Normalize dir path
            real_path += '/'

        dir_id = syncwerk_api.get_dir_id_by_path(repo_id, real_path)
        if not dir_id:
            return api_error(status.HTTP_400_BAD_REQUEST, "Invalid path")

        username = fileshare.username
        try:
            dirs = syncwserv_threaded_rpc.list_dir_with_perm(repo_id, real_path, dir_id,
                    username, -1, -1)
            dirs = dirs if dirs else []
        except RpcsyncwerkError, e:
            logger.error(e)
            return api_error(HTTP_520_OPERATION_FAILED, "Failed to list dir.")

        dir_list, file_list = [], []
        for dirent in dirs:
            dtype = "file"
            entry = {}
            if stat.S_ISDIR(dirent.mode):
                dtype = "dir"
            else:
                if repo.version == 0:
                    entry["size"] = get_file_size(repo.store_id, repo.version,
                                                  dirent.obj_id)
                else:
                    entry["size"] = dirent.size

            entry["type"] = dtype
            entry["name"] = dirent.obj_name
            entry["id"] = dirent.obj_id
            entry["mtime"] = dirent.mtime
            if dtype == 'dir':
                dir_list.append(entry)
            else:
                file_list.append(entry)

        dir_list.sort(lambda x, y: cmp(x['name'].lower(), y['name'].lower()))
        file_list.sort(lambda x, y: cmp(x['name'].lower(), y['name'].lower()))
        dentrys = dir_list + file_list

        # content_type = 'application/json; charset=utf-8'
        # return HttpResponse(json.dumps(dentrys), status=200, content_type=content_type)
        return api_response(data=dentrys)
