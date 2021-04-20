import logging
import posixpath
import os
from django.core.cache import cache
from django.utils.translation import ugettext as _

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from restapi.api3.base import APIView
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.utils.file import view_shared_file, view_file_via_shared_dir
from restapi.api3.utils.repo import view_shared_dir, view_shared_upload_link
from restapi.api3.decorators.share import share_link_audit
from restapi.utils import user_traffic_over_limit, gen_file_get_url
from restapi.share.models import FileShare, UploadLinkShare
from restapi.utils import is_valid_email, gen_token, normalize_cache_key, is_pro_version
from restapi.utils.mail import send_html_email_with_dj_template, MAIL_PRIORITY
import restapi.settings as settings
from restapi.api3.models import KanbanShareLink
from synserv import syncwerk_api, get_commits, get_file_id_by_path
from restapi.views.file import send_file_access_msg
import stat

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema
from constance import config

class SharedFileLinkView(APIView):
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get shared file details',
        operation_description='''Get shared file details''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_='path',
                type='string',
                description='share token',
            ),
            openapi.Parameter(
                name='op',
                in_='query',
                type='string',
                description='op',
                required=True,
            ),
            openapi.Parameter(
                name='dl',
                in_='query',
                type='string',
                description='if this equals 1, then retrieve the download link',
                required=True
            ),
            openapi.Parameter(
                name='raw',
                in_="query",
                type='string',
                description='if this equals 1, then retrieve the raw data',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully',
                examples={
                    'application/json - normal': {
                        "message": "",
                        "data": {
                            "share_link_audit": False,
                            "encoding": "utf-8",
                            "save_to_link": "/rest/share/link/save/?t=57a1604474dc47ab8081",
                            "file_name": "test.csv",
                            "password_protected": False,
                            "file_size": 38,
                            "file_encoding_list": [
                                "auto",
                                "utf-8",
                                "gbk",
                                "ISO-8859-1",
                                "ISO-8859-5"
                            ],
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "traffic_over_limit": False,
                            "use_pdfjs": True,
                            "download_link": "f/57a1604474dc47ab8081/",
                            "expire_date": "",
                            "raw_path": "https://alpha.syncwerk.com/seafhttp/files/d8d9ab76-232a-4be5-8569-02606b6baf82/test.csv",
                            "filetype": "Text",
                            "repo_name": "My Folder",
                            "path": "/test.csv",
                            "permissions": {
                                "can_edit": False,
                                "can_download": True
                            },
                            "err": "",
                            "obj_id": "b87120e9f12c263ea988990a24b2cc89a57845a9",
                            "access_token": "d8d9ab76-232a-4be5-8569-02606b6baf82",
                            "is_expired": False,
                            "fileext": "csv",
                            "file_content": "fewfwefwef,\nfewfewfewf,\nfewfwegtewtert",
                            "token": "57a1604474dc47ab8081",
                            "shared_by": {
                                "user_login_id": "",
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                "user_name": "admin",
                                "user_email": "admin@alpha.syncwerk.com"
                            }
                        }
                    },
                    'application/json - dl': {
                        "message": "",
                        "data": {
                            "dl_url": "https://alpha.syncwerk.com/seafhttp/files/2e1f7935-f004-4ddd-90f5-ae904a92999e/fewhfewf.csv"
                        }
                    },
                    'application/json - raw': {
                        "message": "",
                        "data": {
                            "raw_path": "https://alpha.syncwerk.com/seafhttp/files/2e1f7935-f004-4ddd-90f5-ae904a92999e/fewhfewf.csv"
                        }
                    },
                    "application/json - share link audit enable": {
                        "message": "",
                        "data": {
                            "token": "317861b41c8d475cbc7d",
                            "share_link_audit": True
                        }
                    }
                },
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
                description='Not found',
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
    @share_link_audit
    def get(self, request, fileshare, format=None):
        return view_shared_file(request, fileshare)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get shared file details (POST)',
        operation_description='''Get shared file details''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_='path',
                type='string',
                description='share token',
            ),
            openapi.Parameter(
                name='op',
                in_='query',
                type='string',
                description='op',
                required=True,
            ),
            openapi.Parameter(
                name='dl',
                in_='query',
                type='string',
                description='if this equals 1, then retrieve the download link',
                required=True
            ),
            openapi.Parameter(
                name='raw',
                in_="query",
                type='string',
                description='if this equals 1, then retrieve the raw data',
            ),
            openapi.Parameter(
                name='email',
                in_="formData",
                type='string',
                description='user email',
            ),
            openapi.Parameter(
                name='code',
                in_="formData",
                type='string',
                description='code',
            ),
            openapi.Parameter(
                name='password',
                in_="formData",
                type='string',
                description='password if the share is password protected',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully',
                examples={
                    'application/json - normal': {
                        "message": "",
                        "data": {
                            "share_link_audit": False,
                            "encoding": "utf-8",
                            "save_to_link": "/rest/share/link/save/?t=57a1604474dc47ab8081",
                            "file_name": "test.csv",
                            "password_protected": False,
                            "file_size": 38,
                            "file_encoding_list": [
                                "auto",
                                "utf-8",
                                "gbk",
                                "ISO-8859-1",
                                "ISO-8859-5"
                            ],
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "traffic_over_limit": False,
                            "use_pdfjs": True,
                            "download_link": "f/57a1604474dc47ab8081/",
                            "expire_date": "",
                            "raw_path": "https://alpha.syncwerk.com/seafhttp/files/d8d9ab76-232a-4be5-8569-02606b6baf82/test.csv",
                            "filetype": "Text",
                            "repo_name": "My Folder",
                            "path": "/test.csv",
                            "permissions": {
                                "can_edit": False,
                                "can_download": True
                            },
                            "err": "",
                            "obj_id": "b87120e9f12c263ea988990a24b2cc89a57845a9",
                            "access_token": "d8d9ab76-232a-4be5-8569-02606b6baf82",
                            "is_expired": False,
                            "fileext": "csv",
                            "file_content": "fewfwefwef,\nfewfewfewf,\nfewfwegtewtert",
                            "token": "57a1604474dc47ab8081",
                            "shared_by": {
                                "user_login_id": "",
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                "user_name": "admin",
                                "user_email": "admin@alpha.syncwerk.com"
                            }
                        }
                    },
                    'application/json - dl': {
                        "message": "",
                        "data": {
                            "dl_url": "https://alpha.syncwerk.com/seafhttp/files/2e1f7935-f004-4ddd-90f5-ae904a92999e/fewhfewf.csv"
                        }
                    },
                    'application/json - raw': {
                        "message": "",
                        "data": {
                            "raw_path": "https://alpha.syncwerk.com/seafhttp/files/2e1f7935-f004-4ddd-90f5-ae904a92999e/fewhfewf.csv"
                        }
                    },
                },
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
                description='Not found',
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
    @share_link_audit
    def post(self, request, fileshare, format=None):
        return view_shared_file(request, fileshare)


class SharedDirLinkView(APIView):
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get shared folder details',
        operation_description='''Get shared folder details''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_='path',
                type='string',
                description='share token',
            ),
            openapi.Parameter(
                name='p',
                in_='query',
                type='string',
                description='path of the folder',
            ),
            openapi.Parameter(
                name='mode',
                in_='query',
                type='string',
                description='"list" or "grid"',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "dir_name": "My Folder",
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "share_link_audit": False,
                            "thumbnail_size": 48,
                            "traffic_over_limit": False,
                            "is_expired": False,
                            "password_protected": False,
                            "dir_list": [
                                {
                                    "mtime": 1550568525,
                                    "type": "dir",
                                    "last_modified": "<time datetime=\"2019-02-19T09:28:45\" is=\"relative-time\" title=\"Tue, 19 Feb 2019 09:28:45 +0000\" >17 hours ago</time>",
                                    "obj_name": "fewfewf"
                                }
                            ],
                            "token": "4cf1bd0f37a04dd09bf6",
                            "ENABLE_THUMBNAIL": True,
                            "mode": "list",
                            "expire_date": "",
                            "file_list": [
                                {
                                    "type": "file",
                                    "last_modified": "<time datetime=\"2019-02-19T10:46:46\" is=\"relative-time\" title=\"Tue, 19 Feb 2019 10:46:46 +0000\" >16 hours ago</time>",
                                    "mtime": 1550573206,
                                    "obj_name": "email.csv",
                                    "encoded_thumbnail_src": None,
                                    "is_img": None,
                                    "file_size": 57,
                                    "is_video": None
                                },
                                {
                                    "type": "file",
                                    "last_modified": "<time datetime=\"2019-02-20T02:42:15\" is=\"relative-time\" title=\"Wed, 20 Feb 2019 02:42:15 +0000\" >35 minutes ago</time>",
                                    "mtime": 1550630535,
                                    "obj_name": "test.csv",
                                    "encoded_thumbnail_src": None,
                                    "is_img": None,
                                    "file_size": 38,
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
                                    "My Folder",
                                    "/"
                                ]
                            ],
                            "parent_dir": "/",
                            "repo_name": "My Folder"
                        }
                    },
                    "application/json - share link audit enable": {
                        "message": "",
                        "data": {
                            "token": "317861b41c8d475cbc7d",
                            "share_link_audit": True
                        }
                    }
                },
            ),
            404: openapi.Response(
                description='Not found',
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
    @share_link_audit
    def get(self, request, fileshare, format=None):
        return view_shared_dir(request, fileshare)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get shared folder details (POST)',
        operation_description='''Get shared folder details''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_='path',
                type='string',
                description='share token',
            ),
            openapi.Parameter(
                name='p',
                in_='query',
                type='string',
                description='path of the folder',
            ),
            openapi.Parameter(
                name='mode',
                in_='query',
                type='string',
                description='"list" or "grid"',
            ),
            openapi.Parameter(
                name='email',
                in_="formData",
                type='string',
                description='user email',
            ),
            openapi.Parameter(
                name='code',
                in_="formData",
                type='string',
                description='code',
            ),
            openapi.Parameter(
                name='password',
                in_="formData",
                type='string',
                description='password if the share is password protected',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "dir_name": "My Folder",
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "share_link_audit": False,
                            "thumbnail_size": 48,
                            "traffic_over_limit": False,
                            "is_expired": False,
                            "password_protected": False,
                            "dir_list": [
                                {
                                    "mtime": 1550568525,
                                    "type": "dir",
                                    "last_modified": "<time datetime=\"2019-02-19T09:28:45\" is=\"relative-time\" title=\"Tue, 19 Feb 2019 09:28:45 +0000\" >17 hours ago</time>",
                                    "obj_name": "fewfewf"
                                }
                            ],
                            "token": "4cf1bd0f37a04dd09bf6",
                            "ENABLE_THUMBNAIL": True,
                            "mode": "list",
                            "expire_date": "",
                            "file_list": [
                                {
                                    "type": "file",
                                    "last_modified": "<time datetime=\"2019-02-19T10:46:46\" is=\"relative-time\" title=\"Tue, 19 Feb 2019 10:46:46 +0000\" >16 hours ago</time>",
                                    "mtime": 1550573206,
                                    "obj_name": "email.csv",
                                    "encoded_thumbnail_src": None,
                                    "is_img": None,
                                    "file_size": 57,
                                    "is_video": None
                                },
                                {
                                    "type": "file",
                                    "last_modified": "<time datetime=\"2019-02-20T02:42:15\" is=\"relative-time\" title=\"Wed, 20 Feb 2019 02:42:15 +0000\" >35 minutes ago</time>",
                                    "mtime": 1550630535,
                                    "obj_name": "test.csv",
                                    "encoded_thumbnail_src": None,
                                    "is_img": None,
                                    "file_size": 38,
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
                                    "My Folder",
                                    "/"
                                ]
                            ],
                            "parent_dir": "/",
                            "repo_name": "My Folder"
                        }
                    }
                },
            ),
            404: openapi.Response(
                description='Not found',
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
    @share_link_audit
    def post(self, request, fileshare, format=None):
        return view_shared_dir(request, fileshare)


class SharedDirFileLinkView(APIView):
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='View file via shared folder link',
        operation_description='''View file via shared dir link''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_='path',
                type='string',
                description='share token',
            ),
            openapi.Parameter(
                name='path',
                in_='query',
                type='string',
                description='file path',
                required=True,
            ),
            openapi.Parameter(
                name='dl',
                in_='query',
                type='string',
                description='if this equals 1, then retrieve the download link',
                required=True
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully',
                examples={
                    'application/json - normal': {
                        "message": "",
                        "data": {
                            "share_link_audit": False,
                            "encoding": "utf-8",
                            "file_name": "email.csv",
                            "password_protected": False,
                            "file_size": 57,
                            "file_encoding_list": [
                                "auto",
                                "utf-8",
                                "gbk",
                                "ISO-8859-1",
                                "ISO-8859-5"
                            ],
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "traffic_over_limit": False,
                            "use_pdfjs": True,
                            "download_link": "d/4cf1bd0f37a04dd09bf6/",
                            "from_shared_dir": True,
                            "raw_path": "https://alpha.syncwerk.com/seafhttp/files/98289f2e-39e6-4e3e-8988-5c79cccb63e2/email.csv",
                            "filetype": "Text",
                            "repo_name": "My Folder",
                            "img_prev": None,
                            "zipped": [
                                [
                                    "My Folder",
                                    "/"
                                ],
                                [
                                    "email.csv",
                                    "/email.csv"
                                ]
                            ],
                            "img_next": None,
                            "path": "/email.csv",
                            "permissions": {
                                "can_edit": False,
                                "can_download": True
                            },
                            "err": "",
                            "obj_id": "7fd25d3e8f29ab775dc1411f4bae0df5b0e430de",
                            "access_token": "98289f2e-39e6-4e3e-8988-5c79cccb63e2",
                            "fileext": "csv",
                            "file_content": "test1@grr.la,\ntest2@grr.la,\ntest3@grr.la,\nfefewfew@uu.ll,",
                            "token": "4cf1bd0f37a04dd09bf6",
                            "shared_by": {
                                "user_login_id": "",
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                "user_name": "admin",
                                "user_email": "admin@alpha.syncwerk.com"
                            }
                        }
                    },
                    'application/json - dl': {
                        "message": "",
                        "data": {
                            "dl_url": "https://alpha.syncwerk.com/seafhttp/files/2e1f7935-f004-4ddd-90f5-ae904a92999e/fewhfewf.csv"
                        }
                    },
                },
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
                description='Not found',
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
    @share_link_audit
    def get(self, request, fileshare, format=None):
        return view_file_via_shared_dir(request, fileshare)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='View file via shared folder link (POST)',
        operation_description='''View file via shared dir link''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_='path',
                type='string',
                description='share token',
            ),
            openapi.Parameter(
                name='path',
                in_='query',
                type='string',
                description='file path',
                required=True,
            ),
            openapi.Parameter(
                name='dl',
                in_='query',
                type='string',
                description='if this equals 1, then retrieve the download link',
                required=True
            ),
            openapi.Parameter(
                name='email',
                in_="formData",
                type='string',
                description='user email',
            ),
            openapi.Parameter(
                name='code',
                in_="formData",
                type='string',
                description='code',
            ),
            openapi.Parameter(
                name='password',
                in_="formData",
                type='string',
                description='password if the share is password protected',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully',
                examples={
                    'application/json - normal': {
                        "message": "",
                        "data": {
                            "share_link_audit": False,
                            "encoding": "utf-8",
                            "file_name": "email.csv",
                            "password_protected": False,
                            "file_size": 57,
                            "file_encoding_list": [
                                "auto",
                                "utf-8",
                                "gbk",
                                "ISO-8859-1",
                                "ISO-8859-5"
                            ],
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "traffic_over_limit": False,
                            "use_pdfjs": True,
                            "download_link": "d/4cf1bd0f37a04dd09bf6/",
                            "from_shared_dir": True,
                            "raw_path": "https://alpha.syncwerk.com/seafhttp/files/98289f2e-39e6-4e3e-8988-5c79cccb63e2/email.csv",
                            "filetype": "Text",
                            "repo_name": "My Folder",
                            "img_prev": None,
                            "zipped": [
                                [
                                    "My Folder",
                                    "/"
                                ],
                                [
                                    "email.csv",
                                    "/email.csv"
                                ]
                            ],
                            "img_next": None,
                            "path": "/email.csv",
                            "permissions": {
                                "can_edit": False,
                                "can_download": True
                            },
                            "err": "",
                            "obj_id": "7fd25d3e8f29ab775dc1411f4bae0df5b0e430de",
                            "access_token": "98289f2e-39e6-4e3e-8988-5c79cccb63e2",
                            "fileext": "csv",
                            "file_content": "test1@grr.la,\ntest2@grr.la,\ntest3@grr.la,\nfefewfew@uu.ll,",
                            "token": "4cf1bd0f37a04dd09bf6",
                            "shared_by": {
                                "user_login_id": "",
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                "user_name": "admin",
                                "user_email": "admin@alpha.syncwerk.com"
                            }
                        }
                    },
                    'application/json - dl': {
                        "message": "",
                        "data": {
                            "dl_url": "https://alpha.syncwerk.com/seafhttp/files/2e1f7935-f004-4ddd-90f5-ae904a92999e/fewhfewf.csv"
                        }
                    },
                    "application/json - share link audit enable": {
                        "message": "",
                        "data": {
                            "token": "317861b41c8d475cbc7d",
                            "share_link_audit": True
                        }
                    }
                },
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
                description='Not found',
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
    @share_link_audit
    def post(self, request, fileshare, format=None):
        return view_file_via_shared_dir(request, fileshare)


def recursive_dir_files_only(repo_id, dir_id, fileshare, full_dir_path, repo):
    dir_files = syncwerk_api.list_dir_by_dir_id(repo_id, dir_id)
    urls = []
    for node in dir_files:
        name, ext = os.path.splitext(node.obj_name)
        full_name = posixpath.join(full_dir_path, name + ext)
        if not stat.S_ISDIR(node.mode):
            dl_token = syncwerk_api.get_fileserver_access_token(repo.id,
                                                                node.obj_id, 'download-link', fileshare.username,
                                                                use_onetime=False)

            if not dl_token:
                return api_error(code=status.HTTP_404_NOT_FOUND, msg=_(u'Unable to download file.'))
            urls.append(gen_file_get_url(dl_token, full_name.strip('/').replace('/', '_')))
        else:
            dir_files = recursive_dir_files_only(repo_id, node.obj_id, fileshare, full_name, repo)
            urls += dir_files
    return urls


def isUserAuthenticated(request):
    key = request.COOKIES.get('token')

    if not key:
        return False
    if ' ' in key:
        return False

    try:
        token = Token.objects.get(key=key)
    except Token.DoesNotExist:
        return False

    try:
        username = Profile.objects.get_username_by_login_id(token.user)
        if username is None:
            email = token.user
        else:
            email = username
        user = User.objects.get(email=email)
        if not user.is_active:
            return False
        return True
    except User.DoesNotExist:
        return False


class BatchSharedDirView(APIView):
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Batch download shared directories',
        operation_description='''Batch download shared directories''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_='path',
                type='string',
                description='share token',
            ),
            openapi.Parameter(
                name='path',
                in_='query',
                type='string',
                description='file path',
                required=True,
            ),
            openapi.Parameter(
                name='dl',
                in_='query',
                type='string',
                description='if this equals 1, then retrieve the download link',
                required=True
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully',
                examples={
                    'application/json - normal': {
                        "message": "",
                        "data": {
                            "share_link_audit": False,
                            "encoding": "utf-8",
                            "file_name": "email.csv",
                            "password_protected": False,
                            "file_size": 57,
                            "file_encoding_list": [
                                "auto",
                                "utf-8",
                                "gbk",
                                "ISO-8859-1",
                                "ISO-8859-5"
                            ],
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "traffic_over_limit": False,
                            "use_pdfjs": True,
                            "download_link": "d/4cf1bd0f37a04dd09bf6/",
                            "from_shared_dir": True,
                            "raw_path": "https://alpha.syncwerk.com/seafhttp/files/98289f2e-39e6-4e3e-8988-5c79cccb63e2/email.csv",
                            "filetype": "Text",
                            "repo_name": "My Folder",
                            "img_prev": None,
                            "zipped": [
                                [
                                    "My Folder",
                                    "/"
                                ],
                                [
                                    "email.csv",
                                    "/email.csv"
                                ]
                            ],
                            "img_next": None,
                            "path": "/email.csv",
                            "permissions": {
                                "can_edit": False,
                                "can_download": True
                            },
                            "err": "",
                            "obj_id": "7fd25d3e8f29ab775dc1411f4bae0df5b0e430de",
                            "access_token": "98289f2e-39e6-4e3e-8988-5c79cccb63e2",
                            "fileext": "csv",
                            "file_content": "test1@grr.la,\ntest2@grr.la,\ntest3@grr.la,\nfefewfew@uu.ll,",
                            "token": "4cf1bd0f37a04dd09bf6",
                            "shared_by": {
                                "user_login_id": "",
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                "user_name": "admin",
                                "user_email": "admin@alpha.syncwerk.com"
                            }
                        }
                    },
                    'application/json - dl': {
                        "message": "",
                        "data": {
                            "dl_url": "https://alpha.syncwerk.com/seafhttp/files/2e1f7935-f004-4ddd-90f5-ae904a92999e/fewhfewf.csv"
                        }
                    },
                },
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
                description='Not found',
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
    @share_link_audit
    def get(self, request, fileshare, format=None):
        allowFoldersInBatch = getattr(config, 'ALLOW_FOLDERS_IN_BATCH')
        batchMaxFilesCount = getattr(config, 'BATCH_MAX_FILES_COUNT')
        if is_pro_version() and settings.ENABLE_SHARE_LINK_AUDIT:
            if not isUserAuthenticated(request) and \
                not request.session.get('anonymous_email'):
                # if anonymous user has passed email code check,
                # then his/her email info will be in session.

                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)


        req_path = request.GET.get('path', None)
        if not req_path:
            error_msg = 'path invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # recourse check
        # return api_response(data={'link': share_link_token})
        # fileshare = FileShare.objects.get_valid_dir_link_by_token(share_link_token)
        if not fileshare:
            error_msg = 'share_link_token %s not found.' % fileshare.token
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if req_path[-1] != '/':
            req_path += '/'

        if req_path == '/':
            real_path = fileshare.path
        else:
            real_path = posixpath.join(fileshare.path, req_path.lstrip('/'))

        if real_path[-1] != '/':
            real_path += '/'

        repo_id = fileshare.repo_id
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)
        download_urls = []
        shared_by = fileshare.username
        dirent_name_list = request.GET.getlist('dirents', None)
        if not dirent_name_list:
            error_msg = 'dirents invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if len(dirent_name_list) == 0:
            error_msg = 'dirents invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
        for dirent_name in dirent_name_list:
            dirent_name = dirent_name.strip('/')
            full_dir_path = posixpath.join(real_path, dirent_name)
            filename = os.path.basename(full_dir_path)
            obj_id = syncwerk_api.get_dir_id_by_path(repo_id, full_dir_path)
            if not obj_id:
                obj_id = syncwerk_api.get_file_id_by_path(repo.id, full_dir_path)
                if not obj_id:
                # messages.error(request, _(u'Unable to download file, wrong file path'))
                # return HttpResponseRedirect(next)
                    return api_error(code=status.HTTP_400_BAD_REQUEST, msg=_(u'Unable to download file, wrong file path'))
                if user_traffic_over_limit(fileshare.username):
                # messages.error(request, _(u'Unable to download file, share link traffic is used up.'))
                # return HttpResponseRedirect(next)
                     return api_error(code=status.HTTP_404_NOT_FOUND,
                                 msg=_(u'Unable to download file, share link traffic is used up.'))
                send_file_access_msg(request, repo, real_path, 'share-link')
                try:
                     file_size = syncwerk_api.get_file_size(repo.store_id, repo.version,
                                                       obj_id)
                     send_message('restapi.stats', 'file-download\t%s\t%s\t%s\t%s' %
                             (repo.id, shared_by, obj_id, file_size))
                except Exception as e:
                    logger.error('Error when sending file-download message: %s' % str(e))
                dl_token = syncwerk_api.get_fileserver_access_token(repo.id,
                                                                obj_id, 'download-link', fileshare.username,
                                                                use_onetime=False)

                if not dl_token:
                    return api_error(code=status.HTTP_404_NOT_FOUND, msg=_(u'Unable to download file.'))
                download_urls.append(gen_file_get_url(dl_token, filename))
            else:
                if str(allowFoldersInBatch) != '1':
                    return api_error(status.HTTP_404_NOT_FOUND, _(u"Folders aren't allowed in batch download")+str(allowFoldersInBatch))
                dir_files = recursive_dir_files_only(repo_id, obj_id, fileshare, full_dir_path, repo)
                download_urls += dir_files
            if len(download_urls) > batchMaxFilesCount:
                return api_error(status.HTTP_404_NOT_FOUND, _(u'A lot of files selected for batch download, maximum allowed')+':{}'.format(batchMaxFilesCount))
        if len(download_urls) > batchMaxFilesCount:
            return api_error(status.HTTP_404_NOT_FOUND, _(u'A lot of files selected for batch download, maximum allowed')+':{}'.format(batchMaxFilesCount))

        resp = {
            'urls': download_urls,

        }
        return api_response(data=resp)


class SharedUploadLinkView(APIView):
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='View share upload link',
        operation_description='''View share upload link''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_='path',
                type='string',
                description='share token',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully',
                examples={
                    'application/json - normal': {
                        "message": "",
                        "data": {
                            "enable_upload_folder": True,
                            "share_link_audit": False,
                            "password_protected": False,
                            "enable_resumable_fileupload": False,
                            "path": "/",
                            "max_number_of_files_for_fileupload": 500,
                            "dir_name": "My Folder",
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "no_quota": False,
                            "max_upload_file_size": 209715200,
                            "token": "317861b41c8d475cbc7d",
                            "shared_by": {
                                "user_login_id": "",
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                "user_name": "admin",
                                "user_email": "admin@alpha.syncwerk.com"
                            },
                            "repo_name": "My Folder"
                        }
                    },
                    "application/json - share link audit enable": {
                        "message": "",
                        "data": {
                            "token": "317861b41c8d475cbc7d",
                            "share_link_audit": True
                        }
                    }
                },
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
                description='Not found',
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
    @share_link_audit
    def get(self, request, uploadlink, format=None):
        return view_shared_upload_link(request, uploadlink)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='View share upload link (POST)',
        operation_description='''View share upload link''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_='path',
                type='string',
                description='share token',
            ),
            openapi.Parameter(
                name='email',
                in_="formData",
                type='string',
                description='user email',
            ),
            openapi.Parameter(
                name='code',
                in_="formData",
                type='string',
                description='code',
            ),
            openapi.Parameter(
                name='password',
                in_="formData",
                type='string',
                description='password if the share is password protected',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully',
                examples={
                    'application/json - normal': {
                        "message": "",
                        "data": {
                            "enable_upload_folder": True,
                            "share_link_audit": False,
                            "password_protected": False,
                            "enable_resumable_fileupload": False,
                            "path": "/",
                            "max_number_of_files_for_fileupload": 500,
                            "dir_name": "My Folder",
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "no_quota": False,
                            "max_upload_file_size": 209715200,
                            "token": "317861b41c8d475cbc7d",
                            "shared_by": {
                                "user_login_id": "",
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                "user_name": "admin",
                                "user_email": "admin@alpha.syncwerk.com"
                            },
                            "repo_name": "My Folder"
                        }
                    },
                },
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
                description='Not found',
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
    @share_link_audit
    def post(self, request, uploadlink, format=None):
        return view_shared_upload_link(request, uploadlink)


class ShareLinkAuditView(APIView):
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Send share audit email',
        operation_description='''Generate a token, and record that token with email in cache, expires in one hour, send token to that email address.
        User provide token and email at share link page, if the token and email are valid, record that email in session.''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_='formData',
                type='string',
                description='share token',
                required=True,
            ),
            openapi.Parameter(
                name='email',
                in_="formData",
                type='string',
                description='user email',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully',
                examples={
                    'application/json - normal': {
                        "message": "",
                        "data": {
                            "enable_upload_folder": True,
                            "share_link_audit": False,
                            "password_protected": False,
                            "enable_resumable_fileupload": False,
                            "path": "/",
                            "max_number_of_files_for_fileupload": 500,
                            "dir_name": "My Folder",
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "no_quota": False,
                            "max_upload_file_size": 209715200,
                            "token": "317861b41c8d475cbc7d",
                            "shared_by": {
                                "user_login_id": "",
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                "user_name": "admin",
                                "user_email": "admin@alpha.syncwerk.com"
                            },
                            "repo_name": "My Folder"
                        }
                    },
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
    def post(self, request, format=None):
        token = request.POST.get('token')
        email = request.POST.get('email')
        if not is_valid_email(email):
            return api_error(status.HTTP_400_BAD_REQUEST, msg=_('Email address is not valid'))

        dfs = FileShare.objects.get_valid_file_link_by_token(token)
        ufs = UploadLinkShare.objects.get_valid_upload_link_by_token(token)

        fs = dfs if dfs else ufs
        if fs is None:
            if not KanbanShareLink.objects.filter(token=token).exists():
                return api_error(status.HTTP_400_BAD_REQUEST, msg=_('Share link is not found'))

        cache_key = normalize_cache_key(email, 'share_link_audit_')
        timeout = 60 * 60           # one hour
        code = gen_token(max_length=6)
        cache.set(cache_key, code, timeout)

        # send code to user via email
        subject = _("Verification code for visiting share links")
        c = {
            'code': code,
        }
        try:
            send_html_email_with_dj_template(
                email, dj_template='share/audit_code_email.html',
                context=c, subject=subject, priority=MAIL_PRIORITY.now,
                request=request
            )
            return api_response(msg=_("Verification code has sent to your email successfully."))
        except Exception as e:
            logger.error('Failed to send audit code via email to %s')
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, msg=_('Failed to send a verification code, please try again later.'))
