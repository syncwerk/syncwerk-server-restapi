from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.utils.file import _file_view

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class FilePreviewView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get file preview',
        operation_description='''Get file data for preview''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='folder id.',
            ),
            openapi.Parameter(
                name='p',
                in_="path",
                type='string',
                description='path to the file.',
                required=True,
            ),
            openapi.Parameter(
                name='raw',
                in_="query",
                type='string',
                description='1 or 0. Api will response with the raw data like below',
            ),
            openapi.Parameter(
                name='dl',
                in_="query",
                type='string',
                description='1 or 0. Api will response with the download data like below',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Preview info retrived successfully.',
                examples={
                    'application/json - normal': {
                        "message": "",
                        "data": {
                            "img_next": None,
                            "latest_contributor": "admin@alpha.syncwerk.com",
                            "domain": "alpha.syncwerk.com",
                            "protocol": "https",
                            "fileshare": None,
                            "current_commit": {
                                "commit_id": "d81996b7cfecf6c22e47e1d414fb1ee40f0e4f74",
                                "contact_email": "admin@alpha.syncwerk.com",
                                "name": "admin",
                                "time": "2019-02-19T09:57:44+00:00",
                                "client_version": None,
                                "device_name": None,
                                "email": "admin@alpha.syncwerk.com",
                                "description": "Added \"My Post.jpg\"."
                            },
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
                            "last_commit_id": "d81996b7cfecf6c22e47e1d414fb1ee40f0e4f74",
                            "last_modified": 1548314320,
                            "highlight_keyword": False,
                            "path": "/email.csv",
                            "is_starred": True,
                            "user_perm": "rw",
                            "file_locked": False,
                            "file_perm": "rw",
                            "file_encoding_list": [
                                "auto",
                                "utf-8",
                                "gbk",
                                "ISO-8859-1",
                                "ISO-8859-5"
                            ],
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "err": "",
                            "obj_id": "96030283fc3f5f6112efaf65f076b55e449cb7f5",
                            "file_content": "test1@grr.la,\ntest2@grr.la,\ntest3@grr.la,\n",
                            "file_shared_link": "",
                            "use_pdfjs": True,
                            "encoding": "utf-8",
                            "img_prev": None,
                            "filename": "email.csv",
                            "fileext": "csv",
                            "can_edit_file": True,
                            "parent_dir": "/",
                            "file_enc": "auto",
                            "can_lock_unlock_file": True,
                            "is_pro": True,
                            "locked_by_me": False,
                            "raw_path": "https://alpha.syncwerk.com/seafhttp/files/648cf5e3-9f47-461d-803f-62adf8d3f264/email.csv",
                            "filetype": "Text",
                            "is_repo_owner": 1,
                            "repo_name": "My Folder",
                            'repo_encrypted': True,
                        }
                    },
                    'application/json - raw': {
                        "message": "",
                        "data": {
                            "fileext": "csv",
                            "path": "/email.csv",
                            "filetype": "Text",
                            "raw_url": "https://alpha.syncwerk.com/seafhttp/files/faddd9e3-cb41-42a8-8f25-47488da3c61a/email.csv",
                            "filename": "email.csv"
                        }
                    },
                    'application/json - dl': {
                        "message": "",
                        "data": {
                            "dl_url": "https://alpha.syncwerk.com/seafhttp/files/6ff68b93-8f28-42e5-a319-904eb5730d94/email.csv"
                        }
                    },
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
            404: openapi.Response(
                description='File not found',
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
        
        path = request.GET.get('p', None)
        return _file_view(request, repo_id, path)
