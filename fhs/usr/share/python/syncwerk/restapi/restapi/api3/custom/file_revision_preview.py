from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.utils.file import view_history_file_common

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class FileRevisionPreview(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get file revision preview',
        operation_description='''Get preivew of a specific revision of the file''',
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
                name='commit_id',
                in_="query",
                type='string',
                description='commit id',
                required=True,
            ),
            openapi.Parameter(
                name='obj_id',
                in_="query",
                type='string',
                description='revision object id',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Revison list retrived successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "err": "",
                            "encoding": "utf-8",
                            "file_content": "test1@grr.la,\ntest2@grr.la,\ntest3@grr.la,\n",
                            "file_name": "email.csv",
                            "filetype": "Text",
                            "obj_id": "96030283fc3f5f6112efaf65f076b55e449cb7f5",
                            "current_commit": {
                                "commit_id": "ea4cf7770857da7a08dde837e4eb90fc23476eab",
                                "contact_email": "admin@alpha.syncwerk.com",
                                "name": "admin",
                                "time": "2019-01-24T07:18:40+00:00",
                                "client_version": None,
                                "device_name": None,
                                "email": "admin@alpha.syncwerk.com",
                                "description": "Added \"email.csv\"."
                            },
                            "fileext": "csv",
                            "file_enc": "auto",
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
                            "path": "/email.csv",
                            "repo_name": "My Folder",
                            "raw_path": "https://alpha.syncwerk.com/seafhttp/files/61eca233-bf4b-4385-83f8-7aac8d931854/email.csv",
                            "use_pdfjs": True,
                            "file_encoding_list": [
                                "auto",
                                "utf-8",
                                "gbk",
                                "ISO-8859-1",
                                "ISO-8859-5"
                            ]
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
        return view_history_file_common(request, repo_id)
