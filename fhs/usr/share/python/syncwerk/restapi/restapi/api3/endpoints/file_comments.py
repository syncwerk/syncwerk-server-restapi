# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from synserv import syncwerk_api
from pyrpcsyncwerk import RpcsyncwerkError

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.permissions import IsRepoAccessible
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response, user_to_dict
from restapi.avatar.settings import AVATAR_DEFAULT_SIZE
from restapi.base.models import FileComment
from restapi.utils.repo import get_repo_owner
from restapi.signals import comment_file_successful

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class FileCommentsView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, IsRepoAccessible)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get file comments',
        operation_description='''Get all comments of a file''',
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
                name='avatar_size',
                in_="query",
                type='string',
                description='avatar size',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Comment list retrived successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "comments": [
                                {
                                    "comment": "fdefewf",
                                    "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                    "item_name": "email.csv",
                                    "created_at": "2019-02-19T10:49:54+00:00",
                                    "parent_path": "/",
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                    "user_login_id": "",
                                    "user_name": "admin",
                                    "id": 1,
                                    "user_email": "admin@alpha.syncwerk.com"
                                }
                            ]
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
    def get(self, request, repo_id, format=None):
        
        path = request.GET.get('p', '/').rstrip('/')
        if not path:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Wrong path.')

        try:
            avatar_size = int(request.GET.get('avatar_size',
                                              AVATAR_DEFAULT_SIZE))
        except ValueError:
            avatar_size = AVATAR_DEFAULT_SIZE

        comments = []
        for o in FileComment.objects.get_by_file_path(repo_id, path):
            comment = o.to_dict()
            comment.update(user_to_dict(o.author, request=request,
                                        avatar_size=avatar_size))
            comments.append(comment)

        # return Response({
        #     "comments": comments,
        # })
        resp = {
            "comments": comments,
        }
        return api_response(data=resp)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Comment on file',
        operation_description='''Post a new comment for the file''',
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
                name='comment',
                in_="formData",
                type='string',
                description='comment content',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Comment list retrived successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "comment": "dfewfew",
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "item_name": "email.csv",
                            "created_at": "2019-02-19T10:52:10+00:00",
                            "parent_path": "/",
                            "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                            "user_login_id": "",
                            "user_name": "admin",
                            "id": 2,
                            "user_email": "admin@alpha.syncwerk.com"
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
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid",
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
    def post(self, request, repo_id, format=None):
        path = request.GET.get('p', '/').rstrip('/')
        if not path:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Wrong path.')

        try:
            avatar_size = int(request.GET.get('avatar_size',
                                              AVATAR_DEFAULT_SIZE))
        except ValueError:
            avatar_size = AVATAR_DEFAULT_SIZE

        try:
            obj_id = syncwerk_api.get_file_id_by_path(repo_id,
                                                     path)
        except RpcsyncwerkError as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Internal error.')
        if not obj_id:
            return api_error(status.HTTP_404_NOT_FOUND, 'File not found.')

        comment = request.data.get('comment', '')
        if not comment:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Comment can not be empty.')

        username = request.user.username
        o = FileComment.objects.add_by_file_path(
            repo_id=repo_id, file_path=path, author=username, comment=comment)
        repo = syncwerk_api.get_repo(repo_id)
        repo_owner = get_repo_owner(request, repo.id)
        comment_file_successful.send(sender=None,
                                     repo=repo,
                                     repo_owner=repo_owner,
                                     file_path=path,
                                     comment=comment,
                                     author=username)

        comment = o.to_dict()
        comment.update(user_to_dict(request.user.username, request=request,
                                    avatar_size=avatar_size))
        # return Response(comment, status=201)
        return api_response(code=status.HTTP_201_CREATED, data=comment)
